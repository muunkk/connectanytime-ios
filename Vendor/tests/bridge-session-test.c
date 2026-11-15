/* Tests the saved session through the real Tunnel/ocbridge.c, compiled for the Mac by
 * scripts/test-strap-cookie.sh, against a server in this process that enforces the
 * session's STRAP key the way the ASA appears to: each CONNECT's Verify header must be
 * signed by the key the server holds for the session, and the server then holds the key
 * that CONNECT presented. A CONNECT that fails that gets 401, as a rejoin from a session
 * saved at login did on the phone.
 *
 * That the real ASA works like this is an assumption, as is that its 401 for a key it
 * doesn't hold leaves the session open. What this shows is that, against such a server,
 * a fresh ocb_resume from ocb_session_saved's snapshot is accepted after a login, after
 * every reconnect, and after a CONNECT that went unanswered (through the candidate);
 * that the snapshot can be read while ocb_run reconnects; and that what the bridge's
 * save handler has stored rejoins the session at any moment, including while a
 * reconnect is still waiting for the server's answer.
 *
 * Prints key fingerprints only, never a cookie. */
#include <Security/Security.h>
/* The server below has a self-signed certificate: trust it. Everything else in the
 * bridge's certificate callback runs as on the phone. */
#define SecTrustEvaluateWithError(trust, error) ((void)(trust), (void)(error), true)
#ifdef WITHOUT_STRAP_PATCH
/* The negative control: OpenConnect without openconnect-strap-cookie.patch, to show
 * that the first check below fails there. All the bridge lacks to compile is the
 * function the patch adds; without the patch there is no candidate cookie. */
struct openconnect_info;
static char *openconnect_strap_candidate_cookie(struct openconnect_info *vpninfo)
{
	(void)vpninfo;
	return NULL;
}
typedef void (*openconnect_session_changed_vfn)(void *privdata);
static void openconnect_set_session_changed_handler(struct openconnect_info *vpninfo,
						    openconnect_session_changed_vfn handler)
{
	(void)vpninfo; (void)handler;
}
#endif
#include "ocbridge.c"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int failures;
#define CHECK(cond, what) do { \
	if (cond) printf("ok   %s\n", what); \
	else { printf("FAIL %s (line %d)\n", what, __LINE__); failures++; } } while (0)

/* The server. */

/* What a CONNECT gets. LOSE_REPLY: the server takes the key, and the connection drops
 * before its answer. LOSE_REQUEST: it drops before the server sees the request. HOLD: the
 * server takes the key and then says nothing, the connection left open. HOLD_AFTER_200:
 * it answers 200 and stops mid-headers, likewise. DECLINE: it answers 503 and keeps the
 * key it had. DECLINE_TAKEN: it takes the key, then answers 503. */
enum { ACCEPT, DROP_AFTER_200, LOSE_REPLY, LOSE_REQUEST, HOLD, HOLD_AFTER_200, DECLINE, DECLINE_TAKEN };
static pthread_mutex_t server_lock = PTHREAD_MUTEX_INITIALIZER;
static EVP_PKEY *held;              /* the STRAP public key the server holds for the session */
static char held_fp[17] = "none";
static int next_action = ACCEPT;    /* what the next `next_count` CONNECTs get; then back to ACCEPT */
static int next_count;
static int connects, refused;
static int holding;                 /* connections the server has gone quiet on, ever */
static _Atomic int hold_generation; /* bumped to let them go */
static SSL_CTX *server_ctx;
static int port;

/* The Keychain, as the provider keeps it: the session saved when ocb_connect returns,
 * and from then on by the bridge's save handler, on OpenConnect's thread. And as it
 * was before that handler: saved again only once a reconnect had completed. */
struct saved { char *url, *cookie, *dnsname, *ip, *candidate; };
static pthread_mutex_t keep_lock = PTHREAD_MUTEX_INITIALIZER;
static struct saved kept, kept_after_reconnect;
static int saves;
static int in_run;                  /* ocb_run is on: the server checks what it's handed */
static int new_keys, unsaved_keys;  /* new keys the server took in a run; those not saved first */
static void cookie_key(const char *cookie, char out[17]);

static void fingerprint(const unsigned char *der, int len, char out[17])
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	SHA256(der, len, md);
	for (int i = 0; i < 8; i++) sprintf(out + 2 * i, "%02x", md[i]);
}

static unsigned char *unbase64(const char *b64, int *len)
{
	int n = (int)strlen(b64), pad = 0;
	unsigned char *out = malloc(n + 4);
	while (n > 0 && b64[n - 1 - pad] == '=') pad++;
	int got = EVP_DecodeBlock(out, (const unsigned char *)b64, n);
	if (got < 0) { free(out); return NULL; }
	*len = got - pad;
	return out;
}

/* The value of a request header, copied; NULL if absent. */
static char *header(const char *request, const char *name)
{
	size_t n = strlen(name);
	for (const char *line = strstr(request, "\r\n"); line; line = strstr(line + 2, "\r\n")) {
		line += 2;
		if (!strncasecmp(line, name, n) && line[n] == ':') {
			const char *v = line + n + 1;
			while (*v == ' ') v++;
			return strndup(v, strcspn(v, "\r\n"));
		}
		line -= 2;
	}
	return NULL;
}

/* Does `sig` (base64) verify, with the key the server holds, over this TLS session's
 * channel binding and the presented public key? As OpenConnect's append_strap_verify signs. */
static int strap_verifies(SSL *ssl, const unsigned char *pub, int publen, const char *sig_b64)
{
	unsigned char binding[32];
	int siglen = 0, ok = 0;
	unsigned char *sig = unbase64(sig_b64, &siglen);
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (sig && held && SSL_version(ssl) == TLS1_3_VERSION &&
	    SSL_export_keying_material(ssl, binding, sizeof binding, "EXPORTER-Channel-Binding", 24, NULL, 0, 0) == 1)
		ok = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, held) > 0 &&
		     EVP_DigestVerifyUpdate(md, binding, sizeof binding) > 0 &&
		     EVP_DigestVerifyUpdate(md, pub, publen) > 0 &&
		     EVP_DigestVerifyFinal(md, sig, siglen) == 1;
	EVP_MD_CTX_free(md);
	free(sig);
	return ok;
}

static void hold(const unsigned char *pub, int publen)
{
	const unsigned char *p = pub;
	EVP_PKEY_free(held);
	held = d2i_PUBKEY(NULL, &p, publen);
	fingerprint(pub, publen, held_fp);
}

static const char LOGIN_OK[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config-auth client=\"vpn\" type=\"complete\">"
	"<auth id=\"success\"><message>ok</message></auth>"
	"<session-token>FAKESESSION</session-token></config-auth>\n";
static const char CONNECT_OK[] =
	"HTTP/1.1 200 OK\r\nX-CSTP-Version: 1\r\nX-CSTP-Address: 10.9.0.2\r\n"
	"X-CSTP-Netmask: 255.255.255.0\r\nX-CSTP-MTU: 1300\r\nX-CSTP-DPD: 300\r\n"
	"X-CSTP-Keepalive: 300\r\n\r\n";
static const char REFUSED[] = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
static const char UNAVAILABLE[] =
	"HTTP/1.1 503 Service Unavailable\r\nX-Reason: testing\r\nContent-Length: 0\r\n\r\n";
static const char CONNECT_OK_UNFINISHED[] = "HTTP/1.1 200 OK\r\nX-CSTP-Version: 1\r\n";

/* Says nothing more on this connection, and leaves it open, until let go. */
static void go_quiet(void)
{
	int generation = hold_generation;
	pthread_mutex_lock(&server_lock);
	holding++;
	pthread_mutex_unlock(&server_lock);
	while (hold_generation == generation) usleep(10000);
}

/* One request's head (and body, read and dropped), or NULL when the client is gone. */
static char *read_request(SSL *ssl)
{
	char *req = calloc(1, 65536);
	int len = 0, n;
	char *end;
	while (!(end = strstr(req, "\r\n\r\n"))) {
		if (len >= 65535 || (n = SSL_read(ssl, req + len, 65535 - len)) <= 0) { free(req); return NULL; }
		len += n;
	}
	char *cl = header(req, "Content-Length");
	int want = cl ? atoi(cl) : 0, have = len - (int)(end + 4 - req);
	free(cl);
	char sink[4096];
	while (have < want && (n = SSL_read(ssl, sink, sizeof sink)) > 0) have += n;
	end[4] = 0;
	return req;
}

static void *serve(void *arg)
{
	SSL *ssl = arg;
	char *req = NULL;
	if (SSL_accept(ssl) <= 0) goto out;
	while ((req = read_request(ssl))) {
		char *pub_b64 = header(req, "X-AnyConnect-STRAP-Pubkey");
		int publen = 0;
		unsigned char *pub = pub_b64 ? unbase64(pub_b64, &publen) : NULL;
		if (!strncmp(req, "POST ", 5)) {
			/* A login: the session starts with the key these requests present. */
			pthread_mutex_lock(&server_lock);
			if (pub) hold(pub, publen);
			pthread_mutex_unlock(&server_lock);
			char head[128];
			snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %zu\r\n\r\n",
				 sizeof LOGIN_OK - 1);
			SSL_write(ssl, head, (int)strlen(head));
			SSL_write(ssl, LOGIN_OK, sizeof LOGIN_OK - 1);
		} else if (!strncmp(req, "CONNECT ", 8)) {
			char *sig = header(req, "X-AnyConnect-STRAP-Verify"), *cookie = header(req, "Cookie");
			pthread_mutex_lock(&server_lock);
			int action = next_count > 0 ? next_action : ACCEPT;
			if (next_count > 0) next_count--;
			connects++;
			int ok = pub && sig && cookie && !strcmp(cookie, "webvpn=FAKESESSION") &&
				 strap_verifies(ssl, pub, publen, sig);
			if (!ok) refused++;
			if (ok && action != LOSE_REQUEST && action != DECLINE) {
				char was[17], now[17];
				strcpy(was, held_fp);
				hold(pub, publen);
				strcpy(now, held_fp);
				/* A key the server didn't hold before: in a run, the client must
				 * have saved it already, before it sent this request. */
				pthread_mutex_lock(&keep_lock);
				if (in_run && strcmp(was, now)) {
					char saved_key[17], saved_candidate[17];
					cookie_key(kept.cookie, saved_key);
					cookie_key(kept.candidate, saved_candidate);
					new_keys++;
					if (strcmp(now, saved_key) && strcmp(now, saved_candidate)) unsaved_keys++;
				}
				pthread_mutex_unlock(&keep_lock);
			}
			pthread_mutex_unlock(&server_lock);
			free(sig); free(cookie); free(pub); free(pub_b64); free(req);
			if (action == LOSE_REQUEST || (ok && action == LOSE_REPLY)) goto out; /* no answer */
			if (!ok) { SSL_write(ssl, REFUSED, sizeof REFUSED - 1); goto out; }
			if (action == DECLINE || action == DECLINE_TAKEN) { SSL_write(ssl, UNAVAILABLE, sizeof UNAVAILABLE - 1); goto out; }
			if (action == HOLD) { go_quiet(); goto out; }
			if (action == HOLD_AFTER_200) {
				SSL_write(ssl, CONNECT_OK_UNFINISHED, sizeof CONNECT_OK_UNFINISHED - 1);
				go_quiet();
				goto out;
			}
			SSL_write(ssl, CONNECT_OK, sizeof CONNECT_OK - 1);
			if (action == DROP_AFTER_200) { usleep(300000); goto out; }
			char sink[4096];
			while (SSL_read(ssl, sink, sizeof sink) > 0) {} /* the tunnel, until the client closes it */
			goto out;
		} else {
			static const char nope[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
			SSL_write(ssl, nope, sizeof nope - 1);
		}
		free(pub); free(pub_b64); free(req);
	}
out:;
	int fd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(fd);
	return NULL;
}

static void *listener(void *arg)
{
	int lfd = (int)(intptr_t)arg;
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) continue;
		SSL *ssl = SSL_new(server_ctx);
		SSL_set_fd(ssl, fd);
		pthread_t t;
		pthread_create(&t, NULL, serve, ssl);
		pthread_detach(t);
	}
	return NULL;
}

static void start_server(void)
{
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = X509_new();
	X509_NAME *name = X509_get_subject_name(cert);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
	X509_set_pubkey(cert, key);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"127.0.0.1", -1, -1, 0);
	X509_set_issuer_name(cert, name);
	X509_sign(cert, key, EVP_sha256());
	server_ctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION);
	SSL_CTX_use_certificate(server_ctx, cert);
	SSL_CTX_use_PrivateKey(server_ctx, key);

	int lfd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t len = sizeof addr;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) || listen(lfd, 16) ||
	    getsockname(lfd, (struct sockaddr *)&addr, &len)) { perror("server"); exit(2); }
	port = ntohs(addr.sin_port);
	pthread_t t;
	pthread_create(&t, NULL, listener, (void *)(intptr_t)lfd);
	pthread_detach(t);
}

static void server_next(int action, int count)
{
	pthread_mutex_lock(&server_lock);
	next_action = action;
	next_count = count;
	pthread_mutex_unlock(&server_lock);
}

static void server_key(char out[17])
{
	pthread_mutex_lock(&server_lock);
	strcpy(out, held_fp);
	pthread_mutex_unlock(&server_lock);
}

static int server_count(const int *counter)
{
	pthread_mutex_lock(&server_lock);
	int n = *counter;
	pthread_mutex_unlock(&server_lock);
	return n;
}

/* The client: the bridge, called as PacketTunnelProvider calls it. */

/* What the provider saves. */
static int take_saved(ocb_session *s, struct saved *out)
{
	ocb_saved now;
	memset(out, 0, sizeof *out);
	if (ocb_session_saved(s, &now)) return -1;
	out->url = now.url; out->cookie = now.cookie; out->dnsname = now.dnsname;
	out->ip = now.ip; out->candidate = now.candidate;
	return 0;
}

static void drop_saved(struct saved *v)
{
	free(v->url); free(v->cookie); free(v->dnsname); free(v->ip); free(v->candidate);
	memset(v, 0, sizeof *v);
}

static char *copy(const char *v) { return v ? strdup(v) : NULL; }

/* Saves the session as it stands: as the provider's saveSession. `completed`: a login
 * or a whole reconnect is behind it, which is the only time it used to be saved. */
static void keep(ocb_session *s, int completed)
{
	struct saved now, too;
	if (take_saved(s, &now)) return;
	too = (struct saved){ copy(now.url), copy(now.cookie), copy(now.dnsname), copy(now.ip), copy(now.candidate) };
	pthread_mutex_lock(&keep_lock);
	drop_saved(&kept);
	kept = now;
	saves++;
	if (completed) { drop_saved(&kept_after_reconnect); kept_after_reconnect = too; }
	pthread_mutex_unlock(&keep_lock);
	if (!completed) drop_saved(&too);
}

/* Reads it back, as the next start of the extension would: all a new process has. */
static void read_kept(struct saved *now, struct saved *as_before)
{
	pthread_mutex_lock(&keep_lock);
	*now = (struct saved){ copy(kept.url), copy(kept.cookie), copy(kept.dnsname), copy(kept.ip), copy(kept.candidate) };
	*as_before = (struct saved){ copy(kept_after_reconnect.url), copy(kept_after_reconnect.cookie),
		copy(kept_after_reconnect.dnsname), copy(kept_after_reconnect.ip), copy(kept_after_reconnect.candidate) };
	pthread_mutex_unlock(&keep_lock);
}

/* The bridge's save handler: on OpenConnect's thread, which waits for it. */
static void on_save(void *ctx, ocb_session *s)
{
	(void)ctx;
	keep(s, 0);
}

/* The fingerprint of the public half of the STRAP key a cookie carries, as the server's. */
static void cookie_key(const char *cookie, char out[17])
{
	static const char prefix[] = "openconnect_strapkey=";
	strcpy(out, "none");
	if (!cookie || strncmp(cookie, prefix, sizeof prefix - 1)) return;
	char *b64 = strndup(cookie + sizeof prefix - 1, strcspn(cookie + sizeof prefix - 1, ";"));
	int len = 0, publen;
	unsigned char *der = unbase64(b64, &len), *pub = NULL;
	const unsigned char *p = der;
	EC_KEY *key = der ? d2i_ECPrivateKey(NULL, &p, len) : NULL;
	if (key && (publen = i2d_EC_PUBKEY(key, &pub)) > 0) fingerprint(pub, publen, out);
	OPENSSL_free(pub); EC_KEY_free(key); free(der); free(b64);
}

/* Every line the bridge logs, to check none carries a cookie. */
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static int log_lines, leaked, verbose;
static void on_log(void *ctx, int level, const char *line)
{
	(void)ctx; (void)level;
	pthread_mutex_lock(&log_lock);
	log_lines++;
	if (strstr(line, "openconnect_strapkey") || strstr(line, "webvpn=") || strstr(line, "FAKESESSION")) leaked++;
	pthread_mutex_unlock(&log_lock);
	if (verbose) fprintf(stderr, "    log: %s\n", line);
}

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_cond = PTHREAD_COND_INITIALIZER;
static int reconnects, sleeps;
static ocb_session *running;
static int on_sleep; /* what to do when a reconnect attempt fails: 0 nothing, 1 detach, 2 try again now */

/* On OpenConnect's thread, as the provider's event callback. */
static void on_event(void *ctx, int event, const ocb_config *cfg)
{
	(void)ctx; (void)cfg;
	pthread_mutex_lock(&event_lock);
	ocb_session *s = running;
	pthread_mutex_unlock(&event_lock);
	if (event == OCB_RECONNECTED && s) keep(s, 1); /* as the provider's reconnected(_:) */
	pthread_mutex_lock(&event_lock);
	if (event == OCB_RECONNECTED) reconnects++;
	if (event == OCB_RECONNECTING) {
		sleeps++;
		if (on_sleep == 1) ocb_detach(running);
		if (on_sleep == 2) ocb_reconnect(running);
		on_sleep = 0;
	}
	pthread_cond_broadcast(&event_cond);
	pthread_mutex_unlock(&event_lock);
}

static int event_count(const int *counter)
{
	pthread_mutex_lock(&event_lock);
	int n = *counter;
	pthread_mutex_unlock(&event_lock);
	return n;
}

/* Waits (up to 20 s) for the count to pass `seen`. */
static int wait_past(int *counter, int seen)
{
	struct timespec until;
	clock_gettime(CLOCK_REALTIME, &until);
	until.tv_sec += 20;
	pthread_mutex_lock(&event_lock);
	int rc = 0;
	while (*counter <= seen && !rc) rc = pthread_cond_timedwait(&event_cond, &event_lock, &until);
	int ok = *counter > seen;
	pthread_mutex_unlock(&event_lock);
	return ok;
}

static char url[64];
static ocb_session *new_session(void)
{
	ocb_session *s = ocb_new(url, "netid", "password", "push", on_log, on_event, NULL);
	if (!s) { fprintf(stderr, "ocb_new failed\n"); exit(2); }
	ocb_set_save_handler(s, on_save);
	return s;
}

static ocb_session *login(struct saved *after)
{
	char err[512] = "";
	ocb_session *s = new_session();
	if (ocb_connect(s, err, sizeof err)) { fprintf(stderr, "login failed: %s\n", err); exit(2); }
	if (take_saved(s, after)) { fprintf(stderr, "nothing to save after login\n"); exit(2); }
	keep(s, 1);
	return s;
}

/* A fresh rejoin, as resume() in the provider: a new session, ocb_resume with one
 * cookie. Returns ocb_resume's result; on success leaves the session in *out (or frees it). */
static int resume(const struct saved *v, const char *cookie, ocb_session **out)
{
	char err[512] = "";
	ocb_session *s = new_session();
	int result = ocb_resume(s, v->url, cookie, v->dnsname, v->ip, err, sizeof err);
	if (result == 0 && out) *out = s;
	else ocb_free(s);
	return result;
}

static int run_result, run_over;
static int tun[2];
static void *run_thread(void *arg)
{
	int result = ocb_run(arg, tun[0], 60);
	pthread_mutex_lock(&event_lock);
	run_result = result;
	run_over = 1;
	pthread_mutex_unlock(&event_lock);
	return NULL;
}

static pthread_t start_run(ocb_session *s)
{
	pthread_t t;
	pthread_mutex_lock(&event_lock);
	running = s;
	run_over = 0;
	pthread_mutex_unlock(&event_lock);
	pthread_mutex_lock(&keep_lock);
	in_run = 1;
	pthread_mutex_unlock(&keep_lock);
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tun)) { perror("socketpair"); exit(2); }
	pthread_create(&t, NULL, run_thread, s);
	return t;
}

static void end_run(pthread_t t)
{
	pthread_join(t, NULL);
	pthread_mutex_lock(&keep_lock);
	in_run = 0;
	pthread_mutex_unlock(&keep_lock);
	pthread_mutex_lock(&event_lock);
	running = NULL;
	pthread_mutex_unlock(&event_lock);
	close(tun[0]); close(tun[1]);
}

/* Waits (up to 20 s) for the server to go quiet on one more connection than `seen`. */
static int wait_quiet(int seen)
{
	for (int i = 0; i < 2000 && server_count(&holding) <= seen; i++) usleep(10000);
	return server_count(&holding) > seen;
}

/* Reads the snapshot as fast as it can while the run thread reconnects, as the
 * provider's queue does: every read has to be a whole, well-formed session. */
static _Atomic int reading;
static long reads, bad_reads;
static void *reader(void *arg)
{
	ocb_session *s = arg;
	while (reading) {
		ocb_saved now;
		if (ocb_session_saved(s, &now)) { bad_reads++; continue; }
		if (strncmp(now.cookie, "openconnect_strapkey=", 21) || !strstr(now.cookie, "; webvpn=FAKESESSION") ||
		    strncmp(now.url, "https://127.0.0.1", 17) || (now.candidate && !strcmp(now.candidate, now.cookie)))
			bad_reads++;
		reads++;
		ocb_saved_free(&now);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	verbose = argc > 1;
	alarm(180); /* never hang */
	setvbuf(stdout, NULL, _IONBF, 0);
	start_server();
	snprintf(url, sizeof url, "https://127.0.0.1:%d/", port);
	char server[17], key[17];
	struct saved after_login, v;
	ocb_session *s, *again = NULL;

	/* A. The extension restarts right after a login (no reconnect in between). */
	printf("A. login, then a fresh rejoin from what was saved\n");
	s = login(&after_login);
	server_key(server); cookie_key(after_login.cookie, key);
	printf("     the server holds %s; the saved cookie carries %s\n", server, key);
	CHECK(!strcmp(server, key), "the session saved after login carries the key the server holds");
	ocb_free(s); /* as the process dying: no logout */
	CHECK(resume(&after_login, after_login.cookie, NULL) == 0, "a fresh rejoin from it is accepted");
	drop_saved(&after_login);
#ifdef WITHOUT_STRAP_PATCH
	/* The rest only makes sense once that works. */
	printf(failures ? "%d FAILED\n" : "all passed\n", failures);
	return failures ? 1 : 0;
#endif

	/* B. In-process reconnects (a dropped connection, then on request as kickReconnect),
	 * the snapshot read after each as reconnected(_:) does, and all the while by a
	 * second thread. Then the run ends without a logout. */
	printf("B. login, reconnects, then a fresh rejoin\n");
	server_next(DROP_AFTER_200, 1); /* the login's own CONNECT: the server drops it 0.3 s later */
	s = login(&after_login);
	pthread_t rd, run;
	reading = 1;
	pthread_create(&rd, NULL, reader, s);
	run = start_run(s);
	int ok = 1;
	for (int i = 0; i < 6 && ok; i++) {
		ok = wait_past(&reconnects, i);
		if (!ok) break;
		take_saved(s, &v);
		server_key(server); cookie_key(v.cookie, key);
		printf("     reconnect %d: the server holds %s; the snapshot carries %s%s\n", i + 1, server, key,
		       v.candidate ? " (and a candidate)" : "");
		ok = !strcmp(server, key) && !v.candidate;
		drop_saved(&v);
		if (i < 5) ocb_reconnect(s);
	}
	CHECK(ok, "after each of 6 reconnects the snapshot carries the key the server holds, and no candidate");
	ocb_detach(s);
	end_run(run);
	reading = 0;
	pthread_join(rd, NULL);
	printf("     %ld concurrent reads of the snapshot during the run\n", reads);
	CHECK(reads > 0 && bad_reads == 0, "every concurrent read was a whole session");
	take_saved(s, &v);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(!strcmp(server, key) && !v.candidate, "at the end of the run the snapshot still carries the server's key");
	ocb_free(s);
	CHECK(resume(&after_login, after_login.cookie, NULL) == OCB_SESSION_ENDED,
	      "a fresh rejoin from the session as saved at login is refused (so it must be saved after every reconnect)");
	CHECK(resume(&v, v.cookie, NULL) == 0, "a fresh rejoin from the latest snapshot is accepted");
	drop_saved(&v); drop_saved(&after_login);

	/* C. A reconnect's CONNECT reaches the server (which takes the new key) but its 200
	 * is lost. OpenConnect retries an unanswered CONNECT once, straight away: that has
	 * to present the same key, which the server now holds. */
	printf("C. a reconnect's 200 is lost; OpenConnect's immediate retry\n");
	s = login(&after_login);
	run = start_run(s);
	int seen = event_count(&reconnects), slept, before = server_count(&connects);
	int refused_before = server_count(&refused); /* B's stale rejoin was refused, on purpose */
	server_next(LOSE_REPLY, 1);
	ocb_reconnect(s);
	CHECK(wait_past(&reconnects, seen), "the retry reconnected");
	CHECK(server_count(&connects) == before + 2 && server_count(&refused) == refused_before,
	      "in two CONNECTs, neither refused");
	take_saved(s, &v);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(!strcmp(server, key) && !v.candidate, "the snapshot carries the key the server took, and no candidate");
	drop_saved(&v);

	/* C2. Both that CONNECT and the retry go unanswered, so the attempt fails and
	 * OpenConnect sleeps; the provider's watchdog then kicks it (kickReconnect). */
	printf("C2. the retry's 200 is lost too; the next attempt, on request\n");
	seen = event_count(&reconnects); slept = event_count(&sleeps);
	server_next(LOSE_REPLY, 2);
	pthread_mutex_lock(&event_lock); on_sleep = 2; pthread_mutex_unlock(&event_lock);
	ocb_reconnect(s);
	CHECK(wait_past(&sleeps, slept), "the attempt failed");
	CHECK(wait_past(&reconnects, seen), "the next attempt reconnected");
	take_saved(s, &v);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(!strcmp(server, key) && !v.candidate && server_count(&refused) == refused_before,
	      "the snapshot carries the key the server took, no candidate, nothing refused");
	drop_saved(&v);
	ocb_detach(s);
	end_run(run);
	ocb_free(s);
	drop_saved(&after_login);

	/* D. The same, but the run ends before another attempt (iOS stops the tunnel, or
	 * the provider gives up): the server holds the newer key, which only the candidate
	 * carries. */
	printf("D. a reconnect's 200s are lost, then the run ends\n");
	s = login(&after_login);
	run = start_run(s);
	slept = event_count(&sleeps);
	server_next(LOSE_REPLY, 2);
	pthread_mutex_lock(&event_lock); on_sleep = 1; pthread_mutex_unlock(&event_lock);
	ocb_reconnect(s);
	CHECK(wait_past(&sleeps, slept), "the attempt failed");
	end_run(run);
	take_saved(s, &v);
	ocb_free(s);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(v.candidate != NULL, "the snapshot at the end of the run has a candidate");
	CHECK(strcmp(server, key), "its cookie carries the older key, not the server's");
	cookie_key(v.candidate, key);
	CHECK(!strcmp(server, key), "its candidate carries the key the server holds");
	before = server_count(&refused);
	CHECK(resume(&v, v.cookie, NULL) == OCB_SESSION_ENDED, "a rejoin with the cookie is refused");
	CHECK(v.candidate && resume(&v, v.candidate, &again) == 0, "a rejoin with the candidate is accepted");
	CHECK(server_count(&refused) == before + 1, "exactly one request was refused on the way");
	if (again) {
		struct saved now;
		take_saved(again, &now);
		server_key(server); cookie_key(now.cookie, key);
		CHECK(!strcmp(server, key) && !now.candidate, "and then saves as the cookie, with no candidate");
		drop_saved(&now);
		ocb_free(again);
		again = NULL;
	}
	drop_saved(&v); drop_saved(&after_login);

	/* E. The CONNECTs never reached the server, which still holds the older key. */
	printf("E. a reconnect's CONNECTs are lost on the way, then the run ends\n");
	s = login(&after_login);
	run = start_run(s);
	slept = event_count(&sleeps);
	server_next(LOSE_REQUEST, 2);
	pthread_mutex_lock(&event_lock); on_sleep = 1; pthread_mutex_unlock(&event_lock);
	ocb_reconnect(s);
	CHECK(wait_past(&sleeps, slept), "the attempt failed");
	end_run(run);
	take_saved(s, &v);
	ocb_free(s);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(v.candidate != NULL, "the snapshot at the end of the run has a candidate");
	CHECK(!strcmp(server, key), "its cookie carries the key the server still holds");
	before = server_count(&refused);
	CHECK(resume(&v, v.cookie, NULL) == 0, "a rejoin with the cookie is accepted");
	CHECK(server_count(&refused) == before, "and nothing was refused");
	drop_saved(&v); drop_saved(&after_login);

	/* F. Only the first CONNECT is lost on the way. The immediate retry presents the
	 * new key, which the server never got: 401, and OpenConnect ends the run as if the
	 * session were over. It isn't: the rejoin's cookie still works. */
	printf("F. a reconnect's CONNECT is lost on the way; the retry is refused and ends the run\n");
	s = login(&after_login);
	run = start_run(s);
	before = server_count(&refused);
	server_next(LOSE_REQUEST, 1);
	ocb_reconnect(s);
	end_run(run); /* ends on its own */
	CHECK(event_count(&run_result) == -EPERM && server_count(&refused) == before + 1, "the run ended on the server's 401");
	take_saved(s, &v);
	ocb_free(s);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(v.candidate != NULL && !strcmp(server, key), "the snapshot keeps the server's key in the cookie, and a candidate");
	CHECK(resume(&v, v.cookie, NULL) == 0, "a rejoin with the cookie is accepted: the session goes on");
	drop_saved(&v); drop_saved(&after_login);

	/* G. iOS can end the extension at any moment, such as right here: a reconnect's
	 * CONNECT reached the server, which took the new key, and no answer has come.
	 * OpenConnect is still waiting, so no reconnect has completed and the run hasn't
	 * ended. All a new process has is what was saved by then. */
	struct saved now, as_before;
	printf("G. a reconnect's CONNECT is taken and not answered; the extension dies while it waits\n");
	s = login(&after_login);
	run = start_run(s);
	int quiet = server_count(&holding);
	server_next(HOLD, 1);
	ocb_reconnect(s);
	CHECK(wait_quiet(quiet), "the server took the new key and has gone quiet");
	read_kept(&now, &as_before);
	CHECK(!event_count(&run_over), "the run is still waiting for the answer");
	server_key(server); cookie_key(now.candidate, key);
	CHECK(now.candidate && !strcmp(server, key), "what's saved by now has the server's key, as the candidate");
	CHECK(!as_before.candidate && resume(&as_before, as_before.cookie, NULL) == OCB_SESSION_ENDED,
	      "(saved only after a completed reconnect, as before, it has no candidate and its cookie is refused)");
	CHECK(resume(&now, now.cookie, NULL) == OCB_SESSION_ENDED, "a rejoin with the saved cookie is refused");
	CHECK(now.candidate && resume(&now, now.candidate, NULL) == 0,
	      "a rejoin with the saved candidate is accepted, with the first run still waiting");
	CHECK(!event_count(&run_over), "(it still is)");
	drop_saved(&now); drop_saved(&as_before);
	ocb_detach(s);
	end_run(run);
	hold_generation++;
	ocb_free(s);
	drop_saved(&after_login);

	/* H. The same moment a little later: the server's 200 has arrived and the rest of
	 * its answer hasn't, so the reconnect isn't complete, and may yet fail. */
	printf("H. a reconnect gets its 200 and nothing after; the extension dies while it waits\n");
	s = login(&after_login);
	run = start_run(s);
	quiet = server_count(&holding);
	seen = event_count(&reconnects);
	server_next(HOLD_AFTER_200, 1);
	ocb_reconnect(s);
	CHECK(wait_quiet(quiet), "the server answered 200 and has gone quiet");
	/* The 200 is on its way to the client; the save follows it. */
	for (int i = 0; i < 2000; i++) {
		read_kept(&now, &as_before);
		server_key(server); cookie_key(now.cookie, key);
		if (!strcmp(server, key)) break;
		drop_saved(&now); drop_saved(&as_before);
		usleep(10000);
	}
	CHECK(!event_count(&run_over) && event_count(&reconnects) == seen, "the reconnect hasn't completed, nor the run ended");
	CHECK(now.cookie && !strcmp(server, key) && !now.candidate, "what's saved by now has the server's key in the cookie");
	CHECK(as_before.cookie && resume(&as_before, as_before.cookie, NULL) == OCB_SESSION_ENDED,
	      "(saved only after a completed reconnect, as before, its cookie is refused)");
	CHECK(now.cookie && resume(&now, now.cookie, NULL) == 0, "a rejoin with the saved cookie is accepted");
	drop_saved(&now); drop_saved(&as_before);
	ocb_detach(s);
	end_run(run);
	hold_generation++;
	ocb_free(s);
	drop_saved(&after_login);

	/* I. The server answers a reconnect's CONNECT with an error. It most likely didn't
	 * take the new key, so the next attempt has to be signed by the one it still holds. */
	printf("I. the server answers a reconnect 503, keeping its key; the next attempt, on request\n");
	s = login(&after_login);
	run = start_run(s);
	seen = event_count(&reconnects); slept = event_count(&sleeps);
	refused_before = server_count(&refused);
	server_next(DECLINE, 1);
	pthread_mutex_lock(&event_lock); on_sleep = 2; pthread_mutex_unlock(&event_lock);
	ocb_reconnect(s);
	CHECK(wait_past(&sleeps, slept), "the attempt failed");
	CHECK(wait_past(&reconnects, seen), "the next attempt reconnected");
	take_saved(s, &v);
	server_key(server); cookie_key(v.cookie, key);
	CHECK(!strcmp(server, key) && !v.candidate && server_count(&refused) == refused_before,
	      "the snapshot carries the key the server took, no candidate, nothing refused");
	drop_saved(&v);

	/* J. Or it did take the key before answering 503 (nobody outside Cisco knows which).
	 * Then that next attempt is refused and ends the run, and the candidate rejoins. */
	printf("J. the server takes a reconnect's key, then answers 503; the next attempt ends the run\n");
	before = server_count(&refused);
	server_next(DECLINE_TAKEN, 1);
	pthread_mutex_lock(&event_lock); on_sleep = 2; pthread_mutex_unlock(&event_lock);
	ocb_reconnect(s);
	end_run(run); /* ends on its own */
	CHECK(event_count(&run_result) == -EPERM && server_count(&refused) == before + 1, "the run ended on the server's 401");
	read_kept(&now, &as_before);
	ocb_free(s);
	server_key(server); cookie_key(now.candidate, key);
	CHECK(now.candidate && !strcmp(server, key), "what's saved has the server's key, as the candidate");
	CHECK(resume(&now, now.cookie, NULL) == OCB_SESSION_ENDED, "a rejoin with the cookie is refused");
	CHECK(now.candidate && resume(&now, now.candidate, NULL) == 0, "a rejoin with the candidate is accepted");
	drop_saved(&now); drop_saved(&as_before); drop_saved(&after_login);

	pthread_mutex_lock(&keep_lock);
	int taken = new_keys, unsaved = unsaved_keys, saved_times = saves;
	pthread_mutex_unlock(&keep_lock);
	printf("     %d new keys taken by the server during runs; the session saved %d times\n", taken, saved_times);
	CHECK(taken > 0 && unsaved == 0, "every new key a reconnect handed the server was saved before its request went out");

	pthread_mutex_lock(&log_lock);
	int lines = log_lines, leaks = leaked;
	pthread_mutex_unlock(&log_lock);
	printf("     %d CONNECTs in all; %d log lines from the bridge\n", server_count(&connects), lines);
	CHECK(lines > 0 && leaks == 0, "no log line carried a cookie or the session token");
	printf(failures ? "%d FAILED\n" : "all passed\n", failures);
	return failures ? 1 : 0;
}
