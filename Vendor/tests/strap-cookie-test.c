/* Regression test for openconnect-strap-cookie.patch, run on the Mac: built against the
 * patched OpenConnect 9.21 by scripts/test-strap-cookie.sh. It runs the real
 * start_cstp_connection over an in-memory TLS session (for STRAP's channel binding)
 * with scripted server replies, and checks which STRAP key the session cookie carries.
 * A rejoin parses that cookie on a fresh vpninfo, as ocb_resume does.
 * The same test as ConnectAnytime for Android's, which has the same patch. */
#include "cstp.c" /* start_cstp_connection and strap_cookie are static */

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int failures;
#define CHECK(cond, what) do { \
	if (cond) printf("ok   %s\n", what); \
	else { printf("FAIL %s (line %d)\n", what, __LINE__); failures++; } } while (0)

static void quiet(void *priv, int level, const char *fmt, ...) { (void)priv; (void)level; (void)fmt; }

#ifdef WITHOUT_STRAP_PATCH
/* The negative control: built against OpenConnect without the patch, to show that the
 * checks below fail there. All it lacks to compile is the function the patch adds;
 * without the patch there is no candidate cookie. */
char *openconnect_strap_candidate_cookie(struct openconnect_info *vpninfo)
{
	(void)vpninfo;
	return NULL;
}
#endif

/* The server: replies to send, in order, then a dropped connection. */
static const char *const *replies;
static int reply_count, next_reply;
static char sent[65536];

static int mock_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	(void)vpninfo;
	snprintf(sent, sizeof(sent), "%.*s", (int)len, buf);
	return (int)len;
}

static int mock_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	(void)vpninfo;
	if (next_reply >= reply_count)
		return -EIO;
	snprintf(buf, len, "%s", replies[next_reply++]);
	return (int)strlen(buf);
}

/* A finished TLS 1.3 handshake in memory: append_strap_verify signs its exporter. */
static SSL *tls_session(void)
{
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = X509_new();
	X509_NAME *name = X509_get_subject_name(cert);
	SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method()), *client_ctx = SSL_CTX_new(TLS_client_method());
	SSL *server, *client;
	BIO *a, *b;

	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
	X509_set_pubkey(cert, key);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"test", -1, -1, 0);
	X509_set_issuer_name(cert, name);
	X509_sign(cert, key, EVP_sha256());
	SSL_CTX_use_certificate(server_ctx, cert);
	SSL_CTX_use_PrivateKey(server_ctx, key);
	server = SSL_new(server_ctx);
	client = SSL_new(client_ctx);
	BIO_new_bio_pair(&a, 0, &b, 0);
	SSL_set_bio(client, a, a);
	SSL_set_bio(server, b, b);
	SSL_set_connect_state(client);
	SSL_set_accept_state(server);
	for (int i = 0; i < 20 && !(SSL_is_init_finished(client) && SSL_is_init_finished(server)); i++) {
		SSL_do_handshake(client);
		SSL_do_handshake(server);
	}
	if (!SSL_is_init_finished(client)) {
		fprintf(stderr, "TLS handshake failed\n");
		exit(2);
	}
	return client; /* the server side and contexts leak; it's a test */
}

static struct openconnect_info *new_vpninfo(void)
{
	struct openconnect_info *vpninfo = openconnect_vpninfo_new("test", NULL, NULL, NULL, quiet, NULL);
	/* Nothing listens here, so a reconnect inside start_cstp_connection fails at once. */
	openconnect_parse_url(vpninfo, "https://127.0.0.1:1/");
	openconnect_disable_dtls(vpninfo); /* CSTP is all that carries STRAP */
	openconnect_set_reqmtu(vpninfo, 1400); /* no socket to measure */
	return vpninfo;
}

static void connect_via(struct openconnect_info *vpninfo, const char *const *script, int count)
{
	vpninfo->https_ssl = tls_session();
	vpninfo->ssl_write = mock_write;
	vpninfo->ssl_gets = mock_gets;
	replies = script;
	reply_count = count;
	next_reply = 0;
	sent[0] = 0;
}

/* The STRAP public key the last CONNECT presented. */
static char *sent_pubkey(void)
{
	static const char header[] = "X-AnyConnect-STRAP-Pubkey: ";
	const char *p = strstr(sent, header);
	if (!p)
		return NULL;
	p += sizeof(header) - 1;
	return strndup(p, strcspn(p, "\r\n"));
}

/* What a rejoin does with a saved cookie (cstp_connect on a fresh vpninfo): the public
 * key of the STRAP key it would present. Leaves the vpninfo ready for a CONNECT. */
static char *resume_pubkey(const char *cookie, struct openconnect_info **out)
{
	struct openconnect_info *vpninfo = new_vpninfo();
	const char *key, *webvpn;
	void *der;
	int len;

	openconnect_set_cookie(vpninfo, cookie);
	internal_split_cookies(vpninfo, 0, "webvpn");
	key = http_get_cookie(vpninfo, "openconnect_strapkey");
	webvpn = http_get_cookie(vpninfo, "webvpn");
	if (!key || !webvpn || strcmp(webvpn, "SESSION"))
		return NULL;
	der = openconnect_base64_decode(&len, key);
	if (!der || ingest_strap_privkey(vpninfo, der, len))
		return NULL;
	free(der);
	http_add_cookie(vpninfo, "openconnect_strapkey", "", 1);
	if (out)
		*out = vpninfo;
	return strdup(vpninfo->strap_pubkey);
}

int main(void)
{
	static const char *const ok_then_truncated[] = { "HTTP/1.1 200 OK" };
	struct openconnect_info *vpninfo = new_vpninfo(), *rejoin = NULL;
	struct oc_text_buf *buf = buf_alloc();
	char *login_key, *accepted, *unanswered, *candidate;

	setvbuf(stdout, NULL, _IONBF, 0);
	openconnect_init_ssl();

	/* A login: keys made for the auth request, then the cookie as auth.c builds it,
	 * then cstp_connect's split, which leaves vpninfo->cookies set (so it rekeys). */
	if (generate_strap_keys(vpninfo))
		return 2;
	buf_append(buf, "openconnect_strapkey=");
	append_strap_privkey(vpninfo, buf);
	buf_append(buf, "; webvpn=SESSION");
	vpninfo->cookie = strdup(buf->data);
	buf_free(buf);
	internal_split_cookies(vpninfo, 0, "webvpn");
	http_add_cookie(vpninfo, "openconnect_strapkey", "", 1);
	login_key = strdup(vpninfo->strap_pubkey);

	/* 1. The server answers 200 to a rekeying CONNECT, then the connection drops
	 *    before the rest of the headers. The server holds the new key. */
	connect_via(vpninfo, ok_then_truncated, 1);
	CHECK(start_cstp_connection(vpninfo, 1) != 0, "200 then truncated headers fails the CONNECT");
	accepted = sent_pubkey();
	CHECK(accepted && strcmp(accepted, login_key), "the CONNECT presented a new key");
	CHECK(accepted && !strcmp(accepted, vpninfo->strap_pubkey), "and OpenConnect holds it");
	{
		char *saved = resume_pubkey(vpninfo->cookie, &rejoin);
		CHECK(saved && accepted && !strcmp(saved, accepted), "the cookie now carries the key the 200 accepted");
		free(saved);
	}
	candidate = openconnect_strap_candidate_cookie(vpninfo);
	CHECK(candidate && !strcmp(candidate, vpninfo->cookie), "no separate candidate after a 200");
	free(candidate);

	/* 2. A rejoin from that cookie presents the accepted key, without rekeying. */
	connect_via(rejoin, ok_then_truncated, 1);
	start_cstp_connection(rejoin, 0);
	{
		char *presented = sent_pubkey();
		CHECK(presented && accepted && !strcmp(presented, accepted), "a rejoin presents the accepted key");
		free(presented);
	}

	/* 3. Another rekeying CONNECT goes out and no reply comes back: the server may or
	 *    may not hold that key. The cookie keeps the accepted one; the candidate has
	 *    the new one. */
	connect_via(vpninfo, NULL, 0);
	CHECK(start_cstp_connection(vpninfo, 1) != 0, "a CONNECT with no reply fails");
	unanswered = sent_pubkey();
	CHECK(unanswered && strcmp(unanswered, accepted), "it presented yet another key");
	{
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		CHECK(saved && !strcmp(saved, accepted), "the cookie still carries the accepted key");
		free(saved);
	}
	candidate = openconnect_strap_candidate_cookie(vpninfo);
	{
		char *next = candidate ? resume_pubkey(candidate, NULL) : NULL;
		CHECK(next && unanswered && !strcmp(next, unanswered), "the candidate carries the unanswered key");
		free(next);
	}
	free(candidate);

	/* 4. That key's 200 was lost, so the server holds it, or it never arrived and the
	 *    server still holds the accepted one. OpenConnect retries (its own reopen, then
	 *    ssl_reconnect): each retry must present the same unresolved key, not a newer
	 *    one, or the saved pair would hold neither key the server might have. */
	for (int attempt = 1; attempt <= 2; attempt++) {
		connect_via(vpninfo, NULL, 0);
		start_cstp_connection(vpninfo, 1);
		char *presented = sent_pubkey();
		CHECK(presented && !strcmp(presented, unanswered),
		      attempt == 1 ? "a retry presents the unresolved key again" : "and so does the next");
		free(presented);
	}
	{
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		char *cand = openconnect_strap_candidate_cookie(vpninfo);
		char *next = cand ? resume_pubkey(cand, NULL) : NULL;
		CHECK(saved && !strcmp(saved, accepted) && next && !strcmp(next, unanswered),
		      "the saved pair is still {accepted, unresolved}: whichever the server holds");
		free(saved); free(cand); free(next);
	}

	/* 5. The server held the unresolved key: the retry gets its 200. That key is now
	 *    the accepted one, and the CONNECT after it rekeys again. */
	connect_via(vpninfo, ok_then_truncated, 1);
	start_cstp_connection(vpninfo, 1);
	{
		char *presented = sent_pubkey();
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		CHECK(presented && !strcmp(presented, unanswered) && saved && !strcmp(saved, unanswered),
		      "a 200 on the retry makes the unresolved key the accepted one");
		free(presented); free(saved);
	}
	candidate = openconnect_strap_candidate_cookie(vpninfo);
	CHECK(candidate && !strcmp(candidate, vpninfo->cookie), "and leaves no candidate");
	free(candidate);
	connect_via(vpninfo, ok_then_truncated, 1);
	start_cstp_connection(vpninfo, 1);
	{
		char *presented = sent_pubkey();
		CHECK(presented && strcmp(presented, unanswered), "after a 200, the next CONNECT rekeys");
		free(presented);
	}

	/* 6. A cookie without a STRAP key (server without STRAP, or an older format) is
	 *    left alone. */
	free(vpninfo->cookie);
	vpninfo->cookie = strdup("webvpn=SESSION");
	CHECK(!openconnect_strap_candidate_cookie(vpninfo), "no STRAP key in the cookie: nothing to refresh");

	printf(failures ? "%d FAILED\n" : "all passed\n", failures);
	return failures ? 1 : 0;
}
