/* Regression test for openconnect-strap-cookie.patch, run on the Mac: built against the
 * patched OpenConnect 9.21 by scripts/test-strap-cookie.sh. It runs the real
 * start_cstp_connection over an in-memory TLS session (for STRAP's channel binding)
 * with scripted server replies, and checks which STRAP key the session cookie carries.
 * A rejoin parses that cookie on a fresh vpninfo, as ocb_resume does.
 * Checks 1 to 6 are ConnectAnytime for Android's test of the patch as it has it. 7 and
 * 8 test what this one adds: the handler a client saves the session from, and which key
 * signs a CONNECT that presents an unresolved key again. */
#include <config.h>
#include "openconnect-internal.h"
/* A buffer fails as when out of memory: the fail_buf-th call of buf_error() in cstp.c
 * from when it's set (1 is the request a CONNECT builds), then none. */
static int fail_buf, buf_checks;
#define buf_error(b) (fail_buf && ++buf_checks == fail_buf ? \
	(fail_buf = buf_checks = 0, (b)->error = -ENOMEM) : buf_error(b))
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
static unsigned char binding[TLS_EXPORTER_KEY_SIZE]; /* of the TLS session the request went out on */
static int fail_write; /* the request can't be written: the connection is already gone */

static int mock_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	if (fail_write)
		return -EIO;
	snprintf(sent, sizeof(sent), "%.*s", (int)len, buf);
	SSL_export_keying_material(vpninfo->https_ssl, binding, sizeof(binding),
				   TLS_EXPORTER_LABEL, TLS_EXPORTER_LABEL_SIZE, NULL, 0, 0);
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

static char *sent_header(const char *header)
{
	const char *p = strstr(sent, header);
	if (!p)
		return NULL;
	p += strlen(header);
	return strndup(p, strcspn(p, "\r\n"));
}

/* The STRAP public key the last CONNECT presented. */
static char *sent_pubkey(void)
{
	return sent_header("X-AnyConnect-STRAP-Pubkey: ");
}

/* Whether the last CONNECT's Verify header is this public key's signature over the TLS
 * session's channel binding and the key presented: what a server holding it checks. */
static int signed_by(const char *signer_b64)
{
	char *sig_b64 = sent_header("X-AnyConnect-STRAP-Verify: "), *pub_b64 = sent_pubkey();
	int siglen = 0, publen = 0, keylen = 0, ok = 0;
	unsigned char *sig = sig_b64 ? openconnect_base64_decode(&siglen, sig_b64) : NULL;
	unsigned char *pub = pub_b64 ? openconnect_base64_decode(&publen, pub_b64) : NULL;
	unsigned char *key = signer_b64 ? openconnect_base64_decode(&keylen, signer_b64) : NULL;
	const unsigned char *p = key;
	EVP_PKEY *pkey = key ? d2i_PUBKEY(NULL, &p, keylen) : NULL;
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	if (sig && pub && pkey)
		ok = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pkey) > 0 &&
		     EVP_DigestVerifyUpdate(md, binding, sizeof(binding)) > 0 &&
		     EVP_DigestVerifyUpdate(md, pub, publen) > 0 &&
		     EVP_DigestVerifyFinal(md, sig, siglen) == 1;
	EVP_MD_CTX_free(md);
	EVP_PKEY_free(pkey);
	free(sig); free(pub); free(key); free(sig_b64); free(pub_b64);
	return ok;
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

/* A login: keys made for the auth request, then the cookie as auth.c builds it, then
 * cstp_connect's split, which leaves vpninfo->cookies set (so it rekeys). */
static struct openconnect_info *logged_in(void)
{
	struct openconnect_info *vpninfo = new_vpninfo();
	struct oc_text_buf *buf = buf_alloc();

	if (generate_strap_keys(vpninfo))
		exit(2);
	buf_append(buf, "openconnect_strapkey=");
	append_strap_privkey(vpninfo, buf);
	buf_append(buf, "; webvpn=SESSION");
	vpninfo->cookie = strdup(buf->data);
	buf_free(buf);
	internal_split_cookies(vpninfo, 0, "webvpn");
	http_add_cookie(vpninfo, "openconnect_strapkey", "", 1);
	return vpninfo;
}

#ifndef WITHOUT_STRAP_PATCH
/* What the session-changed handler found each time it was called. */
static struct { int request_sent; char *cookie_key, *candidate_key; } seen[16];
static int changes;

static void on_changed(void *priv)
{
	struct openconnect_info *vpninfo = priv;
	char *candidate = openconnect_strap_candidate_cookie(vpninfo);

	if (changes >= 16)
		exit(2);
	seen[changes].request_sent = sent[0] != 0;
	seen[changes].cookie_key = resume_pubkey(vpninfo->cookie, NULL);
	seen[changes].candidate_key = candidate ? resume_pubkey(candidate, NULL) : NULL;
	changes++;
	free(candidate);
}

/* The patch's later additions: the handler a client saves the session from, and which
 * key signs a CONNECT that presents the unresolved one again. */
static void test_handler_and_signing(void)
{
	static const char *const ok_then_truncated[] = { "HTTP/1.1 200 OK" };
	static const char *const unavailable[] = { "HTTP/1.1 503 Service Unavailable", "X-Reason: testing", "" };
	static const char *const unauthorized[] = { "HTTP/1.1 401 Unauthorized", "" };
	struct openconnect_info *vpninfo = logged_in();
	char *login_key = strdup(vpninfo->strap_pubkey), *presented, *first, *second, *third, *fourth;

	/* 7. A client saves the session from the handler. It has to run before a new key
	 *    goes out, with that key as the candidate, and again at the 200. */
	openconnect_set_session_changed_handler(vpninfo, on_changed);
	connect_via(vpninfo, ok_then_truncated, 1);
	start_cstp_connection(vpninfo, 1);
	first = sent_pubkey();
	CHECK(changes == 2, "the handler runs twice for a rekeying CONNECT that gets its 200");
	CHECK(changes == 2 && !seen[0].request_sent && seen[1].request_sent,
	      "before the request is written, and after the reply");
	CHECK(changes == 2 && first && seen[0].candidate_key && !strcmp(seen[0].candidate_key, first) &&
	      seen[0].cookie_key && !strcmp(seen[0].cookie_key, login_key),
	      "the first time, the candidate carries the key about to be presented and the cookie the accepted one");
	CHECK(changes == 2 && first && seen[1].cookie_key && !strcmp(seen[1].cookie_key, first),
	      "the second time, the cookie carries the key the 200 accepted");

	connect_via(vpninfo, NULL, 0); /* a new key, no reply */
	start_cstp_connection(vpninfo, 1);
	second = sent_pubkey();
	CHECK(changes == 3 && !seen[2].request_sent && second && seen[2].candidate_key &&
	      !strcmp(seen[2].candidate_key, second) && !strcmp(seen[2].cookie_key, first),
	      "an unanswered rekey: once, before the request, with {accepted, new} to save");
	CHECK(signed_by(first), "a rekey is signed by the key it replaces");
	connect_via(vpninfo, NULL, 0); /* the same key again, no reply */
	start_cstp_connection(vpninfo, 1);
	CHECK(changes == 3, "presenting the unresolved key again changes nothing to save");

	/* 8. Which key signs for the unresolved one. After no answer (above, and the bridge
	 *    test's lost 200s): itself, as if the server took it. */
	presented = sent_pubkey();
	CHECK(presented && !strcmp(presented, second) && signed_by(second),
	      "after no answer, the unresolved key signs for itself");
	free(presented);

	/* The server answers with an error: it most likely still holds the accepted key,
	 * so the next CONNECT is the rekey again, signed by that one. */
	connect_via(vpninfo, unavailable, 3);
	CHECK(start_cstp_connection(vpninfo, 1) == -EINVAL, "a 503 fails the CONNECT");
	connect_via(vpninfo, NULL, 0);
	start_cstp_connection(vpninfo, 1);
	presented = sent_pubkey();
	CHECK(changes == 4 && !seen[3].request_sent && seen[3].candidate_key && presented &&
	      !strcmp(seen[3].candidate_key, presented) && !strcmp(seen[3].cookie_key, first),
	      "sending it again after an error, the handler runs first, with the same pair");
	CHECK(presented && !strcmp(presented, second) && signed_by(first) && !signed_by(second),
	      "after a 503, the same unresolved key, signed by the accepted one");
	free(presented);

	/* That one got no answer, so back to the first guess. A 401 ends the session as
	 * far as OpenConnect goes, and changes nothing about which key signs. */
	connect_via(vpninfo, unauthorized, 2);
	CHECK(start_cstp_connection(vpninfo, 1) == -EPERM && signed_by(second),
	      "after no answer again, it signs for itself; a 401 ends the connection");
	connect_via(vpninfo, NULL, 0);
	start_cstp_connection(vpninfo, 1);
	CHECK(signed_by(second), "and a 401 doesn't change which key signs next");

	/* The request can't be written: the server can't have taken the key. */
	connect_via(vpninfo, NULL, 0);
	fail_write = 1;
	start_cstp_connection(vpninfo, 1);
	fail_write = 0;
	CHECK(!sent[0], "a CONNECT that can't be written");
	connect_via(vpninfo, NULL, 0);
	start_cstp_connection(vpninfo, 1);
	presented = sent_pubkey();
	CHECK(presented && !strcmp(presented, second) && signed_by(first) && !signed_by(second),
	      "is sent again signed by the accepted key");
	CHECK(changes == 5 && !seen[4].request_sent, "and the handler runs before it goes out");
	free(presented);

	/* Through all of that only one new key was ever presented, so the pair to save
	 * never changed: the handler only ran again before resending it. */
	{
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		char *cand = openconnect_strap_candidate_cookie(vpninfo);
		char *next = cand ? resume_pubkey(cand, NULL) : NULL;
		CHECK(changes == 5 && saved && !strcmp(saved, first) && next && !strcmp(next, second),
		      "the pair to save is still {accepted, unresolved}");
		free(saved); free(cand); free(next);
	}

	/* Its 200 at last. */
	connect_via(vpninfo, ok_then_truncated, 1);
	start_cstp_connection(vpninfo, 1);
	{
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		CHECK(changes == 6 && saved && !strcmp(saved, second) && seen[5].cookie_key &&
		      !strcmp(seen[5].cookie_key, second),
		      "a 200 settles it: the handler runs with the unresolved key in the cookie");
		free(saved);
	}
	connect_via(vpninfo, ok_then_truncated, 1);
	start_cstp_connection(vpninfo, 1);
	presented = sent_pubkey();
	CHECK(presented && strcmp(presented, second) && signed_by(second),
	      "and the next CONNECT rekeys, signed by it");
	third = presented;

	/* A rekey whose request can't be built: the new key is made but nothing goes out.
	 * The next CONNECT sends that key, so it has to be saved first then. */
	CHECK(changes == 8, "that rekey ran the handler before it and at its 200");
	connect_via(vpninfo, NULL, 0);
	fail_buf = 1;
	CHECK(start_cstp_connection(vpninfo, 1) == -ENOMEM && !sent[0] && changes == 8,
	      "a rekey whose request can't be built sends nothing");
	connect_via(vpninfo, NULL, 0);
	start_cstp_connection(vpninfo, 1);
	fourth = sent_pubkey();
	CHECK(changes == 9 && !seen[8].request_sent && fourth && seen[8].candidate_key &&
	      !strcmp(seen[8].candidate_key, fourth) && strcmp(fourth, third),
	      "the next CONNECT presents that key, and the handler saves it before it goes out");
	CHECK(signed_by(third) && !signed_by(fourth), "signed by the accepted key");

	/* Its 200 comes, but the new key can't be put in the cookie. The cookie keeps the
	 * old key, so the new one stays the candidate and is presented again, never
	 * replaced by a newer one the server may never get. */
	connect_via(vpninfo, ok_then_truncated, 1);
	fail_buf = 2; /* past the request's, to the one putting the key in the cookie */
	start_cstp_connection(vpninfo, 1);
	CHECK(sent[0], "(that CONNECT was sent)");
	{
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		char *cand = openconnect_strap_candidate_cookie(vpninfo);
		char *next = cand ? resume_pubkey(cand, NULL) : NULL;
		CHECK(!fail_buf && saved && !strcmp(saved, third) && next && !strcmp(next, fourth),
		      "a 200 whose key can't be put in the cookie leaves {accepted, that key}");
		free(saved); free(cand); free(next);
	}
	connect_via(vpninfo, NULL, 0);
	start_cstp_connection(vpninfo, 1);
	presented = sent_pubkey();
	CHECK(presented && !strcmp(presented, fourth) && signed_by(fourth),
	      "and the next CONNECT presents it again rather than a newer key");
	free(presented);
	connect_via(vpninfo, ok_then_truncated, 1);
	start_cstp_connection(vpninfo, 1);
	{
		char *saved = resume_pubkey(vpninfo->cookie, NULL);
		CHECK(saved && !strcmp(saved, fourth), "until a 200 puts it in the cookie");
		free(saved);
	}

#ifdef HAVE_DTLS
	/* A rekey that returns early, after its new key is made, through a way out that
	 * doesn't know about STRAP: DTLS with no master secret. Until its request is
	 * written a key counts as not taken, so the next CONNECT resends it, saved first. */
	vpninfo->dtls_state = DTLS_SECRET;
	memset(vpninfo->dtls_secret, 0, sizeof(vpninfo->dtls_secret));
	connect_via(vpninfo, NULL, 0);
	CHECK(start_cstp_connection(vpninfo, 1) == -EINVAL && !sent[0] && changes == 11,
	      "a rekey that stops early (no DTLS secret) sends nothing");
	vpninfo->dtls_state = DTLS_DISABLED;
	connect_via(vpninfo, NULL, 0);
	start_cstp_connection(vpninfo, 1);
	presented = sent_pubkey();
	CHECK(changes == 12 && !seen[11].request_sent && presented && seen[11].candidate_key &&
	      !strcmp(seen[11].candidate_key, presented) && strcmp(presented, fourth) &&
	      signed_by(fourth) && !signed_by(presented),
	      "the next CONNECT resends its key, saved first and signed by the accepted one");
	free(presented);
#endif
	free(third); free(fourth);
}
#endif

int main(void)
{
	static const char *const ok_then_truncated[] = { "HTTP/1.1 200 OK" };
	struct openconnect_info *vpninfo, *rejoin = NULL;
	char *login_key, *accepted, *unanswered, *candidate;

	setvbuf(stdout, NULL, _IONBF, 0);
	openconnect_init_ssl();

	vpninfo = logged_in();
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

#ifndef WITHOUT_STRAP_PATCH
	test_handler_and_signing();
#endif

	printf(failures ? "%d FAILED\n" : "all passed\n", failures);
	return failures ? 1 : 0;
}
