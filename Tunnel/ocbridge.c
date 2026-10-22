#include "ocbridge.h"

#include <openconnect.h>
#include <Security/Security.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct ocb_session {
    struct openconnect_info *vpn;
    int cmd_fd;
    char *user, *password, *second;
    char *server;
    ocb_log_fn log;
    void *ctx;
    bool answered_user, answered_password, answered_second;
    char auth_error[512];
};

static void logf_(struct ocb_session *s, int level, const char *fmt, ...) {
    if (!s->log) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    size_t n = strlen(buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    if (n) s->log(s->ctx, level, buf);
}

// OpenConnect progress. Capped at PRG_INFO: DEBUG/TRACE dump HTTP bodies,
// which include the submitted password.
static void progress_cb(void *priv, int level, const char *fmt, ...) {
    struct ocb_session *s = priv;
    if (level > PRG_INFO || !s->log) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    logf_(s, level, "%s", buf);
}

// Answers each login field at most once, so a wrong password fails instead of
// being retried (and can't lock the account).
static int auth_form_cb(void *priv, struct oc_auth_form *form) {
    struct ocb_session *s = priv;
    if (form->error) logf_(s, PRG_ERR, "Server: %s", form->error);

    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        if (opt->flags & OC_FORM_OPT_IGNORE) continue;
        if (opt->type == OC_FORM_OPT_HIDDEN || opt->type == OC_FORM_OPT_SELECT) continue; // keep server defaults

        const char *value = NULL;
        bool *answered = NULL;
        const char *what = opt->name ? opt->name : "?";
        if (opt->type == OC_FORM_OPT_TEXT && opt->name && !strcmp(opt->name, "username")) {
            value = s->user; answered = &s->answered_user;
        } else if (opt->type == OC_FORM_OPT_PASSWORD && opt->name &&
                   !strcmp(opt->name, "secondary_password")) {
            value = s->second; answered = &s->answered_second;
        } else if (opt->type == OC_FORM_OPT_PASSWORD && opt->name && !strcmp(opt->name, "password")) {
            value = s->password; answered = &s->answered_password;
        }

        if (!value) {
            snprintf(s->auth_error, sizeof s->auth_error, "The server asked for an unexpected field (%s).", what);
            return OC_FORM_RESULT_CANCELLED;
        }
        if (*answered) {
            snprintf(s->auth_error, sizeof s->auth_error,
                     form->error ? "Login failed: %s" : "Login failed. Check your NetID and password.",
                     form->error ? form->error : "");
            return OC_FORM_RESULT_CANCELLED;
        }
        *answered = true;
        openconnect_set_option_value(opt, value);
        logf_(s, PRG_INFO, "Answered %s", what);
        if (value == s->second) logf_(s, PRG_INFO, "Waiting for Duo approval…");
    }
    return OC_FORM_RESULT_OK;
}

// OpenSSL on iOS has no CA store, so OpenConnect asks us. Verify the server's
// chain and hostname with the iOS trust store instead of blindly accepting.
static int validate_cert_cb(void *priv, const char *reason) {
    struct ocb_session *s = priv;
    struct oc_cert *chain = NULL;
    int n = openconnect_get_peer_cert_chain(s->vpn, &chain);
    if (n <= 0) return 1;

    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
    for (int i = 0; i < n; i++) {
        CFDataRef der = CFDataCreate(NULL, chain[i].der_data, chain[i].der_len);
        SecCertificateRef c = der ? SecCertificateCreateWithData(NULL, der) : NULL;
        if (c) { CFArrayAppendValue(certs, c); CFRelease(c); }
        if (der) CFRelease(der);
    }
    openconnect_free_peer_cert_chain(s->vpn, chain);

    // get_hostname() can return the resolved IP; the certificate is issued to the DNS name.
    const char *hostname = openconnect_get_dnsname(s->vpn);
    CFStringRef host = CFStringCreateWithCString(NULL, hostname ? hostname : "", kCFStringEncodingUTF8);
    SecPolicyRef policy = SecPolicyCreateSSL(true, host);
    SecTrustRef trust = NULL;
    CFErrorRef trustError = NULL;
    OSStatus created = CFArrayGetCount(certs) > 0
        ? SecTrustCreateWithCertificates(certs, policy, &trust) : errSecParam;
    bool ok = created == errSecSuccess && SecTrustEvaluateWithError(trust, &trustError);
    char why[160] = "";
    if (trustError) {
        CFStringRef d = CFErrorCopyDescription(trustError);
        if (d) { CFStringGetCString(d, why, sizeof why, kCFStringEncodingUTF8); CFRelease(d); }
        CFRelease(trustError);
    }
    if (trust) CFRelease(trust);
    CFRelease(policy);
    if (host) CFRelease(host);

    if (ok) logf_(s, PRG_INFO, "Server certificate verified by iOS");
    else {
        logf_(s, PRG_ERR, "Server certificate rejected (%s)", reason ? reason : "untrusted");
        snprintf(s->auth_error, sizeof s->auth_error,
                 "The server's certificate isn't trusted (%d certs from %d, host %s, status %d). %s",
                 (int)CFArrayGetCount(certs), n, hostname ? hostname : "?", (int)created, why);
    }
    CFRelease(certs);
    return ok ? 0 : 1;
}

ocb_session *ocb_new(const char *server, const char *user, const char *password,
                     const char *second_password, ocb_log_fn log, void *ctx) {
    static bool ssl_ready = false;
    if (!ssl_ready) { openconnect_init_ssl(); ssl_ready = true; }

    struct ocb_session *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->server = strdup(server);
    s->user = strdup(user);
    s->password = strdup(password);
    s->second = strdup(second_password);
    s->log = log;
    s->ctx = ctx;
    s->vpn = openconnect_vpninfo_new(NULL, validate_cert_cb, NULL, auth_form_cb, progress_cb, s);
    if (!s->vpn) { ocb_free(s); return NULL; }
    openconnect_set_loglevel(s->vpn, PRG_INFO);
    openconnect_set_reported_os(s->vpn, "apple-ios");
    s->cmd_fd = openconnect_setup_cmd_pipe(s->vpn);
    return s;
}

int ocb_connect(ocb_session *s, char *err, size_t errlen) {
    if (openconnect_parse_url(s->vpn, s->server)) {
        snprintf(err, errlen, "Invalid server address.");
        return -1;
    }
    if (openconnect_obtain_cookie(s->vpn)) {
        snprintf(err, errlen, "%s", s->auth_error[0] ? s->auth_error : "Login failed or was cancelled.");
        return -1;
    }
    if (openconnect_make_cstp_connection(s->vpn)) {
        snprintf(err, errlen, "Logged in, but couldn't open the VPN session.");
        return -1;
    }
    if (openconnect_setup_dtls(s->vpn, 60)) logf_(s, PRG_INFO, "DTLS unavailable; using TLS only");
    return 0;
}

static char *dup_or_null(const char *v) { return v && *v ? strdup(v) : NULL; }

static char *join_routes(struct oc_split_include *list) {
    size_t len = 0;
    for (struct oc_split_include *r = list; r; r = r->next) len += strlen(r->route) + 1;
    if (!len) return NULL;
    char *out = calloc(1, len + 1), *p = out;
    for (struct oc_split_include *r = list; r; r = r->next) p += sprintf(p, "%s\n", r->route);
    return out;
}

int ocb_get_config(ocb_session *s, ocb_config *out) {
    const struct oc_ip_info *ip = NULL;
    memset(out, 0, sizeof *out);
    if (openconnect_get_ip_info(s->vpn, &ip, NULL, NULL) || !ip || !ip->addr) return -1;
    out->addr = dup_or_null(ip->addr);
    out->netmask = dup_or_null(ip->netmask ? ip->netmask : "255.255.255.255");
    out->addr6 = dup_or_null(ip->netmask6 ? ip->netmask6 : NULL);
    for (int i = 0; i < 3; i++) out->dns[i] = dup_or_null(ip->dns[i]);
    out->domain = dup_or_null(ip->domain);
    out->gateway = dup_or_null(ip->gateway_addr);
    out->split_includes = join_routes(ip->split_includes);
    out->split_excludes = join_routes(ip->split_excludes);
    out->split_dns = join_routes(ip->split_dns);
    out->mtu = ip->mtu;
    return 0;
}

void ocb_config_free(ocb_config *c) {
    free(c->addr); free(c->netmask); free(c->addr6);
    for (int i = 0; i < 3; i++) free(c->dns[i]);
    free(c->domain); free(c->gateway);
    free(c->split_includes); free(c->split_excludes); free(c->split_dns);
    memset(c, 0, sizeof *c);
}

int ocb_run(ocb_session *s, int tun_fd) {
    if (openconnect_setup_tun_fd(s->vpn, tun_fd)) return -1;
    return openconnect_mainloop(s->vpn, 300, RECONNECT_INTERVAL_MIN);
}

void ocb_cancel(ocb_session *s) {
    char cmd = OC_CMD_CANCEL;
    if (s && s->cmd_fd >= 0) (void)!write(s->cmd_fd, &cmd, 1);
}

static void wipe_free(char *p) {
    if (!p) return;
    memset_s(p, strlen(p), 0, strlen(p));
    free(p);
}

void ocb_free(ocb_session *s) {
    if (!s) return;
    if (s->vpn) openconnect_vpninfo_free(s->vpn);
    wipe_free(s->password);
    wipe_free(s->second);
    free(s->user);
    free(s->server);
    free(s);
}

// iOS doesn't ship these kernel-control declarations (sys/kern_control.h).
#define OCB_AF_SYSTEM 32
#define OCB_CTLIOCGINFO 0xc0644e03UL
struct ocb_ctl_info { uint32_t ctl_id; char ctl_name[96]; };
struct ocb_sockaddr_ctl {
    uint8_t sc_len, sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id, sc_unit, sc_reserved[5];
};

int ocb_find_utun_fd(void) {
    struct ocb_ctl_info info = {0};
    strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof info.ctl_name);
    for (int fd = 0; fd <= 1024; fd++) {
        struct ocb_sockaddr_ctl addr = {0};
        socklen_t len = sizeof addr;
        if (getpeername(fd, (struct sockaddr *)&addr, &len) != 0 || addr.sc_family != OCB_AF_SYSTEM) continue;
        if (info.ctl_id == 0 && ioctl(fd, OCB_CTLIOCGINFO, &info) != 0) continue;
        if (addr.sc_id == info.ctl_id) return fd;
    }
    return -1;
}
