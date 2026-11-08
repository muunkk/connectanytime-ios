// Thin C layer over libopenconnect for the packet tunnel extension.
// Swift can't implement OpenConnect's printf-style callbacks, so they live here.
#ifndef OCBRIDGE_H
#define OCBRIDGE_H

#include <stddef.h>

typedef struct ocb_session ocb_session;
typedef void (*ocb_log_fn)(void *ctx, int level, const char *line);

/// Tunnel settings pushed by the server. Strings are owned by the struct.
typedef struct {
    char *addr, *netmask;     // IPv4
    char *addr6;              // IPv6 "addr/len", may be NULL
    char *dns[3];
    char *domain;
    char *gateway;            // server IP actually connected to
    char *split_includes;     // newline-separated "net/mask", may be NULL
    char *split_excludes;
    char *split_dns;
    int mtu;
    char *key;                // all of the above in one string, to tell configs apart
} ocb_config;

/// OCB_RECONNECTING: the connection dropped and OpenConnect is retrying.
/// OCB_ATTEMPT: a reconnect attempt is starting.
/// OCB_RECONNECTED: back up; `cfg` holds the server's (possibly new) tunnel settings.
/// `cfg` is NULL for the other events, and only valid during the call.
enum { OCB_RECONNECTING, OCB_ATTEMPT, OCB_RECONNECTED };
typedef void (*ocb_event_fn)(void *ctx, int event, const ocb_config *cfg);

ocb_session *ocb_new(const char *server, const char *user, const char *password,
                     const char *second_password, ocb_log_fn log,
                     ocb_event_fn event, void *ctx);

/// Logs in (username, password, then second password for Duo) and opens the
/// VPN session. Blocks until Duo is approved or rejected. 0 on success,
/// OCB_UNREACHABLE if it failed before sending the password (so no Duo push was
/// sent and trying again is safe), any other negative value on other failures.
#define OCB_UNREACHABLE (-3)
int ocb_connect(ocb_session *s, char *err, size_t errlen);

/// Rejoins the session from an earlier login instead of logging in: no password,
/// no Duo. The arguments come from the ocb_session_* getters below; `dnsname` and
/// `ip` (may be NULL) pin the server's name to the address the session was made
/// on. 0 on success, OCB_SESSION_ENDED if the server no longer accepts the session,
/// any other negative value on other failures (e.g. no network).
#define OCB_SESSION_ENDED (-2)
int ocb_resume(ocb_session *s, const char *url, const char *cookie, const char *dnsname,
               const char *ip, char *err, size_t errlen);

/// After ocb_connect or ocb_resume succeeds: what ocb_resume needs to rejoin the
/// session later. Owned by the session. The cookie is a credential; never log it.
const char *ocb_session_url(ocb_session *s);
const char *ocb_session_cookie(ocb_session *s);
const char *ocb_session_dnsname(ocb_session *s);
const char *ocb_session_ip(ocb_session *s);

int ocb_get_config(ocb_session *s, ocb_config *out);
void ocb_config_free(ocb_config *c);

/// Runs the tunnel on `tun_fd` until cancelled or the server ends it. If the
/// connection drops, keeps retrying with the existing session (no new login or
/// Duo) for up to `reconnect_timeout` seconds of sleeps between attempts. Reports
/// OCB_RECONNECTING when it notices a dropped connection and OCB_RECONNECTED after.
int ocb_run(ocb_session *s, int tun_fd, int reconnect_timeout);

/// Thread-safe: drops the current connection and reconnects right away with
/// the existing session, e.g. after switching networks.
void ocb_reconnect(ocb_session *s);

/// Thread-safe: aborts ocb_connect or ocb_run, logging out of the server's session.
void ocb_cancel(ocb_session *s);

/// Thread-safe: like ocb_cancel, but leaves the server's session open, so
/// ocb_resume can rejoin it.
void ocb_detach(ocb_session *s);

void ocb_free(ocb_session *s);

/// The utun file descriptor iOS created for this packet tunnel, or -1.
int ocb_find_utun_fd(void);

#endif
