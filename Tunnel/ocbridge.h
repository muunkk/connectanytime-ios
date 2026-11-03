// Thin C layer over libopenconnect for the packet tunnel extension.
// Swift can't implement OpenConnect's printf-style callbacks, so they live here.
#ifndef OCBRIDGE_H
#define OCBRIDGE_H

#include <stddef.h>

typedef struct ocb_session ocb_session;
typedef void (*ocb_log_fn)(void *ctx, int level, const char *line);
typedef void (*ocb_event_fn)(void *ctx);

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
} ocb_config;

ocb_session *ocb_new(const char *server, const char *user, const char *password,
                     const char *second_password, ocb_log_fn log,
                     ocb_event_fn reconnected, void *ctx);

/// Logs in (username, password, then second password for Duo) and opens the
/// VPN session. Blocks until Duo is approved or rejected. 0 on success.
int ocb_connect(ocb_session *s, char *err, size_t errlen);

int ocb_get_config(ocb_session *s, ocb_config *out);
void ocb_config_free(ocb_config *c);

/// Runs the tunnel on `tun_fd` until cancelled or the server ends it. If the
/// connection drops, keeps retrying with the existing session (no new login or
/// Duo) for up to `reconnect_timeout` seconds. Calls `reconnected` on success.
int ocb_run(ocb_session *s, int tun_fd, int reconnect_timeout);

/// Thread-safe: drops the current connection and reconnects right away with
/// the existing session, e.g. after switching networks.
void ocb_reconnect(ocb_session *s);

/// Thread-safe: aborts ocb_connect or ocb_run.
void ocb_cancel(ocb_session *s);

void ocb_free(ocb_session *s);

/// The utun file descriptor iOS created for this packet tunnel, or -1.
int ocb_find_utun_fd(void);

#endif
