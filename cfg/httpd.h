/* v90d/cfg - minimal HTTP/1.0 status and settings server (RFC 1945 subset).
 *
 *   GET /             HTML status page
 *   GET /status.json  the same as JSON
 *   GET /port2, /status2.json   the same for the second port, when there is one
 *   GET /config       effective configuration as text, secrets redacted
 *   GET /line /modem /users /network /system
 *                     the settings a user changes, one page per subject
 *                     (settings.h); POST on the same path: the form coming
 *                     back, answered 303 to that path with ?saved=1
 *   GET, POST /settings   all of them on one page (no tab leads here)
 *
 *   GET /firmware     which firmware runs, the upload form (firmware.h)
 *   GET /firmware/stock    the question before going back to the stock firmware
 *   POST /firmware/upload, POST /firmware/stock
 *                     checked here (login, origin, length), then the
 *                     connection itself is handed to the owner of the
 *                     server, who gives it to a helper process: see
 *                     httpd_on_firmware()
 *   GET /login        the login page;  POST /login  user name and password
 *   GET /logout       ends the session
 *   POST /restart     sets restart_asked (the Restart button)
 *
 * With an admin password in the config every view above needs a login: the
 * session cookie that POST /login hands out (one session, 15 minutes after
 * its last use, HttpOnly, SameSite=Strict), or HTTP Basic credentials with
 * the user name admin (for scripts). A browser without either is sent to
 * /login (303); a wrong login is answered 401 and holds further tries for
 * a second (429). Without an admin password there is no login and the
 * pages are open to the LAN.
 *
 * /cgi-bin/login, where the
 * stock firmware of the box sent browsers for good, is a 302 to /.
 * HEAD is answered like GET without the body. Any other path is 404, any
 * other method 405 (POST too, except on /settings), anything malformed
 * 400, a request head that does not fit HTTPD_REQ_MAX is 431, a request
 * that does not arrive in time is 408. A query string is ignored, except
 * that /settings?saved=1 adds the line "Settings saved." Every response
 * closes the connection; bytes after the first request are discarded.
 *
 * POST /settings takes an application/x-www-form-urlencoded body of at
 * most HTTPD_POST_MAX octets with a Content-Length. In this order:
 *
 *   401  an admin password is set and the request does not carry it
 *   403  no save callback is registered (httpd_on_save)
 *   403  there is an Origin header and it names another host than Host
 *   400  Transfer-Encoding, or one of the headers used here twice
 *   415  Content-Type is not the form type
 *   411  no Content-Length; 400 if it is not a plain number
 *   413  Content-Length above HTTPD_POST_MAX (answered without reading
 *        the body)
 *   400  the body is malformed: bad percent escape, NUL octet, a field
 *        twice, an unknown field (plain text answer)
 *   400  a value is not acceptable or the resulting config does not pass
 *        cfg_validate: the form again, with the message and with what was
 *        posted (HTML answer)
 *   500  the save callback returned nonzero (plain text answer)
 *   303  saved; Location: /settings?saved=1
 *
 * When the config has a non-empty admin_password, GET, HEAD and POST on
 * /settings need HTTP Basic credentials (RFC 7617) with the user name
 * `admin` and that password; without them the answer is 401 with a
 * WWW-Authenticate challenge. The comparison is constant-time. The status
 * views are never protected. Basic credentials cross the LAN in clear
 * text, like everything else here.
 *
 * Nothing here blocks, allocates or uses a global: all state is in the
 * caller's httpd_t (about 76 KB), so two instances are independent. The
 * daemon calls httpd_poll() from its loop; one call costs one poll() system
 * call with a zero timeout when no socket is ready, and at most one recv
 * and one send per ready connection otherwise. Calling it every 10 to 20 ms
 * is plenty; do not call it per audio sample. The one thing that can take
 * time inside httpd_poll() is the save callback, see httpd_on_save().
 *
 * At most HTTPD_MAX_CONN connections are held. A further one is sent a
 * short 503 (best effort) and closed at once. A connection has
 * rx_timeout_ms from adoption to deliver its whole request, head and body
 * (a deadline for the whole request, not an idle timer, so a
 * byte-at-a-time sender cannot hold a slot), tx_timeout_ms to take the
 * response, and linger_ms after that to close its side before we do.
 *
 * now_ms is any millisecond clock; it may wrap. Timeouts must be below
 * 2^31 ms.
 *
 * The cfg and status structs are read when a request is answered, so the
 * daemon just keeps them up to date. */
#ifndef V90D_CFG_HTTPD_H
#define V90D_CFG_HTTPD_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "status.h"
#include "settings.h"
#include "firmware.h"

#define HTTPD_MAX_CONN     4
#define HTTPD_SESSIONS     4      /* logins at a time; one more replaces the one unused the longest */
#define HTTPD_REQ_MAX      2048   /* largest request head accepted */
#define HTTPD_POST_MAX     SETTINGS_BODY_MAX  /* largest body of a posted
                                     settings form (8192) */
#define HTTPD_HDR_RESERVE  512    /* room for our response head */
#define HTTPD_BODY_MAX     26624  /* largest response body (>= STATUS_HTML_MAX,
                                     STATUS_JSON_MAX, CFG_TEXT_REDACTED_MAX,
                                     SETTINGS_HTML_MAX) */
#define HTTPD_TX_MAX       (HTTPD_HDR_RESERVE + HTTPD_BODY_MAX)
#define HTTPD_FW_UPLOAD_MAX (4u * 1024u * 1024u + 4096u)  /* largest body of POST
                                     /firmware/upload: it is never read here */
#define HTTPD_FW_STOCK_MAX  64    /* largest body of POST /firmware/stock */
#define HTTPD_CTYPE_MAX     200   /* a longer Content-Type on those two is refused */

#define HTTPD_RX_TIMEOUT_MS  5000u
#define HTTPD_TX_TIMEOUT_MS  10000u
#define HTTPD_LINGER_MS      1000u

typedef struct {
    int      fd;                 /* -1 when the slot is free */
    int      state;
    uint32_t deadline;           /* now_ms value at which the state expires */
    size_t   rx_len;
    size_t   tx_off, tx_end;     /* unsent response is tx[tx_off..tx_end) */
    size_t   body_len, body_want;  /* posted body so far and in all; it is
                                    collected in tx[] */
    int      post_page;          /* ... or the settings page (settings.h) it came from */
    int      post_login;         /* the body being collected is a login form (1) or a VPN profile (2) */
    char     rx[HTTPD_REQ_MAX];
    char     tx[HTTPD_TX_MAX];
} httpd_conn_t;

typedef struct {
    uint32_t adopted;            /* connections taken into the table */
    uint32_t rejected;           /* refused: table full or bad fd */
    uint32_t requests;           /* complete request heads parsed */
    uint32_t ok;                 /* 200 responses */
    uint32_t bad;                /* 4xx and 5xx responses */
    uint32_t saves;              /* settings saved (303 responses) */
    uint32_t timeouts;           /* receive, send or linger deadline hit */
    uint32_t tx_stalls;          /* sends that were short or would block */
    uint32_t handed;             /* connections handed over (httpd_on_firmware) */
} httpd_stats_t;

/* The Firmware page's two sides, both optional (see httpd_on_firmware). */
enum { HTTPD_FW_UPLOAD = 1, HTTPD_FW_STOCK = 2 };
enum { HTTPD_FW_WHERE = 0, HTTPD_FW_STATE = 1 };
typedef struct {
    const char *version;         /* what this build calls itself; NULL: V90D_VERSION */
    /* One of the page's two texts (firmware.h) into buf, at most cap - 1
     * octets and a NUL; returns the length, 0 if there is none. Called
     * while a GET is answered, so it must be quick. */
    int       (*text)(void *ctx, int which, char *buf, size_t cap);
    /* A post that passed every check here. fd is the browser's connection,
     * non-blocking; early[0..early_len) is what of the body (content_length
     * octets in all) has been read from it already; ctype is the
     * Content-Type, "" if none came. Return NULL to take it: the answer is
     * then the taker's to write, and the server closes its own descriptor
     * on return, so the taker must hold one of its own by then (a forked
     * child does; otherwise dup). Or return the reason it cannot be done
     * now, which is sent to the browser (409) with the connection kept. */
    const char *(*take)(void *ctx, int what, int fd, const char *early, size_t early_len,
                        size_t content_length, const char *ctype);
    /* POST /firmware/update: install the release the daily check found (its
     * version is in the Firmware page's WHERE text as update_avail). No body.
     * Return NULL once it is under way (the box then downloads, writes and
     * restarts on its own), or the reason it cannot be done now (sent 409,
     * connection kept). NULL here: /firmware/update is refused (501). */
    const char *(*install)(void *ctx);
    void       *ctx;
} httpd_fw_t;

/* Treat as private except the three timeouts, which may be changed after
 * httpd_init(), and stats, which may be read. */
typedef struct httpd {
    cfg_t          *cfg;
    const status_t *status;
    const status_t *status2;        /* port 2, or NULL */
    int           (*save)(void *ctx, const cfg_t *newcfg);
    int           (*vpn)(void *ctx, const char *profile, size_t len); void *vpn_ctx;
    int           (*diag)(void *ctx, char *buf, size_t cap); void *diag_ctx;    /* GET /log */
    status_bbs_rows bbs; void *bbs_ctx;
    const char *bbs_query; size_t bbs_qlen;     /* of the request being answered */
    void           *save_ctx;
    int             listen_fd;   /* -1 when there is none */
    uint32_t        rx_timeout_ms, tx_timeout_ms, linger_ms;
    httpd_stats_t   stats;
    struct {                     /* the login sessions */
        char        sid[33];     /* the cookie value */
        int         on;
        uint32_t    seen;        /* now_ms of its last use */
    } sess[HTTPD_SESSIONS];
    char            sid[33];     /* scratch: the cookie value of the login being answered */
    int             restart_asked;  /* POST /restart was accepted: the owner
                                    restarts the box when the answer is out
                                    (httpd_active() == 0) */
    httpd_fw_t      fw;
    int             hold_on;     /* a wrong login: none accepted until hold_until */
    uint32_t        hold_until;
    httpd_conn_t    conn[HTTPD_MAX_CONN];
} httpd_t;

/* Set up an idle server. cfg and status must outlive it. *cfg is read
 * for every request and is written in one case only: after a save callback
 * (below) has returned 0, the saved config is copied into it. */
void httpd_init(httpd_t *h, cfg_t *cfg, const status_t *status);
/* A second telephone port: its status is at /port2 and /status2.json, and
 * the page at / shows both ports. Must outlive the server. */
void httpd_status2(httpd_t *h, const status_t *status2);

/* Register what happens when the settings form is posted with acceptable
 * values. save() gets the complete new config (it has passed
 * cfg_validate) and stores and applies it, typically with cfg_save(). At
 * that moment *cfg of httpd_init() still holds the old config, so the two
 * can be compared. Return 0 for success: the server then copies *newcfg
 * into *cfg, so every view shows the new values, and redirects the browser
 * to the form. Return nonzero if it could not be stored: *cfg stays as it
 * is and the browser is told (500). newcfg points into the server's stack
 * and is gone when save() returns.
 *
 * save() runs inside httpd_poll(). If it blocks (cfg_save does: write,
 * fsync, rename), so does that call; a daemon that cannot afford this
 * during a call can copy *newcfg, return 0 and store it later.
 *
 * Without a callback (the state after httpd_init, or save = NULL) the form
 * is shown but a post is answered 403. */
void httpd_on_save(httpd_t *h, int (*save)(void *ctx, const cfg_t *newcfg), void *ctx);
/* POST /dreamcast/vpn (text/plain, from the form of the Dreamcast page, at
 * most VPN_PROFILE_MAX octets of profile): a profile that passes
 * vpn_profile_check() is handed to keep(), len 0 = the stored one is to be
 * removed; 0 from it is answered with 303 to the page, anything else with
 * 500. A profile that does not pass is 400 with the page and the reason.
 * Login, Host and Origin rules as for the settings; 403 without a keep. */
/* The BBS page's boards (status.h, status_render_bbs); NULL = no list. */
void httpd_on_bbs(httpd_t *h, status_bbs_rows rows, void *ctx);
void httpd_on_vpn(httpd_t *h, int (*keep)(void *ctx, const char *profile, size_t len), void *ctx);
/* GET /log: a plain-text diagnostics dump (the daemon's recent log and the
 * kernel's) the owner can read or save and attach to a bug report, so a board
 * that misbehaves need not be opened for a serial console. Behind the same
 * login as the other pages. diag() writes at most cap-1 octets and a NUL into
 * buf and returns the length; without this callback /log says so. */
void httpd_on_diag(httpd_t *h, int (*diag)(void *ctx, char *buf, size_t cap), void *ctx);

/* Register the Firmware page's helpers (copied; NULL takes them away).
 * Without `text` the page shows the version only; without `take` it offers
 * no forms and the two posts are answered 403. The posts are checked like
 * the settings form (login or Basic credentials, same origin, by address
 * when there is no password, a Content-Length within HTTPD_FW_UPLOAD_MAX
 * or HTTPD_FW_STOCK_MAX, no Transfer-Encoding), then `take` decides. The
 * body is never read into this server: a firmware is megabytes, and the
 * daemon's loop has 10 ms. */
void httpd_on_firmware(httpd_t *h, const httpd_fw_t *fw);

/* Open a non-blocking listening TCP socket on bind_addr:port (address in
 * host byte order) and keep it in h; httpd_poll() then accepts from it.
 * bind_addr 0 (every address) is taken only together with an ifname, so
 * that it means every address of that interface, and refused (EINVAL)
 * otherwise: this server is for the LAN side only.
 * If ifname is not NULL and the platform has SO_BINDTODEVICE, the socket
 * is also tied to that interface, which is what really keeps the dial-in
 * peer out (binding to the LAN address alone does not: Linux accepts a
 * packet for that address from any interface). Returns 0, or -1 with
 * errno set. */
int httpd_listen(httpd_t *h, uint32_t bind_addr, uint16_t port, const char *ifname);

/* Take over an accepted, connected stream socket. The fd is made
 * non-blocking and is owned by the server from here on, also on failure.
 * Returns the slot index, or -1 if the table is full or the fd is unusable
 * (the fd is closed). */
int httpd_adopt(httpd_t *h, int fd, uint32_t now_ms);

/* One step: accept what is waiting, move every connection along as far as
 * it goes without blocking, enforce the deadlines. */
void httpd_poll(httpd_t *h, uint32_t now_ms);

/* Number of connections in the table. */
int httpd_active(const httpd_t *h);

/* Close the listening socket and every connection. */
void httpd_close(httpd_t *h);

#endif
