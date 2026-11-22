/* v90d/cfg - minimal HTTP/1.0 status and settings server. See httpd.h.
 *
 * Written from RFC 1945 (and RFC 7617 for Basic authentication). A
 * connection walks through these states:
 *
 *   RECV    collect the request head (up to the empty line) in rx[]
 *   BODY    only for a post of the settings form: collect Content-Length
 *           octets of body. They go into tx[], which is idle until the
 *           answer is built, and are decoded into a config on the stack
 *           before the answer overwrites them.
 *   SEND    push the response, built in one piece in tx[]
 *   LINGER  our side is shut down; discard what the client still sends
 *           until it closes, so that closing does not reset the connection
 *           under a response the client has not read yet
 *
 * Each state has a deadline. All socket calls are non-blocking and a
 * connection gets a bounded amount of work per httpd_poll(). */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "httpd.h"
#include "sbuf.h"
#include "page.h"
#include "vpn.h"

enum { HC_FREE = 0, HC_RECV, HC_BODY, HC_SEND, HC_LINGER };
enum { V_ERROR = 0, V_HTML, V_JSON, V_CONFIG, V_HTML2, V_JSON2 /* port 2 */, V_CALLS, V_BBS, V_LOG };
enum { M_GET, M_HEAD, M_POST, M_OTHER };

#define CRED_MAX (6 + CFG_SECRET_MAX)   /* "admin:" and the longest password */

/* the body of a post waits in tx[], and every page fits a response */
typedef char httpd_post_fits_tx[HTTPD_POST_MAX <= HTTPD_TX_MAX ? 1 : -1];
typedef char httpd_pages_fit[HTTPD_BODY_MAX >= STATUS_HTML_MAX && HTTPD_BODY_MAX >= STATUS_JSON_MAX &&
                             HTTPD_BODY_MAX >= CFG_TEXT_REDACTED_MAX &&
                             HTTPD_BODY_MAX >= SETTINGS_HTML_MAX && HTTPD_BODY_MAX >= FIRMWARE_HTML_MAX ? 1 : -1];

static const char CT_TEXT[] = "text/plain; charset=us-ascii";
static const char CT_HTML[] = "text/html; charset=utf-8";
/* extra header lines of some answers */
static const char ALLOW_READ[] = "Allow: GET, HEAD\r\n";
static const char ALLOW_FORM[] = "Allow: GET, HEAD, POST\r\n";
static const char CHALLENGE[]  = "WWW-Authenticate: Basic realm=\"v90d settings\"\r\n";

static int expired(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;      /* correct across wrap */
}

static const char *reason(int code)
{
    switch (code) {
    case 200: return "OK";
    case 302: return "Found";
    case 303: return "See Other";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Request Entity Too Large";
    case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 503: return "Service Unavailable";
    default:  return "Internal Server Error";
    }
}

static void conn_close(httpd_conn_t *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->state = HC_FREE;
    c->rx_len = c->tx_off = c->tx_end = 0;
    c->body_len = c->body_want = 0;
}

/* extra: further header lines, each with its CR LF, or NULL */
static void put_head(sbuf_t *s, int code, const char *ctype, size_t clen, const char *extra)
{
    sb_puts(s, "HTTP/1.0 "); sb_u64(s, (uint64_t)code); sb_putc(s, ' ');
    sb_puts(s, reason(code));
    sb_puts(s, "\r\nServer: v90d\r\nContent-Type: "); sb_puts(s, ctype);
    sb_puts(s, "\r\nContent-Length: "); sb_u64(s, clen);
    sb_puts(s, "\r\nConnection: close\r\n"
               "Cache-Control: no-store\r\n"
               "X-Content-Type-Options: nosniff\r\n"
               "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';"
               " form-action 'self'; frame-ancestors 'none'\r\n");
    if (extra) sb_puts(s, extra);
    sb_puts(s, "\r\n");
}

/* "<code> <reason>\n", then the note as a second line if there is one */
static int error_body(int code, const char *note, char *buf, size_t cap)
{
    sbuf_t s;
    sb_init(&s, buf, cap);
    sb_u64(&s, (uint64_t)code); sb_putc(&s, ' '); sb_puts(&s, reason(code)); sb_putc(&s, '\n');
    if (note) { sb_puts(&s, note); sb_putc(&s, '\n'); }
    return sb_end(&s);
}

static void do_send(httpd_t *h, httpd_conn_t *c, uint32_t now)
{
    ssize_t r = send(c->fd, c->tx + c->tx_off, c->tx_end - c->tx_off, MSG_NOSIGNAL);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) h->stats.tx_stalls++;
        else if (errno != EINTR) conn_close(c);
        return;
    }
    c->tx_off += (size_t)r;
    if (c->tx_off < c->tx_end) { h->stats.tx_stalls++; return; }
    /* all sent: end of our stream, then wait for the client to finish */
    shutdown(c->fd, SHUT_WR);
    c->state = HC_LINGER;
    c->deadline = now + h->linger_ms;
}

/* Start sending a response whose body of blen octets is already in place
 * in tx[], behind the room kept for the head: the head is now put right in
 * front of it. blen < 0 (a renderer that did not fit: cannot happen) turns
 * the answer into a 500. */
static void finish(httpd_t *h, httpd_conn_t *c, int code, const char *ctype, const char *extra,
                   int blen, int head_only, uint32_t now)
{
    char head[HTTPD_HDR_RESERVE];
    char *body = c->tx + HTTPD_HDR_RESERVE;
    sbuf_t s;
    int hlen;

    if (blen < 0) {
        code = 500; ctype = CT_TEXT; extra = NULL;
        blen = error_body(code, NULL, body, HTTPD_BODY_MAX);
    }
    sb_init(&s, head, sizeof head);
    put_head(&s, code, ctype, (size_t)blen, extra);
    hlen = sb_end(&s);
    if (hlen < 0) { conn_close(c); return; }
    memcpy(body - hlen, head, (size_t)hlen);

    if (code == 200) h->stats.ok++;
    else if (code >= 400) h->stats.bad++;
    c->tx_off = (size_t)(HTTPD_HDR_RESERVE - hlen);
    c->tx_end = HTTPD_HDR_RESERVE + (head_only ? 0u : (size_t)blen);
    c->state = HC_SEND;
    c->deadline = now + h->tx_timeout_ms;
    do_send(h, c, now);
}

/* a short plain-text answer: the status line again, and a note if any */
static void respond_text(httpd_t *h, httpd_conn_t *c, int code, const char *extra, const char *note,
                         int head_only, uint32_t now)
{
    int blen = error_body(code, note, c->tx + HTTPD_HDR_RESERVE, HTTPD_BODY_MAX);
    finish(h, c, code, CT_TEXT, extra, blen, head_only, now);
}

/* one of the status views, or with V_ERROR the plain answer for code */
static void respond(httpd_t *h, httpd_conn_t *c, int code, int view, int head_only, uint32_t now)
{
    char *body = c->tx + HTTPD_HDR_RESERVE;

    switch (view) {
    case V_HTML:
    case V_HTML2:
        if (h->status2) {
            const status_t *both[2];
            both[0] = h->status; both[1] = h->status2;
            finish(h, c, code, CT_HTML, NULL, status_render_ports(both, view == V_HTML2, body, HTTPD_BODY_MAX),
                   head_only, now);
        } else {
            finish(h, c, code, CT_HTML, NULL, status_render_html(h->status, body, HTTPD_BODY_MAX),
                   head_only, now);
        }
        break;
    case V_CALLS: {
        const status_t *both[2];
        both[0] = h->status; both[1] = h->status2;
        finish(h, c, code, CT_HTML, NULL, status_render_calls(both, body, HTTPD_BODY_MAX), head_only, now);
        break;
    }
    case V_BBS:
        finish(h, c, code, CT_HTML, NULL, status_render_bbs(h->bbs, h->bbs_ctx, h->bbs_query, h->bbs_qlen, body, HTTPD_BODY_MAX), head_only, now);
        break;
    case V_JSON:
    case V_JSON2:
        finish(h, c, code, "application/json", NULL,
               status_render_json(view == V_JSON2 ? h->status2 : h->status, body, HTTPD_BODY_MAX), head_only, now);
        break;
    case V_CONFIG:
        finish(h, c, code, CT_TEXT, NULL, cfg_write(h->cfg, 0, body, HTTPD_BODY_MAX), head_only, now);
        break;
    case V_LOG:
        if (h->diag)
            finish(h, c, code, CT_TEXT, NULL, (size_t)h->diag(h->diag_ctx, body, HTTPD_BODY_MAX), head_only, now);
        else
            respond_text(h, c, code, NULL, "no diagnostics source\n", head_only, now);
        break;
    default:
        respond_text(h, c, code, code == 405 ? ALLOW_READ : NULL, NULL, head_only, now);
        break;
    }
}

/* Length of the request head in p[0..n) including its empty line, or 0 if
 * the empty line is not there yet. A line ends in LF, CR before it is
 * optional. Only the part from `from` on needs a look. */
static size_t head_end(const char *p, size_t n, size_t from)
{
    size_t i = from > 2 ? from - 2 : 0;
    for (; i < n; i++) {
        if (p[i] != '\n') continue;
        if (i + 1 < n && p[i + 1] == '\n') return i + 2;
        if (i + 2 < n && p[i + 1] == '\r' && p[i + 2] == '\n') return i + 3;
    }
    return 0;
}

/* ---- request headers ------------------------------------------------------- */

typedef struct {
    const char *v;      /* value of the first occurrence, blanks trimmed */
    size_t      len;
    int         count;  /* how many lines carry this name */
} hdr_t;

static int is_blank(char ch) { return ch == ' ' || ch == '\t'; }

/* 1 if a[0..n) is b[0..n) apart from the case of ASCII letters */
static int ieq(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x += 32u;
        if (y >= 'A' && y <= 'Z') y += 32u;
        if (x != y) return 0;
    }
    return 1;
}

/* Look up a header by name (any case) in the head p[0..n). The request
 * line is skipped; a continuation line (one that starts with a blank) is
 * not a header and is not part of a value either. */
static void hdr_find(const char *p, size_t n, const char *name, hdr_t *o)
{
    size_t nl = strlen(name), i = 0;

    o->v = ""; o->len = 0; o->count = 0;
    while (i < n && p[i] != '\n') i++;
    i++;
    while (i < n) {
        size_t b = i, e;
        while (i < n && p[i] != '\n') i++;
        e = i++;
        if (e > b && p[e - 1] == '\r') e--;
        if (e - b <= nl || p[b + nl] != ':' || !ieq(p + b, name, nl)) continue;
        if (o->count++) continue;
        b += nl + 1;
        while (b < e && is_blank(p[b])) b++;
        while (e > b && is_blank(p[e - 1])) e--;
        o->v = p + b;
        o->len = e - b;
    }
}

static int b64_val(char ch)
{
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

/* strict base64: whole quanta, padding only at the very end. -1 if it is
 * malformed or decodes to more than cap octets. */
static int b64_decode(const char *p, size_t n, unsigned char *out, size_t cap, size_t *olen)
{
    size_t i, o = 0;

    if (n == 0 || n % 4u) return -1;
    for (i = 0; i < n; i += 4) {
        int a = b64_val(p[i]), b = b64_val(p[i + 1]), c = b64_val(p[i + 2]), d = b64_val(p[i + 3]);
        size_t pad = 0;
        if (i + 4 == n && p[i + 3] == '=') {
            pad = 1; d = 0;
            if (p[i + 2] == '=') { pad = 2; c = 0; }
        }
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        if (o + 3 - pad > cap) return -1;
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
        if (pad < 2) out[o++] = (unsigned char)(((b & 15) << 4) | (c >> 2));
        if (pad < 1) out[o++] = (unsigned char)(((c & 3) << 6) | d);
    }
    *olen = o;
    return 0;
}

/* 1 if the Authorization value v[0..len) is "Basic" with the credentials
 * admin:<pw>. The comparison takes the same time whatever the credentials
 * are: both sides are laid out in buffers of the same fixed size and every
 * octet is compared. */
static int auth_ok(const char *v, size_t len, const char *pw)
{
    unsigned char got[CRED_MAX], want[CRED_MAX];
    size_t glen, pl = 0, i;
    unsigned diff;

    if (len < 6 || !ieq(v, "basic", 5) || !is_blank(v[5])) return 0;
    for (v += 5, len -= 5; len && is_blank(*v); v++, len--) ;
    memset(got, 0, sizeof got);
    if (b64_decode(v, len, got, sizeof got, &glen)) return 0;
    memset(want, 0, sizeof want);
    memcpy(want, "admin:", 6);
    while (pl < CFG_SECRET_MAX && pw[pl]) { want[6 + pl] = (unsigned char)pw[pl]; pl++; }
    diff = (unsigned)(glen ^ (6 + pl));
    for (i = 0; i < CRED_MAX; i++) diff |= (unsigned)(got[i] ^ want[i]);
    return diff == 0;
}

/* 1 if the Origin header names the host the request was sent to: what
 * follows "://" in it is the Host header, apart from case. An Origin
 * without that (such as "null") or a missing, empty or repeated Host is
 * not the same origin. */
static int same_origin(const hdr_t *origin, const hdr_t *host)
{
    size_t i;
    if (origin->count != 1 || host->count != 1 || host->len == 0) return 0;
    for (i = 0; i + 3 <= origin->len; i++)
        if (memcmp(origin->v + i, "://", 3) == 0) break;
    if (i + 3 > origin->len) return 0;
    i += 3;
    return origin->len - i == host->len && ieq(origin->v + i, host->v, host->len);
}

/* ---- who may see the pages -------------------------------------------------- */

#define SESSION_MS    (15u * 60u * 1000u)   /* a session ends this long after its last use */
#define LOGIN_HOLD_MS 1000u                 /* after a wrong login nobody is heard this long */
#define SID_LEN       32

/* The session whose cookie the request carries, or -1; finding it counts
 * as a use of it. */
static int session_find(httpd_t *h, const char *p, size_t n, uint32_t now)
{
    hdr_t ck;
    size_t i = 0;
    int j, live = 0;

    for (j = 0; j < HTTPD_SESSIONS; j++) {
        if (h->sess[j].on && (uint32_t)(now - h->sess[j].seen) > SESSION_MS) h->sess[j].on = 0;
        live |= h->sess[j].on;
    }
    if (!live) return -1;
    hdr_find(p, n, "cookie", &ck);
    if (ck.count != 1) return -1;
    while (i < ck.len) {
        size_t b, e;
        while (i < ck.len && (is_blank(ck.v[i]) || ck.v[i] == ';')) i++;
        b = i;
        while (i < ck.len && ck.v[i] != ';') i++;
        e = i;
        while (e > b && is_blank(ck.v[e - 1])) e--;
        if (e - b == 4 + SID_LEN && memcmp(ck.v + b, "sid=", 4) == 0) {
            int hit = -1;
            /* every session is compared in full, so that the time taken
             * says nothing about a value that is partly right */
            for (j = 0; j < HTTPD_SESSIONS; j++) {
                unsigned diff = 0;
                size_t k;
                for (k = 0; k < SID_LEN; k++) diff |= (unsigned)(unsigned char)(ck.v[b + 4 + k] ^ h->sess[j].sid[k]);
                if (!diff && h->sess[j].on) hit = j;
            }
            /* keep looking on no match: a browser may send more than one
             * sid cookie (a stale one from an earlier session alongside the
             * live one), and the stale one often comes first */
            if (hit >= 0) { h->sess[hit].seen = now; return hit; }
        }
    }
    return -1;
}

static int session_ok(httpd_t *h, const char *p, size_t n, uint32_t now)
{
    return session_find(h, p, n, now) >= 0;
}

static void sessions_end(httpd_t *h)
{
    int j;
    for (j = 0; j < HTTPD_SESSIONS; j++) h->sess[j].on = 0;
}

/* Without an admin password everybody may. With one: the session cookie
 * of the login page, or Basic credentials (scripts). 1 = may, 0 = may not
 * and offered nothing, -1 = offered Basic credentials that are wrong. */
static int authorised(httpd_t *h, const char *p, size_t n, uint32_t now)
{
    hdr_t hd;

    if (!h->cfg->admin_password[0]) return 1;
    hdr_find(p, n, "authorization", &hd);
    if (hd.count) return hd.count == 1 && auth_ok(hd.v, hd.len, h->cfg->admin_password) ? 1 : -1;
    return session_ok(h, p, n, now);
}

static const char NEED_LOGIN[] = "Location: /login\r\n";
#define NEED_PW "This needs the user name admin and the admin password."

/* the answer to a request that authorised() turned down; html: a page a
 * browser shows, so it is sent to the login page */
static void refuse(httpd_t *h, httpd_conn_t *c, int a, int html, int head_only, uint32_t now)
{
    if (a < 0) respond_text(h, c, 401, CHALLENGE, NEED_PW, head_only, now);
    else if (html) respond_text(h, c, 303, NEED_LOGIN, NULL, head_only, now);
    else respond_text(h, c, 401, NULL, NEED_PW, head_only, now);
}

/* a new session: SID_LEN hex digits from the kernel's random numbers */
static int session_new(httpd_t *h, uint32_t now)
{
    static const char hx[] = "0123456789abcdef";
    unsigned char rnd[SID_LEN / 2];
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC), i, j, at = 0;

    if (fd < 0) return -1;
    while (got < sizeof rnd) {
        ssize_t r = read(fd, rnd + got, sizeof rnd - got);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; break; }
        got += (size_t)r;
    }
    close(fd);
    if (got != sizeof rnd) return -1;
    for (i = 0; i < SID_LEN / 2; i++) {
        h->sid[2 * i] = hx[rnd[i] >> 4];
        h->sid[2 * i + 1] = hx[rnd[i] & 15];
    }
    h->sid[SID_LEN] = '\0';
    /* a free place, or that of the session unused the longest */
    for (j = 0; j < HTTPD_SESSIONS; j++) {
        if (h->sess[j].on && (uint32_t)(now - h->sess[j].seen) > SESSION_MS) h->sess[j].on = 0;
        if (!h->sess[j].on) { at = j; break; }
        if ((uint32_t)(now - h->sess[j].seen) > (uint32_t)(now - h->sess[at].seen)) at = j;
    }
    memcpy(h->sess[at].sid, h->sid, SID_LEN + 1);
    h->sess[at].on = 1;
    h->sess[at].seen = now;
    return 0;
}

/* the body of a posted login form is complete in tx[0..body_want) */
static void login_done(httpd_t *h, httpd_conn_t *c, uint32_t now)
{
    char *body = c->tx + HTTPD_HDR_RESERVE;
    char extra[128];
    sbuf_t s;
    int r = login_check(c->tx, c->body_want, h->cfg->admin_password);

    if (r < 0) { respond_text(h, c, 400, NULL, NULL, 0, now); return; }
    if (r == 0) {
        h->hold_on = 1;
        h->hold_until = now + LOGIN_HOLD_MS;
        finish(h, c, 401, CT_HTML, NULL, login_render_html(1, body, HTTPD_BODY_MAX), 0, now);
        return;
    }
    if (session_new(h, now)) { respond_text(h, c, 500, NULL, NULL, 0, now); return; }
    sb_init(&s, extra, sizeof extra);
    sb_puts(&s, "Location: /\r\nSet-Cookie: sid="); sb_puts(&s, h->sid);
    /* Lax, not Strict: the session cookie is carried by ordinary top-level
     * navigations, including the server's own redirects between / and /login.
     * With Strict some browsers (Firefox) withhold it on a redirected GET, so
     * / -> /login -> / loops forever on a blank page. Lax still keeps the
     * cookie off cross-site POSTs and subresources, and the Host/Origin check
     * above guards the forms, so CSRF stays covered. */
    sb_puts(&s, "; Path=/; HttpOnly; SameSite=Lax\r\n");
    sb_end(&s);
    respond_text(h, c, 303, extra, NULL, 0, now);
}

/* ---- the settings form ----------------------------------------------------- */

/* The body of a post to /dreamcast/vpn is complete in tx[0..body_want): as
 * a form of type text/plain sends it, `profile=` and the text and CR LF, or
 * `remove=1`. */
static void vpn_done(httpd_t *h, httpd_conn_t *c, uint32_t now)
{
    static char text[VPN_PROFILE_MAX + 1];
    char *body = c->tx + HTTPD_HDR_RESERVE;
    char msg[VPN_MSG_MAX], remote[48];
    size_t n = c->body_want, len = 0;
    int page = h->cfg->service != CFG_SERVICE_DREAMCAST && h->cfg->port2.service == CFG_SERVICE_DREAMCAST
               ? SETTINGS_CONSOLES2 : SETTINGS_CONSOLES;

    while (n && (c->tx[n - 1] == '\n' || c->tx[n - 1] == '\r')) n--;
    if (n == 8 && memcmp(c->tx, "remove=1", 8) == 0) {
        len = 0;
    } else if (n >= 8 && memcmp(c->tx, "profile=", 8) == 0) {
        len = n - 8;
        if (len > VPN_PROFILE_MAX) { respond_text(h, c, 413, NULL, NULL, 0, now); return; }
        memcpy(text, c->tx + 8, len);
        text[len++] = '\n';                 /* the end of its last line */
        if (vpn_profile_check(text, len, msg, sizeof msg) != 0) {
            finish(h, c, 400, CT_HTML, NULL, settings_render_page(h->cfg, page, 0, msg, body, HTTPD_BODY_MAX), 0, now);
            return;
        }
    } else {
        respond_text(h, c, 400, NULL, NULL, 0, now);
        return;
    }
    if (h->vpn(h->vpn_ctx, text, len) != 0) {
        respond_text(h, c, 500, NULL, "The profile could not be kept.", 0, now);
        return;
    }
    settings_set_vpn(len && vpn_profile_remote(text, len, remote, sizeof remote) == 0 ? remote : len ? "" : NULL);
    {
        char at[64]; sbuf_t l, s; int blen;
        sb_init(&s, body, HTTPD_BODY_MAX);
        sb_puts(&s, "<!DOCTYPE html>\n<html lang=\"en\"><head><title>" PAGE_NAME " settings</title></head><body>\n<p>Done. <a href=\"");
        sb_puts(&s, settings_page_path(page)); sb_puts(&s, "?saved=1\">Continue</a></p>\n</body></html>\n");
        blen = sb_end(&s);
        sb_init(&l, at, sizeof at);
        sb_puts(&l, "Location: "); sb_puts(&l, settings_page_path(page)); sb_puts(&l, "?saved=1\r\n");
        sb_end(&l);
        finish(h, c, 303, CT_HTML, at, blen, 0, now);
    }
}

/* The body of a post is complete in tx[0..body_want): decode it, and save
 * or say why not. */
static void post_done(httpd_t *h, httpd_conn_t *c, uint32_t now)
{
    char *body = c->tx + HTTPD_HDR_RESERVE;
    char err[SETTINGS_MSG_MAX];
    cfg_t cand;
    sbuf_t s;
    int r;

    if (c->post_login == 1) { login_done(h, c, now); return; }
    if (c->post_login == 2) { vpn_done(h, c, now); return; }
    r = settings_apply(h->cfg, c->tx, c->body_want, &cand, err, sizeof err);

    /* from here on the posted octets are no longer needed and the answer
     * may be written over them */
    if (r == SETTINGS_BAD) {
        respond_text(h, c, 400, NULL, NULL, 0, now);
    } else if (r == SETTINGS_INVALID) {
        finish(h, c, 400, CT_HTML, NULL, settings_render_page(&cand, c->post_page, 0, err, body, HTTPD_BODY_MAX),
               0, now);
    } else if (h->save(h->save_ctx, &cand) != 0) {
        respond_text(h, c, 500, NULL, "The settings could not be saved.", 0, now);
    } else {
        /* a new admin password: whoever holds a session logs in again */
        if (strcmp(h->cfg->admin_password, cand.admin_password) != 0) sessions_end(h);
        *h->cfg = cand;
        h->stats.saves++;
        /* the link is for browsers older than the 303 status code */
        sb_init(&s, body, HTTPD_BODY_MAX);
        sb_puts(&s, "<!DOCTYPE html>\n<html lang=\"en\"><head><title>" PAGE_NAME " settings</title></head><body>\n"
                    "<p>Settings saved. <a href=\"");
        sb_puts(&s, settings_page_path(c->post_page));
        sb_puts(&s, "?saved=1\">Continue</a></p>\n</body></html>\n");
        {
            /* back to the page the form was on */
            char at[64];
            sbuf_t l;
            int blen = sb_end(&s);
            sb_init(&l, at, sizeof at);
            sb_puts(&l, "Location: "); sb_puts(&l, settings_page_path(c->post_page));
            sb_puts(&l, "?saved=1\r\n");
            sb_end(&l);
            finish(h, c, 303, CT_HTML, at, blen, 0, now);
        }
    }
}

/* DNS rebinding: a page on some other site whose name has been pointed at
 * our address is the same origin as far as the browser can tell, so it
 * could read and post the settings; Host and Origin then both carry that
 * name. A browser that was sent to us by address says so in Host. Returns 1
 * if the request has no Host at all (not a browser of this century) or one
 * that is a dotted address with an optional port. */
static int host_is_address(const char *p, size_t n)
{
    hdr_t host;
    size_t i = 0;
    int part;
    hdr_find(p, n, "host", &host);
    if (host.count == 0) return 1;
    if (host.count != 1) return 0;
    for (part = 0; part < 4; part++) {
        size_t d = 0;
        while (i < host.len && host.v[i] >= '0' && host.v[i] <= '9' && d < 3) { i++; d++; }
        if (d == 0) return 0;
        if (part < 3) { if (i >= host.len || host.v[i] != '.') return 0; i++; }
    }
    if (i == host.len) return 1;
    if (host.v[i] != ':' || i + 1 == host.len) return 0;
    for (i++; i < host.len; i++) if (host.v[i] < '0' || host.v[i] > '9') return 0;
    return 1;
}

#define BY_ADDRESS "Open this page by the address of the box, for example http://192.168.1.2/settings."

static void take_body(httpd_t *h, httpd_conn_t *c, size_t n, size_t max, int login, uint32_t now);

/* A request for /settings whose head is c->rx[0..n). query is what follows
 * the ? in the target (qlen octets), NULL if there is none. */
static void settings_request(httpd_t *h, httpd_conn_t *c, size_t n, int method, int page,
                             const char *query, size_t qlen, uint32_t now)
{
    const char *p = c->rx;
    char *body = c->tx + HTTPD_HDR_RESERVE;
    int head_only = method == M_HEAD;

    if (method == M_OTHER) { respond_text(h, c, 405, ALLOW_FORM, NULL, 0, now); return; }

    {
        int a = authorised(h, p, n, now);
        if (a != 1) { refuse(h, c, a, method != M_POST, head_only, now); return; }
    }
    if (!h->cfg->admin_password[0] && !host_is_address(p, n)) {
        /* with a password set, a rebound page gets nowhere: it has no credentials */
        respond_text(h, c, 403, NULL, BY_ADDRESS, head_only, now);
        return;
    }

    if (method != M_POST) {
        int saved = query && qlen == 7 && memcmp(query, "saved=1", 7) == 0;
        finish(h, c, 200, CT_HTML, NULL, settings_render_page(h->cfg, page, saved, NULL, body, HTTPD_BODY_MAX),
               head_only, now);
        return;
    }

    if (!h->save) {
        respond_text(h, c, 403, NULL, "Settings cannot be changed here.", 0, now);
        return;
    }
    c->post_page = page;
    take_body(h, c, n, HTTPD_POST_MAX, 0, now);
}

/* The head c->rx[0..n) announces a posted form: check it, collect the body
 * of at most max octets and hand it to post_done(). */
static void take_body(httpd_t *h, httpd_conn_t *c, size_t n, size_t max, int login, uint32_t now)
{
    const char *p = c->rx;
    hdr_t hd, host;
    size_t cl = 0, have, i;

    c->post_login = login;
    /* a form on some other site must not be able to post here through the
     * user's browser */
    hdr_find(p, n, "origin", &hd);
    if (hd.count) {
        hdr_find(p, n, "host", &host);
        if (!same_origin(&hd, &host)) {
            respond_text(h, c, 403, NULL, "This request comes from another site.", 0, now);
            return;
        }
    }
    hdr_find(p, n, "transfer-encoding", &hd);
    if (hd.count) goto bad;
    hdr_find(p, n, "content-type", &hd);
    if (hd.count > 1) goto bad;
    if (login == 2) {
        if (hd.count == 0 || hd.len < 10 || !ieq(hd.v, "text/plain", 10) || (hd.len > 10 && hd.v[10] != ';' && !is_blank(hd.v[10]))) {
            respond_text(h, c, 415, NULL, NULL, 0, now);
            return;
        }
    } else
    if (hd.count == 0 || hd.len < 33 || !ieq(hd.v, "application/x-www-form-urlencoded", 33) ||
        (hd.len > 33 && hd.v[33] != ';' && !is_blank(hd.v[33]))) {
        respond_text(h, c, 415, NULL, NULL, 0, now);
        return;
    }
    hdr_find(p, n, "content-length", &hd);
    if (hd.count == 0) { respond_text(h, c, 411, NULL, NULL, 0, now); return; }
    if (hd.count > 1 || hd.len == 0) goto bad;
    for (i = 0; i < hd.len; i++) {
        if (hd.v[i] < '0' || hd.v[i] > '9') goto bad;
        if (i < 9) cl = cl * 10u + (size_t)(hd.v[i] - '0');
    }
    if (hd.len > 9 || cl > max) { respond_text(h, c, 413, NULL, NULL, 0, now); return; }

    /* the part of the body that came with the head, then the rest */
    have = c->rx_len - n;
    if (have > cl) have = cl;
    memcpy(c->tx, c->rx + n, have);
    c->body_len = have;
    c->body_want = cl;
    if (have == cl) post_done(h, c, now);
    else c->state = HC_BODY;                    /* same deadline as the head */
    return;

bad:
    respond_text(h, c, 400, NULL, NULL, 0, now);
}

/* ---- the Firmware page ------------------------------------------------------ */

/* A request for /firmware (sub 0), /firmware/upload (1) or /firmware/stock
 * (2) whose head is c->rx[0..n). */
static void firmware_request(httpd_t *h, httpd_conn_t *c, size_t n, int method, int sub, uint32_t now)
{
    const char *p = c->rx, *why;
    char *body = c->tx + HTTPD_HDR_RESERVE;
    char where[FIRMWARE_TEXT_MAX], state[FIRMWARE_TEXT_MAX], ctype[HTTPD_CTYPE_MAX + 1];
    int head_only = method == M_HEAD, a;
    hdr_t hd, host;
    size_t cl = 0, max, have, i;

    if (method == M_OTHER || (sub == 0 && method == M_POST) || ((sub == 1 || sub == 3) && method != M_POST)) {
        respond_text(h, c, 405, (sub == 1 || sub == 3) ? "Allow: POST\r\n" : sub == 2 ? ALLOW_FORM : ALLOW_READ, NULL, head_only, now);
        return;
    }
    a = authorised(h, p, n, now);
    if (a != 1) { refuse(h, c, a, method != M_POST, head_only, now); return; }
    if (!h->cfg->admin_password[0] && !host_is_address(p, n)) {
        respond_text(h, c, 403, NULL, BY_ADDRESS, head_only, now);
        return;
    }
    if (method != M_POST) {
        where[0] = state[0] = '\0';
        if (h->fw.text) {
            (void)h->fw.text(h->fw.ctx, HTTPD_FW_WHERE, where, sizeof where);
            (void)h->fw.text(h->fw.ctx, HTTPD_FW_STATE, state, sizeof state);
            where[sizeof where - 1] = state[sizeof state - 1] = '\0';
        }
        finish(h, c, 200, CT_HTML, NULL,
               sub == 2 ? firmware_render_stock(where, body, HTTPD_BODY_MAX)
                        : firmware_render_html(h->fw.version, where, state, h->fw.take != NULL, body, HTTPD_BODY_MAX),
               head_only, now);
        return;
    }

    /* a post: everything about it is checked here, its body is not ours */
    hdr_find(p, n, "origin", &hd);
    if (hd.count) {
        hdr_find(p, n, "host", &host);
        if (!same_origin(&hd, &host)) {
            respond_text(h, c, 403, NULL, "This request comes from another site.", 0, now);
            return;
        }
    }
    if (sub == 3) {
        const char *why;
        if (!h->fw.install) { respond_text(h, c, 501, NULL, "This firmware cannot update itself.", 0, now); return; }
        why = h->fw.install(h->fw.ctx);
        if (why) { respond_text(h, c, 409, NULL, why, 0, now); return; }
        respond_text(h, c, 200, NULL, "The box is fetching the update, and will check it, write the spare flash"
                     " copy and restart into it. Leave the power on; this takes a few minutes. The settings are kept.", 0, now);
        return;
    }
    if (!h->fw.take) { respond_text(h, c, 403, NULL, "The firmware cannot be changed here.", 0, now); return; }
    hdr_find(p, n, "transfer-encoding", &hd);
    if (hd.count) goto bad;
    hdr_find(p, n, "content-type", &hd);
    if (hd.count > 1 || hd.len > HTTPD_CTYPE_MAX) goto bad;
    if (sub == 2 && (hd.count == 0 || hd.len < 33 || !ieq(hd.v, "application/x-www-form-urlencoded", 33) ||
                     (hd.len > 33 && hd.v[33] != ';' && !is_blank(hd.v[33])))) {
        respond_text(h, c, 415, NULL, NULL, 0, now);
        return;
    }
    memcpy(ctype, hd.v, hd.len); ctype[hd.len] = '\0';
    hdr_find(p, n, "content-length", &hd);
    if (hd.count == 0) { respond_text(h, c, 411, NULL, NULL, 0, now); return; }
    if (hd.count > 1 || hd.len == 0) goto bad;
    for (i = 0; i < hd.len; i++) {
        if (hd.v[i] < '0' || hd.v[i] > '9') goto bad;
        if (i < 9) cl = cl * 10u + (size_t)(hd.v[i] - '0');
    }
    max = sub == 1 ? HTTPD_FW_UPLOAD_MAX : HTTPD_FW_STOCK_MAX;
    if (hd.len > 9 || cl > max) { respond_text(h, c, 413, NULL, NULL, 0, now); return; }

    have = c->rx_len - n;
    if (have > cl) have = cl;
    why = h->fw.take(h->fw.ctx, sub == 1 ? HTTPD_FW_UPLOAD : HTTPD_FW_STOCK, c->fd, c->rx + n, have, cl, ctype);
    if (why) { respond_text(h, c, 409, NULL, why, 0, now); return; }
    /* taken: the answer comes from there, and our descriptor goes */
    h->stats.handed++;
    conn_close(c);
    return;

bad:
    respond_text(h, c, 400, NULL, NULL, 0, now);
}

/* Parse the request head p[0..n) and decide the answer. Nothing in it is
 * trusted: the head must be free of control bytes, the request line must
 * be exactly "METHOD SP path SP HTTP/1.digits", and the path is only ever
 * compared with the four we serve. It is never decoded, never used as a
 * file name. */
static void handle(httpd_t *h, httpd_conn_t *c, size_t n, uint32_t now)
{
    const char *p = c->rx, *e, *q, *uri, *ver;
    size_t i, mlen, ulen, plen;
    int method, head_only, view;

    h->stats.requests++;
    for (i = 0; i < n; i++) {
        unsigned ch = (unsigned char)p[i];
        if ((ch < 0x20 && ch != '\r' && ch != '\n' && ch != '\t') || ch == 0x7f) goto bad;
    }
    e = memchr(p, '\n', n);                     /* there is one: head_end found it */
    if (e > p && e[-1] == '\r') e--;

    /* method: 1..16 upper case letters */
    for (q = p; q < e && *q >= 'A' && *q <= 'Z'; q++) ;
    mlen = (size_t)(q - p);
    if (mlen < 1 || mlen > 16 || q == e || *q != ' ') goto bad;

    /* request target: visible ASCII, must be an absolute path */
    uri = ++q;
    for (; q < e && *q > 0x20 && *q < 0x7f; q++) ;
    ulen = (size_t)(q - uri);
    if (ulen < 1 || uri[0] != '/' || q == e || *q != ' ') goto bad;

    /* version: HTTP/1.x, then the line must end */
    ver = ++q;
    if ((size_t)(e - ver) < 8 || memcmp(ver, "HTTP/1.", 7) != 0) goto bad;
    for (q = ver + 7; q < e && *q >= '0' && *q <= '9'; q++) ;
    if (q != e) goto bad;

    if (mlen == 3 && memcmp(p, "GET", 3) == 0) method = M_GET;
    else if (mlen == 4 && memcmp(p, "HEAD", 4) == 0) method = M_HEAD;
    else if (mlen == 4 && memcmp(p, "POST", 4) == 0) method = M_POST;
    else method = M_OTHER;

    q = memchr(uri, '?', ulen);
    plen = q ? (size_t)(q - uri) : ulen;
    page_consoles_tab = h->cfg->service == CFG_SERVICE_DREAMCAST || h->cfg->port2.service == CFG_SERVICE_DREAMCAST
                      || h->cfg->service == CFG_SERVICE_SATURN || h->cfg->port2.service == CFG_SERVICE_SATURN;
    settings_set_two_ports(h->status2 != NULL);    /* one port (HT801): no port-2 pages */
    if (plen >= 9 && memcmp(uri, "/firmware", 9) == 0) {
        int sub = plen == 9 ? 0 : plen == 16 && memcmp(uri + 9, "/upload", 7) == 0 ? 1
                : plen == 15 && memcmp(uri + 9, "/stock", 6) == 0 ? 2
                : plen == 16 && memcmp(uri + 9, "/update", 7) == 0 ? 3 : -1;
        if (sub >= 0) { firmware_request(h, c, n, method, sub, now); return; }
    }
    if (settings_page_of(uri, plen) >= 0) {
        settings_request(h, c, n, method, settings_page_of(uri, plen), q ? q + 1 : NULL, q ? ulen - plen - 1 : 0, now);
        return;
    }
    if (plen == 14 && memcmp(uri, "/dreamcast/vpn", 14) == 0) {
        int a;
        if (method != M_POST) { respond_text(h, c, 405, "Allow: POST\r\n", NULL, method == M_HEAD, now); return; }
        a = authorised(h, c->rx, n, now);
        if (a != 1) { refuse(h, c, a, 0, 0, now); return; }
        if (!h->cfg->admin_password[0] && !host_is_address(c->rx, n)) { respond_text(h, c, 403, NULL, BY_ADDRESS, 0, now); return; }
        if (!h->vpn) { respond_text(h, c, 403, NULL, "A profile cannot be kept here.", 0, now); return; }
        take_body(h, c, n, VPN_PROFILE_MAX + 12, 2, now);
        return;
    }
    if (plen == 8 && memcmp(uri, "/restart", 8) == 0) {
        char *body = c->tx + HTTPD_HDR_RESERVE;
        hdr_t og, host;
        sbuf_t s;
        int a;

        if (method != M_POST) { respond_text(h, c, 405, "Allow: POST\r\n", NULL, method == M_HEAD, now); return; }
        a = authorised(h, c->rx, n, now);
        if (a != 1) { refuse(h, c, a, 0, 0, now); return; }
        if (!h->cfg->admin_password[0] && !host_is_address(c->rx, n)) {
            respond_text(h, c, 403, NULL, BY_ADDRESS, 0, now);
            return;
        }
        hdr_find(c->rx, n, "origin", &og);
        if (og.count) {
            hdr_find(c->rx, n, "host", &host);
            if (!same_origin(&og, &host)) {
                respond_text(h, c, 403, NULL, "This request comes from another site.", 0, now);
                return;
            }
        }
        /* the owner of the server looks at restart_asked and does it, once
         * this answer is out; whatever body came with the post is not read */
        h->restart_asked = 1;
        sb_init(&s, body, HTTPD_BODY_MAX);
        page_top(&s, "restart", "<meta http-equiv=\"refresh\" content=\"25;url=/\">\n", -1, "Restart");
        sb_puts(&s, "<section class=\"hero\"><span class=\"b s1\">restarting</span>\n"
                    "<p class=\"sum\">The box is restarting. This page comes back by itself in"
                    " 25 seconds.</p></section>\n" PAGE_END);
        finish(h, c, 200, CT_HTML, NULL, sb_end(&s), 0, now);
        return;
    }
    if (plen == 6 && memcmp(uri, "/login", 6) == 0) {
        char *body = c->tx + HTTPD_HDR_RESERVE;
        if (method == M_OTHER) { respond_text(h, c, 405, ALLOW_FORM, NULL, 0, now); return; }
        if (!h->cfg->admin_password[0]) {       /* nothing to log in to */
            respond_text(h, c, 303, "Location: /settings\r\n", NULL, method == M_HEAD, now);
        } else if (method == M_POST) {
            if (h->hold_on && (int32_t)(h->hold_until - now) > 0)
                respond_text(h, c, 429, NULL, "Wait a second and try again.", 0, now);
            else { h->hold_on = 0; take_body(h, c, n, LOGIN_BODY_MAX, 1, now); }
        } else if (authorised(h, c->rx, n, now) == 1) {
            respond_text(h, c, 303, "Location: /\r\n", NULL, method == M_HEAD, now);
        } else {
            finish(h, c, 200, CT_HTML, NULL, login_render_html(0, body, HTTPD_BODY_MAX),
                   method == M_HEAD, now);
        }
        return;
    }
    /* the status views: read only, a query string is ignored but for /bbs */
    if (method != M_GET && method != M_HEAD) { respond(h, c, 405, V_ERROR, 0, now); return; }
    head_only = method == M_HEAD;
    if (plen == 1) view = V_HTML;
    else if (plen == 12 && memcmp(uri, "/status.json", 12) == 0) view = V_JSON;
    else if (h->status2 && plen == 6 && memcmp(uri, "/port2", 6) == 0) view = V_HTML2;
    else if (h->status2 && plen == 13 && memcmp(uri, "/status2.json", 13) == 0) view = V_JSON2;
    else if (plen == 6 && memcmp(uri, "/calls", 6) == 0) view = V_CALLS;
    else if (plen == 4 && memcmp(uri, "/bbs", 4) == 0) {         /* its page and its search are in the query */
        view = V_BBS; h->bbs_query = q ? q + 1 : NULL; h->bbs_qlen = q ? ulen - plen - 1 : 0;
    }
    else if (plen == 7 && memcmp(uri, "/config", 7) == 0) view = V_CONFIG;
    else if (plen == 4 && memcmp(uri, "/log", 4) == 0) view = V_LOG;
    else if (plen == 7 && memcmp(uri, "/logout", 7) == 0) {
        { int j = session_find(h, c->rx, n, now); if (j >= 0) h->sess[j].on = 0; }
        respond_text(h, c, 303, "Location: /\r\nSet-Cookie: sid=; Path=/; Max-Age=0\r\n", NULL, head_only, now);
        return;
    }
    else if (plen == 14 && memcmp(uri, "/cgi-bin/login", 14) == 0) {
        /* where the stock firmware of the box sent browsers for good */
        respond_text(h, c, 302, "Location: /\r\n", NULL, head_only, now);
        return;
    }
    else { respond(h, c, 404, V_ERROR, head_only, now); return; }
    /* /config and /log carry the box's own detail (settings, logs, dmesg).
     * With no admin password set they are served only to a request that named
     * the box by its address, not by a host name: a name can be pointed at the
     * box by a hostile page (DNS rebinding) to read them from a browser on the
     * LAN. */
    if ((view == V_CONFIG || view == V_LOG) && !h->cfg->admin_password[0] && !host_is_address(c->rx, n)) {
        respond_text(h, c, 403, NULL, BY_ADDRESS, head_only, now);
        return;
    }
    {
        int a = authorised(h, c->rx, n, now);
        if (a != 1) { refuse(h, c, a, view != V_JSON && view != V_JSON2, head_only, now); return; }
    }
    respond(h, c, 200, view, head_only, now);
    return;

bad:
    respond(h, c, 400, V_ERROR, 0, now);
}

static void do_recv(httpd_t *h, httpd_conn_t *c, uint32_t now)
{
    size_t old = c->rx_len, n;
    ssize_t r = recv(c->fd, c->rx + old, HTTPD_REQ_MAX - old, 0);
    if (r < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) conn_close(c);
        return;
    }
    if (r == 0) { conn_close(c); return; }      /* gone before finishing the head */
    c->rx_len += (size_t)r;
    n = head_end(c->rx, c->rx_len, old);
    if (n) handle(h, c, n, now);
    else if (c->rx_len >= HTTPD_REQ_MAX) respond(h, c, 431, V_ERROR, 0, now);
}

static void do_body(httpd_t *h, httpd_conn_t *c, uint32_t now)
{
    ssize_t r = recv(c->fd, c->tx + c->body_len, c->body_want - c->body_len, 0);
    if (r < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) conn_close(c);
        return;
    }
    if (r == 0) { conn_close(c); return; }      /* gone before finishing the body */
    c->body_len += (size_t)r;
    if (c->body_len == c->body_want) post_done(h, c, now);
}

static void do_linger(httpd_conn_t *c)
{
    char junk[1024];
    int i;
    for (i = 0; i < 4; i++) {
        ssize_t r = recv(c->fd, junk, sizeof junk, 0);
        if (r > 0) continue;
        if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) conn_close(c);
        return;
    }
}

void httpd_init(httpd_t *h, cfg_t *cfg, const status_t *status)
{
    int i;
    memset(h, 0, sizeof *h);
    h->cfg = cfg;
    h->status = status;
    h->status2 = NULL;
    h->listen_fd = -1;
    h->rx_timeout_ms = HTTPD_RX_TIMEOUT_MS;
    h->tx_timeout_ms = HTTPD_TX_TIMEOUT_MS;
    h->linger_ms = HTTPD_LINGER_MS;
    for (i = 0; i < HTTPD_MAX_CONN; i++) h->conn[i].fd = -1;
}

void httpd_on_firmware(httpd_t *h, const httpd_fw_t *fw)
{
    if (fw) h->fw = *fw;
    else memset(&h->fw, 0, sizeof h->fw);
}

void httpd_on_bbs(httpd_t *h, status_bbs_rows rows, void *ctx) { h->bbs = rows; h->bbs_ctx = ctx; }

void httpd_on_vpn(httpd_t *h, int (*keep)(void *ctx, const char *profile, size_t len), void *ctx)
{
    h->vpn = keep;
    h->vpn_ctx = ctx;
}

void httpd_on_save(httpd_t *h, int (*save)(void *ctx, const cfg_t *newcfg), void *ctx)
{
    h->save = save;
    h->save_ctx = ctx;
}

void httpd_on_diag(httpd_t *h, int (*diag)(void *ctx, char *buf, size_t cap), void *ctx)
{
    h->diag = diag;
    h->diag_ctx = ctx;
}

static int set_nonblock_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
    return 0;
}

int httpd_adopt(httpd_t *h, int fd, uint32_t now_ms)
{
    httpd_conn_t *c;
    int i;

    if (fd < 0 || set_nonblock_cloexec(fd) < 0) {
        if (fd >= 0) close(fd);
        h->stats.rejected++;
        return -1;
    }
    for (i = 0; i < HTTPD_MAX_CONN; i++)
        if (h->conn[i].state == HC_FREE) break;
    if (i == HTTPD_MAX_CONN) {
        /* table full: say so if the socket takes it right now, and go */
        char msg[HTTPD_HDR_RESERVE + 64], body[64];
        sbuf_t s;
        int blen = error_body(503, NULL, body, sizeof body), len;
        sb_init(&s, msg, sizeof msg);
        put_head(&s, 503, CT_TEXT, (size_t)blen, NULL);
        sb_puts(&s, body);
        len = sb_end(&s);
        if (len > 0 && send(fd, msg, (size_t)len, MSG_NOSIGNAL) < 0) { /* best effort */ }
        close(fd);
        h->stats.rejected++;
        return -1;
    }
    c = &h->conn[i];
    c->fd = fd;
    c->state = HC_RECV;
    c->deadline = now_ms + h->rx_timeout_ms;
    c->rx_len = c->tx_off = c->tx_end = 0;
    c->body_len = c->body_want = 0;
    h->stats.adopted++;
    return i;
}

void httpd_poll(httpd_t *h, uint32_t now_ms)
{
    struct pollfd p[HTTPD_MAX_CONN + 1];
    httpd_conn_t *who[HTTPD_MAX_CONN + 1];
    int n = 0, i, k;

    if (h->listen_fd >= 0) {
        p[n].fd = h->listen_fd; p[n].events = POLLIN; p[n].revents = 0;
        who[n++] = NULL;
    }
    for (i = 0; i < HTTPD_MAX_CONN; i++) {
        httpd_conn_t *c = &h->conn[i];
        if (c->state == HC_FREE) continue;
        if (expired(now_ms, c->deadline)) {
            h->stats.timeouts++;
            if (c->state == HC_RECV || c->state == HC_BODY) respond(h, c, 408, V_ERROR, 0, now_ms);
            else conn_close(c);
            if (c->state == HC_FREE) continue;
        }
        p[n].fd = c->fd;
        p[n].events = (short)(c->state == HC_SEND ? POLLOUT : POLLIN);
        p[n].revents = 0;
        who[n++] = c;
    }
    if (n == 0 || poll(p, (nfds_t)n, 0) <= 0) return;

    for (i = 0; i < n; i++) {
        httpd_conn_t *c = who[i];
        if (!p[i].revents) continue;
        if (!c) {
            /* the listening socket comes first in p[], so the slots handed
             * out here are ones no later entry of who[] points to */
            for (k = 0; k < HTTPD_MAX_CONN; k++) {
                int fd = accept(h->listen_fd, NULL, NULL);
                if (fd < 0) break;
                httpd_adopt(h, fd, now_ms);
            }
            continue;
        }
        if (p[i].revents & POLLNVAL) { conn_close(c); continue; }
        switch (c->state) {
        case HC_RECV:   do_recv(h, c, now_ms); break;
        case HC_BODY:   do_body(h, c, now_ms); break;
        case HC_SEND:   do_send(h, c, now_ms); break;
        case HC_LINGER: do_linger(c); break;
        default: break;
        }
    }
}

int httpd_active(const httpd_t *h)
{
    int i, n = 0;
    for (i = 0; i < HTTPD_MAX_CONN; i++)
        if (h->conn[i].state != HC_FREE) n++;
    return n;
}

void httpd_close(httpd_t *h)
{
    int i;
    if (h->listen_fd >= 0) close(h->listen_fd);
    h->listen_fd = -1;
    for (i = 0; i < HTTPD_MAX_CONN; i++)
        if (h->conn[i].state != HC_FREE) conn_close(&h->conn[i]);
}

int httpd_listen(httpd_t *h, uint32_t bind_addr, uint16_t port, const char *ifname)
{
    struct sockaddr_in sa;
    int fd, one = 1, saved;

    if (port == 0 || h->listen_fd >= 0) { errno = EINVAL; return -1; }
#ifdef SO_BINDTODEVICE
    if (bind_addr == 0 && !ifname) { errno = EINVAL; return -1; }
#else
    if (bind_addr == 0) { errno = EINVAL; return -1; }
#endif
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_nonblock_cloexec(fd) < 0) goto fail;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) goto fail;
#ifdef SO_BINDTODEVICE
    if (ifname && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
                             (socklen_t)(strlen(ifname) + 1)) < 0) goto fail;
#else
    (void)ifname;
#endif
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(bind_addr);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) goto fail;
    if (listen(fd, HTTPD_MAX_CONN) < 0) goto fail;
    h->listen_fd = fd;
    return 0;

fail:
    saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

void httpd_status2(httpd_t *h, const status_t *status2) { h->status2 = status2; }
