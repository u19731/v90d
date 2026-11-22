/* Tests for the HTTP status and settings server. No TCP: every connection
 * is one end of a socketpair() handed to httpd_adopt(), the test plays the
 * client on the other end, and time is a counter the test advances by hand.
 * Every request byte is treated as hostile: truncated, oversized, slow,
 * pipelined and random input, table exhaustion, readers that stall, and
 * for the settings form bad bodies, missing or wrong credentials and
 * requests from other sites. */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "test.h"
#include "httpd.h"
#include "vpn.h"
#include "settings.h"
#include "page.h"

static httpd_t  H;
static cfg_t    C;
static status_t S;
static uint32_t now = 0xffffc000u;      /* the clock wraps during the run */
static int      got_eof;

/* ---- client side ----------------------------------------------------------- */

static void step_h(httpd_t *h, int n) { while (n-- > 0) { httpd_poll(h, now); now++; } }
static void step(int n) { step_h(&H, n); }

static int count_fds(void)
{
    int fd, n = 0;
    for (fd = 0; fd < 256; fd++)
        if (fcntl(fd, F_GETFD) != -1) n++;
    return n;
}

/* new connection: server end adopted, client end (non-blocking) in *cli */
static int open_conn_h(httpd_t *h, int *cli)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    *cli = sv[0];
    return httpd_adopt(h, sv[1], now);
}
static int open_conn(int *cli) { return open_conn_h(&H, cli); }

static int csend(int fd, const void *p, size_t n)
{
    return (int)send(fd, p, n, MSG_NOSIGNAL);
}
static int cputs(int fd, const char *z) { return csend(fd, z, strlen(z)); }

/* read what the server sends until EOF or maxsteps polls; NUL terminates.
 * got_eof: 1 = orderly end, 2 = reset, 0 = still open */
static int cread_h(httpd_t *h, int fd, char *buf, int cap, int maxsteps)
{
    int len = 0;
    got_eof = 0;
    while (maxsteps-- > 0 && len < cap - 1) {
        ssize_t r;
        step_h(h, 1);
        r = recv(fd, buf + len, (size_t)(cap - 1 - len), 0);
        if (r > 0) len += (int)r;
        else if (r == 0) { got_eof = 1; break; }
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { got_eof = 2; break; }
    }
    buf[len] = '\0';
    return len;
}
static int cread(int fd, char *buf, int cap, int maxsteps) { return cread_h(&H, fd, buf, cap, maxsteps); }

/* one whole exchange on a fresh connection; returns the response length */
static int exchange_n(const void *req, size_t n, char *resp, int cap)
{
    int c, len;
    if (open_conn(&c) < 0) { close(c); resp[0] = 0; return -1; }
    csend(c, req, n);
    len = cread(c, resp, cap, 200);
    close(c);
    step(3);
    return len;
}
static int exchange(const char *req, char *resp, int cap) { return exchange_n(req, strlen(req), resp, cap); }

typedef struct { int code; int clen; const char *body; int body_len; } resp_t;

/* 1 if r is one complete, well-formed response of ours */
static int parse_resp(const char *r, int len, resp_t *o)
{
    const char *e, *cl;
    memset(o, 0, sizeof *o);
    if (len < 12 || strncmp(r, "HTTP/1.0 ", 9) != 0 || r[12] != ' ') return 0;
    o->code = atoi(r + 9);
    e = strstr(r, "\r\n\r\n");
    if (!e) return 0;
    cl = strstr(r, "\r\nContent-Length: ");
    if (!cl || cl > e) return 0;
    o->clen = atoi(cl + 18);
    if (!strstr(r, "\r\nConnection: close\r\n")) return 0;
    o->body = e + 4;
    o->body_len = len - (int)(o->body - r);
    return 1;
}

static char resp[HTTPD_TX_MAX + 4096];
static char want[HTTPD_BODY_MAX];

/* status code of a one-shot request; -1 if the answer is not well-formed */
static int code_of_n(const void *req, size_t n)
{
    resp_t r;
    int len = exchange_n(req, n, resp, sizeof resp);
    if (len == 0) return 0;
    if (!parse_resp(resp, len, &r)) return -1;
    if (r.clen != r.body_len) return -2;
    return r.code;
}
static int code_of(const char *req) { return code_of_n(req, strlen(req)); }

static void fixture(void)
{
    st_call_t call;
    int i;
    cfg_default(&C);
    C.auth = CFG_AUTH_CHAP;
    C.n_users = 2;
    strcpy(C.users[0].name, "alice"); strcpy(C.users[0].secret, "TOPSECRET-A");
    strcpy(C.users[1].name, "bob");   strcpy(C.users[1].secret, "TOPSECRET-B");
    status_init(&S);
    S.line = ST_LINE_CONNECTED; S.modulation = ST_MOD_V90;
    S.down_bps = 50666; S.up_bps = 28800;
    strcpy(S.peer_name, "alice<&>");
    for (i = 0; i < STATUS_MAX_CALLS; i++) {
        memset(&call, 0, sizeof call);
        call.start_time = 1700000000u + (uint32_t)i;
        call.duration_s = 60;
        status_add_call(&S, &call);
    }
    httpd_init(&H, &C, &S);
}

/* ---- tests ----------------------------------------------------------------- */

static int diag_stub(void *ctx, char *buf, size_t cap)
{
    const char *s = "DIAGTEST line one\nDIAGTEST line two\n";
    size_t len = strlen(s);
    (void)ctx;
    if (len > cap - 1) len = cap - 1;
    memcpy(buf, s, len);
    buf[len] = 0;
    return (int)len;
}

static void test_views(void)
{
    resp_t r;
    int len, n;

    CHECK_EQ_I(httpd_active(&H), 0);
    CHECK_EQ_I(H.listen_fd, -1);
    /* the wildcard address is refused before any socket is made */
    errno = 0;
    CHECK_EQ_I(httpd_listen(&H, 0, 80, NULL), -1);
    CHECK_EQ_I(errno, EINVAL);
    CHECK_EQ_I(H.listen_fd, -1);

    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strncmp(resp, "HTTP/1.0 200 OK\r\n", 17) == 0);
    CHECK(strstr(resp, "\r\nContent-Type: text/html; charset=utf-8\r\n") != NULL);
    CHECK(strstr(resp, "\r\nX-Content-Type-Options: nosniff\r\n") != NULL);
    CHECK(strstr(resp, "\r\nCache-Control: no-store\r\n") != NULL);
    n = status_render_html(&S, want, sizeof want);
    CHECK(n > 0);
    CHECK_EQ_I(r.clen, n);
    CHECK_EQ_I(r.body_len, n);
    CHECK(r.body && memcmp(r.body, want, (size_t)n) == 0);
    CHECK(got_eof == 1);
    CHECK_EQ_I(httpd_active(&H), 0);

    len = exchange("GET /status.json HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "\r\nContent-Type: application/json\r\n") != NULL);
    n = status_render_json(&S, want, sizeof want);
    CHECK_EQ_I(r.clen, n);
    CHECK_EQ_I(r.body_len, n);
    CHECK(r.body && memcmp(r.body, want, (size_t)n) == 0);

    len = exchange("GET /config HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "\r\nContent-Type: text/plain; charset=us-ascii\r\n") != NULL);
    n = cfg_write(&C, 0, want, sizeof want);
    CHECK_EQ_I(r.clen, n);
    CHECK_EQ_I(r.body_len, n);
    CHECK(r.body && memcmp(r.body, want, (size_t)n) == 0);
    CHECK(strstr(resp, "TOPSECRET") == NULL);
    CHECK(strstr(resp, "user = \"alice\" <redacted>\n") != NULL);

    /* /log: nothing until a diagnostics source is registered, then its text */
    len = exchange("GET /log HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "\r\nContent-Type: text/plain; charset=us-ascii\r\n") != NULL);
    CHECK(strstr(resp, "no diagnostics source") != NULL);
    httpd_on_diag(&H, diag_stub, NULL);
    len = exchange("GET /log HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "\r\nContent-Type: text/plain; charset=us-ascii\r\n") != NULL);
    CHECK_EQ_I(r.clen, (int)strlen("DIAGTEST line one\nDIAGTEST line two\n"));
    CHECK(strstr(resp, "DIAGTEST line one\nDIAGTEST line two\n") != NULL);
    httpd_on_diag(&H, NULL, NULL);

    /* The stock firmware of the box sent browsers from / to /cgi-bin/login
     * for good; a browser that remembers is sent back. */
    len = exchange("GET /cgi-bin/login HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 302);
    CHECK(strstr(resp, "\r\nLocation: /\r\n") != NULL);
    len = exchange("GET /cgi-bin/other HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 404);

    /* the views follow the structs: nothing is cached */
    S.down_bps = 44000;
    len = exchange("GET /status.json HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "\"down_bps\":44000") != NULL);
    CHECK(strstr(resp, "\"v92\":false") != NULL && strstr(resp, "\"modulation\":\"v90\"") != NULL);
    S.v92 = 1; S.modulation = ST_MOD_V92; S.up_bps = 44000;
    len = exchange("GET /status.json HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "\"v92\":true") != NULL && strstr(resp, "\"modulation\":\"v92\"") != NULL);
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<tr><th>Modulation</th><td>V.92</td></tr>") != NULL);
    CHECK(strstr(resp, "<tr><th>V.92</th><td>on</td></tr>") != NULL);
    S.v92 = 0; S.modulation = ST_MOD_V90; S.up_bps = 28800;

    /* HEAD: same head, no body */
    len = exchange("HEAD / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK_EQ_I(r.clen, status_render_html(&S, want, sizeof want));
    CHECK_EQ_I(r.body_len, 0);
    len = exchange("HEAD /nope HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 404);
    CHECK(r.clen > 0);
    CHECK_EQ_I(r.body_len, 0);

    /* tolerated variations */
    CHECK_EQ_I(code_of("GET / HTTP/1.1\r\nHost: 192.168.1.2\r\nUser-Agent: x/1.0\r\nAccept: */*\r\n\r\n"), 200);
    CHECK(strncmp(resp, "HTTP/1.0 200", 12) == 0);
    CHECK_EQ_I(code_of("GET / HTTP/1.0\n\n"), 200);
    CHECK_EQ_I(code_of("GET / HTTP/1.0\r\n\n"), 200);
    CHECK_EQ_I(code_of("GET / HTTP/1.0\nHost: x\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /status.json?pretty=1&x=/../ HTTP/1.0\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /? HTTP/1.0\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /config?x HTTP/1.0\r\nX-Bin: \xff\xfe\r\n\r\n"), 200);
    CHECK_EQ_I(H.stats.ok, 16);     /* the two GET /log above are in this count */
}

static void test_refusals(void)
{
    static const char *const not_found[] = {
        "/nope", "/index.html", "/status", "/status.jso", "/status.jsonx", "/status.json/",
        "/config/", "/config.txt", "/Config", "/CONFIG", "//", "//config", "/./config",
        "/../config", "/config/..", "/config/../../../../etc/passwd", "/../../../etc/shadow",
        "/..%2f..%2fetc%2fpasswd", "/%2e%2e/config", "/%63onfig", "/config%00", "/config;x",
        "/config#x", "/\\..\\config", "/status.json%20", "/etc/passwd", "/proc/self/environ",
    };
    static const char *const bad[] = {
        "\r\n\r\n",
        "GET\r\n\r\n",
        "GET /\r\n\r\n",                        /* HTTP/0.9 simple request: not served */
        "GET / \r\n\r\n",
        "GET  / HTTP/1.0\r\n\r\n",
        "GET / HTTP/1.0 \r\n\r\n",
        "GET / HTTP/1.0 extra\r\n\r\n",
        " GET / HTTP/1.0\r\n\r\n",
        "GET / HTTP/2.0\r\n\r\n",
        "GET / HTTP/1.\r\n\r\n",
        "GET / HTTP/1.x\r\n\r\n",
        "GET / http/1.0\r\n\r\n",
        "GET / HTTP/1.0x\r\n\r\n",
        "get / HTTP/1.0\r\n\r\n",
        "G=T / HTTP/1.0\r\n\r\n",
        "GETGETGETGETGETGETGET / HTTP/1.0\r\n\r\n",     /* method too long */
        "GET config HTTP/1.0\r\n\r\n",
        "GET * HTTP/1.0\r\n\r\n",
        "GET http://192.168.1.2/config HTTP/1.0\r\n\r\n",   /* no proxying */
        "GET /con fig HTTP/1.0\r\n\r\n",
        "GET /\tconfig HTTP/1.0\r\n\r\n",
        "GET /caf\xc3\xa9 HTTP/1.0\r\n\r\n",
        "GET /\x7f HTTP/1.0\r\n\r\n",
        "GET / HTTP/1.0\r\nX: a\x01-\r\n\r\n",
        "GET / HTTP/1.0\rX\n\r\n",
    };
    char req[256];
    resp_t r;
    size_t i;
    int len;

    for (i = 0; i < sizeof not_found / sizeof not_found[0]; i++) {
        snprintf(req, sizeof req, "GET %s HTTP/1.0\r\n\r\n", not_found[i]);
        CHECK_EQ_I(code_of(req), 404);
        CHECK(strstr(resp, "TOPSECRET") == NULL && strstr(resp, "root:") == NULL);
    }
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int code = code_of(bad[i]);
        CHECK_EQ_I(code, 400);
        if (code != 400) printf("  bad[%d]\n", (int)i);
    }
    /* NUL bytes: in the path, after the path, in a header */
    CHECK_EQ_I(code_of_n("GET /config\0 HTTP/1.0\r\n\r\n", 25), 400);
    CHECK_EQ_I(code_of_n("GET /\0config HTTP/1.0\r\n\r\n", 25), 400);
    CHECK_EQ_I(code_of_n("GET /config\0.html HTTP/1.0\r\n\r\n", 30), 400);
    CHECK_EQ_I(code_of_n("GET / HTTP/1.0\r\nX: \0\r\n\r\n", 24), 400);
    CHECK_EQ_I(code_of_n("\0\0\0\0\r\n\r\n", 8), 400);
    /* the start of a TLS hello, as a browser trying https would send */
    CHECK_EQ_I(code_of_n("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n", 15), 400);

    /* other methods: 405 with Allow, whatever the path */
    {
        static const char *const m[] = { "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT",
                                         "PATCH", "PROPFIND", "GETS", "HEADER", "G" };
        for (i = 0; i < sizeof m / sizeof m[0]; i++) {
            snprintf(req, sizeof req, "%s /config HTTP/1.0\r\nContent-Length: 5\r\n\r\nhello", m[i]);
            CHECK_EQ_I(code_of(req), 405);
            CHECK(strstr(resp, "\r\nAllow: GET, HEAD\r\n") != NULL);
            CHECK(strstr(resp, "TOPSECRET") == NULL && strstr(resp, "alice") == NULL);
        }
        CHECK_EQ_I(code_of("POST /nope HTTP/1.0\r\n\r\n"), 405);
    }

    /* error bodies are small plain text */
    len = exchange("GET /nope HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK(strncmp(resp, "HTTP/1.0 404 Not Found\r\n", 24) == 0);
    CHECK(strstr(resp, "\r\nContent-Type: text/plain; charset=us-ascii\r\n") != NULL);
    CHECK(r.body && strcmp(r.body, "404 Not Found\n") == 0);
    CHECK_EQ_I(httpd_active(&H), 0);
}

static void test_truncated(void)
{
    static const char full[] = "GET /status.json HTTP/1.0\r\nHost: x\r\n\r\n";
    size_t cut, split;
    int c, len;
    resp_t r;

    /* every proper prefix, then the client goes away: no answer, slot freed */
    for (cut = 0; cut < sizeof full - 1; cut++) {
        CHECK(open_conn(&c) >= 0);
        csend(c, full, cut);
        step(2);
        CHECK_EQ_I(httpd_active(&H), 1);
        shutdown(c, SHUT_WR);
        len = cread(c, resp, sizeof resp, 20);
        CHECK_EQ_I(len, 0);
        CHECK_EQ_I(got_eof, 1);
        close(c);
        CHECK_EQ_I(httpd_active(&H), 0);
    }
    /* client vanishes without a byte, before the first poll */
    CHECK(open_conn(&c) >= 0);
    close(c);
    step(2);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* the head split in two at every position still parses */
    for (split = 1; split < sizeof full - 1; split++) {
        CHECK(open_conn(&c) >= 0);
        csend(c, full, split);
        step(2);
        csend(c, full + split, sizeof full - 1 - split);
        len = cread(c, resp, sizeof resp, 50);
        CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
        close(c);
        step(2);
        CHECK_EQ_I(httpd_active(&H), 0);
    }

    /* request sent, client closes without reading: no SIGPIPE, slot freed */
    CHECK(open_conn(&c) >= 0);
    cputs(c, full);
    close(c);
    step(3);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* request sent, write side shut: the answer still arrives */
    CHECK(open_conn(&c) >= 0);
    cputs(c, full);
    shutdown(c, SHUT_WR);
    len = cread(c, resp, sizeof resp, 50);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
    close(c);
    step(2);
    CHECK_EQ_I(httpd_active(&H), 0);
}

static void test_timeouts(void)
{
    static const char full[] = "GET / HTTP/1.0\r\nUser-Agent: slow\r\n\r\n";
    uint32_t t0, to0;
    size_t i;
    int c, len;
    resp_t r;

    /* a silent client is answered 408 exactly at the deadline */
    CHECK(open_conn(&c) >= 0);
    t0 = now;
    to0 = H.stats.timeouts;
    cputs(c, "GET / HTTP/1.0\r\n");            /* no blank line, ever */
    step(5);
    now = t0 + H.rx_timeout_ms - 1;
    step(1);                                    /* polled at deadline - 1 */
    CHECK_EQ_I(recv(c, resp, sizeof resp, 0), -1);
    CHECK_EQ_I(httpd_active(&H), 1);
    len = cread(c, resp, sizeof resp, 20);      /* first poll here is at the deadline */
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 408);
    CHECK_EQ_I(got_eof, 1);
    CHECK_EQ_I(H.stats.timeouts, to0 + 1);
    /* the client never closes: the linger deadline frees the slot */
    CHECK_EQ_I(httpd_active(&H), 1);
    now += H.linger_ms;
    step(1);
    CHECK_EQ_I(httpd_active(&H), 0);
    close(c);

    /* slow but in time: one byte every 50 ms, 37 bytes, about 1.8 s */
    CHECK(open_conn(&c) >= 0);
    for (i = 0; i < sizeof full - 1; i++) {
        csend(c, full + i, 1);
        step(1);
        now += 49;
    }
    len = cread(c, resp, sizeof resp, 20);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    close(c);
    step(2);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* too slow: a byte every 200 ms keeps the connection busy but cannot
     * hold the slot past the deadline */
    CHECK(open_conn(&c) >= 0);
    t0 = now;
    for (i = 0; i < sizeof full - 1; i++) {
        if (csend(c, full + i, 1) != 1) break;
        step(1);
        now += 199;
        if ((uint32_t)(now - t0) > H.rx_timeout_ms + 400u) break;
    }
    len = cread(c, resp, sizeof resp, 20);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 408);
    CHECK((uint32_t)(now - t0) < H.rx_timeout_ms + 1000u);
    close(c);
    step(2);
    CHECK_EQ_I(httpd_active(&H), 0);
}

static void test_oversized(void)
{
    static char big[4 * HTTPD_REQ_MAX];
    static const char head[] = "GET / HTTP/1.0\r\nX-Pad: ";
    size_t hl = sizeof head - 1;
    resp_t r;
    int c, len, i;

    /* a head of exactly HTTPD_REQ_MAX bytes is served */
    memset(big, 'a', sizeof big);
    memcpy(big, head, hl);
    memcpy(big + HTTPD_REQ_MAX - 4, "\r\n\r\n", 4);
    CHECK_EQ_I(code_of_n(big, HTTPD_REQ_MAX), 200);
    /* one byte more is not */
    memset(big, 'a', sizeof big);
    memcpy(big, head, hl);
    memcpy(big + HTTPD_REQ_MAX - 3, "\r\n\r\n", 4);
    CHECK_EQ_I(code_of_n(big, HTTPD_REQ_MAX + 1), 431);
    CHECK(strncmp(resp, "HTTP/1.0 431 Request Header Fields Too Large\r\n", 46) == 0);

    /* endless header: refused as soon as the limit is reached, long before
     * the timeout, and the rest of the flood is discarded */
    memset(big, 'a', sizeof big);
    memcpy(big, head, hl);
    CHECK(open_conn(&c) >= 0);
    CHECK_EQ_I(csend(c, big, sizeof big), (int)sizeof big);
    len = cread(c, resp, sizeof resp, 100);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 431);
    CHECK_EQ_I(got_eof, 1);
    for (i = 0; i < 20; i++) { csend(c, big, sizeof big); step(1); }
    CHECK_EQ_I(httpd_active(&H), 1);
    close(c);
    now += H.linger_ms;                         /* at the latest */
    step(1);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* endless request line without any line end */
    memset(big, '/', sizeof big);
    memcpy(big, "GET ", 4);
    CHECK_EQ_I(code_of_n(big, sizeof big), 431);
    /* endless garbage */
    memset(big, 0xff, sizeof big);
    CHECK_EQ_I(code_of_n(big, sizeof big), 431);
    CHECK_EQ_I(httpd_active(&H), 0);
}

static void test_pipelined(void)
{
    static char big[3000];
    resp_t r;
    int c, len, n;
    const char *second;

    /* two requests in one write: HTTP/1.0, one answer, then close */
    len = exchange("GET /status.json HTTP/1.0\r\n\r\nGET /config HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK_EQ_I(r.clen, r.body_len);
    second = strstr(resp + 5, "HTTP/1.0 ");
    CHECK(second == NULL);
    CHECK(strstr(resp, "[network]") == NULL);
    CHECK_EQ_I(got_eof, 1);

    /* a request followed by garbage, binary included */
    n = snprintf(big, sizeof big, "GET / HTTP/1.0\r\n\r\n");
    memset(big + n, 0x00, 500);
    memset(big + n + 500, 0xff, 500);
    memcpy(big + n + 1000, "\r\n\r\nPOST /config HTTP/1.0\r\n\r\n", 29);
    memset(big + n + 1029, 'Z', sizeof big - (size_t)n - 1029);
    len = exchange_n(big, sizeof big, resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK_EQ_I(r.clen, r.body_len);
    CHECK_EQ_I(got_eof, 1);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* garbage that keeps coming after the answer: the client still gets a
     * clean end of stream, and the slot is freed by the linger deadline at
     * the latest */
    CHECK(open_conn(&c) >= 0);
    cputs(c, "GET / HTTP/1.0\r\n\r\n");
    len = cread(c, resp, sizeof resp, 50);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    for (n = 0; n < 50; n++) { csend(c, big, sizeof big); step(1); }
    CHECK_EQ_I(httpd_active(&H), 1);
    now += H.linger_ms;
    step(1);
    CHECK_EQ_I(httpd_active(&H), 0);
    close(c);
}

static void test_table(void)
{
    int c[HTTPD_MAX_CONN + 2], slot[HTTPD_MAX_CONN], i, j, len;
    uint32_t rej = H.stats.rejected;
    resp_t r;

    for (i = 0; i < HTTPD_MAX_CONN; i++) {
        slot[i] = open_conn(&c[i]);
        CHECK(slot[i] >= 0 && slot[i] < HTTPD_MAX_CONN);
        for (j = 0; j < i; j++) CHECK(slot[i] != slot[j]);
    }
    CHECK_EQ_I(httpd_active(&H), HTTPD_MAX_CONN);

    /* the fifth and sixth are turned away at once with a 503 */
    for (i = HTTPD_MAX_CONN; i < HTTPD_MAX_CONN + 2; i++) {
        CHECK_EQ_I(open_conn(&c[i]), -1);
        cputs(c[i], "GET / HTTP/1.0\r\n\r\n");
        len = cread(c[i], resp, sizeof resp, 10);
        CHECK(parse_resp(resp, len, &r));
        CHECK_EQ_I(r.code, 503);
        CHECK(got_eof != 0);
        close(c[i]);
    }
    CHECK_EQ_I(H.stats.rejected, rej + 2);
    CHECK_EQ_I(httpd_active(&H), HTTPD_MAX_CONN);

    /* the four inside are not disturbed */
    cputs(c[2], "GET /status.json HTTP/1.0\r\n\r\n");
    len = cread(c[2], resp, sizeof resp, 50);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
    close(c[2]);
    step(2);
    CHECK_EQ_I(httpd_active(&H), HTTPD_MAX_CONN - 1);

    /* and a freed slot is usable again */
    CHECK_EQ_I(open_conn(&c[2]), slot[2]);
    CHECK_EQ_I(httpd_active(&H), HTTPD_MAX_CONN);
    CHECK_EQ_I(open_conn(&c[4]), -1);
    close(c[4]);

    /* idlers cannot hold the table: all four time out */
    now += H.rx_timeout_ms;
    for (i = 0; i < HTTPD_MAX_CONN; i++) {
        len = cread(c[i], resp, sizeof resp, 10);
        CHECK(parse_resp(resp, len, &r));
        CHECK_EQ_I(r.code, 408);
        close(c[i]);
    }
    step(2);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* unusable descriptors */
    CHECK_EQ_I(httpd_adopt(&H, -1, now), -1);
    CHECK_EQ_I(httpd_adopt(&H, 9999, now), -1);
    i = open("/dev/null", O_RDWR);
    CHECK(i >= 0);
    if (httpd_adopt(&H, i, now) >= 0) step(2);     /* not a socket: dropped on first use */
    CHECK_EQ_I(httpd_active(&H), 0);
}

/* A reader that stalls. The server end's send buffer is filled with junk
 * before the server gets it, so its first send cannot complete: this is
 * deterministic, whatever the kernel's buffer sizes are. */
static int open_stuffed(int *cli, int *junk)
{
    int sv[2], small = 1024;
    char j[256];
    ssize_t w;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK);
    memset(j, 'J', sizeof j);
    *junk = 0;
    while ((w = send(sv[1], j, sizeof j, MSG_NOSIGNAL)) > 0) *junk += (int)w;
    *cli = sv[0];
    return httpd_adopt(&H, sv[1], now);
}

static void test_slow_reader(void)
{
    static char all[400000];
    uint32_t stalls, to0;
    int c, c2, junk, len, i, total, eof;
    resp_t r;

    /* never reads: the daemon's poll keeps returning, other clients are
     * served, and the send deadline frees the slot */
    CHECK(open_stuffed(&c, &junk) >= 0);
    CHECK(junk > 0);
    stalls = H.stats.tx_stalls;
    to0 = H.stats.timeouts;
    cputs(c, "GET / HTTP/1.0\r\n\r\n");
    step(50);
    CHECK_EQ_I(httpd_active(&H), 1);
    CHECK(H.stats.tx_stalls > stalls);
    CHECK_EQ_I(code_of("GET /status.json HTTP/1.0\r\n\r\n"), 200);
    CHECK_EQ_I(httpd_active(&H), 1);
    now += H.tx_timeout_ms;
    step(1);
    CHECK_EQ_I(httpd_active(&H), 0);
    CHECK_EQ_I(H.stats.timeouts, to0 + 1);
    close(c);

    /* reads 97 bytes per poll: the whole response arrives intact */
    CHECK(open_stuffed(&c, &junk) >= 0);
    CHECK((size_t)junk + HTTPD_TX_MAX < sizeof all);
    stalls = H.stats.tx_stalls;
    cputs(c, "GET / HTTP/1.0\r\n\r\n");
    step(5);
    CHECK(H.stats.tx_stalls > stalls);
    total = 0; eof = 0;
    for (i = 0; i < 100000 && !eof && total + 97 < (int)sizeof all; i++) {
        ssize_t n;
        step(1);
        n = recv(c, all + total, 97, 0);
        if (n > 0) total += (int)n;
        else if (n == 0) eof = 1;
        /* meanwhile another client is not kept waiting */
        if (i == 3) {
            CHECK(open_conn(&c2) >= 0);
            cputs(c2, "GET /config HTTP/1.0\r\n\r\n");
            len = cread(c2, resp, sizeof resp, 20);
            CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
            close(c2);
        }
    }
    CHECK_EQ_I(eof, 1);
    CHECK(total > junk);
    for (i = 0; i < junk && all[i] == 'J'; i++) ;
    CHECK_EQ_I(i, junk);
    all[total] = '\0';
    CHECK(parse_resp(all + junk, total - junk, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK_EQ_I(r.clen, r.body_len);
    len = status_render_html(&S, want, sizeof want);
    CHECK_EQ_I(r.body_len, len);
    CHECK(r.body && memcmp(r.body, want, (size_t)len) == 0);
    close(c);
    step(2);
    CHECK_EQ_I(httpd_active(&H), 0);
}

/* the largest bodies the three views can produce must fit a response */
static void test_worst_case(void)
{
    static cfg_t wc;
    static status_t ws;
    static httpd_t wh;
    static const char *const paths[] = { "/", "/status.json", "/config", "/settings" };
    char req[64];
    resp_t r;
    int c, len, i;

    cfg_default(&wc);
    wc.n_users = CFG_MAX_USERS;
    for (i = 0; i < CFG_MAX_USERS; i++) {
        memset(wc.users[i].name, 0x80 + i, CFG_NAME_MAX);
        memset(wc.users[i].secret, 0x01, CFG_SECRET_MAX);
    }
    memset(&ws, 0xff, sizeof ws);
    memset(ws.peer_name, '"', sizeof ws.peer_name);
    ws.n_calls = STATUS_MAX_CALLS;
    httpd_init(&wh, &wc, &ws);
    for (i = 0; i < 4; i++) {
        CHECK(open_conn_h(&wh, &c) >= 0);
        snprintf(req, sizeof req, "GET %s HTTP/1.0\r\n\r\n", paths[i]);
        cputs(c, req);
        len = cread_h(&wh, c, resp, sizeof resp, 50);
        CHECK(parse_resp(resp, len, &r));
        CHECK_EQ_I(r.code, 200);
        CHECK_EQ_I(r.clen, r.body_len);
        CHECK(r.clen > 3000 && r.clen <= HTTPD_BODY_MAX);
        close(c);
        step_h(&wh, 2);
    }
    CHECK_EQ_I(httpd_active(&wh), 0);

    /* two instances do not share anything: H still serves its own structs */
    len = exchange("GET /config HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "user = \"alice\" <redacted>") != NULL);
    CHECK_EQ_I(wh.stats.ok, 4);

    /* httpd_close drops everything */
    CHECK(open_conn_h(&wh, &c) >= 0);
    CHECK(open_conn_h(&wh, &i) >= 0);
    CHECK_EQ_I(httpd_active(&wh), 2);
    httpd_close(&wh);
    CHECK_EQ_I(httpd_active(&wh), 0);
    CHECK_EQ_I(recv(c, resp, sizeof resp, 0), 0);
    CHECK_EQ_I(recv(i, resp, sizeof resp, 0), 0);
    close(c); close(i);
}

/* ---- the settings form ----------------------------------------------------- */

static struct {
    int   calls;
    int   rc;               /* what the callback answers */
    cfg_t got;              /* the config it was handed */
    int   old_busy;         /* C.busy_chance as the callback saw it */
    void *ctx;
} sv;

static int on_save(void *ctx, const cfg_t *newcfg)
{
    sv.calls++;
    sv.ctx = ctx;
    sv.got = *newcfg;
    sv.old_busy = C.busy_chance;
    return sv.rc;
}

static char reqbuf[HTTPD_REQ_MAX + 2 * HTTPD_POST_MAX];

/* POST /settings with extra header lines (each ending in CR LF) and a
 * body; the status code */
static int post_to(const char *path, const char *hdrs, const char *body)
{
    int n = snprintf(reqbuf, sizeof reqbuf,
                     "POST %s HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                     "Content-Length: %d\r\n%s\r\n%s", path, (int)strlen(body), hdrs, body);
    return code_of_n(reqbuf, (size_t)n);
}
static int post(const char *hdrs, const char *body) { return post_to("/settings", hdrs, body); }

/* "Authorization: Basic <base64 of user:pass>\r\n" */
static const char *basic(const char *user, const char *pass)
{
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static char out[512];
    unsigned char in[256];
    size_t n = (size_t)snprintf((char *)in, sizeof in, "%s:%s", user, pass), i, o;
    o = (size_t)snprintf(out, sizeof out, "Authorization: Basic ");
    for (i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16 | (i + 1 < n ? (unsigned)in[i + 1] << 8 : 0u) |
                     (i + 2 < n ? (unsigned)in[i + 2] : 0u);
        out[o++] = a[v >> 18];
        out[o++] = a[(v >> 12) & 63u];
        out[o++] = i + 1 < n ? a[(v >> 6) & 63u] : '=';
        out[o++] = i + 2 < n ? a[v & 63u] : '=';
    }
    strcpy(out + o, "\r\n");
    return out;
}

static void test_settings_page(void)
{
    resp_t r;
    int len, n;

    /* the form, rendered from the live config */
    len = exchange("GET /settings HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "\r\nContent-Type: text/html; charset=utf-8\r\n") != NULL);
    CHECK(strstr(resp, "\r\nCache-Control: no-store\r\n") != NULL);
    n = settings_render_html(&C, 0, NULL, want, sizeof want);
    CHECK(n > 0);
    CHECK_EQ_I(r.clen, n);
    CHECK_EQ_I(r.body_len, n);
    CHECK(r.body && memcmp(r.body, want, (size_t)n) == 0);
    CHECK(strstr(resp, "value=\"alice\"") != NULL);
    CHECK(strstr(resp, "TOPSECRET") == NULL);
    CHECK(strstr(resp, "<a href=\"/\">Dashboard</a>") != NULL);
    CHECK(strstr(resp, "Settings saved") == NULL);
    CHECK_EQ_I(got_eof, 1);
    /* and the status page leads here */
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<a href=\"/line\">Line</a>") != NULL);

    /* the note after a save, only for exactly that query */
    len = exchange("GET /settings?saved=1 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
    CHECK(strstr(resp, "<p><b>Settings saved.</b></p>") != NULL);
    CHECK_EQ_I(code_of("GET /settings?saved=0 HTTP/1.0\r\n\r\n"), 200);
    CHECK(strstr(resp, "Settings saved") == NULL);
    CHECK_EQ_I(code_of("GET /settings?saved=1&x=<b> HTTP/1.0\r\n\r\n"), 200);
    CHECK(strstr(resp, "Settings saved") == NULL && strstr(resp, "<b>&") == NULL);
    CHECK_EQ_I(code_of("GET /settings? HTTP/1.1\r\nHost: 192.168.1.2\r\n\r\n"), 200);

    len = exchange("HEAD /settings HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK_EQ_I(r.clen, n);
    CHECK_EQ_I(r.body_len, 0);

    /* near misses are not the page */
    CHECK_EQ_I(code_of("GET /settings/ HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /setting HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /Settings HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /settings%3Fsaved=1 HTTP/1.0\r\n\r\n"), 404);

    /* other methods: 405, and Allow names the three that work here */
    CHECK_EQ_I(code_of("PUT /settings HTTP/1.0\r\nContent-Length: 7\r\n\r\nrings=3"), 405);
    CHECK(strstr(resp, "\r\nAllow: GET, HEAD, POST\r\n") != NULL);
    CHECK_EQ_I(code_of("DELETE /settings HTTP/1.0\r\n\r\n"), 405);
    CHECK_EQ_I(code_of("OPTIONS /settings HTTP/1.0\r\n\r\n"), 405);
    /* POST is for the form only */
    CHECK_EQ_I(post_to("/", "", "rings=3"), 405);
    CHECK(strstr(resp, "\r\nAllow: GET, HEAD\r\n") != NULL);
    CHECK_EQ_I(post_to("/config", "", "rings=3"), 405);
    CHECK_EQ_I(post_to("/settings/x", "", "rings=3"), 405);
}

static void test_settings_post(void)
{
    cfg_t before;
    resp_t r;
    int len;

    /* without a save callback nothing can be changed */
    before = C;
    CHECK_EQ_I(post("", "busy_chance=40"), 403);
    CHECK(strstr(resp, "\r\nContent-Type: text/plain; charset=us-ascii\r\n") != NULL);
    CHECK(strstr(resp, "\r\n\r\n403 Forbidden\n") != NULL);
    CHECK(memcmp(&C, &before, sizeof C) == 0);
    CHECK_EQ_I(code_of("GET /settings HTTP/1.0\r\n\r\n"), 200);      /* reading is fine */

    httpd_on_save(&H, on_save, &sv);
    memset(&sv, 0, sizeof sv);

    /* a good post: callback, then redirect, and the new values are served */
    CHECK_EQ_I(post("", "busy_chance=40&number=5550000&pass1=NEWSECRET&v92=on&max_upstream=48000"), 303);
    len = (int)strlen(resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 303);
    CHECK(strncmp(resp, "HTTP/1.0 303 See Other\r\n", 24) == 0);
    CHECK(strstr(resp, "\r\nLocation: /settings?saved=1\r\n") != NULL);
    CHECK_EQ_I(r.clen, r.body_len);
    CHECK(r.body && strstr(r.body, "<a href=\"/settings?saved=1\">") != NULL);  /* for old browsers */
    CHECK(strstr(resp, "NEWSECRET") == NULL);
    CHECK_EQ_I(got_eof, 1);
    CHECK_EQ_I(sv.calls, 1);
    CHECK(sv.ctx == &sv);
    CHECK_EQ_I(sv.got.busy_chance, 40);
    CHECK_EQ_I(sv.got.v92, 1); CHECK_EQ_I(sv.got.max_up, 48000); CHECK_EQ_I(sv.got.port2.v92, 1);
    CHECK(strcmp(sv.got.line_number, "5550000") == 0);
    CHECK_EQ_I(sv.old_busy, 0);                 /* the callback still saw the old config in C */
    CHECK_EQ_I(C.busy_chance, 40);              /* and now it is the new one */
    CHECK(strcmp(C.line_number, "5550000") == 0);
    CHECK(strcmp(C.users[1].secret, "NEWSECRET") == 0);
    CHECK(strcmp(C.users[0].secret, "TOPSECRET-A") == 0);
    CHECK(memcmp(&C, &sv.got, sizeof C) == 0);
    CHECK_EQ_I(H.stats.saves, 1);
    CHECK_EQ_I(cfg_validate(&C, NULL, 0), CFG_OK);
    CHECK_EQ_I(code_of("GET /settings?saved=1 HTTP/1.0\r\n\r\n"), 200);
    CHECK(strstr(resp, "name=\"busy_chance\" size=\"6\" maxlength=\"5\" value=\"40\">") != NULL);
    CHECK(strstr(resp, "<option value=\"on\" selected>On: offer PCM upstream to V.92 callers</option>") != NULL);
    CHECK(strstr(resp, "name=\"max_upstream\" size=\"6\" maxlength=\"5\" value=\"48000\">") != NULL);
    CHECK(strstr(resp, "value=\"5550000\"") != NULL);
    CHECK(strstr(resp, "SECRET") == NULL);
    CHECK_EQ_I(code_of("GET /config HTTP/1.0\r\n\r\n"), 200);
    CHECK(strstr(resp, "\nnumber = 5550000\n") != NULL && strstr(resp, "\nbusy_chance = 40\n") != NULL);
    CHECK(strstr(resp, "\nmax_upstream = 48000\n") != NULL && strstr(resp, "\nv42bis = on\nv92 = on\nx2 = off\nk56 = off\nrings = 1\n") != NULL);
    CHECK(strstr(resp, "SECRET") == NULL);

    /* a value that is not acceptable: the form again with the reason, 400,
     * no callback, nothing changed */
    before = C;
    CHECK_EQ_I(post("", "rings=3&busy_chance=101&user5=%3Cb%3E"), 400);
    len = (int)strlen(resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 400);
    CHECK_EQ_I(r.clen, r.body_len);
    CHECK(strstr(resp, "\r\nContent-Type: text/html; charset=utf-8\r\n") != NULL);
    CHECK(strstr(resp, "<p><b>Not saved:</b> [ppp] user &#39;&lt;b&gt;&#39;: a new user needs a password</p>") != NULL);
    CHECK(strstr(resp, "name=\"rings\" size=\"6\" maxlength=\"5\" value=\"3\">") != NULL);   /* what was typed */
    CHECK(strstr(resp, "value=\"&lt;b&gt;\"") != NULL);
    CHECK(strstr(resp, "<b>\"") == NULL && strstr(resp, "SECRET") == NULL);
    CHECK_EQ_I(sv.calls, 1);
    CHECK(memcmp(&C, &before, sizeof C) == 0);
    CHECK_EQ_I(post("", "busy_chance=101"), 400);
    CHECK(strstr(resp, "Not saved:</b> [line] busy_chance: 101 is out of range 0..100</p>") != NULL);
    CHECK_EQ_I(post("", "auth=none&user0=&user1=&auth=chap"), 400);       /* (auth twice: malformed) */
    CHECK_EQ_I(post("", "user0=&user1="), 400);
    CHECK(strstr(resp, "[ppp] auth: chap needs at least one user") != NULL);
    CHECK(memcmp(&C, &before, sizeof C) == 0);

    /* a body that is not a form of ours: plain 400 */
    {
        static const char *const bad[] = { "rings", "rings=3&rings=4", "bogus=1", "rings=%zz", "rings=%00",
                                           "rings=3&", "addr=10.0.0.1", "rings=3\r\n" };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            CHECK_EQ_I(post("", bad[i]), 400);
            CHECK(strstr(resp, "\r\n\r\n400 Bad Request\n") != NULL);
        }
    }
    {
        static const char nul[] = "POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                                  "Content-Length: 8\r\n\r\nrings=3\0";
        CHECK_EQ_I(code_of_n(nul, sizeof nul - 1), 400);
        CHECK(strstr(resp, "\r\n\r\n400 Bad Request\n") != NULL);
    }
    CHECK_EQ_I(sv.calls, 1);
    CHECK(memcmp(&C, &before, sizeof C) == 0);

    /* an empty form changes nothing but is a save all the same */
    CHECK_EQ_I(post("", ""), 303);
    CHECK_EQ_I(sv.calls, 2);
    CHECK(memcmp(&C, &before, sizeof C) == 0);

    /* the callback cannot store it: 500 with a plain message, old config stays */
    sv.rc = -1;
    CHECK_EQ_I(post("", "busy_chance=77"), 500);
    CHECK(strstr(resp, "\r\nContent-Type: text/plain; charset=us-ascii\r\n") != NULL);
    CHECK(strstr(resp, "\r\n\r\n500 Internal Server Error\nThe settings could not be saved.\n") != NULL);
    CHECK_EQ_I(sv.calls, 3);
    CHECK_EQ_I(sv.got.busy_chance, 77);
    CHECK_EQ_I(C.busy_chance, 40);
    CHECK(memcmp(&C, &before, sizeof C) == 0);
    CHECK_EQ_I(H.stats.saves, 2);
    sv.rc = 0;

    /* Content-Type: ours, in any case, with parameters; anything else 415 */
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\ncontent-type:APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8\r\n"
                       "CONTENT-LENGTH:  7 \r\n\r\nrings=3"), 303);
    CHECK_EQ_I(C.rings, 3);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Length: 7\r\n\r\nrings=4"), 415);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nrings=4"), 415);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: multipart/form-data; boundary=x\r\n"
                       "Content-Length: 7\r\n\r\nrings=4"), 415);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencodedx\r\n"
                       "Content-Length: 7\r\n\r\nrings=4"), 415);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/json\r\n"
                       "Content-Length: 11\r\n\r\n{\"rings\":4}"), 415);
    CHECK_EQ_I(C.rings, 3);

    /* Content-Length: needed, one, a plain number */
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nrings=4"), 411);
    CHECK(strncmp(resp, "HTTP/1.0 411 Length Required\r\n", 30) == 0);
    {
        static const char *const cl[] = { "", "x", "-1", "+7", "7 7", "0x7", "7,7", "7.0", " " };
        size_t i;
        for (i = 0; i < sizeof cl / sizeof cl[0]; i++) {
            snprintf(reqbuf, sizeof reqbuf, "POST /settings HTTP/1.0\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n\r\nrings=4", cl[i]);
            CHECK_EQ_I(code_of(reqbuf), 400);
        }
        CHECK_EQ_I(post("Content-Length: 7\r\n", "rings=4"), 400);        /* twice, even if equal */
        CHECK_EQ_I(post("Content-Type: application/x-www-form-urlencoded\r\n", "rings=4"), 400);
        CHECK_EQ_I(post("Transfer-Encoding: chunked\r\n", "rings=4"), 400);
    }
    CHECK_EQ_I(C.rings, 3);
    /* a short Content-Length cuts the body there */
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 7\r\n\r\nrings=5&bogus=1"), 303);
    CHECK_EQ_I(C.rings, 5);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 0\r\n\r\nrings=6"), 303);
    CHECK_EQ_I(C.rings, 5);
    CHECK_EQ_I(httpd_active(&H), 0);
}

static void test_settings_size(void)
{
    static char big[HTTPD_POST_MAX + 64];
    cfg_t before = C;
    resp_t r;
    int c, len, n, calls = sv.calls;
    uint32_t t0;

    /* more than HTTPD_POST_MAX is refused from the head alone, at once */
    CHECK(open_conn(&c) >= 0);
    t0 = now;
    n = snprintf(reqbuf, sizeof reqbuf, "POST /settings HTTP/1.0\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n", HTTPD_POST_MAX + 1);
    csend(c, reqbuf, (size_t)n);
    len = cread(c, resp, sizeof resp, 20);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 413);
    CHECK(strncmp(resp, "HTTP/1.0 413 Request Entity Too Large\r\n", 39) == 0);
    CHECK((uint32_t)(now - t0) < 100u);
    /* the body that follows anyway is thrown away */
    memset(big, 'a', sizeof big);
    for (n = 0; n < 4; n++) { csend(c, big, sizeof big); step(1); }
    CHECK_EQ_I(httpd_active(&H), 1);
    close(c);
    now += H.linger_ms;                         /* at the latest */
    step(1);
    CHECK_EQ_I(httpd_active(&H), 0);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 99999999999999999999999999\r\n\r\n"), 413);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 4294967303\r\n\r\nrings=3"), 413);      /* 2^32 + 7 */

    /* exactly HTTPD_POST_MAX is read and decoded: here found malformed ... */
    memset(big, 'a', HTTPD_POST_MAX); big[HTTPD_POST_MAX] = '\0';
    CHECK_EQ_I(post("", big), 400);
    CHECK(strstr(resp, "\r\n\r\n400 Bad Request\n") != NULL);
    /* ... and here well-formed, with a password that is far too long (no
     * acceptable form is this large) */
    memcpy(big, "rings=7&pass0=", 14);
    CHECK_EQ_I(post("", big), 400);
    CHECK(strstr(resp, "Not saved:</b> [ppp] user 1: password is longer than 64 octets</p>") != NULL);
    CHECK(strstr(resp, "name=\"rings\" size=\"6\" maxlength=\"5\" value=\"7\">") != NULL);
    CHECK_EQ_I(sv.calls, calls);
    CHECK(memcmp(&C, &before, sizeof C) == 0);

    /* the largest form a browser can send: 16 names of 63 and passwords of
     * 64 octets, every octet as %HH */
    {
        int i, k;
        n = snprintf(big, sizeof big, "number=%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A%%2A"
                     "&tones=eu&rings=10&busy_chance=100&drop_mean=10080&session_limit=10080"
                     "&idle_timeout=10080&mods=1&mod_v90=1&mod_v22bis=1&mod_v22=1&mod_v21=1"
                     "&max_downstream=56000&max_upstream=48000&v92=off&auth=chap");
        for (i = 0; i < CFG_MAX_USERS; i++) {
            n += snprintf(big + n, sizeof big - (size_t)n, "&user%d=%c", i, 'a' + i);
            for (k = 1; k < CFG_NAME_MAX; k++) n += snprintf(big + n, sizeof big - (size_t)n, "%%22");
            n += snprintf(big + n, sizeof big - (size_t)n, "&pass%d=", i);
            for (k = 0; k < CFG_SECRET_MAX; k++) n += snprintf(big + n, sizeof big - (size_t)n, "%%FF");
        }
        n += snprintf(big + n, sizeof big - (size_t)n, "&admin_password=");
        for (k = 0; k < CFG_SECRET_MAX; k++) n += snprintf(big + n, sizeof big - (size_t)n, "%%FF");
        CHECK(n > 6000 && n <= HTTPD_POST_MAX);
        CHECK_EQ_I(post("", big), 303);
        CHECK_EQ_I(C.n_users, CFG_MAX_USERS);
        CHECK_EQ_I(strlen(C.users[15].name), CFG_NAME_MAX);
        CHECK_EQ_I(strlen(C.users[15].secret), CFG_SECRET_MAX);
        CHECK_EQ_I(strlen(C.admin_password), CFG_SECRET_MAX);
        /* its form still fits a response (it now needs the password) */
        memset(big, 0xff, CFG_SECRET_MAX); big[CFG_SECRET_MAX] = '\0';
        snprintf(reqbuf, sizeof reqbuf, "GET /settings HTTP/1.0\r\n%s\r\n", basic("admin", big));
        len = exchange(reqbuf, resp, sizeof resp);
        CHECK(parse_resp(resp, len, &r));
        CHECK_EQ_I(r.code, 200);
        CHECK_EQ_I(r.clen, r.body_len);
        CHECK(r.clen > 11000 && r.clen <= HTTPD_BODY_MAX);
        snprintf(reqbuf, sizeof reqbuf, "GET /config HTTP/1.0\r\n%s\r\n", basic("admin", big));
        CHECK_EQ_I(code_of(reqbuf), 200);
    }
    C = before;

    /* a head like a current browser sends with a form fits the request buffer */
    n = snprintf(reqbuf, sizeof reqbuf,
        "POST /settings HTTP/1.1\r\n"
        "Host: 192.168.1.2\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 13\r\n"
        "Cache-Control: max-age=0\r\n"
        "Authorization: Basic YWRtaW46MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==\r\n"
        "Origin: http://192.168.1.2\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/141.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Referer: http://192.168.1.2/settings?saved=1\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: en-US,en;q=0.9,ro;q=0.8,de;q=0.7,fr;q=0.6\r\n"
        "Cookie: some=cookie; another=cookie-from-a-different-thing-on-this-address-0123456789\r\n"
        "\r\nbusy_chance=5");
    CHECK(n > 800 && n < HTTPD_REQ_MAX);
    CHECK_EQ_I(code_of_n(reqbuf, (size_t)n), 303);
    CHECK_EQ_I(C.busy_chance, 5);
    C = before;
    CHECK_EQ_I(httpd_active(&H), 0);
}

static void test_settings_body(void)
{
    static const char head[] = "POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                               "Content-Length: 28\r\n\r\n";
    static const char body[] = "rings=2&busy_chance=9&pass0=";       /* 28 octets */
    char full[sizeof head + sizeof body];
    size_t fl, hl = sizeof head - 1, split, cut;
    cfg_t before = C;
    uint32_t t0, to0;
    resp_t r;
    int c, len, calls;

    CHECK_EQ_I(sizeof body - 1, 28);
    memcpy(full, head, hl);
    memcpy(full + hl, body, sizeof body);
    fl = strlen(full);

    /* the request cut in two at every place, head or body */
    calls = sv.calls;
    for (split = 1; split < fl; split++) {
        C.rings = 1; C.busy_chance = 0;
        CHECK(open_conn(&c) >= 0);
        csend(c, full, split);
        step(2);
        CHECK_EQ_I(httpd_active(&H), 1);
        csend(c, full + split, fl - split);
        len = cread(c, resp, sizeof resp, 50);
        CHECK(parse_resp(resp, len, &r) && r.code == 303 && r.clen == r.body_len);
        CHECK(C.rings == 2 && C.busy_chance == 9);
        close(c);
        step(2);
        CHECK_EQ_I(httpd_active(&H), 0);
    }
    CHECK_EQ_I(sv.calls, calls + (int)fl - 1);

    /* one octet per poll */
    C.rings = 1;
    CHECK(open_conn(&c) >= 0);
    for (split = 0; split < fl; split++) { csend(c, full + split, 1); step(1); }
    len = cread(c, resp, sizeof resp, 50);
    CHECK(parse_resp(resp, len, &r) && r.code == 303);
    CHECK_EQ_I(C.rings, 2);
    close(c);
    step(2);

    /* every proper prefix, then the client goes away: nothing is saved,
     * nothing is answered, the slot is freed */
    C = before;
    calls = sv.calls;
    for (cut = hl; cut < fl; cut++) {
        CHECK(open_conn(&c) >= 0);
        csend(c, full, cut);
        step(2);
        CHECK_EQ_I(httpd_active(&H), 1);
        shutdown(c, SHUT_WR);
        len = cread(c, resp, sizeof resp, 20);
        CHECK_EQ_I(len, 0);
        CHECK_EQ_I(got_eof, 1);
        close(c);
        CHECK_EQ_I(httpd_active(&H), 0);
    }
    CHECK_EQ_I(sv.calls, calls);
    CHECK(memcmp(&C, &before, sizeof C) == 0);

    /* a body that stops coming: 408 at the deadline of the whole request */
    CHECK(open_conn(&c) >= 0);
    t0 = now;
    to0 = H.stats.timeouts;
    csend(c, full, fl - 1);
    step(5);
    now = t0 + H.rx_timeout_ms - 1;
    step(1);
    CHECK_EQ_I(recv(c, resp, sizeof resp, 0), -1);
    CHECK_EQ_I(httpd_active(&H), 1);
    len = cread(c, resp, sizeof resp, 20);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 408);
    CHECK_EQ_I(H.stats.timeouts, to0 + 1);
    csend(c, full + fl - 1, 1);                 /* too late */
    close(c);
    step(3);
    CHECK_EQ_I(httpd_active(&H), 0);
    /* a slow body does not move the deadline either */
    CHECK(open_conn(&c) >= 0);
    t0 = now;
    csend(c, full, hl);
    for (split = hl; split < fl; split++) {
        if (csend(c, full + split, 1) != 1) break;
        step(1);
        now += 399;
        if ((uint32_t)(now - t0) > H.rx_timeout_ms + 800u) break;
    }
    len = cread(c, resp, sizeof resp, 20);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 408);
    close(c);
    step(3);
    CHECK_EQ_I(sv.calls, calls);
    CHECK(memcmp(&C, &before, sizeof C) == 0);

    /* what follows the body is not looked at */
    snprintf(reqbuf, sizeof reqbuf, "%s&bogus=1\r\n\r\nPOST /settings HTTP/1.0\r\n\r\n", full);
    CHECK_EQ_I(code_of(reqbuf), 303);
    CHECK(strstr(resp + 5, "HTTP/1.0 ") == NULL);
    CHECK_EQ_I(sv.calls, calls + 1);
    C = before;

    /* four posts at once, bodies arriving interleaved */
    {
        int cc[HTTPD_MAX_CONN], i;
        size_t k;
        calls = sv.calls;
        for (i = 0; i < HTTPD_MAX_CONN; i++) CHECK(open_conn(&cc[i]) >= 0);
        for (k = 0; k < fl; k += 5)
            for (i = 0; i < HTTPD_MAX_CONN; i++) {
                csend(cc[i], full + k, fl - k < 5 ? fl - k : 5);
                step(1);
            }
        for (i = 0; i < HTTPD_MAX_CONN; i++) {
            len = cread(cc[i], resp, sizeof resp, 50);
            CHECK(parse_resp(resp, len, &r) && r.code == 303 && r.clen == r.body_len);
            close(cc[i]);
        }
        step(3);
        CHECK_EQ_I(sv.calls, calls + HTTPD_MAX_CONN);
        CHECK_EQ_I(httpd_active(&H), 0);
    }
    C = before;
}

static void test_settings_origin(void)
{
    cfg_t before = C;
    int calls = sv.calls;

    /* no Origin (old browsers, command line clients): allowed */
    CHECK_EQ_I(post("Host: 192.168.1.2\r\n", "rings=2"), 303);
    CHECK_EQ_I(post("", "rings=2"), 303);
    /* Origin of this very host: allowed */
    CHECK_EQ_I(post("Host: 192.168.1.2\r\nOrigin: http://192.168.1.2\r\n", "rings=2"), 303);
    CHECK_EQ_I(post("Origin: http://192.168.1.2:8080\r\nHost: 192.168.1.2:8080\r\n", "rings=2"), 303);
    CHECK_EQ_I(sv.calls, calls + 4);
    C = before;
    calls = sv.calls;
    /* DNS rebinding: a hostile page whose name is pointed at our address is
     * "same origin" for the browser, Host and Origin agree, and both carry
     * that name. Without an admin password the settings therefore answer
     * only to a Host that is an address (or to a client that sends none). */
    CHECK_EQ_I(post("host:v90d.LAN\r\norigin:  HTTP://V90D.lan \r\n", "rings=2"), 403);
    CHECK_EQ_I(post("Host: evil.example\r\n", "rings=2"), 403);
    CHECK_EQ_I(post("Host: 192.168.1.2.evil.example\r\n", "rings=2"), 403);
    CHECK_EQ_I(post("Host: 1.2.3\r\n", "rings=2"), 403);
    CHECK_EQ_I(post("Host: 192.168.1.2:x\r\n", "rings=2"), 403);
    CHECK_EQ_I(code_of("GET /settings HTTP/1.1\r\nHost: evil.example\r\n\r\n"), 403);
    CHECK_EQ_I(code_of("GET /config HTTP/1.1\r\nHost: evil.example\r\n\r\n"), 403);
    CHECK_EQ_I(code_of("GET /log HTTP/1.1\r\nHost: evil.example\r\n\r\n"), 403);     /* same gate as /config */
    CHECK_EQ_I(code_of("GET /settings HTTP/1.1\r\nHost: 10.0.0.7:8080\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /config HTTP/1.1\r\nHost: 10.0.0.7\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /log HTTP/1.1\r\nHost: 10.0.0.7\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"), 200);     /* the status page tells no secrets */
    CHECK_EQ_I(sv.calls, calls);
    /* with an admin password a name is fine: the hostile page has no credentials */
    strcpy(C.admin_password, "pw");
    CHECK_EQ_I(post("Host: v90d.lan\r\nAuthorization: Basic YWRtaW46cHc=\r\n", "rings=2"), 303);
    CHECK_EQ_I(post("Host: v90d.lan\r\n", "rings=2"), 401);
    C = before;
    calls = sv.calls;
    /* anything else: refused, nothing saved */
    {
        static const char *const cross[] = {
            "Host: 192.168.1.2\r\nOrigin: http://evil.example\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://192.168.1.20\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://192.168.1.2.evil.example\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://192.168.1.2:8080\r\n",
            "Host: 192.168.1.2:8080\r\nOrigin: http://192.168.1.2\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://192.168.1.2@evil.example\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://evil.example/192.168.1.2\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://192.168.1.2/\r\n",
            "Host: 192.168.1.2\r\nOrigin: null\r\n",
            "Host: 192.168.1.2\r\nOrigin: 192.168.1.2\r\n",
            "Host: 192.168.1.2\r\nOrigin:\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://\r\n",
            "Origin: http://192.168.1.2\r\n",                              /* no Host to compare with */
            "Host:\r\nOrigin: http://\r\n",
            "Host: 192.168.1.2\r\nHost: evil.example\r\nOrigin: http://evil.example\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://192.168.1.2\r\nOrigin: http://evil.example\r\n",
            "Host: 192.168.1.2\r\nOrigin: http://evil.example\r\nOrigin: http://192.168.1.2\r\n",
        };
        size_t i;
        for (i = 0; i < sizeof cross / sizeof cross[0]; i++) {
            int code = post(cross[i], "rings=9");
            CHECK_EQ_I(code, 403);
            if (code != 403) printf("  cross[%d]\n", (int)i);
            CHECK(strstr(resp, "\r\n\r\n403 Forbidden\n") != NULL);
        }
    }
    CHECK_EQ_I(sv.calls, calls);
    CHECK(memcmp(&C, &before, sizeof C) == 0);
    /* reading the form is not restricted by Origin */
    CHECK_EQ_I(code_of("GET /settings HTTP/1.0\r\nHost: 192.168.1.2\r\nOrigin: http://evil.example\r\n\r\n"), 200);
}

static void test_settings_auth(void)
{
    static const char pw[] = "s3cret: \"x\"";
    char hdr[600], long_pw[CFG_SECRET_MAX + 2];
    cfg_t before = C;
    resp_t r;
    int len, calls = sv.calls;

    strcpy(C.admin_password, pw);

    /* no credentials at all: a browser. It is sent to the login page (no
     * Basic challenge, which would pop up the browser's own dialog); no
     * form, no secret */
    len = exchange("GET /settings HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 303);
    CHECK(strstr(resp, "\r\nLocation: /login\r\n") != NULL);
    CHECK(strstr(resp, "WWW-Authenticate") == NULL);
    CHECK_EQ_I(r.clen, r.body_len);
    CHECK(strstr(resp, "<form") == NULL && strstr(resp, "alice") == NULL && strstr(resp, "s3cret") == NULL);
    len = exchange("HEAD /settings HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 303 && r.body_len == 0);
    CHECK_EQ_I(post("", "rings=9"), 401);
    CHECK(strstr(resp, "WWW-Authenticate") == NULL);
    /* Basic credentials that are wrong: the challenge, as before */
    CHECK_EQ_I(post(basic("admin", "nope"), "rings=9"), 401);
    CHECK(strstr(resp, "\r\nWWW-Authenticate: Basic realm=\"v90d settings\"\r\n") != NULL);
    /* the challenge comes before every other objection to a post */
    CHECK_EQ_I(post("Origin: http://evil.example\r\nHost: x\r\n", "rings=9"), 401);
    CHECK_EQ_I(code_of("POST /settings HTTP/1.0\r\nContent-Length: 999999\r\n\r\n"), 401);
    /* but a method that is never served needs no password to be told so */
    CHECK_EQ_I(code_of("DELETE /settings HTTP/1.0\r\n\r\n"), 405);

    /* the right ones */
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\n%s\r\n", basic("admin", pw));
    len = exchange(hdr, resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "<form") != NULL && strstr(resp, "A password is set") != NULL);
    CHECK(strstr(resp, "s3cret") == NULL);
    CHECK_EQ_I(post(basic("admin", pw), "rings=4"), 303);
    CHECK_EQ_I(C.rings, 4);
    CHECK_EQ_I(sv.calls, calls + 1);
    /* scheme and header name in any case, blanks around the token */
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nauthorization:   bAsIc   %.*s \r\n\r\n",
             (int)strlen(basic("admin", pw) + 21) - 2, basic("admin", pw) + 21);
    CHECK_EQ_I(code_of(hdr), 200);

    /* wrong ones, every kind */
    {
        static const struct { const char *u, *p; } wrong[] = {
            { "admin", "" }, { "admin", "s3cret" }, { "admin", "s3cret: \"x" }, { "admin", "s3cret: \"x\"\"" },
            { "admin", "S3cret: \"x\"" }, { "admin", "s3cret: \"x\" " }, { "admin", " s3cret: \"x\"" },
            { "admin", "t3cret: \"x\"" }, { "admin", "s3cret: \"x#" }, { "admin", "admin" },
            { "Admin", "s3cret: \"x\"" }, { "root", "s3cret: \"x\"" }, { "", "s3cret: \"x\"" },
            { "admi", "n:s3cret: \"x\"" }, { "admin:", "s3cret: \"x\"" }, { "admin", ":s3cret: \"x\"" },
            { "alice", "TOPSECRET-A" }, { "", "" },
        };
        static const char *const junk[] = {
            "Authorization: Basic\r\n", "Authorization: Basic \r\n", "Authorization:\r\n",
            "Authorization: Basic !!!!\r\n", "Authorization: Basic YWRtaW4\r\n",
            "Authorization: Basic YWRtaW46czNjcmV0OiAieCI\r\n",        /* right, padding cut off */
            "Authorization: Basic YWRtaW46czNjcmV0OiAieCI==\r\n",
            "Authorization: Basic YWRt aW46czNjcmV0OiAieCI=\r\n",
            "Authorization: Basic =WRtaW46czNjcmV0OiAieCI=\r\n",
            "Authorization: Basic YWRtaW46czNjcmV0OiAieCI=YWRt\r\n",
            "Authorization: Bearer YWRtaW46czNjcmV0OiAieCI=\r\n",
            "Authorization: BasicYWRtaW46czNjcmV0OiAieCI=\r\n",
            "Authorization: Digest username=\"admin\"\r\n",
            "Authorization: admin:s3cret: \"x\"\r\n",
            "Authorisation: Basic YWRtaW46czNjcmV0OiAieCI=\r\n",
            "X-Authorization: Basic YWRtaW46czNjcmV0OiAieCI=\r\n",
            "Cookie: Authorization: Basic YWRtaW46czNjcmV0OiAieCI=\r\n",
        };
        size_t k;
        /* the reference token above is the right one, or the cases prove nothing */
        CHECK(strcmp(basic("admin", pw), "Authorization: Basic YWRtaW46czNjcmV0OiAieCI=\r\n") == 0);
        for (k = 0; k < sizeof wrong / sizeof wrong[0]; k++) {
            int code;
            snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\n%s\r\n", basic(wrong[k].u, wrong[k].p));
            code = code_of(hdr);
            CHECK_EQ_I(code, 401);
            if (code != 401) printf("  wrong[%d]\n", (int)k);
            CHECK(strstr(resp, "<form") == NULL);
        }
        for (k = 0; k < sizeof junk / sizeof junk[0]; k++) {
            int code;
            snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\n%s\r\n", junk[k]);
            /* the last three are no Authorization header at all: a browser
             * without a session, which is sent to the login page */
            int want_code = k + 3 >= sizeof junk / sizeof junk[0] ? 303 : 401;
            code = code_of(hdr);
            CHECK_EQ_I(code, want_code);
            if (code != want_code) printf("  junk[%d]\n", (int)k);
            CHECK(strstr(resp, "<form") == NULL);
            CHECK_EQ_I(post(junk[k], "rings=9"), 401);
        }
        /* two Authorization lines, even two right ones */
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\n%s", basic("admin", pw));
        snprintf(hdr + strlen(hdr), sizeof hdr - strlen(hdr), "%s\r\n", basic("admin", pw));
        CHECK_EQ_I(code_of(hdr), 401);
        /* a very long token */
        {
            static const char start[] = "GET /settings HTTP/1.0\r\nAuthorization: Basic ";
            memset(hdr, 'A', sizeof hdr);
            memcpy(hdr, start, sizeof start - 1);
            memcpy(hdr + sizeof hdr - 5, "\r\n\r\n", 5);
            CHECK_EQ_I(code_of(hdr), 401);
        }
    }
    CHECK_EQ_I(C.rings, 4);
    CHECK_EQ_I(sv.calls, calls + 1);

    /* the other views are closed as well: pages lead to the login page,
     * the JSON view just says no; all open to the right credentials */
    CHECK_EQ_I(code_of("GET / HTTP/1.0\r\n\r\n"), 303);
    CHECK(strstr(resp, "\r\nLocation: /login\r\n") != NULL && strstr(resp, "alice") == NULL);
    CHECK_EQ_I(code_of("GET /status.json HTTP/1.0\r\n\r\n"), 401);
    CHECK(strstr(resp, "WWW-Authenticate") == NULL && strstr(resp, "down_bps") == NULL);
    CHECK_EQ_I(code_of("GET /config HTTP/1.0\r\n\r\n"), 303);
    CHECK(strstr(resp, "[line]") == NULL);
    snprintf(hdr, sizeof hdr, "GET / HTTP/1.0\r\n%s\r\n", basic("admin", pw));
    CHECK_EQ_I(code_of(hdr), 200);
    snprintf(hdr, sizeof hdr, "GET /status.json HTTP/1.0\r\n%s\r\n", basic("admin", pw));
    CHECK_EQ_I(code_of(hdr), 200);
    snprintf(hdr, sizeof hdr, "GET /status.json HTTP/1.0\r\n%s\r\n", basic("admin", "no"));
    CHECK_EQ_I(code_of(hdr), 401);
    CHECK(strstr(resp, "WWW-Authenticate") != NULL);
    snprintf(hdr, sizeof hdr, "GET /config HTTP/1.0\r\n%s\r\n", basic("admin", pw));
    CHECK_EQ_I(code_of(hdr), 200);
    CHECK(strstr(resp, "admin_password = <redacted>\n") != NULL && strstr(resp, "s3cret") == NULL);
    /* neither the login page nor the old stock address tell anything */
    CHECK_EQ_I(code_of("GET /cgi-bin/login HTTP/1.0\r\n\r\n"), 302);

    /* passwords of 1 and of 64 octets, and octets above 127 */
    strcpy(C.admin_password, "x");
    CHECK_EQ_I(post(basic("admin", "x"), "rings=5"), 303);
    CHECK_EQ_I(post(basic("admin", "xx"), "rings=6"), 401);
    CHECK_EQ_I(post(basic("admin", ""), "rings=6"), 401);
    /* the right credentials with a NUL octet after them are not the right ones */
    CHECK_EQ_I(post("Authorization: Basic YWRtaW46eA==\r\n", "rings=5"), 303);
    CHECK_EQ_I(post("Authorization: Basic YWRtaW46eAA=\r\n", "rings=6"), 401);
    CHECK_EQ_I(post("Authorization: Basic YWRtaW46eAAA\r\n", "rings=6"), 401);
    memset(long_pw, 'p', sizeof long_pw);
    long_pw[0] = (char)0xff; long_pw[1] = (char)0x80;
    long_pw[CFG_SECRET_MAX] = '\0';
    strcpy(C.admin_password, long_pw);
    CHECK_EQ_I(post(basic("admin", long_pw), "rings=6"), 303);
    long_pw[CFG_SECRET_MAX] = 'p'; long_pw[CFG_SECRET_MAX + 1] = '\0';
    CHECK_EQ_I(post(basic("admin", long_pw), "rings=7"), 401);
    long_pw[CFG_SECRET_MAX - 1] = '\0';
    CHECK_EQ_I(post(basic("admin", long_pw), "rings=7"), 401);
    CHECK_EQ_I(C.rings, 6);

    /* changing the password through the form: the old one stops working */
    strcpy(C.admin_password, "old");
    CHECK_EQ_I(post(basic("admin", "old"), "admin_password=new"), 303);
    CHECK(strcmp(C.admin_password, "new") == 0);
    CHECK_EQ_I(post(basic("admin", "old"), "rings=8"), 401);
    snprintf(hdr, sizeof hdr, "GET /settings?saved=1 HTTP/1.0\r\n%s\r\n", basic("admin", "new"));
    CHECK_EQ_I(code_of(hdr), 200);
    CHECK(strstr(resp, "value=\"new\"") == NULL);
    /* an empty field keeps it, the checkbox removes it and opens the page */
    CHECK_EQ_I(post(basic("admin", "new"), "admin_password=&rings=8"), 303);
    CHECK(strcmp(C.admin_password, "new") == 0);
    CHECK_EQ_I(post(basic("admin", "new"), "admin_password=&admin_clear=1"), 303);
    CHECK(C.admin_password[0] == '\0');
    CHECK_EQ_I(code_of("GET /settings HTTP/1.0\r\n\r\n"), 200);
    CHECK(strstr(resp, "No password is set") != NULL);
    /* with no password set, credentials are simply not looked at */
    CHECK_EQ_I(post(basic("admin", "whatever"), "rings=9"), 303);
    CHECK_EQ_I(post("Authorization: garbage\r\n", "rings=10"), 303);
    CHECK_EQ_I(C.rings, 10);

    C = before;
    CHECK_EQ_I(httpd_active(&H), 0);
}

static uint32_t rnd_state = 0x1234abcdu;
static uint32_t rnd(void)
{
    rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5;
    return rnd_state;
}

/* Random and mutated requests. Whatever arrives, the server answers with
 * one well-formed response or with nothing, and gives the slot back. */
static void test_fuzz(void)
{
    static const char *const seeds[] = {
        "GET / HTTP/1.0\r\n\r\n",
        "GET /status.json HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n",
        "HEAD /config?x=1 HTTP/1.0\r\n\r\n",
        "POST /config HTTP/1.0\r\nContent-Length: 3\r\n\r\nabc",
        "GET /../../etc/passwd HTTP/1.0\r\n\r\n",
    };
    static const char *const words[] = { "GET", "HEAD", "POST", " ", " ", "/", "/config", "/status.json",
        "..", "%00", "?", "HTTP/1.0", "HTTP/1.1", "HTTP/", "\r\n", "\r\n\r\n", "\n", "\r", ":", "\t" };
    unsigned char req[2 * HTTPD_REQ_MAX];
    int iter, bad_resp = 0, leaked = 0, codes[6] = { 0, 0, 0, 0, 0, 0 }, silent = 0;

    for (iter = 0; iter < 3000; iter++) {
        size_t n = 0, i;
        int c, len, kind = (int)(rnd() % 4u);
        resp_t r;

        if (kind == 0) {                                /* pure noise */
            n = rnd() % 400u;
            for (i = 0; i < n; i++) req[i] = (unsigned char)rnd();
        } else if (kind == 1 || kind == 2) {            /* a valid request, damaged */
            const char *s = seeds[rnd() % 5u];
            n = strlen(s);
            memcpy(req, s, n);
            if (kind == 1) {
                unsigned k = 1u + rnd() % 3u;
                while (k--) req[rnd() % n] = (unsigned char)rnd();
            } else {
                n = rnd() % (n + 1u);                   /* cut short */
            }
        } else {                                        /* plausible tokens, shuffled */
            unsigned k = 1u + rnd() % 12u;
            while (k--) {
                const char *w = words[rnd() % 20u];
                memcpy(req + n, w, strlen(w));
                n += strlen(w);
            }
        }
        if (rnd() % 16u == 0) {                         /* now and then far too long */
            memset(req + n, 'A' + (int)(rnd() % 26u), sizeof req - n);
            n = sizeof req;
        }

        if (open_conn(&c) < 0) { leaked++; close(c); break; }
        csend(c, req, n);
        if (rnd() & 1u) {                               /* give up ... */
            shutdown(c, SHUT_WR);
            len = cread(c, resp, sizeof resp, 30);
        } else {                                        /* ... or hang until the deadline */
            len = cread(c, resp, sizeof resp, 5);
            if (len == 0 && !got_eof) {
                now += H.rx_timeout_ms;
                len = cread(c, resp, sizeof resp, 30);
            }
        }
        if (len == 0) {
            silent++;
        } else if (!parse_resp(resp, len, &r) || got_eof != 1 ||
                   (r.clen != r.body_len &&     /* only a HEAD answer may lack its body */
                    !(n >= 5 && memcmp(req, "HEAD ", 5) == 0 && r.body_len == 0))) {
            bad_resp++;
            printf("  iter %d: malformed answer (%d bytes, eof %d, kind %d, req %d bytes)\n%.60s\n",
                   iter, len, got_eof, kind, (int)n, resp);
        } else {
            switch (r.code) {
            case 200: codes[0]++; break;
            case 400: codes[1]++; break;
            case 404: codes[2]++; break;
            case 405: codes[3]++; break;
            case 408: codes[4]++; break;
            case 431: codes[5]++; break;
            default:  bad_resp++; printf("  iter %d: code %d\n", iter, r.code);
            }
        }
        close(c);
        step(2);
        if (httpd_active(&H) != 0) { leaked++; printf("  iter %d: slot not freed\n", iter); break; }
    }
    CHECK_EQ_I(iter, 3000);
    CHECK_EQ_I(bad_resp, 0);
    CHECK_EQ_I(leaked, 0);
    printf("  fuzz: 200=%d 400=%d 404=%d 405=%d 408=%d 431=%d silent=%d\n",
           codes[0], codes[1], codes[2], codes[3], codes[4], codes[5], silent);
    /* the run reached every outcome, so the generator is not degenerate */
    CHECK(codes[0] > 0 && codes[1] > 0 && codes[2] > 0 && codes[3] > 0 && codes[4] > 0 &&
          codes[5] > 0 && silent > 0);
}

/* Damaged posts of the form; the seeds set and remove the admin password,
 * so the run goes through both states. Whatever
 * arrives, the answer is one well-formed response or none, the slot comes
 * back, and the config the server holds is valid and only ever changed
 * through the callback. */
/* the settings pages: each its own path, form and way back */
/* two ports: a second dashboard and a second JSON view */
static void test_two_ports(void)
{
    static status_t S2;
    resp_t r;
    int len;

    fixture();
    /* one port: these do not exist */
    CHECK_EQ_I(code_of("GET /port2 HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /status2.json HTTP/1.0\r\n\r\n"), 404);
    /* a one-port box: the port-2 settings pages do not exist either, and the
     * Line page offers no Port 2 link */
    CHECK_EQ_I(code_of("GET /line2 HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /modem2 HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 404);
    len = exchange("GET /line HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "/line2") == NULL);
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && strstr(resp, "Port 2") == NULL);

    status_init(&S2);
    S2.line = ST_LINE_TRAINING; S2.calls_total = 3;
    httpd_status2(&H, &S2);
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<p class=\"sw\"><b>Port 1</b> <a href=\"/port2\">Port 2</a></p>") != NULL);
    CHECK(strstr(resp, "<tr><th>Modulation</th><td>V.90</td></tr>") != NULL);
    len = exchange("GET /port2 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<p class=\"sw\"><a href=\"/\">Port 1</a> <b>Port 2</b></p>") != NULL);
    CHECK(strstr(resp, "<tr><th>State</th><td>negotiating</td></tr>") != NULL);
    len = exchange("GET /status2.json HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "\"line\":\"negotiating\"") != NULL && strstr(resp, "\"calls_total\":3") != NULL);
    len = exchange("GET /status.json HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && strstr(resp, "\"line\":\"connected\"") != NULL);
    CHECK_EQ_I(code_of("POST /port2 HTTP/1.0\r\nContent-Length: 0\r\n\r\n"), 405);
    /* the calls of both ports on one page */
    len = exchange("GET /calls HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<h2>Call history</h2>") != NULL && strstr(resp, "<th>Port</th>") != NULL);
    CHECK(strstr(resp, "<a href=\"/calls\">Calls</a>") == NULL);     /* the active tab is no link */
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<a href=\"/calls\">Calls</a>") != NULL);
    /* the Dreamcast tab: on every page, and only while a port has that service */
    CHECK(strstr(resp, "/dreamcast") == NULL);
    /* the Consoles tab shows for a dreamcast or a saturn port, and the page
     * carries both the dreamcast switches and the saturn one */
    C.port2.service = CFG_SERVICE_DREAMCAST;
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<a href=\"/dreamcast\">Consoles</a>") != NULL);
    len = exchange("GET /dreamcast2 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && strstr(resp, "<select name=\"dreamcast_lan\">") != NULL
          && strstr(resp, "<select name=\"saturn_matchmaking\">") != NULL);
    C.port2.service = CFG_SERVICE_INTERNET;
    C.service = CFG_SERVICE_SATURN;
    len = exchange("GET /firmware HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<a href=\"/dreamcast\">Consoles</a>") != NULL);
    CHECK_EQ_I(code_of("GET /saturn HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 404);   /* no separate Saturn tab */
    C.service = CFG_SERVICE_INTERNET;
    len = exchange("GET /firmware HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "/dreamcast") == NULL);
    CHECK_EQ_I(code_of("POST /calls HTTP/1.0\r\nContent-Length: 0\r\n\r\n"), 405);
    /* behind the login like the rest */
    strcpy(C.admin_password, "pw");
    CHECK_EQ_I(code_of("GET /port2 HTTP/1.0\r\n\r\n"), 303);
    CHECK_EQ_I(code_of("GET /calls HTTP/1.0\r\n\r\n"), 303);
    CHECK_EQ_I(code_of("GET /status2.json HTTP/1.0\r\n\r\n"), 401);
    fixture();                          /* as the tests after this one expect it */
    httpd_on_save(&H, on_save, &sv);
}

static void test_pages(void)
{
    cfg_t before;
    resp_t r;
    int len;

    fixture();
    httpd_on_save(&H, on_save, &sv);
    before = C;
    len = exchange("GET /line HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<form method=\"post\" action=\"/line\">") != NULL && strstr(resp, "name=\"user0\"") == NULL);
    CHECK_EQ_I(code_of("GET /modem HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /users HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /network HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /system HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 200);
    CHECK_EQ_I(code_of("GET /lines HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("DELETE /line HTTP/1.0\r\n\r\n"), 405);
    /* saving leads back to the page it came from */
    CHECK_EQ_I(post_to("/line", "Host: 192.168.1.2\r\n", "rings=5"), 303);
    CHECK(strstr(resp, "\r\nLocation: /line?saved=1\r\n") != NULL);
    CHECK_EQ_I(C.rings, 5);
    len = exchange("GET /line?saved=1 HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<p><b>Settings saved.</b></p>") != NULL && strstr(resp, "action=\"/line\"") != NULL);
    CHECK_EQ_I(post_to("/network", "Host: 192.168.1.2\r\n", "gateway=192.168.1.1&lan=static"), 303);
    CHECK(strstr(resp, "\r\nLocation: /network?saved=1\r\n") != NULL);
    CHECK(C.lan_gateway == 0xC0A80101u);
    /* a value that will not do: the same page again with what was typed */
    CHECK_EQ_I(post_to("/network", "Host: 192.168.1.2\r\n", "address=10.1.2"), 400);
    CHECK(strstr(resp, "Not saved:</b> [network] address: &#39;10.1.2&#39; is not an IPv4 address</p>") != NULL);
    CHECK(strstr(resp, "action=\"/network\"") != NULL && strstr(resp, "name=\"number\"") == NULL);
    /* behind the login like everything else */
    strcpy(C.admin_password, "pw");
    CHECK_EQ_I(code_of("GET /users HTTP/1.0\r\n\r\n"), 303);
    CHECK(strstr(resp, "\r\nLocation: /login\r\n") != NULL);
    CHECK_EQ_I(post_to("/system", "", "admin_clear=1"), 401);
    C = before;
    fixture();
    httpd_on_save(&H, on_save, &sv);
}

/* the Restart button of the settings page */
static void test_restart(void)
{
    cfg_t before = C;
    char hdr[400];

    fixture();
    CHECK_EQ_I(H.restart_asked, 0);
    CHECK_EQ_I(code_of("GET /restart HTTP/1.0\r\n\r\n"), 405);
    CHECK(strstr(resp, "\r\nAllow: POST\r\n") != NULL);
    /* from another site: no */
    CHECK_EQ_I(post_to("/restart", "Origin: http://evil.example\r\nHost: 192.168.1.2\r\n", ""), 403);
    /* by a name instead of the address, without a password: no (as for the settings) */
    CHECK_EQ_I(post_to("/restart", "Host: box.example\r\n", ""), 403);
    CHECK_EQ_I(H.restart_asked, 0);
    /* with a password set and none given: no */
    strcpy(C.admin_password, "pw");
    CHECK_EQ_I(post_to("/restart", "Host: 192.168.1.2\r\n", ""), 401);
    CHECK_EQ_I(H.restart_asked, 0);
    snprintf(hdr, sizeof hdr, "Host: 192.168.1.2\r\n%s", basic("admin", "pw"));
    CHECK_EQ_I(post_to("/restart", hdr, ""), 200);
    CHECK_EQ_I(H.restart_asked, 1);
    CHECK(strstr(resp, "<title>Nestaliga restart</title>") != NULL);
    CHECK(strstr(resp, "<meta http-equiv=\"refresh\" content=\"25;url=/\">") != NULL);
    C = before;
    fixture();
    CHECK_EQ_I(post_to("/restart", "Host: 192.168.1.2\r\nOrigin: http://192.168.1.2\r\n", "x=1"), 200);
    CHECK_EQ_I(H.restart_asked, 1);
    fixture();                          /* as the tests after this one expect it */
    httpd_on_save(&H, on_save, &sv);
}

/* ---- the Firmware page: shown here, its two posts handed on ---------------- */

static struct {
    int  calls, what, fd, refuse;
    char early[HTTPD_REQ_MAX + 1]; size_t early_len, clen;
    char ctype[HTTPD_CTYPE_MAX + 1];
} fw;
static const char *fw_where = "scheme=loader\nset=B\nboard=9610003725A known\nunconfirmed=1\nimage_name=v90d ht802 <1>\n"
                              "image_octets=2182398\nsettings=0x1c0000\nstock=A good\n";
static int fw_text(void *ctx, int which, char *buf, size_t cap)
{
    const char *t = which == HTTPD_FW_WHERE ? fw_where : (const char *)ctx;
    snprintf(buf, cap, "%s", t);
    return (int)strlen(buf);
}
static const char *fw_take(void *ctx, int what, int fd, const char *early, size_t early_len, size_t clen, const char *ctype)
{
    (void)ctx;
    fw.calls++; fw.what = what; fw.clen = clen;
    fw.early_len = early_len; memcpy(fw.early, early, early_len); fw.early[early_len] = 0;
    snprintf(fw.ctype, sizeof fw.ctype, "%s", ctype);
    if (fw.refuse) return "A call is in progress.";
    fw.fd = dup(fd);                    /* what a forked helper would hold */
    return NULL;
}
static int fw_inst_calls, fw_inst_refuse;
static const char *fw_install(void *ctx)
{
    (void)ctx;
    fw_inst_calls++;
    return fw_inst_refuse ? "A call is in progress." : NULL;
}

static void test_firmware(void)
{
    static const char UP[] = "POST /firmware/upload HTTP/1.0\r\nHost: 192.168.1.2\r\n";
    httpd_fw_t f;
    char req[1200], hdr[400], got[64];
    resp_t r;
    int len, c, fds;
    ssize_t k;

    fixture();
    /* without anybody behind it: the version, and no forms */
    len = exchange("GET /firmware HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
    CHECK(strstr(resp, "<title>Nestaliga firmware</title>") != NULL && strstr(resp, "<b>Firmware</b>") != NULL);
    CHECK(strstr(resp, "<tr><th>Version</th><td>" V90D_VERSION "</td></tr>") != NULL);
    CHECK(strstr(resp, "<form") == NULL);
    snprintf(req, sizeof req, "%sContent-Length: 4\r\n\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 403);
    CHECK_EQ_I(code_of("POST /firmware/stock HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 13\r\n\r\nconfirm=stock"), 403);

    memset(&f, 0, sizeof f);
    f.version = "9.8.7 <test>"; f.text = fw_text; f.take = fw_take; f.install = fw_install; f.ctx = "writing v90d & co";
    httpd_on_firmware(&H, &f);
    memset(&fw, 0, sizeof fw);
    len = exchange("GET /firmware HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
    CHECK(strstr(resp, "<td>9.8.7 &lt;test&gt;</td>") != NULL);
    CHECK(strstr(resp, "by the v90d loader, from set B of the flash") != NULL);
    CHECK(strstr(resp, "v90d ht802 &lt;1&gt;, 2182398 octets") != NULL);
    CHECK(strstr(resp, "<p>writing v90d &amp; co</p>") != NULL);
    CHECK(strstr(resp, "<form method=\"post\" action=\"/firmware/upload\" enctype=\"multipart/form-data\">") != NULL);
    CHECK(strstr(resp, "<a href=\"/firmware/stock\">") != NULL);
    CHECK_EQ_I(code_of("HEAD /firmware HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), -2);    /* a head and no body */
    len = exchange("GET /firmware/stock HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200 && r.clen == r.body_len);
    CHECK(strstr(resp, "<form method=\"post\" action=\"/firmware/stock\">") != NULL);
    CHECK(strstr(resp, "name=\"confirm\" value=\"stock\" required>") != NULL);
    /* paths and methods */
    CHECK_EQ_I(code_of("GET /firmware/upload HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 405);
    CHECK(strstr(resp, "\r\nAllow: POST\r\n") != NULL);
    CHECK_EQ_I(code_of("POST /firmware HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Length: 0\r\n\r\n"), 405);
    CHECK_EQ_I(code_of("DELETE /firmware/stock HTTP/1.0\r\n\r\n"), 405);
    CHECK_EQ_I(code_of("GET /firmware/ HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /firmwares HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(code_of("GET /firmware/uploads HTTP/1.0\r\n\r\n"), 404);
    CHECK_EQ_I(fw.calls, 0);

    /* the self-update route: GET is not allowed; POST hands off to install */
    CHECK_EQ_I(code_of("GET /firmware/update HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 405);
    CHECK(strstr(resp, "\r\nAllow: POST\r\n") != NULL);
    fw_inst_calls = fw_inst_refuse = 0;
    CHECK_EQ_I(code_of("POST /firmware/update HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Length: 0\r\n\r\n"), 200);
    CHECK_EQ_I(fw_inst_calls, 1);
    fw_inst_refuse = 1;                 /* a call in progress: the reason is sent, 409 */
    CHECK_EQ_I(code_of("POST /firmware/update HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Length: 0\r\n\r\n"), 409);
    CHECK_EQ_I(fw_inst_calls, 2);
    f.install = NULL; httpd_on_firmware(&H, &f);     /* no installer behind it: not implemented */
    CHECK_EQ_I(code_of("POST /firmware/update HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Length: 0\r\n\r\n"), 501);
    CHECK_EQ_I(fw_inst_calls, 2);
    f.install = fw_install; httpd_on_firmware(&H, &f);
    fw_inst_refuse = 0;

    /* a post that is not in order never reaches the taker */
    snprintf(req, sizeof req, "%s\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 411);
    snprintf(req, sizeof req, "%sContent-Length: %u\r\n\r\nabcd", UP, HTTPD_FW_UPLOAD_MAX + 1u);
    CHECK_EQ_I(code_of(req), 413);
    snprintf(req, sizeof req, "%sContent-Length: 12345678901\r\n\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 413);
    snprintf(req, sizeof req, "%sContent-Length: 4x\r\n\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 400);
    snprintf(req, sizeof req, "%sContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 400);
    snprintf(req, sizeof req, "%sTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n", UP);
    CHECK_EQ_I(code_of(req), 400);
    snprintf(req, sizeof req, "%sOrigin: http://evil.example\r\nContent-Length: 4\r\n\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 403);
    CHECK_EQ_I(code_of("POST /firmware/upload HTTP/1.0\r\nHost: box.example\r\nContent-Length: 4\r\n\r\nabcd"), 403);
    {
        char longct[HTTPD_CTYPE_MAX + 40];
        memset(longct, 'a', sizeof longct); longct[sizeof longct - 1] = 0;
        snprintf(req, sizeof req, "%sContent-Type: %s\r\nContent-Length: 4\r\n\r\nabcd", UP, longct);
        CHECK_EQ_I(code_of(req), 400);
    }
    CHECK_EQ_I(code_of("POST /firmware/stock HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nconfirm=stock"), 415);
    CHECK_EQ_I(code_of("POST /firmware/stock HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 65\r\n\r\nconfirm=stock"), 413);
    CHECK_EQ_I(fw.calls, 0);
    /* behind the login like the settings */
    strcpy(C.admin_password, "pw");
    CHECK_EQ_I(code_of("GET /firmware HTTP/1.0\r\n\r\n"), 303);
    CHECK(strstr(resp, "\r\nLocation: /login\r\n") != NULL);
    CHECK_EQ_I(code_of("GET /firmware/stock HTTP/1.0\r\n\r\n"), 303);
    snprintf(req, sizeof req, "%sContent-Length: 4\r\n\r\nabcd", UP);
    CHECK_EQ_I(code_of(req), 401);
    snprintf(req, sizeof req, "POST /firmware/upload HTTP/1.0\r\nHost: 192.168.1.2\r\n%sContent-Length: 4\r\n\r\nabcd", basic("admin", "no"));
    CHECK_EQ_I(code_of(req), 401);
    CHECK_EQ_I(fw.calls, 0);

    /* the taker says no: the browser is told why, by us */
    fw.refuse = 1;
    snprintf(hdr, sizeof hdr, "%s", basic("admin", "pw"));
    snprintf(req, sizeof req, "POST /firmware/upload HTTP/1.0\r\nHost: 192.168.1.2\r\n%sContent-Length: 4\r\n\r\nabcd", hdr);
    CHECK_EQ_I(code_of(req), 409);
    CHECK(strstr(resp, "A call is in progress.") != NULL);
    CHECK_EQ_I(fw.calls, 1);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* the taker says yes: it has the connection, with what had arrived of the body */
    fw.refuse = 0;
    fds = count_fds();
    CHECK(open_conn(&c) >= 0);
    snprintf(req, sizeof req, "POST /firmware/upload HTTP/1.0\r\nHost: 192.168.1.2\r\n%s"
             "Content-Type: multipart/form-data; boundary=----x\r\nContent-Length: 10\r\n\r\nabcd", hdr);
    cputs(c, req);
    step(3);
    CHECK_EQ_I(fw.calls, 2);
    CHECK_EQ_I(fw.what, HTTPD_FW_UPLOAD);
    CHECK_EQ_I(fw.clen, 10);
    CHECK_EQ_I(fw.early_len, 4);
    CHECK(strcmp(fw.early, "abcd") == 0);
    CHECK(strcmp(fw.ctype, "multipart/form-data; boundary=----x") == 0);
    CHECK_EQ_I(httpd_active(&H), 0);                    /* the server has forgotten it */
    CHECK_EQ_I(H.stats.handed, 1);
    cputs(c, "efghij");                                 /* the rest goes to the taker, and its answer comes back */
    k = recv(fw.fd, got, sizeof got, 0);
    CHECK(k == 6 && memcmp(got, "efghij", 6) == 0);
    CHECK_EQ_I(send(fw.fd, "HTTP/1.0 200 OK\r\n\r\nfine", 23, MSG_NOSIGNAL), 23);
    close(fw.fd);
    k = recv(c, got, sizeof got, 0);
    CHECK(k == 23 && memcmp(got, "HTTP/1.0 200 OK\r\n\r\nfine", 23) == 0);
    CHECK_EQ_I(recv(c, got, sizeof got, 0), 0);
    close(c);
    CHECK_EQ_I(count_fds(), fds);

    /* a body longer than it says: only what belongs to it is passed on */
    CHECK(open_conn(&c) >= 0);
    snprintf(req, sizeof req, "POST /firmware/stock HTTP/1.0\r\nHost: 192.168.1.2\r\n%s"
             "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nconfirm=stockGET / HTTP/1.0\r\n\r\n", hdr);
    cputs(c, req);
    step(3);
    CHECK_EQ_I(fw.calls, 3);
    CHECK_EQ_I(fw.what, HTTPD_FW_STOCK);
    CHECK(fw.clen == 13 && fw.early_len == 13 && strcmp(fw.early, "confirm=stock") == 0);
    close(fw.fd); close(c);
    step(3);
    CHECK_EQ_I(count_fds(), fds);
    CHECK_EQ_I(httpd_active(&H), 0);

    /* taken away again */
    httpd_on_firmware(&H, NULL);
    snprintf(req, sizeof req, "POST /firmware/upload HTTP/1.0\r\nHost: 192.168.1.2\r\n%sContent-Length: 4\r\n\r\nabcd", hdr);
    CHECK_EQ_I(code_of(req), 403);
    fixture();
    httpd_on_save(&H, on_save, &sv);
}

/* the value of the session cookie in the response, "" if there is none */
static const char *sid_of(const char *r)
{
    static char sid[80];
    const char *p = strstr(r, "\r\nSet-Cookie: sid="), *e;
    sid[0] = '\0';
    if (!p) return sid;
    p += 18; e = p;
    while (*e && *e != ';' && *e != '\r' && (size_t)(e - p) < sizeof sid - 1) e++;
    memcpy(sid, p, (size_t)(e - p)); sid[e - p] = '\0';
    return sid;
}

/* The login page: with an admin password set, the settings open to a
 * session that POST /login starts with the user name admin and that
 * password. */
static void test_login(void)
{
    static const char pw[] = "s3cret+&=";
    cfg_t before = C;
    char hdr[400], sid[80], sid2[80];
    resp_t r;
    int len, i;

    fixture();
    httpd_on_save(&H, on_save, &sv);
    strcpy(C.admin_password, pw);

    /* the page */
    len = exchange("GET /login HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "\r\nContent-Type: text/html; charset=utf-8\r\n") != NULL);
    CHECK(strstr(resp, "<title>Nestaliga login</title>") != NULL);
    CHECK(strstr(resp, "<form method=\"post\" action=\"/login\">") != NULL);
    CHECK(strstr(resp, "name=\"user\"") != NULL && strstr(resp, "type=\"password\" name=\"password\"") != NULL);
    CHECK(strstr(resp, "<nav><b>Login</b></nav>") != NULL && strstr(resp, "href=") == NULL);
    CHECK(strstr(resp, "s3cret") == NULL && strstr(resp, "Set-Cookie") == NULL);
    CHECK(strstr(resp, "Wrong") == NULL);
    CHECK_EQ_I(code_of("DELETE /login HTTP/1.0\r\n\r\n"), 405);

    /* wrong name or password: the page again with a line saying so, no session */
    CHECK_EQ_I(post_to("/login", "", "user=admin&password=nope"), 401);
    CHECK(strstr(resp, "Wrong user name or password") != NULL && strstr(resp, "<form") != NULL);
    CHECK(strstr(resp, "Set-Cookie") == NULL && strstr(resp, "WWW-Authenticate") == NULL);
    /* and for a second after a failure nobody is listened to, right or wrong */
    CHECK_EQ_I(post_to("/login", "", "user=admin&password=s3cret%2B%26%3D"), 429);
    CHECK(strstr(resp, "Set-Cookie") == NULL);
    now += 1001;
    CHECK_EQ_I(post_to("/login", "", "user=root&password=s3cret%2B%26%3D"), 401);
    now += 1001;
    CHECK_EQ_I(post_to("/login", "", "user=admin"), 401);
    now += 1001;
    CHECK_EQ_I(post_to("/login", "", "password=s3cret%2B%26%3D"), 401);
    now += 1001;
    /* malformed, from another site, too long */
    CHECK_EQ_I(post_to("/login", "", "user=admin&password=%zz"), 400);
    CHECK_EQ_I(post_to("/login", "", "user=admin&user=admin&password=x"), 400);
    CHECK_EQ_I(post_to("/login", "Origin: http://evil.example\r\nHost: 192.168.1.2\r\n",
                       "user=admin&password=s3cret%2B%26%3D"), 403);
    CHECK_EQ_I(code_of("POST /login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 5000\r\n\r\n"), 413);
    CHECK(strstr(resp, "Set-Cookie") == NULL);

    /* right: a session cookie that scripts cannot read and other sites
     * cannot send, and on to the settings */
    CHECK_EQ_I(post_to("/login", "Origin: http://192.168.1.2\r\nHost: 192.168.1.2\r\n",
                       "user=admin&password=s3cret%2B%26%3D"), 303);
    CHECK(strstr(resp, "\r\nLocation: /\r\n") != NULL);
    strcpy(sid, sid_of(resp));
    CHECK_EQ_I((int)strlen(sid), 32);
    for (i = 0; i < 32; i++) CHECK((sid[i] >= '0' && sid[i] <= '9') || (sid[i] >= 'a' && sid[i] <= 'f'));
    snprintf(hdr, sizeof hdr, "\r\nSet-Cookie: sid=%s; Path=/; HttpOnly; SameSite=Lax\r\n", sid);
    CHECK(strstr(resp, hdr) != NULL);
    CHECK(strstr(resp, "s3cret") == NULL);

    /* with it: the form, with a way out; posting works */
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: theme=dark; sid=%s\r\n\r\n", sid);
    len = exchange(hdr, resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r));
    CHECK_EQ_I(r.code, 200);
    CHECK(strstr(resp, "<form method=\"post\" action=\"/settings\">") != NULL);
    CHECK(strstr(resp, "href=\"/logout\">Log out</a>") != NULL);
    snprintf(hdr, sizeof hdr, "Cookie: sid=%s\r\n", sid);
    CHECK_EQ_I(post(hdr, "rings=6"), 303);
    CHECK_EQ_I(C.rings, 6);
    /* the login page itself has nothing to ask a session */
    snprintf(hdr, sizeof hdr, "GET /login HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid);
    len = exchange(hdr, resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 303 && strstr(resp, "\r\nLocation: /\r\n") != NULL);

    /* not with another value, a prefix, a longer one, or two cookies */
    {
        char bad[80];
        strcpy(bad, sid); bad[5] = bad[5] == '0' ? '1' : '0';
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", bad);
        CHECK_EQ_I(code_of(hdr), 303);
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%.31s\r\n\r\n", sid);
        CHECK_EQ_I(code_of(hdr), 303);
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s0\r\n\r\n", sid);
        CHECK_EQ_I(code_of(hdr), 303);
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: xsid=%s\r\n\r\n", sid);
        CHECK_EQ_I(code_of(hdr), 303);
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\nCookie: sid=%s\r\n\r\n", sid, sid);
        CHECK_EQ_I(code_of(hdr), 303);
        /* a stale sid beside the live one in one header, either order: the
         * live one is still found (a browser carrying an old session cookie) */
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s; sid=%s\r\n\r\n", bad, sid);
        CHECK_EQ_I(code_of(hdr), 200);
        snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s; sid=%s\r\n\r\n", sid, bad);
        CHECK_EQ_I(code_of(hdr), 200);
        CHECK_EQ_I(code_of("GET /settings HTTP/1.0\r\nCookie: sid=\r\n\r\n"), 303);
        CHECK_EQ_I(code_of("GET /settings HTTP/1.0\r\nCookie: sid=00000000000000000000000000000000\r\n\r\n"), 303);
    }

    /* a session lasts 15 minutes from its last use */
    now += 14u * 60u * 1000u;
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid);
    CHECK_EQ_I(code_of(hdr), 200);
    now += 14u * 60u * 1000u;
    CHECK_EQ_I(code_of(hdr), 200);
    now += 15u * 60u * 1000u + 1u;
    CHECK_EQ_I(code_of(hdr), 303);
    CHECK_EQ_I(code_of(hdr), 303);

    /* a new login is a new session; the old value stays dead */
    CHECK_EQ_I(post_to("/login", "", "user=admin&password=s3cret%2B%26%3D"), 303);
    strcpy(sid2, sid_of(resp));
    CHECK_EQ_I((int)strlen(sid2), 32);
    CHECK(strcmp(sid, sid2) != 0);
    CHECK_EQ_I(code_of(hdr), 303);
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid2);
    CHECK_EQ_I(code_of(hdr), 200);

    /* Somebody else logging in does not log this one out: there is room
     * for HTTPD_SESSIONS logins at a time (a browser, a second computer, a
     * script). One more takes the place of the one unused the longest. */
    {
        char more[HTTPD_SESSIONS][80], h2[400];
        int k;
        for (k = 1; k < HTTPD_SESSIONS; k++) {
            now += 1000;
            CHECK_EQ_I(post_to("/login", "", "user=admin&password=s3cret%2B%26%3D"), 303);
            strcpy(more[k], sid_of(resp));
            CHECK(strcmp(more[k], sid2) != 0);
        }
        CHECK_EQ_I(code_of(hdr), 200);                      /* the first is still in */
        for (k = 1; k < HTTPD_SESSIONS; k++) {
            snprintf(h2, sizeof h2, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[k]);
            CHECK_EQ_I(code_of(h2), 200);
        }
        /* all places taken; more[1] is now the one unused the longest */
        now += 1000;
        CHECK_EQ_I(code_of(hdr), 200);
        for (k = 2; k < HTTPD_SESSIONS; k++) {
            now += 1000;
            snprintf(h2, sizeof h2, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[k]);
            CHECK_EQ_I(code_of(h2), 200);
        }
        now += 1000;
        CHECK_EQ_I(post_to("/login", "", "user=admin&password=s3cret%2B%26%3D"), 303);
        strcpy(more[0], sid_of(resp));
        snprintf(h2, sizeof h2, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[1]);
        CHECK_EQ_I(code_of(h2), 303);
        snprintf(h2, sizeof h2, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[0]);
        CHECK_EQ_I(code_of(h2), 200);
        CHECK_EQ_I(code_of(hdr), 200);
        /* logging out ends one session and no other */
        snprintf(h2, sizeof h2, "GET /logout HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[0]);
        CHECK_EQ_I(code_of(h2), 303);
        snprintf(h2, sizeof h2, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[0]);
        CHECK_EQ_I(code_of(h2), 303);
        CHECK_EQ_I(code_of(hdr), 200);
        snprintf(h2, sizeof h2, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", more[2]);
        CHECK_EQ_I(code_of(h2), 200);
    }

    /* logging out ends it and clears the cookie */
    snprintf(hdr, sizeof hdr, "GET /logout HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid2);
    len = exchange(hdr, resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 303 && strstr(resp, "\r\nLocation: /\r\n") != NULL);
    CHECK(strstr(resp, "\r\nSet-Cookie: sid=; Path=/; Max-Age=0\r\n") != NULL);
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid2);
    CHECK_EQ_I(code_of(hdr), 303);
    /* somebody else's logout request does nothing to a session */
    CHECK_EQ_I(post_to("/login", "", "user=admin&password=s3cret%2B%26%3D"), 303);
    strcpy(sid, sid_of(resp));
    CHECK_EQ_I(code_of("GET /logout HTTP/1.0\r\n\r\n"), 303);
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid);
    CHECK_EQ_I(code_of(hdr), 200);

    /* changing the password ends every session */
    CHECK_EQ_I(post_to("/login", "", "user=admin&password=s3cret%2B%26%3D"), 303);
    strcpy(sid2, sid_of(resp));
    snprintf(hdr, sizeof hdr, "Cookie: sid=%s\r\n", sid);
    CHECK_EQ_I(post(hdr, "admin_password=other"), 303);
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid);
    CHECK_EQ_I(code_of(hdr), 303);
    snprintf(hdr, sizeof hdr, "GET /settings HTTP/1.0\r\nCookie: sid=%s\r\n\r\n", sid2);
    CHECK_EQ_I(code_of(hdr), 303);

    /* without an admin password there is nothing to log in to */
    C.admin_password[0] = '\0';
    len = exchange("GET /login HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 303 && strstr(resp, "\r\nLocation: /settings\r\n") != NULL);
    CHECK_EQ_I(post_to("/login", "", "user=admin&password="), 303);
    CHECK(strstr(resp, "Set-Cookie") == NULL);
    C = before;
}

static void test_settings_fuzz(void)
{
    static const char *const seeds[] = {
        "POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 31\r\n\r\nrings=3&busy_chance=20&tones=eu",
        "POST /settings HTTP/1.1\r\nHost: 192.168.1.2\r\nOrigin: http://192.168.1.2\r\n"
        "Authorization: Basic YWRtaW46cHc=\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 47\r\n\r\nnumber=5551234&user3=dave&pass3=d%20d&mod_v21=0",
        "POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 40\r\n\r\nauth=pap&user0=&pass0=&admin_password=pw",
        "GET /settings?saved=1 HTTP/1.0\r\nAuthorization: Basic YWRtaW46cHc=\r\n\r\n",
        "POST /settings HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Authorization: Basic YWRtaW46cHc=\r\nContent-Length: 21\r\n\r\nadmin_clear=1&rings=2",
    };
    cfg_t before = C, last;
    int iter, bad_resp = 0, leaked = 0, invalid = 0, unsaved = 0, calls;
    int codes[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, silent = 0;

    last = C;
    for (iter = 0; iter < 4000; iter++) {
        unsigned char req[1024];
        const char *s = seeds[rnd() % 5u];
        size_t n = strlen(s);
        int c, len, kind = (int)(rnd() % 4u);
        resp_t r;

        memcpy(req, s, n);
        if (kind == 1) {
            unsigned k = 1u + rnd() % 3u;
            while (k--) req[rnd() % n] = (unsigned char)rnd();
        } else if (kind == 2) {
            unsigned k = 1u + rnd() % 3u;
            while (k--) req[rnd() % n] = (unsigned char)"&=%+0159 \r\n:aZ"[rnd() % 14u];
        } else if (kind == 3) {
            n = rnd() % (n + 1u);
        }
        last = C;
        calls = sv.calls;
        if (open_conn(&c) < 0) { leaked++; close(c); break; }
        csend(c, req, n);
        if (rnd() & 1u) {
            shutdown(c, SHUT_WR);
            len = cread(c, resp, sizeof resp, 30);
        } else {
            len = cread(c, resp, sizeof resp, 5);
            if (len == 0 && !got_eof) {
                now += H.rx_timeout_ms;
                len = cread(c, resp, sizeof resp, 30);
            }
        }
        if (len == 0) {
            silent++;
        } else if (!parse_resp(resp, len, &r) || got_eof != 1 || r.clen != r.body_len) {
            bad_resp++;
            printf("  iter %d: malformed answer (%d bytes, eof %d, kind %d)\n%.60s\n", iter, len, got_eof, kind, resp);
        } else {
            static const int known[10] = { 200, 303, 400, 401, 403, 404, 405, 408, 411, 413 };
            int k;
            for (k = 0; k < 10 && known[k] != r.code; k++) ;
            if (k < 10) codes[k]++;
            else if (r.code != 415 && r.code != 431) { bad_resp++; printf("  iter %d: code %d\n", iter, r.code); }
            /* the config changes with a 303 and a callback, and only then */
            /* (a 303 is also how a browser is sent to another page) */
            {
                int saved = r.code == 303 && strstr(resp, "\r\nLocation: /settings?saved=1\r\n") != NULL;
                if (saved != (sv.calls == calls + 1)) unsaved++;
                if (!saved && memcmp(&C, &last, sizeof C) != 0) unsaved++;
                if (saved && memcmp(&C, &sv.got, sizeof C) != 0) unsaved++;
            }
        }
        if (len == 0 && (sv.calls != calls || memcmp(&C, &last, sizeof C) != 0)) unsaved++;
        if (cfg_validate(&C, NULL, 0) != CFG_OK) invalid++;
        if (strstr(resp, "TOPSECRET") != NULL) bad_resp++;
        close(c);
        step(2);
        if (httpd_active(&H) != 0) { leaked++; printf("  iter %d: slot not freed\n", iter); break; }
        if (bad_resp || invalid || unsaved) { printf("  iter %d kind %d\n", iter, kind); break; }
    }
    CHECK_EQ_I(iter, 4000);
    CHECK_EQ_I(bad_resp, 0);
    CHECK_EQ_I(leaked, 0);
    CHECK_EQ_I(invalid, 0);
    CHECK_EQ_I(unsaved, 0);
    printf("  settings fuzz: 200=%d 303=%d 400=%d 401=%d 403=%d 404=%d 405=%d 408=%d 411=%d 413=%d silent=%d\n",
           codes[0], codes[1], codes[2], codes[3], codes[4], codes[5], codes[6], codes[7], codes[8],
           codes[9], silent);
    CHECK(codes[0] > 0 && codes[1] > 0 && codes[2] > 0 && codes[3] > 0 && codes[4] > 0 &&
          codes[7] > 0 && silent > 0);
    C = before;
}

/* The VPN profile of the Dreamcast page: posted as plain text to
 * /dreamcast/vpn, checked (vpn.h), handed to whoever keeps it. */
static char vpn_got[VPN_PROFILE_MAX + 1]; static size_t vpn_len; static int vpn_calls, vpn_fail;
static int on_vpn(void *ctx, const char *t, size_t n)
{
    (void)ctx; vpn_calls++;
    vpn_len = n; memcpy(vpn_got, t, n); vpn_got[n] = 0;
    return vpn_fail ? -1 : 0;
}
static int vpn_post(const char *ctype, const char *body, char *out, size_t cap)
{
    static char req[20000];
    int n = snprintf(req, sizeof req, "POST /dreamcast/vpn HTTP/1.0\r\nHost: 192.168.1.2\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n%s",
                     ctype, (unsigned)strlen(body), body);
    return exchange_n(req, (size_t)n, out, cap);
}
/* the BBS page: what to dial, and the boards the daemon knows */
static char bbs_q[40]; static int bbs_skip, bbs_max, bbs_total = 3;
static size_t bbs_rows(void *ctx, const char *q, int skip, int max, char *buf, size_t cap, int *shown, int *left)
{
    static const char rows[] = "<tr><td>Telehack</td><td><code>telehack</code></td><td>227 835 3422</td></tr>\n";
    (void)ctx;
    snprintf(bbs_q, sizeof bbs_q, "%s", q); bbs_skip = skip; bbs_max = max;
    if (cap < sizeof rows || skip >= bbs_total) { *shown = 0; *left = 0; return 0; }
    memcpy(buf, rows, sizeof rows - 1); *shown = 1; *left = bbs_total - skip - 1;
    return sizeof rows - 1;
}
static void test_bbs_page(void)
{
    resp_t r; int len;
    fixture();
    len = exchange("GET /bbs HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<h2>Bulletin boards</h2>") != NULL);
    CHECK(strstr(resp, "1 800 227 3425") != NULL && strstr(resp, "1 800 BBS DIAL") != NULL);
    CHECK(strstr(resp, "227 835 3422") != NULL);                    /* the example of a board's own number */
    CHECK(strstr(resp, "host:port") == NULL);
    CHECK(strstr(resp, "<a href=\"/bbs\">BBS</a>") == NULL);       /* the active tab is no link */
    CHECK(strstr(resp, "The list of boards is not there.") != NULL); /* nobody gives rows here */
    CHECK(strstr(resp, "</html>") != NULL);
    httpd_on_bbs(&H, bbs_rows, NULL);
    len = exchange("GET /bbs HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<th>Board</th><th>Name at the prompt</th><th>Number</th>") != NULL);
    CHECK(strstr(resp, "<td><code>telehack</code></td>") != NULL);
    CHECK(strstr(resp, "</html>") != NULL);
    /* pages of STATUS_BBS_PAGE boards and a search, all in the address: no script */
    CHECK_EQ_I(bbs_skip, 0); CHECK_EQ_I(bbs_max, STATUS_BBS_PAGE); CHECK(strcmp(bbs_q, "") == 0);
    CHECK(strstr(resp, "<form method=\"get\" action=\"/bbs\">") != NULL);
    CHECK(strstr(resp, "<input type=\"text\" name=\"q\" size=\"24\" maxlength=\"32\" value=\"\">") != NULL);
    CHECK(strstr(resp, "Boards 1 to 1 of 3") != NULL);
    CHECK(strstr(resp, "<a href=\"/bbs?p=2\">Next</a>") != NULL);
    CHECK(strstr(resp, ">Previous</a>") == NULL);
    bbs_total = 250;
    len = exchange("GET /bbs?p=2 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK_EQ_I(bbs_skip, STATUS_BBS_PAGE);
    CHECK(strstr(resp, "Boards 101 to 101 of 250") != NULL);
    CHECK(strstr(resp, "<a href=\"/bbs?p=1\">Previous</a>") != NULL);
    CHECK(strstr(resp, "<a href=\"/bbs?p=3\">Next</a>") != NULL);
    /* a search is letters and digits, as at the prompt; the rest never reaches the page */
    len = exchange("GET /bbs?q=Tele+Hack%3Cb%3E&p=2 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strcmp(bbs_q, "telehackb") == 0); CHECK_EQ_I(bbs_skip, STATUS_BBS_PAGE);
    CHECK(strstr(resp, "name=\"q\" size=\"24\" maxlength=\"32\" value=\"telehackb\">") != NULL);
    CHECK(strstr(resp, "<a href=\"/bbs?p=3&amp;q=telehackb\">Next</a>") != NULL);
    CHECK(strstr(resp, "<a href=\"/bbs\">All boards</a>") != NULL);
    CHECK(strstr(resp, "<b>") == NULL || strstr(resp, "Hack<b>") == NULL);
    /* a page past the end, nonsense for a page */
    bbs_total = 3;
    len = exchange("GET /bbs?p=9 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<td colspan=\"3\">none</td>") != NULL);
    CHECK(strstr(resp, "<a href=\"/bbs?p=8\">Previous</a>") != NULL); CHECK(strstr(resp, ">Next</a>") == NULL);
    len = exchange("GET /bbs?p=-4&q= HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200); CHECK_EQ_I(bbs_skip, 0);
    len = exchange("GET /bbs?p=99999999999 HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200); CHECK(bbs_skip >= 0);
    CHECK_EQ_I(code_of("POST /bbs HTTP/1.0\r\nContent-Length: 0\r\n\r\n"), 405);
    /* the tab is on the other pages */
    len = exchange("GET / HTTP/1.0\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "<a href=\"/bbs\">BBS</a>") != NULL);
    httpd_on_bbs(&H, NULL, NULL);
}

static void test_vpn_profile(void)
{
    resp_t r; int len; static char big[VPN_PROFILE_MAX + 600]; size_t i;

    fixture();
    C.service = CFG_SERVICE_DREAMCAST;
    vpn_calls = 0; vpn_fail = 0;
    /* nobody keeps profiles here: refused */
    len = vpn_post("text/plain", "profile=client\r\nremote a 1\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 403);
    httpd_on_vpn(&H, on_vpn, NULL);
    /* the page: a form for it, and what is known about the stored one */
    settings_set_vpn(NULL);
    len = exchange("GET /dreamcast HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 200);
    CHECK(strstr(resp, "<form method=\"post\" action=\"/dreamcast/vpn\" enctype=\"text/plain\">") != NULL);
    CHECK(strstr(resp, "<textarea name=\"profile\"") != NULL);
    CHECK(strstr(resp, "No profile is stored.") != NULL);
    /* a good one */
    len = vpn_post("text/plain", "profile=client\r\nremote vpn.example 1194\r\n<ca>\r\nabc\r\n</ca>\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 303);
    CHECK(strstr(resp, "Location: /dreamcast?saved=1\r\n") != NULL);
    CHECK_EQ_I(vpn_calls, 1);
    CHECK(strcmp(vpn_got, "client\r\nremote vpn.example 1194\r\n<ca>\r\nabc\r\n</ca>\n") == 0);   /* one line end at the end */
    len = exchange("GET /dreamcast HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "A profile is stored (server vpn.example 1194).") != NULL);
    CHECK(strstr(resp, "abc") == NULL);                     /* never shown again */
    /* one that is not let through: said why, nothing kept */
    len = vpn_post("text/plain; charset=UTF-8", "profile=client\r\nremote a 1\r\nup /bin/sh\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 400);
    CHECK(strstr(resp, "<b>Not saved:</b> line 3: &#39;up&#39; is not allowed in a profile here") != NULL ||
          strstr(resp, "<b>Not saved:</b> line 3: 'up' is not allowed in a profile here") != NULL);
    CHECK_EQ_I(vpn_calls, 1);
    /* taking it away */
    len = vpn_post("text/plain", "remove=1\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 303);
    CHECK_EQ_I(vpn_calls, 2); CHECK_EQ_I(vpn_len, 0);
    len = exchange("GET /dreamcast HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n", resp, sizeof resp);
    CHECK(strstr(resp, "No profile is stored.") != NULL);
    /* the keeper fails */
    vpn_fail = 1;
    len = vpn_post("text/plain", "profile=remote a 1\r\n\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 500);
    vpn_fail = 0;
    /* other shapes */
    len = vpn_post("application/x-www-form-urlencoded", "profile=remote+a+1", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 415);
    len = vpn_post("text/plain", "something=else\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 400);
    memcpy(big, "profile=", 8);
    for (i = 8; i < sizeof big - 1; i++) big[i] = i % 50 == 49 ? '\n' : '#';
    big[sizeof big - 1] = 0;
    len = vpn_post("text/plain", big, resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code == 413);
    CHECK_EQ_I(code_of("GET /dreamcast/vpn HTTP/1.0\r\nHost: 192.168.1.2\r\n\r\n"), 405);
    /* from another site's page: no */
    {
        static const char x[] = "POST /dreamcast/vpn HTTP/1.0\r\nHost: 192.168.1.2\r\nOrigin: http://evil.example\r\n"
                                "Content-Type: text/plain\r\nContent-Length: 12\r\n\r\nremove=1\r\n\r\n";
        len = exchange(x, resp, sizeof resp);
        CHECK(parse_resp(resp, len, &r) && r.code == 403);
    }
    /* behind the login like every setting */
    strcpy(C.admin_password, "pw");
    len = vpn_post("text/plain", "remove=1\r\n", resp, sizeof resp);
    CHECK(parse_resp(resp, len, &r) && r.code != 303 && r.code != 200);
    CHECK_EQ_I(vpn_calls, 3);
    settings_set_vpn(NULL);
}

int main(void)
{
    int fds = count_fds();
    fixture();
    test_views();
    test_refusals();
    test_truncated();
    test_timeouts();
    test_oversized();
    test_pipelined();
    test_table();
    test_slow_reader();
    test_worst_case();
    test_fuzz();
    test_settings_page();
    test_settings_post();
    test_settings_size();
    test_settings_body();
    test_settings_origin();
    test_settings_auth();
    test_login();
    test_restart();
    test_firmware();
    test_pages();
    test_two_ports();
    test_bbs_page();
    test_vpn_profile();
    test_settings_fuzz();
    httpd_close(&H);
    CHECK_EQ_I(httpd_active(&H), 0);
    CHECK_EQ_I(count_fds(), fds);               /* no descriptor leaked anywhere */
    CHECK(now < 0x80000000u);                   /* the clock did wrap on the way */
    T_REPORT("test_httpd");
}
