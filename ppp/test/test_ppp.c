/* Session-level unit test: the server is driven with hand-built frames and
 * its replies are checked octet by octet. (The end-to-end run against a
 * full client peer is in test_e2e.c.) */
#include <string.h>
#include "test.h"
#include "ppp.h"
#include "ppp_md5.h"

#define OUR_IP   PPP_IP4(10, 0, 0, 1)
#define PEER_IP  PPP_IP4(10, 0, 0, 2)
#define DNS1     PPP_IP4(192, 168, 1, 53)
#define DNS2     PPP_IP4(9, 9, 9, 9)

static ppp_t S;

/* ---- capture of what the server transmits ---- */
typedef struct {
    uint16_t proto;
    size_t   n;            /* information field length */
    size_t   hdr;          /* header octets on the wire (4 = uncompressed) */
    uint8_t  d[1600];
} frame_t;
#define MAXF 12
static frame_t out[MAXF];
static int n_out;
static ppp_hdlc_rx_t dec;
static uint8_t wire[PPP_TX_BUF];
static size_t wire_n;

static void pull(void)
{
    n_out = 0;
    wire_n = ppp_output_bytes(&S, wire, sizeof wire);
    for (size_t i = 0; i < wire_n; i++) {
        if (ppp_hdlc_rx_byte(&dec, wire[i]) && n_out < MAXF) {
            frame_t *f = &out[n_out];
            size_t off;
            if (ppp_hdlc_parse(dec.buf, dec.len, 1, 1, &f->proto, &off) == 0) {
                f->hdr = off;
                f->n = dec.len - off;
                memcpy(f->d, dec.buf + off, f->n);
                n_out++;
            }
        }
    }
}

/* first captured frame with this protocol and (for control protocols)
 * code; code 0 matches anything */
static frame_t *find(uint16_t proto, uint8_t code)
{
    for (int i = 0; i < n_out; i++)
        if (out[i].proto == proto && (code == 0 || out[i].d[0] == code))
            return &out[i];
    return NULL;
}

/* ---- injection ---- */
static void push_raw(const uint8_t *hdr, size_t hn, const uint8_t *d, size_t n, uint32_t accm)
{
    static uint8_t w[3200];
    size_t k = ppp_hdlc_encode(w, sizeof w, hdr, hn, d, n, accm, 1);
    ppp_input_bytes(&S, w, k);
}

static void push(uint16_t proto, const uint8_t *d, size_t n)
{
    uint8_t h[4] = { 0xff, 0x03, (uint8_t)(proto >> 8), (uint8_t)proto };
    push_raw(h, 4, d, n, 0xffffffffu);
}

static void push_cp(uint16_t proto, uint8_t code, uint8_t id, const uint8_t *d, size_t n)
{
    uint8_t p[1600];
    p[0] = code; p[1] = id; p[2] = (uint8_t)((n + 4) >> 8); p[3] = (uint8_t)(n + 4);
    if (n) memcpy(p + 4, d, n);
    push(proto, p, n + 4);
}

/* ---- callbacks ---- */
static uint8_t ip_got[1600];
static size_t ip_len;
static int ip_count;
static void on_ip(void *ctx, const uint8_t *pkt, size_t len)
{
    (void)ctx;
    ip_count++;
    ip_len = len;
    memcpy(ip_got, pkt, len);
}
static ppp_phase_t phases[32];
static int n_phases;
static void on_phase(void *ctx, ppp_phase_t ph)
{
    (void)ctx;
    if (n_phases < 32) phases[n_phases++] = ph;
}

static const ppp_user_t users[] = { { "alice", "wonderland" }, { "bob", "s3cret~}" } };

static void base_cfg(ppp_config_t *c)
{
    ppp_config_default(c);
    c->auth = PPP_AUTH_CHAP | PPP_AUTH_PAP;
    c->users = users;
    c->n_users = 2;
    c->our_ip = OUR_IP;
    c->peer_ip = PEER_IP;
    c->dns1 = DNS1;
    c->dns2 = DNS2;
    c->seed = 0x1234abcd;
    c->ip_rx = on_ip;
    c->phase_cb = on_phase;
}

static void start(const ppp_config_t *c)
{
    ppp_init(&S, c);
    ppp_hdlc_rx_init(&dec, PPP_HDLC_BUF);
    dec.rx_accm = 0;
    n_phases = 0;
    ip_count = 0;
    ppp_lower_up(&S);
}

static ppp_status_t st;
static ppp_status_t *status(void)
{
    ppp_get_status(&S, &st);
    return &st;
}

/* option value lookup in a control packet (d starts at the code octet) */
static const uint8_t *opt(const frame_t *f, uint8_t type, size_t *vlen)
{
    size_t pos = 0;
    uint8_t t;
    const uint8_t *v;
    while (ppp_fsm_next_option(f->d + 4, f->n - 4, &pos, &t, &v, vlen))
        if (t == type) return v;
    return NULL;
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Complete LCP by hand: Ack the server's request, send ours. Returns the
 * magic number the server chose. */
static uint32_t lcp_up(const uint8_t *peer_opts, size_t n)
{
    frame_t *cr;
    uint32_t magic = 0;
    size_t vl;
    const uint8_t *v;

    pull();
    cr = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    CHECK(cr != NULL);
    if (!cr) return 0;
    v = opt(cr, 5, &vl);
    if (v) magic = be32(v);
    push_cp(PPP_PROTO_LCP, PPP_CONF_ACK, cr->d[1], cr->d + 4, cr->n - 4);
    push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 1, peer_opts, n);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_CONF_ACK) != NULL);
    return magic;
}

static const uint8_t peer_lcp[] = { 5, 6, 0x11, 0x22, 0x33, 0x44 };

static void chap_answer(const frame_t *ch, const char *user, const char *secret)
{
    ppp_md5_t m;
    uint8_t rsp[100];
    size_t ul = strlen(user);

    rsp[0] = 16;
    ppp_md5_init(&m);
    ppp_md5_update(&m, &ch->d[1], 1);
    ppp_md5_update(&m, (const uint8_t *)secret, strlen(secret));
    ppp_md5_update(&m, ch->d + 5, ch->d[4]);
    ppp_md5_final(&m, rsp + 1);
    memcpy(rsp + 17, user, ul);
    push_cp(PPP_PROTO_CHAP, 2, ch->d[1], rsp, 17 + ul);
}

/* an MS-CHAPv2 Response to the server's Challenge ch (RFC 2759): a fixed
 * peer challenge, then the NT-Response over the server's authenticator
 * challenge, then the user name */
static void mschap2_answer(const frame_t *ch, const char *user, const char *secret)
{
    static const uint8_t peer[16] = { 0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
                                      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    uint8_t rsp[1 + 49 + 64];
    size_t ul = strlen(user);

    rsp[0] = 49;
    memcpy(rsp + 1, peer, 16);
    memset(rsp + 1 + 16, 0, 8);
    ppp_mschap2_nt_response(ch->d + 5, peer, (const uint8_t *)user, ul,
                            (const uint8_t *)secret, strlen(secret), rsp + 1 + 24);
    rsp[1 + 48] = 0;
    memcpy(rsp + 50, user, ul);
    push_cp(PPP_PROTO_CHAP, 2, ch->d[1], rsp, 50 + ul);
}

/* bring the link to the Network phase with CHAP as alice */
static uint32_t to_network(const uint8_t *peer_opts, size_t n)
{
    uint32_t magic = lcp_up(peer_opts, n);
    frame_t *ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch != NULL);
    if (ch) chap_answer(ch, "alice", "wonderland");
    pull();
    CHECK(find(PPP_PROTO_CHAP, 3) != NULL);
    CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    return magic;
}

/* finish IPCP by hand (after to_network; the pending output still holds
 * the server's IPCP request) */
static void ipcp_up(void)
{
    frame_t *cr = find(PPP_PROTO_IPCP, PPP_CONF_REQ);
    const uint8_t mine[] = { 3, 6, 10, 0, 0, 2 };
    CHECK(cr != NULL);
    if (!cr) return;
    push_cp(PPP_PROTO_IPCP, PPP_CONF_ACK, cr->d[1], cr->d + 4, cr->n - 4);
    push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 1, mine, sizeof mine);
    pull();
    CHECK(find(PPP_PROTO_IPCP, PPP_CONF_ACK) != NULL);
    CHECK_EQ_I(status()->ip_up, 1);
}

/* ------------------------------------------------------------------ */

static void test_first_request(void)
{
    ppp_config_t c;
    frame_t *cr;
    size_t i;

    base_cfg(&c);
    ppp_init(&S, &c);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK_EQ_I(ppp_output_pending(&S), 0);
    /* input before carrier is ignored */
    push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 1, peer_lcp, sizeof peer_lcp);
    CHECK_EQ_I(ppp_output_pending(&S), 0);

    start(&c);
    CHECK_EQ_I(status()->phase, PPP_PHASE_ESTABLISH);
    CHECK(ppp_output_pending(&S) > 0);
    pull();
    CHECK_EQ_I(ppp_output_pending(&S), 0);
    CHECK_EQ_I(n_out, 1);
    cr = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    CHECK(cr != NULL);
    if (cr) {
        /* ACCM 0, CHAP with MD5, Magic-Number, PFC, ACFC */
        const uint8_t a[] = { 2, 6, 0, 0, 0, 0, 3, 5, 0xc2, 0x23, 5, 5, 6 };
        const uint8_t b[] = { 7, 2, 8, 2 };
        CHECK_EQ_I(cr->n, 4 + 13 + 4 + 4);
        CHECK_EQ_I((cr->d[2] << 8) | cr->d[3], cr->n);
        CHECK(memcmp(cr->d + 4, a, 13) == 0);
        CHECK(be32(cr->d + 17) != 0);
        CHECK(memcmp(cr->d + 21, b, 4) == 0);
        CHECK_EQ_I(cr->hdr, 4);
    }
    /* LCP goes out with every control character escaped: none on the wire */
    CHECK_EQ_I(wire[0], 0x7e);
    CHECK_EQ_I(wire[wire_n - 1], 0x7e);
    for (i = 0; i < wire_n; i++)
        CHECK(wire[i] >= 0x20);

    /* a non-default MRU is requested, first */
    c.mru = 1400;
    c.auth = PPP_AUTH_NONE;
    c.no_pfc = c.no_acfc = 1;
    start(&c);
    pull();
    cr = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    CHECK(cr != NULL);
    if (cr) {
        const uint8_t a[] = { 1, 4, 0x05, 0x78, 2, 6, 0, 0, 0, 0, 5, 6 };
        CHECK_EQ_I(cr->n, 4 + 12 + 4);
        CHECK(memcmp(cr->d + 4, a, 12) == 0);
    }
}

static void test_peer_request(void)
{
    ppp_config_t c;
    frame_t *f;
    uint32_t magic;
    size_t vl;

    base_cfg(&c);
    start(&c);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    magic = f ? be32(opt(f, 5, &vl)) : 0;

    /* everything acceptable: Ack with identical options and identifier */
    {
        const uint8_t o[] = { 1, 4, 0x05, 0xdc, 2, 6, 0, 0, 0, 0,
                              5, 6, 1, 2, 3, 4, 7, 2, 8, 2 };
        push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 0x21, o, sizeof o);
        pull();
        CHECK_EQ_I(n_out, 1);
        f = find(PPP_PROTO_LCP, PPP_CONF_ACK);
        CHECK(f && f->d[1] == 0x21 && f->n == 4 + sizeof o && memcmp(f->d + 4, o, sizeof o) == 0);
    }
    /* unknown options (callback 0x0d, MRRU 0x11) and Quality-Protocol and
     * an Authentication-Protocol request aimed at us: Configure-Reject
     * listing exactly those, in order */
    {
        const uint8_t o[] = { 1, 4, 0x05, 0xdc, 0x0d, 3, 6, 5, 6, 1, 2, 3, 4,
                              0x11, 4, 0x05, 0xdc, 3, 4, 0xc0, 0x23,
                              4, 8, 0xc0, 0x25, 0, 0, 0, 0 };
        const uint8_t want[] = { 0x0d, 3, 6, 0x11, 4, 0x05, 0xdc, 3, 4, 0xc0, 0x23,
                                 4, 8, 0xc0, 0x25, 0, 0, 0, 0 };
        push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 0x22, o, sizeof o);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CONF_REJ);
        CHECK(f && f->d[1] == 0x22 && f->n == 4 + sizeof want &&
              memcmp(f->d + 4, want, sizeof want) == 0);
    }
    /* unacceptable values: Nak carrying only those options, with values
     * we would take. MRU below the minimum, Magic-Number zero. */
    {
        const uint8_t o[] = { 1, 4, 0, 20, 2, 6, 0, 0, 0, 0, 5, 6, 0, 0, 0, 0 };
        push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 0x23, o, sizeof o);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CONF_NAK);
        CHECK(f != NULL);
        if (f) {
            const uint8_t mru[] = { 1, 4, 0x05, 0xdc, 5, 6 };
            CHECK_EQ_I(f->d[1], 0x23);
            CHECK_EQ_I(f->n, 4 + 4 + 6);
            CHECK(memcmp(f->d + 4, mru, 6) == 0);
            CHECK(be32(f->d + 10) != 0 && be32(f->d + 10) != magic);
        }
    }
    /* something to Nak and something to Reject: the Reject goes first,
     * alone (RFC 1661 5.4) */
    {
        const uint8_t o[] = { 1, 4, 0, 20, 0x0d, 3, 6 };
        const uint8_t want[] = { 0x0d, 3, 6 };
        push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 0x24, o, sizeof o);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CONF_REJ);
        CHECK(f && f->n == 4 + sizeof want && memcmp(f->d + 4, want, sizeof want) == 0);
        CHECK(find(PPP_PROTO_LCP, PPP_CONF_NAK) == NULL);
    }
    /* our own magic number coming back: Nak with a different one */
    {
        uint8_t o[] = { 5, 6, 0, 0, 0, 0 };
        o[2] = (uint8_t)(magic >> 24); o[3] = (uint8_t)(magic >> 16);
        o[4] = (uint8_t)(magic >> 8);  o[5] = (uint8_t)magic;
        push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 0x25, o, sizeof o);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CONF_NAK);
        CHECK(f && f->n == 10 && f->d[4] == 5 && be32(f->d + 6) != magic);
    }
    /* non-LCP traffic during Establish is silently discarded */
    {
        const uint8_t o[] = { 3, 6, 0, 0, 0, 0 };
        uint32_t before = status()->counters.rx_discards;
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 1, o, sizeof o);
        push(0x8057, o, sizeof o);
        pull();
        CHECK_EQ_I(n_out, 0);
        CHECK_EQ_I(status()->counters.rx_discards, before + 2);
    }
    /* Max-Failure: after 5 Naks the next unacceptable value is Rejected */
    {
        const uint8_t o[] = { 1, 4, 0, 20 };
        int i, naks = 0, rejs = 0;
        base_cfg(&c);
        start(&c);
        pull();
        for (i = 0; i < 7; i++) {
            push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, (uint8_t)i, o, sizeof o);
            pull();
            if (find(PPP_PROTO_LCP, PPP_CONF_NAK)) naks++;
            f = find(PPP_PROTO_LCP, PPP_CONF_REJ);
            if (f) { rejs++; CHECK(f->n == 8 && memcmp(f->d + 4, o, 4) == 0); }
        }
        CHECK_EQ_I(naks, 5);
        CHECK_EQ_I(rejs, 2);
    }
}

static void test_auth_negotiation(void)
{
    ppp_config_t c;
    frame_t *f;
    size_t vl;
    const uint8_t *v;
    const uint8_t nak_pap[] = { 3, 4, 0xc0, 0x23 };
    const uint8_t nak_mschap[] = { 3, 5, 0xc2, 0x23, 0x80 };
    const uint8_t rej_chap[] = { 3, 5, 0xc2, 0x23, 5 };

    /* CHAP preferred; peer Naks asking for PAP; we fall back */
    base_cfg(&c);
    start(&c);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    push_cp(PPP_PROTO_LCP, PPP_CONF_NAK, f->d[1], nak_pap, sizeof nak_pap);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    CHECK(f != NULL);
    v = f ? opt(f, 3, &vl) : NULL;
    CHECK(v && vl == 2 && v[0] == 0xc0 && v[1] == 0x23);

    /* peer Naks with an algorithm we do not have (MS-CHAP): try PAP */
    start(&c);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    push_cp(PPP_PROTO_LCP, PPP_CONF_NAK, f->d[1], nak_mschap, sizeof nak_mschap);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    v = f ? opt(f, 3, &vl) : NULL;
    CHECK(v && vl == 2 && v[0] == 0xc0 && v[1] == 0x23);
    /* ... and if it Naks PAP too, nothing is left: terminate */
    push_cp(PPP_PROTO_LCP, PPP_CONF_NAK, f->d[1], nak_mschap, sizeof nak_mschap);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_REFUSED);

    /* CHAP only: a Nak for PAP cannot be honoured */
    c.auth = PPP_AUTH_CHAP;
    start(&c);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    push_cp(PPP_PROTO_LCP, PPP_CONF_NAK, f->d[1], nak_pap, sizeof nak_pap);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_REFUSED);

    /* PAP only: request PAP; peer may Nak towards CHAP in vain */
    c.auth = PPP_AUTH_PAP;
    start(&c);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    v = f ? opt(f, 3, &vl) : NULL;
    CHECK(v && vl == 2 && v[0] == 0xc0 && v[1] == 0x23);

    /* authentication is mandatory: a Configure-Reject of it ends the link */
    base_cfg(&c);
    start(&c);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
    push_cp(PPP_PROTO_LCP, PPP_CONF_REJ, f->d[1], rej_chap, sizeof rej_chap);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_REFUSED);
    /* Terminate-Ack completes it; the phase callback saw Dead last */
    f = find(PPP_PROTO_LCP, PPP_TERM_REQ);
    push_cp(PPP_PROTO_LCP, PPP_TERM_ACK, f->d[1], NULL, 0);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK(n_phases >= 2 && phases[n_phases - 1] == PPP_PHASE_DEAD);

    /* Reject of the optional options: they are dropped from the request */
    {
        const uint8_t rej[] = { 2, 6, 0, 0, 0, 0, 5, 6, 0, 0, 0, 0, 7, 2, 8, 2 };
        uint8_t r[sizeof rej];
        base_cfg(&c);
        start(&c);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
        memcpy(r, rej, sizeof rej);
        memcpy(r + 8, opt(f, 5, &vl), 4);
        push_cp(PPP_PROTO_LCP, PPP_CONF_REJ, f->d[1], r, sizeof r);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CONF_REQ);
        CHECK(f && f->n == 4 + 5 && f->d[4] == 3);
    }
}

static void test_chap(void)
{
    ppp_config_t c;
    frame_t *ch, *f;
    uint8_t chal1[16];

    base_cfg(&c);
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    CHECK_EQ_I(status()->auth, PPP_AUTH_CHAP);
    ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch != NULL);
    if (!ch) return;
    /* Challenge: 16-octet value, then our name */
    CHECK_EQ_I(ch->d[4], 16);
    CHECK_EQ_I(ch->n, 4 + 1 + 16 + 4);
    CHECK(memcmp(ch->d + 21, "v90d", 4) == 0);
    memcpy(chal1, ch->d + 5, 16);

    /* IPCP is not accepted before authentication completes */
    {
        const uint8_t o[] = { 3, 6, 0, 0, 0, 0 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 1, o, sizeof o);
        pull();
        CHECK_EQ_I(n_out, 0);
    }
    /* a Response with the wrong identifier is ignored */
    {
        frame_t bad = *ch;
        bad.d[1] ^= 0x55;
        chap_answer(&bad, "alice", "wonderland");
        pull();
        CHECK_EQ_I(n_out, 0);
        CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    }
    chap_answer(ch, "alice", "wonderland");
    pull();
    f = find(PPP_PROTO_CHAP, 3);
    CHECK(f && f->d[1] == ch->d[1]);
    CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    CHECK_EQ_I(status()->authenticated, 1);
    CHECK(strcmp(status()->peer_name, "alice") == 0);
    /* IPCP starts: our request announces our address */
    f = find(PPP_PROTO_IPCP, PPP_CONF_REQ);
    {
        const uint8_t want[] = { 3, 6, 10, 0, 0, 1 };
        CHECK(f && f->n == 10 && memcmp(f->d + 4, want, 6) == 0);
    }
    /* a repeated Response gets the same Success again (RFC 1994 4.1) */
    chap_answer(ch, "alice", "wonderland");
    pull();
    CHECK(find(PPP_PROTO_CHAP, 3) != NULL);

    /* wrong secret: Failure, then the link is terminated. This is a new
     * call on the same session object (carrier cycled, no re-init). */
    ppp_lower_down(&S);
    ppp_lower_up(&S);
    lcp_up(peer_lcp, sizeof peer_lcp);
    ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch != NULL);
    if (!ch) return;
    /* a new call gets a new challenge value */
    CHECK(memcmp(chal1, ch->d + 5, 16) != 0);
    chap_answer(ch, "alice", "Wonderland");
    pull();
    CHECK(find(PPP_PROTO_CHAP, 4) != NULL);
    CHECK(find(PPP_PROTO_CHAP, 3) == NULL);
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_FAILED);
    CHECK_EQ_I(status()->authenticated, 0);

    /* unknown user: same outcome */
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    ch = find(PPP_PROTO_CHAP, 1);
    if (ch) chap_answer(ch, "mallory", "wonderland");
    pull();
    CHECK(find(PPP_PROTO_CHAP, 4) != NULL);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_FAILED);

    /* no Response at all: the Challenge is retransmitted on the restart
     * timer, then the link is closed */
    c.restart_ms = 1000;
    c.max_configure = 3;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch != NULL);
    if (ch) memcpy(chal1, ch->d + 5, 16);
    ppp_tick(&S, 1000);
    pull();
    ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch && memcmp(chal1, ch->d + 5, 16) == 0);
    ppp_tick(&S, 1000);
    pull();
    CHECK(find(PPP_PROTO_CHAP, 1) != NULL);
    ppp_tick(&S, 1000);
    pull();
    CHECK(find(PPP_PROTO_CHAP, 1) == NULL);
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_TIMEOUT);
}

static void test_mschap2(void)
{
    ppp_config_t c;
    frame_t *ch, *f;

    base_cfg(&c);
    c.auth = PPP_AUTH_MSCHAPV2;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    CHECK_EQ_I(status()->auth, PPP_AUTH_MSCHAPV2);
    /* the challenge is a 16-octet value then our name, as for CHAP-MD5 */
    ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch != NULL);
    if (!ch) return;
    CHECK_EQ_I(ch->d[4], 16);

    /* good credentials: authenticated, and Success carries "S=..." */
    mschap2_answer(ch, "alice", "wonderland");
    pull();
    f = find(PPP_PROTO_CHAP, 3);
    CHECK(f != NULL);
    CHECK(f && f->n >= 4 + 42 && f->d[4] == 'S' && f->d[5] == '=');
    CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    CHECK_EQ_I(status()->authenticated, 1);
    CHECK(strcmp(status()->peer_name, "alice") == 0);
    /* MPPE master keys were derived from the exchange */
    CHECK_EQ_I(S.mppe_have, 1);

    /* a repeated Response gets the same Success */
    mschap2_answer(ch, "alice", "wonderland");
    pull();
    CHECK(find(PPP_PROTO_CHAP, 3) != NULL);

    /* wrong secret: Failure "E=...", link terminated */
    ppp_lower_down(&S);
    ppp_lower_up(&S);
    lcp_up(peer_lcp, sizeof peer_lcp);
    ch = find(PPP_PROTO_CHAP, 1);
    CHECK(ch != NULL);
    if (!ch) return;
    mschap2_answer(ch, "alice", "Wonderland");
    pull();
    f = find(PPP_PROTO_CHAP, 4);
    CHECK(f && f->d[4] == 'E' && f->d[5] == '=');
    CHECK(find(PPP_PROTO_CHAP, 3) == NULL);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_FAILED);
    CHECK_EQ_I(status()->authenticated, 0);
}

static void pap_request(uint8_t id, const char *user, const char *pass)
{
    uint8_t d[200];
    size_t ul = strlen(user), pl = strlen(pass);
    d[0] = (uint8_t)ul;
    memcpy(d + 1, user, ul);
    d[1 + ul] = (uint8_t)pl;
    memcpy(d + 2 + ul, pass, pl);
    push_cp(PPP_PROTO_PAP, 1, id, d, 2 + ul + pl);
}

static int my_pap_calls;
static int my_pap(void *ctx, const uint8_t *u, size_t ul, const uint8_t *p, size_t pl)
{
    (void)ctx;
    my_pap_calls++;
    return ul == 3 && memcmp(u, "eve", 3) == 0 && pl == 4 && memcmp(p, "open", 4) == 0;
}
static int my_secret(void *ctx, const uint8_t *u, size_t ul, uint8_t *s, size_t max)
{
    (void)ctx; (void)max;
    if (ul == 5 && memcmp(u, "carol", 5) == 0) { memcpy(s, "xyzzy", 5); return 5; }
    return -1;
}

static void test_pap(void)
{
    ppp_config_t c;
    frame_t *f;

    base_cfg(&c);
    c.auth = PPP_AUTH_PAP;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    CHECK_EQ_I(status()->auth, PPP_AUTH_PAP);
    CHECK_EQ_I(n_out, 1);                 /* just the LCP Ack: PAP waits */
    pap_request(7, "bob", "s3cret~}");
    pull();
    f = find(PPP_PROTO_PAP, 2);
    CHECK(f && f->d[1] == 7);
    /* Authenticate-Ack carries a message length octet and the message */
    CHECK(f && f->n >= 5 && f->d[4] == f->n - 5);
    CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    CHECK(strcmp(status()->peer_name, "bob") == 0);
    /* the Ack may have been lost: a repeated request is Acked again */
    pap_request(8, "bob", "s3cret~}");
    pull();
    f = find(PPP_PROTO_PAP, 2);
    CHECK(f && f->d[1] == 8);

    /* wrong password */
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    pap_request(1, "bob", "s3cret");
    pull();
    f = find(PPP_PROTO_PAP, 3);
    CHECK(f && f->d[1] == 1);
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_FAILED);

    /* truncated request: ignored, no crash */
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    {
        const uint8_t d[] = { 9, 'b', 'o', 'b' };
        push_cp(PPP_PROTO_PAP, 1, 1, d, sizeof d);
        pull();
        CHECK_EQ_I(n_out, 0);
        CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    }
    /* a CHAP packet when PAP was negotiated is not acted on */
    {
        const uint8_t d[] = { 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'b' };
        push_cp(PPP_PROTO_CHAP, 2, 1, d, sizeof d);
        pull();
        CHECK(find(PPP_PROTO_CHAP, 0) == NULL);
        CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    }
    /* peer never sends a request: timeout */
    ppp_tick(&S, 29999);
    CHECK_EQ_I(status()->phase, PPP_PHASE_AUTHENTICATE);
    ppp_tick(&S, 1);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    CHECK_EQ_I(status()->end_reason, PPP_END_AUTH_TIMEOUT);

    /* caller-supplied checks instead of the static table */
    c.pap_cb = my_pap;
    c.users = NULL; c.n_users = 0;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    pap_request(1, "eve", "open");
    pull();
    CHECK(find(PPP_PROTO_PAP, 2) != NULL);
    CHECK_EQ_I(my_pap_calls, 1);
    c.pap_cb = NULL;
    c.secret_cb = my_secret;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    pap_request(1, "carol", "xyzzy");
    pull();
    CHECK(find(PPP_PROTO_PAP, 2) != NULL);
    c.auth = PPP_AUTH_CHAP;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    f = find(PPP_PROTO_CHAP, 1);
    CHECK(f != NULL);
    if (f) chap_answer(f, "carol", "xyzzy");
    pull();
    CHECK(find(PPP_PROTO_CHAP, 3) != NULL);

    /* no authentication configured: straight to Network */
    base_cfg(&c);
    c.auth = PPP_AUTH_NONE;
    start(&c);
    lcp_up(peer_lcp, sizeof peer_lcp);
    CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    CHECK(find(PPP_PROTO_IPCP, PPP_CONF_REQ) != NULL);
}

static void test_ipcp(void)
{
    ppp_config_t c;
    frame_t *f, *cr;
    uint8_t srv_id;

    base_cfg(&c);
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    cr = find(PPP_PROTO_IPCP, PPP_CONF_REQ);
    CHECK(cr != NULL);
    if (!cr) return;
    srv_id = cr->d[1];
    CHECK_EQ_I(ppp_send_ip(&S, (const uint8_t *)"x", 1), PPP_ERR_DOWN);

    /* IP before IPCP is open: discarded */
    {
        const uint8_t ip[] = { 0x45, 0, 0, 20 };
        push(PPP_PROTO_IP, ip, sizeof ip);
        CHECK_EQ_I(ip_count, 0);
    }
    /* Windows-style request: VJ compression, address 0, both DNS, both
     * NBNS. First answer: Reject of VJ and the NBNS options only. */
    {
        const uint8_t o[] = { 2, 6, 0x00, 0x2d, 0x0f, 0x01, 3, 6, 0, 0, 0, 0,
                              129, 6, 0, 0, 0, 0, 130, 6, 0, 0, 0, 0,
                              131, 6, 0, 0, 0, 0, 132, 6, 0, 0, 0, 0 };
        const uint8_t want[] = { 2, 6, 0x00, 0x2d, 0x0f, 0x01,
                                 130, 6, 0, 0, 0, 0, 132, 6, 0, 0, 0, 0 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 1, o, sizeof o);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_REJ);
        CHECK(f && f->d[1] == 1 && f->n == 4 + sizeof want &&
              memcmp(f->d + 4, want, sizeof want) == 0);
    }
    /* second: Nak assigning the address and giving the DNS servers */
    {
        const uint8_t o[] = { 3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0, 131, 6, 0, 0, 0, 0 };
        const uint8_t want[] = { 3, 6, 10, 0, 0, 2, 129, 6, 192, 168, 1, 53,
                                 131, 6, 9, 9, 9, 9 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 2, o, sizeof o);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_NAK);
        CHECK(f && f->d[1] == 2 && f->n == 4 + sizeof want &&
              memcmp(f->d + 4, want, sizeof want) == 0);
        /* third: the peer asks for exactly that: Ack */
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 3, want, sizeof want);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_ACK);
        CHECK(f && f->d[1] == 3 && f->n == 4 + sizeof want &&
              memcmp(f->d + 4, want, sizeof want) == 0);
    }
    CHECK_EQ_I(status()->ip_up, 0);
    push_cp(PPP_PROTO_IPCP, PPP_CONF_ACK, srv_id, cr->d + 4, cr->n - 4);
    CHECK_EQ_I(status()->ip_up, 1);
    CHECK_EQ_I(status()->ipcp_state, PPP_FSM_OPENED);
    CHECK(status()->our_ip == OUR_IP);
    CHECK(status()->peer_ip == PEER_IP);
    CHECK(status()->dns1 == DNS1 && status()->dns2 == DNS2);

    /* a peer insisting on another address is Nak'd back to ours */
    {
        const uint8_t o[] = { 3, 6, 172, 16, 0, 9 };
        const uint8_t want[] = { 3, 6, 10, 0, 0, 2 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 4, o, sizeof o);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_NAK);
        CHECK(f && f->n == 10 && memcmp(f->d + 4, want, 6) == 0);
        CHECK_EQ_I(status()->ip_up, 0);       /* renegotiating */
    }

    /* request without any address option: Nak appending the option */
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    {
        const uint8_t want[] = { 3, 6, 10, 0, 0, 2 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 1, NULL, 0);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_NAK);
        CHECK(f && f->n == 10 && memcmp(f->d + 4, want, 6) == 0);
    }
    /* deprecated IP-Addresses option (type 1): Reject */
    {
        const uint8_t o[] = { 1, 10, 0, 0, 0, 0, 0, 0, 0, 0 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 2, o, sizeof o);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_REJ);
        CHECK(f && f->n == 14 && memcmp(f->d + 4, o, 10) == 0);
    }

    /* no DNS configured: the DNS options are Rejected; peer_ip 0 accepts
     * whatever nonzero address the peer proposes */
    c.dns1 = c.dns2 = 0;
    c.peer_ip = 0;
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    cr = find(PPP_PROTO_IPCP, PPP_CONF_REQ);
    {
        const uint8_t o[] = { 3, 6, 172, 16, 0, 9, 129, 6, 0, 0, 0, 0 };
        const uint8_t want[] = { 129, 6, 0, 0, 0, 0 };
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 1, o, sizeof o);
        pull();
        f = find(PPP_PROTO_IPCP, PPP_CONF_REJ);
        CHECK(f && f->n == 10 && memcmp(f->d + 4, want, 6) == 0);
        push_cp(PPP_PROTO_IPCP, PPP_CONF_REQ, 2, o, 6);
        pull();
        CHECK(find(PPP_PROTO_IPCP, PPP_CONF_ACK) != NULL);
        if (cr) push_cp(PPP_PROTO_IPCP, PPP_CONF_ACK, cr->d[1], cr->d + 4, cr->n - 4);
        CHECK(status()->peer_ip == PPP_IP4(172, 16, 0, 9));
        CHECK_EQ_I(status()->ip_up, 1);
    }
    /* the peer closes IPCP: we Ack, and since IP is all this link is for,
     * the whole link is then closed */
    push_cp(PPP_PROTO_IPCP, PPP_TERM_REQ, 9, NULL, 0);
    pull();
    f = find(PPP_PROTO_IPCP, PPP_TERM_ACK);
    CHECK(f && f->d[1] == 9);
    CHECK_EQ_I(status()->ip_up, 0);
    ppp_tick(&S, 3000);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->end_reason, PPP_END_IPCP_FAILED);
}

static void test_data_and_lcp_codes(void)
{
    ppp_config_t c;
    frame_t *f;
    uint32_t magic;
    uint8_t pkt[1500];
    size_t i;

    base_cfg(&c);
    start(&c);
    magic = to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();

    /* IP both ways */
    for (i = 0; i < sizeof pkt; i++) pkt[i] = (uint8_t)(i * 13 + 1);
    push(PPP_PROTO_IP, pkt, 1500);
    CHECK_EQ_I(ip_count, 1);
    CHECK(ip_len == 1500 && memcmp(ip_got, pkt, 1500) == 0);
    CHECK_EQ_I(ppp_send_ip(&S, pkt, 1500), 0);
    pull();
    f = find(PPP_PROTO_IP, 0);
    CHECK(f && f->n == 1500 && memcmp(f->d, pkt, 1500) == 0);
    CHECK_EQ_I(f ? f->hdr : 0, 4);      /* peer did not ask for compression */
    CHECK_EQ_I(ppp_send_ip(&S, pkt, 1501), PPP_ERR_SIZE);
    CHECK_EQ_I(status()->counters.rx_ip, 1);
    CHECK_EQ_I(status()->counters.tx_ip, 1);

    /* Echo-Request: Echo-Reply with our magic number and the same data */
    {
        const uint8_t d[] = { 0x11, 0x22, 0x33, 0x44, 'h', 'e', 'y' };
        push_cp(PPP_PROTO_LCP, 9, 0x5a, d, sizeof d);
        pull();
        f = find(PPP_PROTO_LCP, 10);
        CHECK(f && f->d[1] == 0x5a && f->n == 4 + 7);
        CHECK(f && be32(f->d + 4) == magic && memcmp(f->d + 8, "hey", 3) == 0);
    }
    /* Discard-Request: nothing comes back */
    {
        const uint8_t d[] = { 0x11, 0x22, 0x33, 0x44, 1, 2, 3 };
        push_cp(PPP_PROTO_LCP, 11, 1, d, sizeof d);
        pull();
        CHECK_EQ_I(n_out, 0);
    }
    /* unknown LCP code (12, Identification): Code-Reject with a copy */
    {
        const uint8_t d[] = { 0x11, 0x22, 0x33, 0x44, 'i', 'd' };
        const uint8_t want[] = { 12, 0x33, 0, 10, 0x11, 0x22, 0x33, 0x44, 'i', 'd' };
        push_cp(PPP_PROTO_LCP, 12, 0x33, d, sizeof d);
        pull();
        f = find(PPP_PROTO_LCP, PPP_CODE_REJ);
        CHECK(f && f->n == 4 + sizeof want && memcmp(f->d + 4, want, sizeof want) == 0);
    }
    /* unknown protocol (IPV6CP): Protocol-Reject naming it, with a copy
     * of the information field */
    {
        const uint8_t d[] = { 1, 1, 0, 14, 1, 10, 0, 0, 0, 0, 0, 0, 0, 1 };
        uint32_t before = status()->counters.rx_unknown_proto;
        push(0x8057, d, sizeof d);
        pull();
        f = find(PPP_PROTO_LCP, 8);
        CHECK(f && f->n == 4 + 2 + sizeof d);
        CHECK(f && f->d[4] == 0x80 && f->d[5] == 0x57 && memcmp(f->d + 6, d, sizeof d) == 0);
        CHECK_EQ_I(status()->counters.rx_unknown_proto, before + 1);
    }
    /* a big unknown-protocol frame: the reject is cut to fit the peer MRU */
    {
        push(0x802b, pkt, 1500);
        pull();
        f = find(PPP_PROTO_LCP, 8);
        CHECK(f && f->n == 1500);
        CHECK(f && ((f->d[2] << 8) | f->d[3]) == 1500);
    }
    /* the peer Protocol-Rejects IPCP: IP is impossible, link closes */
    {
        const uint8_t d[] = { 0x80, 0x21, 1, 1, 0, 4 };
        push_cp(PPP_PROTO_LCP, 8, 1, d, sizeof d);
        pull();
        CHECK_EQ_I(status()->ip_up, 0);
        CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
        CHECK_EQ_I(status()->end_reason, PPP_END_IPCP_FAILED);
    }

    /* peer-initiated termination */
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();
    n_phases = 0;
    push_cp(PPP_PROTO_LCP, PPP_TERM_REQ, 0x44, NULL, 0);
    pull();
    f = find(PPP_PROTO_LCP, PPP_TERM_ACK);
    CHECK(f && f->d[1] == 0x44);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    CHECK_EQ_I(status()->ip_up, 0);
    CHECK_EQ_I(ppp_send_ip(&S, pkt, 100), PPP_ERR_DOWN);
    ppp_tick(&S, 3000);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK_EQ_I(status()->end_reason, PPP_END_PEER_TERMINATED);
    CHECK(n_phases == 2 && phases[0] == PPP_PHASE_TERMINATE && phases[1] == PPP_PHASE_DEAD);
    /* dead means dead: nothing is answered until the carrier cycles */
    push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 1, peer_lcp, sizeof peer_lcp);
    pull();
    CHECK_EQ_I(n_out, 0);
    ppp_lower_down(&S);
    ppp_lower_up(&S);
    CHECK_EQ_I(status()->phase, PPP_PHASE_ESTABLISH);
    CHECK_EQ_I(status()->end_reason, PPP_END_NONE);
    to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();

    /* renegotiation: a Configure-Request while Opened takes the link back
     * to Establish and IP down */
    push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 0x70, peer_lcp, sizeof peer_lcp);
    CHECK_EQ_I(status()->phase, PPP_PHASE_ESTABLISH);
    CHECK_EQ_I(status()->ip_up, 0);
    CHECK_EQ_I(status()->authenticated, 0);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_CONF_REQ) != NULL);
    CHECK(find(PPP_PROTO_LCP, PPP_CONF_ACK) != NULL);

    /* local close */
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();
    ppp_close(&S);
    pull();
    f = find(PPP_PROTO_LCP, PPP_TERM_REQ);
    CHECK(f != NULL);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    if (f) push_cp(PPP_PROTO_LCP, PPP_TERM_ACK, f->d[1], NULL, 0);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK_EQ_I(status()->end_reason, PPP_END_LOCAL_CLOSE);

    /* carrier loss mid-session */
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();
    ppp_send_ip(&S, pkt, 100);
    ppp_lower_down(&S);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK_EQ_I(status()->end_reason, PPP_END_LOWER_DOWN);
    CHECK_EQ_I(status()->ip_up, 0);
    CHECK_EQ_I(ppp_output_pending(&S), 0);
}

static void test_compression_and_accm(void)
{
    ppp_config_t c;
    frame_t *f;
    /* peer: ACCM with only XON/XOFF, PFC, ACFC, MRU 296 */
    const uint8_t po[] = { 1, 4, 0x01, 0x28, 2, 6, 0x00, 0x0a, 0x00, 0x00,
                           5, 6, 9, 9, 9, 9, 7, 2, 8, 2 };
    const uint8_t ip[] = { 0x45, 0x11, 0x13, 0x01, 0x7e, 0x7d, 0xff };
    const uint8_t h_full[] = { 0xff, 0x03, 0x00, 0x21 };
    const uint8_t h_acfc[] = { 0x00, 0x21 };
    const uint8_t h_pfc[]  = { 0xff, 0x03, 0x21 };
    const uint8_t h_both[] = { 0x21 };
    uint8_t big[400];
    size_t i;

    memset(big, 0x55, sizeof big);
    base_cfg(&c);
    start(&c);
    to_network(po, sizeof po);
    ipcp_up();
    CHECK_EQ_I(status()->peer_mru, 296);
    CHECK(status()->tx_accm == 0x000a0000u);
    CHECK(status()->rx_accm == 0);
    CHECK_EQ_I(ppp_send_ip(&S, big, 297), PPP_ERR_SIZE);
    CHECK_EQ_I(ppp_send_ip(&S, big, 296), 0);
    pull();

    /* transmit: header compressed to the single octet 0x21, XON/XOFF
     * escaped, other control characters raw, flag/escape always stuffed */
    CHECK_EQ_I(ppp_send_ip(&S, ip, sizeof ip), 0);
    pull();
    f = find(PPP_PROTO_IP, 0);
    CHECK(f && f->hdr == 1 && f->n == sizeof ip && memcmp(f->d, ip, sizeof ip) == 0);
    {
        const uint8_t want[] = { 0x7e, 0x21, 0x45, 0x7d, 0x31, 0x7d, 0x33, 0x01,
                                 0x7d, 0x5e, 0x7d, 0x5d, 0xff };
        CHECK(wire_n > sizeof want && memcmp(wire, want, sizeof want) == 0);
    }
    /* LCP itself is never compressed and always fully escaped */
    {
        const uint8_t d[] = { 9, 9, 9, 9, 1, 2 };
        push_cp(PPP_PROTO_LCP, 9, 1, d, sizeof d);
        pull();
        f = find(PPP_PROTO_LCP, 10);
        CHECK(f && f->hdr == 4);
        for (i = 0; i < wire_n; i++)
            CHECK(wire[i] >= 0x20);
    }
    /* receive: all four header forms are accepted (we asked for both
     * compressions and the peer Ack'd), with control characters raw since
     * our ACCM is 0 */
    push_raw(h_full, 4, ip, sizeof ip, 0);
    push_raw(h_acfc, 2, ip, sizeof ip, 0);
    push_raw(h_pfc, 3, ip, sizeof ip, 0);
    push_raw(h_both, 1, ip, sizeof ip, 0);
    CHECK_EQ_I(ip_count, 4);
    CHECK(ip_len == sizeof ip && memcmp(ip_got, ip, sizeof ip) == 0);
    CHECK_EQ_I(status()->counters.rx_bad_header, 0);

    /* without negotiation the compressed forms are dropped and counted */
    c.no_pfc = c.no_acfc = 1;
    start(&c);
    pull();
    push_cp(PPP_PROTO_LCP, PPP_CONF_REQ, 1, po, sizeof po);
    pull();
    f = find(PPP_PROTO_LCP, PPP_CONF_REJ);     /* PFC and ACFC refused */
    CHECK(f && f->n == 8 && memcmp(f->d + 4, po + sizeof po - 4, 4) == 0);
    start(&c);
    to_network(po, sizeof po - 4);
    ipcp_up();
    push_raw(h_acfc, 2, ip, sizeof ip, 0);
    push_raw(h_pfc, 3, ip, sizeof ip, 0);
    push_raw(h_both, 1, ip, sizeof ip, 0);
    CHECK_EQ_I(ip_count, 0);
    CHECK_EQ_I(status()->counters.rx_bad_header, 3);
    push_raw(h_full, 4, ip, sizeof ip, 0);
    CHECK_EQ_I(ip_count, 1);
    /* and nothing was agreed for our direction either, so we send plain */
    pull();
    CHECK_EQ_I(ppp_send_ip(&S, ip, sizeof ip), 0);
    pull();
    f = find(PPP_PROTO_IP, 0);
    CHECK(f && f->hdr == 4);

    /* line errors are counted */
    {
        uint8_t w[64];
        size_t k = ppp_hdlc_encode(w, sizeof w, h_full, 4, ip, sizeof ip, 0xffffffffu, 1);
        w[6] ^= 0x40;
        ppp_input_bytes(&S, w, k);
        CHECK_EQ_I(status()->counters.rx_bad_fcs, 1);
        CHECK_EQ_I(ip_count, 1);
    }
}

static void test_tx_buffer(void)
{
    ppp_config_t c;
    frame_t *f;
    static uint8_t pkt[1500];
    int sent = 0, r = 0;

    base_cfg(&c);
    start(&c);
    to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();
    memset(pkt, 0x7e, sizeof pkt);      /* worst case: every octet stuffed */
    while (sent < 100 && (r = ppp_send_ip(&S, pkt, sizeof pkt)) == 0)
        sent++;
    CHECK_EQ_I(r, PPP_ERR_FULL);
    CHECK(sent >= 2);
    CHECK(ppp_output_pending(&S) <= PPP_TX_BUF - PPP_TX_RESERVE);
    /* control traffic still fits in the reserve */
    {
        const uint8_t d[] = { 0x11, 0x22, 0x33, 0x44 };
        push_cp(PPP_PROTO_LCP, 9, 1, d, sizeof d);
    }
    /* partial pulls drain in order */
    {
        uint8_t chunk[97];
        size_t n, total = 0, pending = ppp_output_pending(&S);
        int frames = 0, echo = 0;
        while ((n = ppp_output_bytes(&S, chunk, sizeof chunk)) > 0) {
            total += n;
            for (size_t i = 0; i < n; i++) {
                if (ppp_hdlc_rx_byte(&dec, chunk[i])) {
                    frames++;
                    if (dec.buf[2] == 0xc0 && dec.buf[4] == 10) echo = 1;
                    else CHECK(dec.len == 1504 && dec.buf[100] == 0x7e);
                }
            }
        }
        CHECK_EQ_I(total, pending);
        CHECK_EQ_I(frames, sent + 1);
        CHECK_EQ_I(echo, 1);
    }
    /* room again */
    CHECK_EQ_I(ppp_send_ip(&S, pkt, sizeof pkt), 0);
    pull();
    f = find(PPP_PROTO_IP, 0);
    CHECK(f && f->n == 1500);
    CHECK_EQ_I(status()->counters.tx_dropped, 0);
}

static void test_keepalive(void)
{
    ppp_config_t c;
    frame_t *f;
    uint32_t magic;
    int i;

    base_cfg(&c);
    c.echo_interval_ms = 1000;
    c.echo_max_fail = 3;
    start(&c);
    magic = to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();

    /* answered echoes keep the link up indefinitely */
    for (i = 0; i < 10; i++) {
        ppp_tick(&S, 999);
        pull();
        CHECK(find(PPP_PROTO_LCP, 9) == NULL);
        ppp_tick(&S, 1);
        pull();
        f = find(PPP_PROTO_LCP, 9);
        CHECK(f != NULL);
        if (f) {
            const uint8_t r[] = { 0x11, 0x22, 0x33, 0x44 };
            CHECK(f->n == 8 && be32(f->d + 4) == magic);
            push_cp(PPP_PROTO_LCP, 10, f->d[1], r, 4);
        }
    }
    CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    /* three unanswered echoes, then the peer is declared dead */
    for (i = 0; i < 3; i++) {
        ppp_tick(&S, 1000);
        pull();
        CHECK(find(PPP_PROTO_LCP, 9) != NULL);
        CHECK_EQ_I(status()->phase, PPP_PHASE_NETWORK);
    }
    ppp_tick(&S, 1000);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    CHECK_EQ_I(status()->phase, PPP_PHASE_TERMINATE);
    CHECK_EQ_I(status()->end_reason, PPP_END_KEEPALIVE);
    /* Max-Terminate requests 3 s apart, then Dead */
    ppp_tick(&S, 3000);
    pull();
    CHECK(find(PPP_PROTO_LCP, PPP_TERM_REQ) != NULL);
    ppp_tick(&S, 3000);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK_EQ_I(status()->end_reason, PPP_END_KEEPALIVE);

    /* an echo reply carrying our own magic number is a loop, not a peer */
    start(&c);
    magic = to_network(peer_lcp, sizeof peer_lcp);
    ipcp_up();
    for (i = 0; i < 4; i++) {
        ppp_tick(&S, 1000);
        pull();
        f = find(PPP_PROTO_LCP, 9);
        if (f) push_cp(PPP_PROTO_LCP, 10, f->d[1], f->d + 4, 4);
    }
    CHECK_EQ_I(status()->end_reason, PPP_END_KEEPALIVE);
}

static void test_no_peer_and_loopback(void)
{
    ppp_config_t c;
    int i, reqs = 0;
    uint8_t buf[512];
    size_t n;

    /* nobody answers: Max-Configure requests, then Dead */
    base_cfg(&c);
    start(&c);
    for (i = 0; i < 12; i++) {
        pull();
        if (find(PPP_PROTO_LCP, PPP_CONF_REQ)) reqs++;
        ppp_tick(&S, 3000);
    }
    CHECK_EQ_I(reqs, 10);
    CHECK_EQ_I(status()->phase, PPP_PHASE_DEAD);
    CHECK_EQ_I(status()->end_reason, PPP_END_NEGOTIATION);
    CHECK(n_phases >= 2 && phases[0] == PPP_PHASE_ESTABLISH && phases[n_phases - 1] == PPP_PHASE_DEAD);

    /* looped-back line: everything we send comes straight back */
    start(&c);
    for (i = 0; i < 200 && status()->end_reason == PPP_END_NONE; i++) {
        while ((n = ppp_output_bytes(&S, buf, sizeof buf)) > 0)
            ppp_input_bytes(&S, buf, n);
        ppp_tick(&S, 100);
    }
    CHECK_EQ_I(status()->end_reason, PPP_END_LOOPBACK);

    /* garbage input never crashes or answers */
    start(&c);
    pull();
    {
        uint32_t x = 99;
        for (i = 0; i < 20000; i++) {
            uint8_t b;
            x = x * 1664525u + 1013904223u;
            b = (uint8_t)(x >> 24);
            ppp_input_bytes(&S, &b, 1);
        }
        CHECK_EQ_I(status()->phase, PPP_PHASE_ESTABLISH);
    }
}

/* Random but well-framed packets in every phase: the parsers must never
 * read or write out of bounds (run this under a sanitizer to be sure; it
 * is in the normal run as a crash and sanity check). */
static void test_fuzz(void)
{
    static const uint16_t protos[] = { PPP_PROTO_LCP, PPP_PROTO_LCP, PPP_PROTO_PAP,
        PPP_PROTO_CHAP, PPP_PROTO_IPCP, PPP_PROTO_IP, 0x8057, 0x00fd, 0xc025 };
    ppp_config_t c;
    uint32_t x = 2463534242u;
    uint8_t d[300], sink[4096];
    int i, ups = 0;

    base_cfg(&c);
    c.echo_interval_ms = 500;
    start(&c);
    for (i = 0; i < 60000; i++) {
        size_t n, k;
        uint16_t proto;

        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        proto = protos[x % 9];
        n = (x >> 8) % 70;
        for (k = 0; k < n; k++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            d[k] = (uint8_t)(x >> 11);
        }
        if (n >= 4) {
            /* mostly plausible headers: small codes, mostly right lengths,
             * option-like contents with small type and length octets */
            d[0] = (uint8_t)(d[0] % 14);
            d[2] = 0;
            if (d[3] & 1) d[3] = (uint8_t)n;
            for (k = 4; k + 1 < n; k += (size_t)d[k + 1] > 1 ? d[k + 1] : 2) {
                d[k] = (uint8_t)(d[k] % 10);
                d[k + 1] = (uint8_t)(2 + d[k + 1] % 6);
            }
        }
        push(proto, d, n);
        if ((x & 0xff) == 0)
            ppp_tick(&S, 700);
        if ((x & 0x3ff) == 1)
            ppp_close(&S);
        if (status()->phase == PPP_PHASE_DEAD || (x & 0xfff) == 2) {
            /* now and then get a session properly up so the fuzz also
             * hits the Opened states */
            if (x & 0x1000) {
                start(&c);
            } else {
                start(&c);
                to_network(peer_lcp, sizeof peer_lcp);
                ipcp_up();
                ups++;
            }
        }
        while (ppp_output_bytes(&S, sink, sizeof sink) > 0)
            ;
        if (status()->ip_up && (x & 7) == 3)
            ppp_send_ip(&S, d, n);
    }
    CHECK(ups > 5);
    CHECK(ppp_output_pending(&S) <= PPP_TX_BUF);
    CHECK(status()->counters.rx_frames > 0);
}

int main(void)
{
    test_first_request();
    test_peer_request();
    test_auth_negotiation();
    test_chap();
    test_mschap2();
    test_pap();
    test_ipcp();
    test_data_and_lcp_codes();
    test_compression_and_accm();
    test_tx_buffer();
    test_keepalive();
    test_no_peer_and_loopback();
    test_fuzz();
    T_REPORT("test_ppp");
}
