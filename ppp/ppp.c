/* PPP server session: phases (RFC 1661 3.2), LCP, PAP/CHAP authenticator,
 * IPCP with address assignment and DNS, CCP with PPP Deflate and MPPC.
 * See ppp.h for the API. */
#include <string.h>
#include "ppp.h"
#include "ppp_md5.h"

/* LCP configuration options (RFC 1661 section 6) */
#define LCP_OPT_MRU      1
#define LCP_OPT_ACCM     2
#define LCP_OPT_AUTH     3
#define LCP_OPT_MAGIC    5
#define LCP_OPT_PFC      7
#define LCP_OPT_ACFC     8
/* LCP codes beyond the common seven (RFC 1661 section 5) */
#define LCP_PROTO_REJ    8
#define LCP_ECHO_REQ     9
#define LCP_ECHO_REP     10
#define LCP_DISCARD_REQ  11
/* IPCP options (RFC 1332 section 3, RFC 1877 section 1) */
#define IPCP_OPT_ADDR    3
#define IPCP_OPT_DNS1    129
#define IPCP_OPT_DNS2    131
/* PAP codes (RFC 1334 2.2) and CHAP codes (RFC 1994 section 4) */
#define PAP_REQUEST      1
#define PAP_ACK          2
#define PAP_NAK          3
#define CHAP_CHALLENGE   1
#define CHAP_RESPONSE    2
#define CHAP_SUCCESS     3
#define CHAP_FAILURE     4
#define CHAP_ALG_MD5     5
#define CHAP_ALG_MSCHAP2 0x81

/* CCP codes beyond the common seven (RFC 1962 section 3) and the options
 * we know (RFC 1962 section 4, RFC 2118 section 2, RFC 1979 section 3; 24
 * is the number PPP Deflate had in its draft, still offered by pppd) */
#define CCP_RESET_REQ    14
#define CCP_RESET_ACK    15
#define CCP_OPT_MPPC     18
#define CCP_OPT_DEFLATE_DRAFT 24
#define CCP_OPT_DEFLATE  26
#define DEFLATE_METHOD   8   /* RFC 1979 section 3 */
#define MPPC_BIT         1u  /* RFC 2118 section 2: the only bit we take */
#define RESET_TRIES      3   /* Reset-Requests before CCP is negotiated anew */
#define CW_NAK_LIMIT     3   /* Naks of one of our options before we drop it */

#define LOOP_LIMIT       5   /* own magic seen this often: looped back */

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ---------------------------------------------------------------- */
/* nonce generator: an MD5-stirred pool. Its quality is that of the seed
 * and of whatever the caller feeds to ppp_add_entropy(). */

static void pool_mix(ppp_t *p, const uint8_t *data, size_t n, uint8_t tag,
                     uint8_t out[16])
{
    ppp_md5_t m;
    uint8_t extra[13];

    put32(extra, p->pool_ctr);
    put32(extra + 4, p->uptime_ms);
    put32(extra + 8, p->rx_octets);
    extra[12] = tag;
    ppp_md5_init(&m);
    ppp_md5_update(&m, p->pool, 16);
    ppp_md5_update(&m, extra, sizeof extra);
    ppp_md5_update(&m, data, n);
    ppp_md5_final(&m, out);
}

void ppp_add_entropy(ppp_t *p, const uint8_t *data, size_t n)
{
    p->pool_ctr++;
    pool_mix(p, data, n, 'e', p->pool);
}

static void nonce(ppp_t *p, uint8_t *out, size_t n)
{
    uint8_t block[16];

    while (n > 0) {
        size_t k = n < 16 ? n : 16;
        p->pool_ctr++;
        pool_mix(p, NULL, 0, 'o', block);     /* output */
        pool_mix(p, NULL, 0, 'n', p->pool);   /* next pool state */
        memcpy(out, block, k);
        out += k;
        n -= k;
    }
}

static uint32_t new_magic(ppp_t *p, uint32_t avoid)
{
    uint8_t b[4];
    uint32_t m;

    do {
        nonce(p, b, 4);
        m = get32(b);
    } while (m == 0 || m == avoid);
    return m;
}

/* ---------------------------------------------------------------- */
/* phase and termination bookkeeping */

static void set_phase(ppp_t *p, ppp_phase_t ph)
{
    if (p->phase == ph)
        return;
    p->phase = ph;
    if (p->cfg.phase_cb)
        p->cfg.phase_cb(p->cfg.ctx, ph);
}

static void set_end(ppp_t *p, ppp_end_t why)
{
    if (p->end_reason == PPP_END_NONE)
        p->end_reason = why;
}

/* ask for the link to be closed once the current packet is dealt with
 * (closing from inside an automaton callback would re-enter it) */
static void request_close(ppp_t *p, ppp_end_t why)
{
    if (p->pending_close == PPP_END_NONE)
        p->pending_close = why;
}

static void do_close(ppp_t *p, ppp_end_t why)
{
    if (p->phase == PPP_PHASE_DEAD)
        return;
    set_end(p, why);
    ppp_fsm_close(&p->lcp);
    if (p->lcp.state == PPP_FSM_CLOSING)
        set_phase(p, PPP_PHASE_TERMINATE);
}

static void run_pending(ppp_t *p)
{
    if (p->pending_close != PPP_END_NONE) {
        ppp_end_t why = p->pending_close;
        p->pending_close = PPP_END_NONE;
        do_close(p, why);
    }
}

/* ---------------------------------------------------------------- */
/* transmit path */

/* Frame one packet into the transmit buffer. The information field is
 * h + a + b. Returns 0, or -1 if there is no room (leaving `reserve`
 * octets untouched). */
static int tx_frame(ppp_t *p, uint16_t proto,
                    const uint8_t *h, size_t hn,
                    const uint8_t *a, size_t an,
                    const uint8_t *b, size_t bn, size_t reserve)
{
    uint8_t hdr[4];
    size_t hl = 0, n = 0;
    uint32_t accm;
    int attempt;

    if (proto == PPP_PROTO_LCP) {
        /* RFC 1662 7: LCP always goes out in the default framing, so the
         * peer can read it whatever state its negotiation is in */
        accm = 0xffffffffu;
        hdr[hl++] = 0xff;
        hdr[hl++] = 0x03;
        hdr[hl++] = (uint8_t)(proto >> 8);
        hdr[hl++] = (uint8_t)proto;
    } else {
        accm = p->tx_accm;
        if (!p->tx_acfc) {
            hdr[hl++] = 0xff;
            hdr[hl++] = 0x03;
        }
        if (!(p->tx_pfc && proto < 0x100))
            hdr[hl++] = (uint8_t)(proto >> 8);
        hdr[hl++] = (uint8_t)proto;
    }

    if (p->tx_head == p->tx_tail)
        p->tx_head = p->tx_tail = 0;
    for (attempt = 0; attempt < 2 && n == 0; attempt++) {
        ppp_hdlc_tx_t tx;
        size_t room = PPP_TX_BUF - p->tx_tail;

        room = room > reserve ? room - reserve : 0;
        /* an opening flag only when the line has been idle */
        ppp_hdlc_tx_begin(&tx, p->txbuf + p->tx_tail, room, accm,
                          p->tx_head == p->tx_tail);
        ppp_hdlc_tx_add(&tx, hdr, hl);
        ppp_hdlc_tx_add(&tx, h, hn);
        ppp_hdlc_tx_add(&tx, a, an);
        ppp_hdlc_tx_add(&tx, b, bn);
        n = ppp_hdlc_tx_end(&tx);
        if (n == 0) {
            if (p->tx_head == 0)
                break;
            /* slide the unsent octets down and try once more */
            memmove(p->txbuf, p->txbuf + p->tx_head, p->tx_tail - p->tx_head);
            p->tx_tail -= p->tx_head;
            p->tx_head = 0;
        }
    }
    if (n == 0)
        return -1;
    p->tx_tail += n;
    p->cnt.tx_frames++;
    return 0;
}

/* a control-protocol style packet: code, identifier, length, data */
static void tx_cp(ppp_t *p, uint16_t proto, uint8_t code, uint8_t id,
                  const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    uint8_t h[4];
    size_t len = 4 + an + bn;

    h[0] = code;
    h[1] = id;
    h[2] = (uint8_t)(len >> 8);
    h[3] = (uint8_t)len;
    if (tx_frame(p, proto, h, 4, a, an, b, bn, 0) != 0)
        p->cnt.tx_dropped++;
}

/* The transmit buffer holds whole frames one behind the other, each ended
 * by a flag, and the flag octet occurs nowhere else in it (RFC 1662 4.2).
 * So the frames still waiting can be told apart, which the two functions
 * below use for the CCP reset exchange: on a slow line without error
 * control the buffer holds half a minute of traffic, and a reset that had
 * to queue behind it would leave the link decompressing nothing for that
 * long. */

/* index just behind the frame that is going out now */
static size_t tx_cut(const ppp_t *p)
{
    size_t i = p->tx_head;

    while (i < p->tx_tail && p->txbuf[i] != PPP_FLAG)
        i++;
    return i < p->tx_tail ? i + 1 : p->tx_tail;
}

/* Take the compressed datagrams that have not begun to go out back out of
 * the buffer: the peer has asked for a reset and discards them anyway
 * (RFC 1962 3.1). Everything else stays, in its order. */
static void tx_purge_compressed(ppp_t *p)
{
    size_t rd = tx_cut(p), wr = rd;

    while (rd < p->tx_tail) {
        size_t e = rd, k = rd, hn = 0;
        uint8_t hd[4];

        while (e < p->tx_tail && p->txbuf[e] != PPP_FLAG)
            e++;
        if (e == p->tx_tail)
            e--;                            /* not reached: frames end in a flag */
        /* the start of the frame with the escapes undone: Address and
         * Control if they are there, then the Protocol field */
        while (k < e && hn < 4) {
            uint8_t c = p->txbuf[k++];

            if (c == PPP_ESCAPE && k < e)
                c = p->txbuf[k++] ^ 0x20;
            hd[hn++] = c;
        }
        k = hn >= 2 && hd[0] == 0xff && hd[1] == 0x03 ? 2 : 0;
        if (hn > k && (hd[k] == PPP_PROTO_COMP ||
                       (hn > k + 1 && hd[k] == 0 && hd[k + 1] == PPP_PROTO_COMP))) {
            p->cnt.comp_tx_purged++;
        } else {
            memmove(p->txbuf + wr, p->txbuf + rd, e + 1 - rd);
            wr += e + 1 - rd;
        }
        rd = e + 1;
    }
    p->tx_tail = wr;
}

/* A control packet without data that goes out next, in front of what is
 * waiting (its place among data frames means nothing). */
static void tx_cp_next(ppp_t *p, uint16_t proto, uint8_t code, uint8_t id)
{
    uint8_t tmp[40];
    size_t held = p->tx_tail - p->tx_head, start, cut, n;

    tx_cp(p, proto, code, id, NULL, 0, NULL, 0);
    if (p->tx_tail - p->tx_head <= held)
        return;                             /* no room: it was dropped */
    start = p->tx_head + held;
    n = p->tx_tail - start;
    cut = tx_cut(p);
    if (cut >= start || n > sizeof tmp)
        return;
    memcpy(tmp, p->txbuf + start, n);
    memmove(p->txbuf + cut + n, p->txbuf + cut, start - cut);
    memcpy(p->txbuf + cut, tmp, n);
}

static void fsm_send(ppp_fsm_t *f, uint8_t code, uint8_t id,
                     const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    ppp_t *p = (ppp_t *)f->ctx;

    tx_cp(p, f == &p->lcp ? PPP_PROTO_LCP : f == &p->ipcp ? PPP_PROTO_IPCP : PPP_PROTO_CCP,
          code, id, a, an, b, bn);
}

/* ---------------------------------------------------------------- */
/* option judging shared by LCP and IPCP */

/* Verdict on one option of the peer's request. For PPP_CONF_NAK the value
 * we would accept is written to sugg (at most 8 octets) and *slen. */
typedef int (*judge_fn)(ppp_t *p, uint8_t type, const uint8_t *val, size_t vlen,
                        uint8_t *sugg, size_t *slen);

/* RFC 1661 5.3/5.4: if anything must be rejected, answer with a Reject
 * listing only those options; otherwise, if anything is unacceptable,
 * a Nak listing only those with acceptable values; otherwise Ack. Once
 * Max-Failure Naks have gone out, further Naks become Rejects (4.6). */
static int negotiate(ppp_t *p, ppp_fsm_t *f, judge_fn judge,
                     const uint8_t *opts, size_t len,
                     uint8_t *out, size_t max, size_t *outlen)
{
    int exhausted = f->failures >= f->max_failure;
    int worst = PPP_CONF_ACK, pass;
    size_t n = 0;

    for (pass = 0; pass < 2; pass++) {
        size_t pos = 0, vlen, slen;
        uint8_t type, sugg[8];
        const uint8_t *val;

        while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
            int v;

            slen = 0;
            v = judge(p, type, val, vlen, sugg, &slen);
            if (v == PPP_CONF_NAK && exhausted)
                v = PPP_CONF_REJ;
            if (pass == 0) {
                if (v == PPP_CONF_REJ)
                    worst = PPP_CONF_REJ;
                else if (v == PPP_CONF_NAK && worst == PPP_CONF_ACK)
                    worst = PPP_CONF_NAK;
            } else if (v == worst) {
                if (worst == PPP_CONF_REJ) {
                    if (n + 2 + vlen <= max) {
                        memcpy(out + n, val - 2, 2 + vlen);
                        n += 2 + vlen;
                    }
                } else if (n + 2 + slen <= max) {
                    out[n] = type;
                    out[n + 1] = (uint8_t)(2 + slen);
                    memcpy(out + n + 2, sugg, slen);
                    n += 2 + slen;
                }
            }
        }
        if (worst == PPP_CONF_ACK)
            break;
    }
    *outlen = n;
    return worst;
}

/* ---------------------------------------------------------------- */
/* LCP */

static void lcp_reset(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    p->mru = p->cfg.mru;
    p->w_mru = (p->mru != PPP_MAX_MRU);
    p->accm = p->cfg.accm;
    p->w_accm = (p->accm != 0xffffffffu);
    p->w_magic = !p->cfg.no_magic;
    p->magic = p->w_magic ? new_magic(p, 0) : 0;
    p->w_pfc = !p->cfg.no_pfc;
    p->w_acfc = !p->cfg.no_acfc;
    if (p->cfg.auth & PPP_AUTH_MSCHAPV2)
        p->w_auth = PPP_AUTH_MSCHAPV2;
    else if (p->cfg.auth & PPP_AUTH_CHAP)
        p->w_auth = PPP_AUTH_CHAP;
    else if (p->cfg.auth & PPP_AUTH_PAP)
        p->w_auth = PPP_AUTH_PAP;
    else
        p->w_auth = PPP_AUTH_NONE;
    p->auth_tried = p->w_auth;
    p->loop_count = 0;
}

static size_t lcp_build_cr(ppp_fsm_t *f, uint8_t *o, size_t max)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t n = 0;

    (void)max;   /* at most 25 octets; the scratch area is far larger */
    if (p->w_mru) {
        o[n++] = LCP_OPT_MRU;
        o[n++] = 4;
        o[n++] = (uint8_t)(p->mru >> 8);
        o[n++] = (uint8_t)p->mru;
    }
    if (p->w_accm) {
        o[n++] = LCP_OPT_ACCM;
        o[n++] = 6;
        put32(o + n, p->accm);
        n += 4;
    }
    if (p->w_auth == PPP_AUTH_CHAP || p->w_auth == PPP_AUTH_MSCHAPV2) {
        o[n++] = LCP_OPT_AUTH;
        o[n++] = 5;
        o[n++] = (uint8_t)(PPP_PROTO_CHAP >> 8);
        o[n++] = (uint8_t)PPP_PROTO_CHAP;
        o[n++] = p->w_auth == PPP_AUTH_MSCHAPV2 ? CHAP_ALG_MSCHAP2 : CHAP_ALG_MD5;
    } else if (p->w_auth == PPP_AUTH_PAP) {
        o[n++] = LCP_OPT_AUTH;
        o[n++] = 4;
        o[n++] = (uint8_t)(PPP_PROTO_PAP >> 8);
        o[n++] = (uint8_t)PPP_PROTO_PAP;
    }
    if (p->w_magic) {
        o[n++] = LCP_OPT_MAGIC;
        o[n++] = 6;
        put32(o + n, p->magic);
        n += 4;
    }
    if (p->w_pfc) {
        o[n++] = LCP_OPT_PFC;
        o[n++] = 2;
    }
    if (p->w_acfc) {
        o[n++] = LCP_OPT_ACFC;
        o[n++] = 2;
    }
    return n;
}

static int lcp_judge(ppp_t *p, uint8_t type, const uint8_t *val, size_t vlen,
                     uint8_t *sugg, size_t *slen)
{
    switch (type) {
    case LCP_OPT_MRU: {
        unsigned mru = vlen == 2 ? ((unsigned)val[0] << 8) | val[1] : 0;
        if (mru >= PPP_MIN_MRU) {
            /* a larger MRU than we can ever fill is fine: we just never
             * send more than PPP_MAX_MRU */
            p->pend_mru = (uint16_t)(mru > PPP_MAX_MRU ? PPP_MAX_MRU : mru);
            return PPP_CONF_ACK;
        }
        sugg[0] = (uint8_t)(PPP_MAX_MRU >> 8);
        sugg[1] = (uint8_t)(PPP_MAX_MRU & 0xff);
        *slen = 2;
        return PPP_CONF_NAK;
    }
    case LCP_OPT_ACCM:
        if (vlen != 4)
            return PPP_CONF_REJ;
        p->pend_accm = get32(val);
        return PPP_CONF_ACK;
    case LCP_OPT_MAGIC: {
        uint32_t m = vlen == 4 ? get32(val) : 0;
        /* zero is not a magic number; our own number means we may be
         * talking to ourselves (RFC 1661 6.4): Nak with a fresh one */
        if (m != 0 && !(p->w_magic && m == p->magic)) {
            p->pend_magic = m;
            return PPP_CONF_ACK;
        }
        put32(sugg, new_magic(p, p->magic));
        *slen = 4;
        return PPP_CONF_NAK;
    }
    case LCP_OPT_PFC:
        if (vlen != 0 || p->cfg.no_pfc)
            return PPP_CONF_REJ;
        p->pend_pfc = 1;
        return PPP_CONF_ACK;
    case LCP_OPT_ACFC:
        if (vlen != 0 || p->cfg.no_acfc)
            return PPP_CONF_REJ;
        p->pend_acfc = 1;
        return PPP_CONF_ACK;
    default:
        /* includes Authentication-Protocol (we are the authenticator and
         * do not authenticate ourselves) and Quality-Protocol */
        return PPP_CONF_REJ;
    }
}

static int lcp_recv_cr(ppp_fsm_t *f, const uint8_t *opts, size_t len,
                       uint8_t *out, size_t max, size_t *outlen)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;

    /* defaults for whatever the peer does not mention */
    p->pend_mru = PPP_MAX_MRU;
    p->pend_accm = 0xffffffffu;
    p->pend_magic = 0;
    p->pend_pfc = p->pend_acfc = 0;

    /* Loopback detection (RFC 1661 6.4): a request carrying the magic
     * number of our own last request may be that request coming back. A
     * Nak with a different number MUST be sent; this takes precedence over
     * judging the other options. Several in a row and we call it a loop. */
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type != LCP_OPT_MAGIC || vlen != 4)
            continue;
        if (p->w_magic && get32(val) == p->magic) {
            if (++p->loop_count >= LOOP_LIMIT)
                request_close(p, PPP_END_LOOPBACK);
            if (max >= 6) {
                out[0] = LCP_OPT_MAGIC;
                out[1] = 6;
                put32(out + 2, new_magic(p, p->magic));
                *outlen = 6;
                return PPP_CONF_NAK;
            }
        } else {
            p->loop_count = 0;
        }
    }
    return negotiate(p, f, lcp_judge, opts, len, out, max, outlen);
}

static void lcp_recv_ack(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    /* the automaton already checked the Ack equals our request; the
     * requested values take effect in lcp_up() */
    (void)f; (void)opts; (void)len;
}

/* The peer will not do the method we asked for. Pick another one we are
 * allowed to use and have not tried, or give up: authentication is not
 * optional on a dial-in server. */
static void lcp_auth_refused(ppp_t *p, unsigned suggestion)
{
    unsigned left = p->cfg.auth & ~(unsigned)p->auth_tried;
    unsigned next = 0;

    if (suggestion & left)
        next = suggestion;
    else if (left & PPP_AUTH_PAP)
        next = PPP_AUTH_PAP;
    else if (left & PPP_AUTH_CHAP)
        next = PPP_AUTH_CHAP;
    if (!next) {
        request_close(p, PPP_END_AUTH_REFUSED);
        return;
    }
    p->w_auth = (uint8_t)next;
    p->auth_tried |= (uint8_t)next;
}

static void lcp_recv_nak(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;

    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        switch (type) {
        case LCP_OPT_MRU:
            if (p->w_mru && vlen == 2) {
                unsigned mru = ((unsigned)val[0] << 8) | val[1];
                if (mru >= PPP_MIN_MRU && mru <= PPP_MAX_MRU) {
                    p->mru = (uint16_t)mru;
                    p->w_mru = (mru != PPP_MAX_MRU);
                }
            }
            break;
        case LCP_OPT_ACCM:
            /* the peer needs more characters escaped: take the union */
            if (p->w_accm && vlen == 4)
                p->accm |= get32(val);
            break;
        case LCP_OPT_AUTH:
            if (p->w_auth) {
                unsigned sug = 0;
                if (vlen == 2 && val[0] == 0xc0 && val[1] == 0x23)
                    sug = PPP_AUTH_PAP;
                else if (vlen == 3 && val[0] == 0xc2 && val[1] == 0x23 &&
                         val[2] == CHAP_ALG_MD5)
                    sug = PPP_AUTH_CHAP;
                lcp_auth_refused(p, sug);
            }
            break;
        case LCP_OPT_MAGIC:
            if (p->w_magic)
                p->magic = new_magic(p, p->magic);
            break;
        default:
            /* options we did not request: the peer would like us to ask
             * for them; we do not have to */
            break;
        }
    }
}

static void lcp_recv_rej(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;

    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        switch (type) {
        case LCP_OPT_MRU:   p->w_mru = 0; p->mru = PPP_MAX_MRU; break;
        case LCP_OPT_ACCM:  p->w_accm = 0; break;
        case LCP_OPT_MAGIC: p->w_magic = 0; p->magic = 0; break;
        case LCP_OPT_PFC:   p->w_pfc = 0; break;
        case LCP_OPT_ACFC:  p->w_acfc = 0; break;
        case LCP_OPT_AUTH:
            /* the peer does not authenticate at all */
            if (p->w_auth)
                request_close(p, PPP_END_AUTH_REFUSED);
            break;
        default:
            break;
        }
    }
}

static void auth_start(ppp_t *p);
static void network_start(ppp_t *p);
static void network_stop(ppp_t *p);

static void lcp_up(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    /* what the peer asked for governs what we send ... */
    p->peer_mru = p->pend_mru;
    p->tx_accm = p->pend_accm;
    p->peer_magic = p->pend_magic;
    p->tx_pfc = p->pend_pfc;
    p->tx_acfc = p->pend_acfc;
    p->lcp.peer_mru = p->peer_mru;
    p->ipcp.peer_mru = p->peer_mru;
    p->ccp.peer_mru = p->peer_mru;
    /* ... and what we asked for governs what we accept */
    p->rx.rx_accm = p->w_accm ? p->accm : 0xffffffffu;
    p->rx_pfc = p->w_pfc;
    p->rx_acfc = p->w_acfc;

    p->echo_timer = 0;
    p->echo_pending = 0;
    p->auth_proto = p->w_auth;
    p->auth_done = p->auth_ok = 0;
    if (p->auth_proto) {
        set_phase(p, PPP_PHASE_AUTHENTICATE);
        auth_start(p);
    } else {
        network_start(p);
    }
}

static void lcp_down(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    network_stop(p);
    p->auth_proto = PPP_AUTH_NONE;
    p->auth_done = p->auth_ok = 0;
    p->mppe_have = 0;
    /* back to the default framing */
    p->peer_mru = PPP_MAX_MRU;
    p->tx_accm = 0xffffffffu;
    p->peer_magic = 0;
    p->tx_pfc = p->tx_acfc = p->rx_pfc = p->rx_acfc = 0;
    p->rx.rx_accm = 0xffffffffu;
    p->lcp.peer_mru = 0;

    if (f->state == PPP_FSM_CLOSING || f->state == PPP_FSM_STOPPING)
        set_phase(p, PPP_PHASE_TERMINATE);
    else if (f->state != PPP_FSM_STARTING)
        set_phase(p, PPP_PHASE_ESTABLISH);   /* renegotiation */
}

static void lcp_finished(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    set_end(p, PPP_END_NEGOTIATION);
    set_phase(p, PPP_PHASE_DEAD);
}

static int lcp_ext_code(ppp_fsm_t *f, uint8_t code, uint8_t id,
                        const uint8_t *data, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    uint32_t ours = p->w_magic ? p->magic : 0;

    switch (code) {
    case LCP_PROTO_REJ: {
        unsigned proto;
        /* RFC 1661 5.7: only meaningful in the Opened state */
        if (f->state != PPP_FSM_OPENED || len < 2)
            return PPP_FSM_EXT_NONE;
        proto = ((unsigned)data[0] << 8) | data[1];
        if (proto == PPP_PROTO_LCP)
            return PPP_FSM_EXT_RXJ_BAD;
        if (proto == PPP_PROTO_IPCP || proto == PPP_PROTO_IP) {
            /* without IP this link has no purpose */
            if (p->phase == PPP_PHASE_NETWORK)
                ppp_fsm_protocol_rejected(&p->ipcp);
            request_close(p, PPP_END_IPCP_FAILED);
        } else if (proto == PPP_PROTO_CCP) {
            /* the peer has no CCP: the link goes on uncompressed */
            ppp_fsm_protocol_rejected(&p->ccp);
        } else if (proto == PPP_PROTO_COMP) {
            /* it will not take compressed datagrams after all */
            ppp_fsm_close(&p->ccp);
        } else if ((proto == PPP_PROTO_PAP && p->auth_proto == PPP_AUTH_PAP) ||
                   (proto == PPP_PROTO_CHAP && (p->auth_proto == PPP_AUTH_CHAP ||
                                                p->auth_proto == PPP_AUTH_MSCHAPV2))) {
            if (!p->auth_ok)
                request_close(p, PPP_END_AUTH_REFUSED);
        }
        return PPP_FSM_EXT_RXJ_GOOD;
    }
    case LCP_ECHO_REQ:
        if (f->state == PPP_FSM_OPENED && len >= 4) {
            uint8_t m[4];
            size_t room = (size_t)p->peer_mru - 8;
            size_t dn = len - 4;

            /* our own number in a request: the line is looped; no reply */
            if (ours != 0 && get32(data) == ours)
                return PPP_FSM_EXT_RXR;
            put32(m, ours);
            if (dn > room)
                dn = room;
            f->ops->send(f, LCP_ECHO_REP, id, m, 4, data + 4, dn);
        }
        return PPP_FSM_EXT_RXR;
    case LCP_ECHO_REP:
        if (f->state == PPP_FSM_OPENED && len >= 4) {
            /* a reply with our own magic number is our request coming
             * back, not a live peer */
            if (ours == 0 || get32(data) != ours)
                p->echo_pending = 0;
        }
        return PPP_FSM_EXT_RXR;
    case LCP_DISCARD_REQ:
        return PPP_FSM_EXT_RXR;
    default:
        return PPP_FSM_EXT_RUC;
    }
}

static const ppp_fsm_ops_t lcp_ops = {
    fsm_send, lcp_reset, lcp_build_cr, lcp_recv_cr,
    lcp_recv_ack, lcp_recv_nak, lcp_recv_rej,
    lcp_up, lcp_down, NULL, lcp_finished, lcp_ext_code
};

static void keepalive_tick(ppp_t *p, uint32_t ms)
{
    uint8_t m[4];

    if (!p->cfg.echo_interval_ms || p->lcp.state != PPP_FSM_OPENED)
        return;
    /* a peer that Code-Rejected Echo-Request cannot be probed */
    if (p->lcp.rejected_codes & (1u << LCP_ECHO_REQ))
        return;
    p->echo_timer += ms;
    if (p->echo_timer < p->cfg.echo_interval_ms)
        return;
    p->echo_timer = 0;
    if (p->echo_pending >= p->cfg.echo_max_fail) {
        request_close(p, PPP_END_KEEPALIVE);
        return;
    }
    p->echo_pending++;
    put32(m, p->w_magic ? p->magic : 0);
    tx_cp(p, PPP_PROTO_LCP, LCP_ECHO_REQ, ppp_fsm_new_id(&p->lcp), m, 4, NULL, 0);
}

/* ---------------------------------------------------------------- */
/* authentication (we are the authenticator) */

static const char msg_ok[] = "Welcome";
static const char msg_bad[] = "Authentication failed";

static int lookup_secret(ppp_t *p, const uint8_t *user, size_t ulen,
                         uint8_t *secret, size_t max)
{
    size_t i;

    if (p->cfg.secret_cb) {
        int n = p->cfg.secret_cb(p->cfg.ctx, user, ulen, secret, max);
        return (n < 0 || (size_t)n > max) ? -1 : n;
    }
    for (i = 0; i < p->cfg.n_users; i++) {
        const ppp_user_t *u = &p->cfg.users[i];
        size_t sl;

        if (strlen(u->name) != ulen || memcmp(u->name, user, ulen) != 0)
            continue;
        sl = strlen(u->secret);
        if (sl > max)
            return -1;
        memcpy(secret, u->secret, sl);
        return (int)sl;
    }
    return -1;
}

/* compare without an early exit, so timing does not tell how many leading
 * octets matched */
static int same_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;

    while (n--)
        diff |= (uint8_t)(*a++ ^ *b++);
    return diff == 0;
}

static void chap_send_challenge(ppp_t *p)
{
    uint8_t v[17];
    const char *name = p->cfg.hostname;

    v[0] = 16;
    memcpy(v + 1, p->challenge, 16);
    tx_cp(p, PPP_PROTO_CHAP, CHAP_CHALLENGE, p->auth_id, v, 17,
          (const uint8_t *)name, strlen(name));
}

static void auth_start(ppp_t *p)
{
    p->auth_timer = p->lcp.restart_ms;
    p->auth_tries = 1;
    if (p->auth_proto == PPP_AUTH_CHAP || p->auth_proto == PPP_AUTH_MSCHAPV2) {
        /* RFC 1994 4.1: a new identifier and an unpredictable value for
         * every new challenge (the 16-octet MS-CHAPv2 authenticator
         * challenge is sent the same way) */
        p->auth_id++;
        nonce(p, p->challenge, 16);
        chap_send_challenge(p);
    }
    /* PAP: the peer speaks first (RFC 1334 2.2); we only wait */
}

static void auth_tick(ppp_t *p, uint32_t ms)
{
    if (p->phase != PPP_PHASE_AUTHENTICATE || p->auth_done)
        return;
    while (ms >= p->auth_timer) {
        ms -= p->auth_timer;
        p->auth_timer = p->lcp.restart_ms;
        if (p->auth_tries >= p->lcp.max_configure) {
            request_close(p, PPP_END_AUTH_TIMEOUT);
            return;
        }
        p->auth_tries++;
        if (p->auth_proto == PPP_AUTH_CHAP || p->auth_proto == PPP_AUTH_MSCHAPV2)
            chap_send_challenge(p);   /* retransmission: same id and value */
    }
    p->auth_timer -= ms;
}

static void auth_reply(ppp_t *p, uint8_t id)
{
    const char *msg = p->auth_ok ? msg_ok : msg_bad;
    size_t ml = strlen(msg);

    if (p->auth_proto == PPP_AUTH_MSCHAPV2) {
        /* RFC 2759 section 5: Success carries "S=<auth response> M=<text>",
         * Failure "E=<error> R=<retry> V=<version>". We do not offer a retry. */
        if (p->auth_ok) {
            uint8_t m[42 + 10];
            memcpy(m, p->mschap2_resp, 42);
            memcpy(m + 42, " M=Welcome", 10);
            tx_cp(p, PPP_PROTO_CHAP, CHAP_SUCCESS, id, m, sizeof m, NULL, 0);
        } else {
            static const char e[] = "E=691 R=0 V=3";
            tx_cp(p, PPP_PROTO_CHAP, CHAP_FAILURE, id, (const uint8_t *)e, sizeof e - 1, NULL, 0);
        }
    } else if (p->auth_proto == PPP_AUTH_CHAP) {
        tx_cp(p, PPP_PROTO_CHAP, p->auth_ok ? CHAP_SUCCESS : CHAP_FAILURE, id,
              (const uint8_t *)msg, ml, NULL, 0);
    } else {
        uint8_t l = (uint8_t)ml;
        tx_cp(p, PPP_PROTO_PAP, p->auth_ok ? PAP_ACK : PAP_NAK, id,
              &l, 1, (const uint8_t *)msg, ml);
    }
}

static void auth_finish(ppp_t *p, uint8_t id, int ok,
                        const uint8_t *user, size_t ulen)
{
    size_t i;

    p->auth_done = 1;
    p->auth_ok = (uint8_t)(ok != 0);
    auth_reply(p, id);
    if (!ok) {
        /* RFC 1334 2.2.1 / RFC 1994 4.2: after a failure, end the link */
        request_close(p, PPP_END_AUTH_FAILED);
        return;
    }
    if (ulen > PPP_NAME_MAX)
        ulen = PPP_NAME_MAX;
    for (i = 0; i < ulen; i++)       /* keep the name printable for logs */
        p->peer_name[i] = (user[i] >= 0x20 && user[i] < 0x7f) ? (char)user[i] : '?';
    p->peer_name[ulen] = 0;
    network_start(p);
}

/* validate the common header; returns the data length or -1 */
static int cp_header(const uint8_t *pkt, size_t n)
{
    size_t len;

    if (n < 4)
        return -1;
    len = ((size_t)pkt[2] << 8) | pkt[3];
    if (len < 4 || len > n)
        return -1;
    return (int)(len - 4);
}

static void pap_input(ppp_t *p, const uint8_t *pkt, size_t n)
{
    int dl = cp_header(pkt, n);
    const uint8_t *d = pkt + 4, *user, *pass;
    size_t ul, pl;
    int ok;

    if (dl < 0 || pkt[0] != PAP_REQUEST)
        return;
    if (p->auth_done) {
        /* our answer was probably lost: repeat it (RFC 1334 2.2.1) */
        auth_reply(p, pkt[1]);
        return;
    }
    if (dl < 1)
        return;
    ul = d[0];
    if ((size_t)dl < 1 + ul + 1)
        return;
    user = d + 1;
    pl = d[1 + ul];
    if ((size_t)dl < 2 + ul + pl)
        return;
    pass = d + 2 + ul;

    if (p->cfg.pap_cb) {
        ok = p->cfg.pap_cb(p->cfg.ctx, user, ul, pass, pl) != 0;
    } else {
        uint8_t secret[PPP_SECRET_MAX];
        int sl = lookup_secret(p, user, ul, secret, sizeof secret);
        ok = sl >= 0 && (size_t)sl == pl && same_bytes(secret, pass, pl);
        memset(secret, 0, sizeof secret);
    }
    auth_finish(p, pkt[1], ok, user, ul);
}

static void chap_input(ppp_t *p, const uint8_t *pkt, size_t n)
{
    int dl = cp_header(pkt, n);
    const uint8_t *d = pkt + 4, *user;
    uint8_t secret[PPP_SECRET_MAX], want[24];
    size_t vs, ul;
    int sl, ok = 0;

    if (dl < 0 || pkt[0] != CHAP_RESPONSE)
        return;
    /* RFC 1994 4.1: the Response identifier must be the Challenge's */
    if (pkt[1] != p->auth_id)
        return;
    if (p->auth_done) {
        /* same answer for a repeated Response */
        auth_reply(p, pkt[1]);
        return;
    }
    if (dl < 1)
        return;
    vs = d[0];
    if ((size_t)dl < 1 + vs)
        return;
    user = d + 1 + vs;
    ul = (size_t)dl - 1 - vs;

    sl = lookup_secret(p, user, ul, secret, sizeof secret);
    if (p->auth_proto == PPP_AUTH_MSCHAPV2) {
        /* RFC 2759: the 49-octet value is PeerChallenge[16], Reserved[8],
         * NT-Response[24], Flags[1]. Our challenge is the authenticator
         * challenge. Match the NT-Response, then build the authenticator
         * response and derive the MPPE master keys. */
        if (sl >= 0 && vs == 49) {
            const uint8_t *peer = d + 1, *ntr = d + 1 + 24;
            ppp_mschap2_nt_response(p->challenge, peer, user, ul, secret, (size_t)sl, want);
            ok = same_bytes(want, ntr, 24);
            if (ok) {
                ppp_mschap2_auth_response(secret, (size_t)sl, ntr, peer, p->challenge,
                                          user, ul, p->mschap2_resp);
                ppp_mppe_master_keys(secret, (size_t)sl, ntr, 16, p->mppe_send, p->mppe_recv);
                p->mppe_have = 1;
            }
        }
    } else if (sl >= 0 && vs == 16) {
        /* RFC 1994 4.1: MD5 over identifier, secret, challenge value */
        ppp_md5_t m;
        ppp_md5_init(&m);
        ppp_md5_update(&m, &p->auth_id, 1);
        ppp_md5_update(&m, secret, (size_t)sl);
        ppp_md5_update(&m, p->challenge, 16);
        ppp_md5_final(&m, want);
        ok = same_bytes(want, d + 1, 16);
    }
    memset(secret, 0, sizeof secret);
    auth_finish(p, pkt[1], ok, user, ul);
}

/* ---------------------------------------------------------------- */
/* IPCP */

static void ipcp_reset(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    p->our_ip = p->cfg.our_ip;
    p->w_addr = (p->our_ip != 0);
    p->addr_naks = 0;
}

static size_t ipcp_build_cr(ppp_fsm_t *f, uint8_t *o, size_t max)
{
    ppp_t *p = (ppp_t *)f->ctx;

    (void)max;
    if (!p->w_addr)
        return 0;
    o[0] = IPCP_OPT_ADDR;
    o[1] = 6;
    put32(o + 2, p->our_ip);
    return 6;
}

static int ipcp_judge(ppp_t *p, uint8_t type, const uint8_t *val, size_t vlen,
                      uint8_t *sugg, size_t *slen)
{
    uint32_t v = vlen == 4 ? get32(val) : 0;
    uint32_t dns;

    switch (type) {
    case IPCP_OPT_ADDR:
        if (p->cfg.peer_ip == 0) {
            /* no address to hand out: take what the peer brings */
            if (v == 0)
                return PPP_CONF_REJ;
            p->pend_peer_ip = v;
            return PPP_CONF_ACK;
        }
        if (v == p->cfg.peer_ip) {
            p->pend_peer_ip = v;
            return PPP_CONF_ACK;
        }
        put32(sugg, p->cfg.peer_ip);
        *slen = 4;
        return PPP_CONF_NAK;
    case IPCP_OPT_DNS1:
    case IPCP_OPT_DNS2:
        dns = type == IPCP_OPT_DNS1 ? p->cfg.dns1 : p->cfg.dns2;
        if (dns == 0)
            return PPP_CONF_REJ;
        if (v == dns)
            return PPP_CONF_ACK;
        put32(sugg, dns);
        *slen = 4;
        return PPP_CONF_NAK;
    default:
        /* IP-Compression-Protocol (Van Jacobson) is not implemented; the
         * deprecated IP-Addresses option and NBNS are not supported */
        return PPP_CONF_REJ;
    }
}

static int ipcp_recv_cr(ppp_fsm_t *f, const uint8_t *opts, size_t len,
                        uint8_t *out, size_t max, size_t *outlen)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    int has_addr = 0, r;

    p->pend_peer_ip = 0;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen))
        if (type == IPCP_OPT_ADDR)
            has_addr = 1;
    r = negotiate(p, f, ipcp_judge, opts, len, out, max, outlen);
    if (r == PPP_CONF_ACK && !has_addr && p->cfg.peer_ip != 0) {
        /* RFC 1332 3.3: the peer did not ask for an address; a Nak may
         * add the option to tell it which one to use */
        if (f->failures < f->max_failure && max >= 6) {
            out[0] = IPCP_OPT_ADDR;
            out[1] = 6;
            put32(out + 2, p->cfg.peer_ip);
            *outlen = 6;
            return PPP_CONF_NAK;
        }
        p->pend_peer_ip = p->cfg.peer_ip;   /* it will not; assume ours */
    }
    return r;
}

static void ipcp_recv_ack(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    (void)f; (void)opts; (void)len;
}

static void ipcp_recv_nak(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;

    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type != IPCP_OPT_ADDR || vlen != 4)
            continue;
        if (p->cfg.our_ip == 0) {
            /* we were not given an address: let the peer name ours */
            p->our_ip = get32(val);
            p->w_addr = (p->our_ip != 0);
        } else if (++p->addr_naks >= f->max_failure) {
            /* our address is configured and not up for discussion */
            request_close(p, PPP_END_IPCP_FAILED);
        }
    }
}

static void ipcp_recv_rej(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;

    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen))
        if (type == IPCP_OPT_ADDR)
            p->w_addr = 0;
}

static void ipcp_up(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    p->peer_ip = p->pend_peer_ip;
}

static void ipcp_finished(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    /* IPCP gave up or was closed by the peer. IP is the only network
     * protocol here, so the link has nothing left to carry. */
    if (!p->ipcp_closing && p->phase == PPP_PHASE_NETWORK)
        request_close(p, PPP_END_IPCP_FAILED);
}

static const ppp_fsm_ops_t ipcp_ops = {
    fsm_send, ipcp_reset, ipcp_build_cr, ipcp_recv_cr,
    ipcp_recv_ack, ipcp_recv_nak, ipcp_recv_rej,
    ipcp_up, NULL, NULL, ipcp_finished, NULL
};

/* ---------------------------------------------------------------- */
/* CCP (RFC 1962)
 *
 * An option in a Configure-Request names an algorithm the sender of the
 * request is willing to decompress (RFC 1962 section 4). So our request
 * is about the direction we receive and the peer's request about the
 * direction we transmit; the two are settled independently and may come
 * out different, or one of them empty.
 *
 * Our request carries one algorithm at a time: PPP Deflate, then the same
 * under its draft number, then MPPC, each dropped when the peer rejects
 * it; in the end an empty request (nothing compressed towards us). That
 * way an Ack never leaves open which algorithm the peer will use.
 *
 * Of the peer's request we take one option: Deflate before Deflate under
 * the draft number before MPPC. Everything else in it is rejected, so the
 * peer comes back with that one alone and gets its Ack. */

static unsigned comp_of(unsigned opt)
{
    return opt == CCP_OPT_MPPC ? PPP_COMP_MPPC : opt ? PPP_COMP_DEFLATE : PPP_COMP_NONE;
}

static unsigned cw_bit(unsigned opt)
{
    return opt == CCP_OPT_DEFLATE ? 1u : opt == CCP_OPT_DEFLATE_DRAFT ? 2u : 4u;
}

/* the next algorithm to ask the peer for, 0 when none is left */
static void ccp_pick(ppp_t *p)
{
    static const uint8_t order[3] = { CCP_OPT_DEFLATE, CCP_OPT_DEFLATE_DRAFT, CCP_OPT_MPPC };
    int i;

    p->cw_opt = 0;
    p->cw_naks = 0;
    if (p->cfg.comp_no_rx)
        return;
    for (i = 0; i < 3; i++) {
        if ((p->cfg.comp & comp_of(order[i])) && !(p->cw_tried & cw_bit(order[i]))) {
            p->cw_opt = order[i];
            return;
        }
    }
}

static void ccp_drop_wish(ppp_t *p)
{
    if (p->cw_opt)
        p->cw_tried |= (uint8_t)cw_bit(p->cw_opt);
    ccp_pick(p);
}

static void ccp_reset(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    /* what the peer refused earlier in this session stays refused */
    p->cw_wbits = p->cfg.deflate_wbits;
    ccp_pick(p);
}

static size_t ccp_build_cr(ppp_fsm_t *f, uint8_t *o, size_t max)
{
    ppp_t *p = (ppp_t *)f->ctx;

    (void)max;
    if (p->cw_opt == CCP_OPT_MPPC) {
        /* RFC 2118 section 2 */
        o[0] = CCP_OPT_MPPC;
        o[1] = 6;
        put32(o + 2, MPPC_BIT);
        return 6;
    }
    if (p->cw_opt) {
        /* RFC 1979 section 3: window (log2 - 8) and method in one octet,
         * then MBZ and the check method, both zero. Four octets in all,
         * as the figure there shows (its text says "Length 3"). */
        o[0] = p->cw_opt;
        o[1] = 4;
        o[2] = (uint8_t)((p->cw_wbits - 8) << 4 | DEFLATE_METHOD);
        o[3] = 0;
        return 4;
    }
    return 0;
}

static int ccp_judge(ppp_t *p, uint8_t type, const uint8_t *val, size_t vlen,
                     uint8_t *sugg, size_t *slen)
{
    /* RFC 1962 section 4: an option we do not know MUST be rejected; one
     * we know but will not use next to the one we chose is rejected too */
    if (type != p->cchosen)
        return PPP_CONF_REJ;
    if (type == CCP_OPT_MPPC) {
        /* vlen is 4 (checked when it was chosen). RFC 2118 section 2: all
         * other bits MUST be 0. Windows sets its encryption bits (RFC
         * 3078) here as well: the Nak says compression only. */
        if (get32(val) == MPPC_BIT) {
            p->cpend_opt = type;
            p->cpend_wbits = 0;
            return PPP_CONF_ACK;
        }
        put32(sugg, MPPC_BIT);
        *slen = 4;
        return PPP_CONF_NAK;
    }
    /* PPP Deflate. The window is the most the peer's decompressor holds;
     * we may use less (RFC 1979 section 3), so any valid size is fine. */
    if (vlen == 2 && (val[0] & 0x0f) == DEFLATE_METHOD && val[1] == 0 &&
        (val[0] >> 4) + 8 <= 15) {
        p->cpend_opt = type;
        p->cpend_wbits = (uint8_t)((val[0] >> 4) + 8);
        return PPP_CONF_ACK;
    }
    sugg[0] = (uint8_t)((15 - 8) << 4 | DEFLATE_METHOD);
    if (vlen >= 1 && (val[0] >> 4) + 8 <= 15)
        sugg[0] = (uint8_t)((val[0] & 0xf0) | DEFLATE_METHOD);
    sugg[1] = 0;
    *slen = 2;
    return PPP_CONF_NAK;
}

static int ccp_recv_cr(ppp_fsm_t *f, const uint8_t *opts, size_t len,
                       uint8_t *out, size_t max, size_t *outlen)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    int rank = 0;

    p->cpend_opt = 0;
    p->cpend_wbits = 0;
    p->cchosen = 0;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        int r = 0;

        if (type == CCP_OPT_DEFLATE && (p->cfg.comp & PPP_COMP_DEFLATE)) r = 3;
        else if (type == CCP_OPT_DEFLATE_DRAFT && (p->cfg.comp & PPP_COMP_DEFLATE)) r = 2;
        else if (type == CCP_OPT_MPPC && (p->cfg.comp & PPP_COMP_MPPC) && vlen == 4) r = 1;
        if (r > rank) {
            rank = r;
            p->cchosen = type;
        }
    }
    return negotiate(p, f, ccp_judge, opts, len, out, max, outlen);
}

static void ccp_recv_ack(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    (void)f; (void)opts; (void)len;
}

static void ccp_recv_nak(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    int ours = 0;

    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type != p->cw_opt)
            continue;
        ours = 1;
        if (type != CCP_OPT_MPPC && vlen == 2 && (val[0] & 0x0f) == DEFLATE_METHOD &&
            val[1] == 0 && (val[0] >> 4) + 8 <= p->cw_wbits) {
            /* the peer compresses with a smaller window than we offered */
            p->cw_wbits = (uint8_t)((val[0] >> 4) + 8);
            if (++p->cw_naks > CW_NAK_LIMIT)
                ccp_drop_wish(p);
        } else {
            /* a larger window than we have, another method, or MPPC with
             * bits we do not do: not with us */
            ccp_drop_wish(p);
        }
    }
    /* RFC 1962 section 4: a Nak lists what would be acceptable. If ours is
     * not in it, try the next one; the order gets to whatever it names. */
    if (!ours && len > 0)
        ccp_drop_wish(p);
}

static void ccp_recv_rej(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;

    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen))
        if (type == p->cw_opt)
            ccp_drop_wish(p);
}

static void ccp_up(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    p->tx_alg = (uint8_t)comp_of(p->cpend_opt);
    p->rx_alg = (uint8_t)comp_of(p->cw_opt);
    /* RFC 1979 2.1 / RFC 2118 3.1: both counts start at 0 with an empty history */
    p->tx_seq = p->rx_seq = 0;
    p->rx_wait = 0;
    p->comp_credit = PPP_MAX_MRU;
    p->cnt.ccp_opens++;
    if (p->tx_alg == PPP_COMP_DEFLATE) {
        ppp_deflate_enc_init(&p->cenc.d, p->cpend_wbits, NULL);
        p->cnt.comp_tx_wbits = p->cenc.d.wbits;
    } else if (p->tx_alg == PPP_COMP_MPPC) {
        ppp_mppc_enc_init(&p->cenc.m);
        p->cnt.comp_tx_wbits = 0;
    }
    if (p->rx_alg == PPP_COMP_DEFLATE) {
        ppp_deflate_dec_init(&p->cdec.d);
        p->cnt.comp_rx_wbits = p->cw_wbits;
    } else if (p->rx_alg == PPP_COMP_MPPC) {
        ppp_mppc_dec_init(&p->cdec.m);
        p->cnt.comp_rx_wbits = 0;
    }
    if (p->tx_alg) p->cnt.comp_tx = p->tx_alg;
    if (p->rx_alg) p->cnt.comp_rx = p->rx_alg;
}

static void ccp_down(ppp_fsm_t *f)
{
    ppp_t *p = (ppp_t *)f->ctx;

    /* RFC 1962 2.1: compressed datagrams only while CCP is Opened */
    p->tx_alg = p->rx_alg = PPP_COMP_NONE;
    p->rx_wait = 0;
}

/* Negotiate CCP anew from the Opened state (RFC 1979 section 2 allows
 * this in place of a Reset-Request; here it is the way out when resets
 * get no answer). */
static void ccp_renegotiate(ppp_t *p)
{
    if (p->ccp.state != PPP_FSM_OPENED)
        return;
    ppp_fsm_down(&p->ccp);
    ppp_fsm_up(&p->ccp);
}

/* RFC 1962 3.1: the decompressor has lost step. Ask the peer to start its
 * compressor afresh; until it has, compressed packets are discarded. */
static void comp_rx_error(ppp_t *p)
{
    p->cnt.comp_rx_errors++;
    p->cnt.comp_rx_dropped++;
    if (p->ccp.rejected_codes & (1u << CCP_RESET_REQ)) {
        ccp_renegotiate(p);                 /* the peer has no Reset-Request */
        return;
    }
    p->rx_wait = 1;
    p->rr_id = ppp_fsm_new_id(&p->ccp);
    p->rr_tries = 1;
    p->rr_timer = p->cfg.comp_reset_ms ? p->cfg.comp_reset_ms : p->ccp.restart_ms;
    tx_cp_next(p, PPP_PROTO_CCP, CCP_RESET_REQ, p->rr_id);
}

/* RFC 1962 3.1: the request again, with the same identifier; when that has
 * been done often enough, CCP from the start */
static void comp_reset_again(ppp_t *p)
{
    if (p->rr_tries >= RESET_TRIES) {
        ccp_renegotiate(p);
        return;
    }
    p->rr_tries++;
    p->rr_timer = p->cfg.comp_reset_ms ? p->cfg.comp_reset_ms : p->ccp.restart_ms;
    tx_cp_next(p, PPP_PROTO_CCP, CCP_RESET_REQ, p->rr_id);
}

static void ccp_tick(ppp_t *p, uint32_t ms)
{
    uint32_t rate = p->cfg.comp_rate ? p->cfg.comp_rate : PPP_COMP_RATE;

    if (p->ccp.state != PPP_FSM_OPENED)
        return;
    if (p->comp_credit < PPP_MAX_MRU) {
        p->comp_credit += (int32_t)(ms * rate);
        if (p->comp_credit > PPP_MAX_MRU)
            p->comp_credit = PPP_MAX_MRU;
    }
    if (!p->rx_wait)
        return;
    if (ms < p->rr_timer) {
        p->rr_timer -= ms;
        return;
    }
    p->rr_timer = 0;
    /* With MPPC nothing answers a Reset-Request but the next packet, which
     * carries FLUSHED (RFC 2118 4.3; the Reset-Ack is not used). A peer
     * with nothing to send is not a peer that did not hear us: there the
     * request is repeated only when a packet shows that it is needed
     * (comp_input). */
    if (p->rx_alg == PPP_COMP_DEFLATE)
        comp_reset_again(p);
}

static int ccp_ext_code(ppp_fsm_t *f, uint8_t code, uint8_t id,
                        const uint8_t *data, size_t len)
{
    ppp_t *p = (ppp_t *)f->ctx;

    (void)data; (void)len;
    switch (code) {
    case CCP_RESET_REQ:
        if (f->state != PPP_FSM_OPENED)
            return PPP_FSM_EXT_NONE;
        /* RFC 1962 3.1: reset the compressor, and a Reset-Ack MUST go out
         * with the request's identifier, every time. */
        if (p->tx_alg == PPP_COMP_DEFLATE) {
            /* RFC 1979 section 2: history cleared, sequence number 0 */
            ppp_deflate_enc_reset(&p->cenc.d);
            p->tx_seq = 0;
        } else if (p->tx_alg == PPP_COMP_MPPC) {
            /* RFC 2118 4.3: history flushed, FLUSHED on the next packet;
             * the coherency count goes on */
            ppp_mppc_enc_flush(&p->cenc.m);
        }
        p->cnt.comp_tx_resets++;
        /* what is still waiting was compressed before the reset: the peer
         * could do nothing with it, and the Reset-Ack would wait behind it */
        tx_purge_compressed(p);
        f->ops->send(f, CCP_RESET_ACK, id, NULL, 0, NULL, 0);
        return PPP_FSM_EXT_NONE;
    case CCP_RESET_ACK:
        /* RFC 1962 3.1: for each Reset-Ack with the expected identifier.
         * MPPC does not use it: there the FLUSHED bit of a packet says
         * where the peer started afresh (RFC 2118 4.3). */
        if (f->state == PPP_FSM_OPENED && p->rx_wait && id == p->rr_id &&
            p->rx_alg == PPP_COMP_DEFLATE) {
            ppp_deflate_dec_reset(&p->cdec.d);
            p->rx_seq = 0;
            p->rx_wait = 0;
        }
        return PPP_FSM_EXT_NONE;
    default:
        return PPP_FSM_EXT_RUC;
    }
}

static const ppp_fsm_ops_t ccp_ops = {
    fsm_send, ccp_reset, ccp_build_cr, ccp_recv_cr,
    ccp_recv_ack, ccp_recv_nak, ccp_recv_rej,
    ccp_up, ccp_down, NULL, NULL, ccp_ext_code
};

static void network_start(ppp_t *p)
{
    set_phase(p, PPP_PHASE_NETWORK);
    ppp_fsm_open(&p->ipcp);
    ppp_fsm_up(&p->ipcp);
    /* RFC 1962 section 2: CCP belongs to the Network-Layer Protocol phase */
    p->cw_tried = 0;
    if (p->cfg.comp) {
        ppp_fsm_open(&p->ccp);
        ppp_fsm_up(&p->ccp);
    }
}

/* take IPCP and CCP all the way back to Initial, whatever state they are in */
static void network_stop(ppp_t *p)
{
    p->ipcp_closing = 1;
    ppp_fsm_down(&p->ipcp);
    ppp_fsm_close(&p->ipcp);
    p->ipcp_closing = 0;
    p->peer_ip = 0;
    ppp_fsm_down(&p->ccp);
    ppp_fsm_close(&p->ccp);
}

/* ---------------------------------------------------------------- */
/* receive path */

static void protocol_reject(ppp_t *p, uint16_t proto,
                            const uint8_t *info, size_t n)
{
    uint8_t pr[2];
    size_t room = (size_t)p->peer_mru - 6;   /* LCP header + protocol */

    p->cnt.rx_unknown_proto++;
    pr[0] = (uint8_t)(proto >> 8);
    pr[1] = (uint8_t)proto;
    if (n > room)
        n = room;
    tx_cp(p, PPP_PROTO_LCP, LCP_PROTO_REJ, ppp_fsm_new_id(&p->lcp),
          pr, 2, info, n);
}

/* a network-layer packet, as it arrived or after decompression */
static void net_input(ppp_t *p, uint16_t proto, const uint8_t *info, size_t n)
{
    switch (proto) {
    case PPP_PROTO_IPCP:
        ppp_fsm_input(&p->ipcp, info, n);
        break;
    case PPP_PROTO_IP:
        if (p->ipcp.state == PPP_FSM_OPENED) {
            p->cnt.rx_ip++;
            if (p->cfg.ip_rx)
                p->cfg.ip_rx(p->cfg.ctx, info, n);
        } else {
            p->cnt.rx_discards++;
        }
        break;
    default:
        protocol_reject(p, proto, info, n);
        break;
    }
}

/* a compressed datagram (protocol 0x00FD) while a decompressor is on */
static void comp_input(ppp_t *p, const uint8_t *info, size_t n)
{
    const uint8_t *d;
    unsigned hdr;
    uint16_t proto;
    size_t off;
    int r;

    p->cnt.comp_rx_in += (uint32_t)n;
    if (n < 3) {
        if (!p->rx_wait)
            comp_rx_error(p);
        return;
    }
    hdr = (unsigned)info[0] << 8 | info[1];
    if (p->rx_alg == PPP_COMP_DEFLATE) {
        /* RFC 1979 section 2: everything is discarded between an error
         * and the Reset-Ack; the sequence number is checked before the
         * packet is decoded */
        if (p->rx_wait) {
            p->cnt.comp_rx_dropped++;
            return;
        }
        r = hdr == p->rx_seq ? ppp_deflate_decompress(&p->cdec.d, info + 2, n - 2, p->cbuf_rx, sizeof p->cbuf_rx) : -1;
        if (r < 1) {
            comp_rx_error(p);
            return;
        }
        p->rx_seq++;
        d = p->cbuf_rx;
    } else {
        /* RFC 2118 3.1 and 4.3 */
        if (hdr & PPP_MPPC_FLUSHED) {
            /* the peer started afresh with this packet: so do we, and its
             * count is the one to go by */
            ppp_mppc_dec_flush(&p->cdec.m);
            p->rx_seq = hdr & PPP_MPPC_COUNT_MASK;
            p->rx_wait = 0;
        } else if (p->rx_wait) {
            p->cnt.comp_rx_dropped++;
            /* still the old history, a Restart period after we asked */
            if (p->rr_timer == 0)
                comp_reset_again(p);
            return;
        }
        if ((hdr & PPP_MPPC_COUNT_MASK) != p->rx_seq || (hdr & PPP_MPPC_ENCRYPTED)) {
            comp_rx_error(p);
            return;
        }
        p->rx_seq = (p->rx_seq + 1) & PPP_MPPC_COUNT_MASK;
        if (hdr & PPP_MPPC_COMPRESSED) {
            r = ppp_mppc_decompress(&p->cdec.m, (hdr & PPP_MPPC_AT_FRONT) != 0,
                                    info + 2, n - 2, p->cbuf_rx, sizeof p->cbuf_rx);
            if (r < 1) {
                comp_rx_error(p);
                return;
            }
            d = p->cbuf_rx;
        } else {
            /* sent as it was because it would have grown (section 3,
             * "Data Expansion"); the peer flushes after it */
            d = info + 2;
            r = (int)(n - 2);
        }
    }
    /* The packet starts with its Protocol field (RFC 1979 2.1: in one
     * octet where the number allows; RFC 2118 3.1 does not say, so either
     * form is taken: the first octet of a two-octet number is even, RFC
     * 1661 section 2). */
    if (d[0] & 1) {
        proto = d[0];
        off = 1;
    } else if (r >= 2 && (d[1] & 1)) {
        proto = (uint16_t)((unsigned)d[0] << 8 | d[1]);
        off = 2;
    } else {
        p->cnt.rx_bad_header++;
        return;
    }
    p->cnt.comp_rx_out += (uint32_t)((size_t)r - off);
    /* only network-layer packets are ever compressed (RFC 1979 section 2,
     * RFC 2118 section 3) */
    if (proto >= 0x4000 || proto == PPP_PROTO_COMP || proto == 0x00fb) {
        p->cnt.rx_bad_header++;
        return;
    }
    net_input(p, proto, d + off, (size_t)r - off);
}

static void handle_frame(ppp_t *p)
{
    const uint8_t *info;
    uint16_t proto;
    size_t off, n;

    if (ppp_hdlc_parse(p->rx.buf, p->rx.len, p->rx_acfc, p->rx_pfc,
                       &proto, &off) != 0) {
        p->cnt.rx_bad_header++;
        return;
    }
    info = p->rx.buf + off;
    n = p->rx.len - off;

    if (proto == PPP_PROTO_LCP) {
        int was_open = p->lcp.state == PPP_FSM_OPENED;

        ppp_fsm_input(&p->lcp, info, n);
        if (was_open && p->lcp.state == PPP_FSM_STOPPING &&
            n > 0 && info[0] == PPP_TERM_REQ)
            set_end(p, PPP_END_PEER_TERMINATED);
        return;
    }
    /* RFC 1661 3.4: before LCP is Opened everything else is discarded */
    if (p->lcp.state != PPP_FSM_OPENED) {
        p->cnt.rx_discards++;
        return;
    }
    if (proto == PPP_PROTO_PAP || proto == PPP_PROTO_CHAP) {
        int match = proto == PPP_PROTO_PAP
                        ? p->auth_proto == PPP_AUTH_PAP
                        : (p->auth_proto == PPP_AUTH_CHAP || p->auth_proto == PPP_AUTH_MSCHAPV2);

        if (match) {
            if (proto == PPP_PROTO_PAP)
                pap_input(p, info, n);
            else
                chap_input(p, info, n);
        } else if (p->phase == PPP_PHASE_NETWORK) {
            protocol_reject(p, proto, info, n);
        } else {
            p->cnt.rx_discards++;
        }
        return;
    }
    /* RFC 1661 3.5: network-layer traffic only after authentication */
    if (p->phase != PPP_PHASE_NETWORK) {
        p->cnt.rx_discards++;
        return;
    }
    /* RFC 1979 section 2, "Data Expansion": with Deflate, a packet that
     * arrives in its native form was sent that way because it did not
     * shrink. It still went through the peer's compressor, so it goes
     * into our history and takes a sequence number: every protocol number
     * from 0x0000 to 0x3FFF except the two for compressed datagrams. The
     * Protocol field is taken in its one-octet form where it has one
     * (RFC 1979 2.1), however it came. */
    if (p->rx_alg == PPP_COMP_DEFLATE && !p->rx_wait && proto < 0x4000 &&
        proto != PPP_PROTO_COMP && proto != 0x00fb) {
        uint8_t pf[2];
        size_t pl = 0;

        if (proto > 0xff)
            pf[pl++] = (uint8_t)(proto >> 8);
        pf[pl++] = (uint8_t)proto;
        ppp_deflate_dec_add(&p->cdec.d, pf, pl, info, n);
        p->rx_seq++;
        p->cnt.comp_rx_in += (uint32_t)n;
        p->cnt.comp_rx_out += (uint32_t)n;
    }
    switch (proto) {
    case PPP_PROTO_CCP:
        if (p->cfg.comp)
            ppp_fsm_input(&p->ccp, info, n);
        else
            protocol_reject(p, proto, info, n);
        break;
    case PPP_PROTO_COMP:
        if (p->rx_alg != PPP_COMP_NONE)
            comp_input(p, info, n);
        else if (p->cfg.comp)
            p->cnt.rx_discards++;       /* RFC 1962 2.1: not before CCP is Opened */
        else
            protocol_reject(p, proto, info, n);
        break;
    default:
        net_input(p, proto, info, n);
        break;
    }
}

/* ---------------------------------------------------------------- */
/* public API */

void ppp_config_default(ppp_config_t *c)
{
    memset(c, 0, sizeof *c);
    c->hostname = "v90d";
    c->mru = PPP_MAX_MRU;
    c->restart_ms = 3000;
    c->max_configure = 10;
    c->max_terminate = 2;
    c->max_failure = 5;
    c->echo_max_fail = 3;
    c->comp = PPP_COMP_DEFLATE | PPP_COMP_MPPC;
}

static void fsm_setup(ppp_t *p, ppp_fsm_t *f, const ppp_fsm_ops_t *ops)
{
    ppp_fsm_init(f, ops, p, p->scratch, sizeof p->scratch);
    f->restart_ms = p->cfg.restart_ms;
    f->max_configure = p->cfg.max_configure;
    f->max_terminate = p->cfg.max_terminate;
    f->max_failure = p->cfg.max_failure;
}

void ppp_init(ppp_t *p, const ppp_config_t *cfg)
{
    uint8_t seed[4];

    memset(p, 0, sizeof *p);
    p->cfg = *cfg;
    /* zero means "default" for these */
    if (!p->cfg.hostname) p->cfg.hostname = "v90d";
    if (!p->cfg.restart_ms) p->cfg.restart_ms = 3000;
    if (!p->cfg.max_configure) p->cfg.max_configure = 10;
    if (!p->cfg.max_terminate) p->cfg.max_terminate = 2;
    if (!p->cfg.max_failure) p->cfg.max_failure = 5;
    if (!p->cfg.echo_max_fail) p->cfg.echo_max_fail = 3;
    if (p->cfg.mru == 0 || p->cfg.mru > PPP_MAX_MRU) p->cfg.mru = PPP_MAX_MRU;
    if (p->cfg.mru < PPP_MIN_MRU) p->cfg.mru = PPP_MIN_MRU;
    if (!p->cfg.users) p->cfg.n_users = 0;

    fsm_setup(p, &p->lcp, &lcp_ops);
    fsm_setup(p, &p->ipcp, &ipcp_ops);
    fsm_setup(p, &p->ccp, &ccp_ops);
    p->cfg.comp &= PPP_COMP_DEFLATE | PPP_COMP_MPPC;
    if (p->cfg.deflate_wbits < PPP_DEFLATE_MIN_WBITS || p->cfg.deflate_wbits > PPP_DEFLATE_MAX_WBITS)
        p->cfg.deflate_wbits = PPP_DEFLATE_MAX_WBITS;
    ppp_hdlc_rx_init(&p->rx, PPP_HDLC_BUF);
    p->peer_mru = PPP_MAX_MRU;
    p->tx_accm = 0xffffffffu;
    p->phase = PPP_PHASE_DEAD;

    put32(seed, cfg->seed);
    ppp_add_entropy(p, seed, 4);
}

void ppp_lower_up(ppp_t *p)
{
    if (p->lcp.state != PPP_FSM_INITIAL || p->phase != PPP_PHASE_DEAD)
        ppp_lower_down(p);

    /* a new call: fresh framing state, counters and bookkeeping */
    ppp_hdlc_rx_init(&p->rx, PPP_HDLC_BUF);
    memset(&p->cnt, 0, sizeof p->cnt);
    p->tx_head = p->tx_tail = 0;
    p->end_reason = PPP_END_NONE;
    p->pending_close = PPP_END_NONE;
    p->peer_name[0] = 0;
    p->peer_ip = 0;
    p->our_ip = p->cfg.our_ip;

    set_phase(p, PPP_PHASE_ESTABLISH);
    ppp_fsm_open(&p->lcp);
    ppp_fsm_up(&p->lcp);
}

void ppp_lower_down(ppp_t *p)
{
    if (p->phase != PPP_PHASE_DEAD)
        set_end(p, PPP_END_LOWER_DOWN);
    ppp_fsm_down(&p->lcp);        /* This-Layer-Down if it was Opened */
    network_stop(p);
    ppp_fsm_close(&p->lcp);       /* settle in Initial */
    p->pending_close = PPP_END_NONE;
    p->tx_head = p->tx_tail = 0;  /* nothing can be sent any more */
    set_phase(p, PPP_PHASE_DEAD);
}

void ppp_close(ppp_t *p)
{
    do_close(p, PPP_END_LOCAL_CLOSE);
}

void ppp_input_bytes(ppp_t *p, const uint8_t *buf, size_t n)
{
    size_t i;

    for (i = 0; i < n && p->phase != PPP_PHASE_DEAD; i++) {
        p->rx_octets++;
        if (ppp_hdlc_rx_byte(&p->rx, buf[i])) {
            handle_frame(p);
            run_pending(p);
        }
    }
}

size_t ppp_output_pending(const ppp_t *p)
{
    return p->tx_tail - p->tx_head;
}

size_t ppp_output_bytes(ppp_t *p, uint8_t *buf, size_t max)
{
    size_t n = p->tx_tail - p->tx_head;

    if (n > max)
        n = max;
    memcpy(buf, p->txbuf + p->tx_head, n);
    p->tx_head += n;
    return n;
}

/* An IP packet through the compressor agreed for our direction. Whatever
 * comes of it must go out, in this order: the peer's history follows
 * ours packet by packet. So room for the worst case is made sure of
 * before the compressor sees the packet. */
static int send_compressed(ppp_t *p, const uint8_t *pkt, size_t len)
{
    /* every octet escaped, header, FCS, flags; and the uncompressed MPPC
     * form has four octets in front of the packet */
    size_t need = 2 * (len + 10) + 2 + PPP_TX_RESERVE;
    uint8_t h[4];
    size_t cn, sent;
    int r;

    if (PPP_TX_BUF - (p->tx_tail - p->tx_head) < need)
        return PPP_ERR_FULL;
    if (p->comp_credit <= 0)
        return PPP_ERR_FULL;
    if (p->comp_queue && p->tx_tail - p->tx_head > p->comp_queue)
        return PPP_ERR_FULL;
    p->comp_credit -= (int32_t)len;

    if (p->tx_alg == PPP_COMP_DEFLATE) {
        /* RFC 1979 2.1: the Protocol field in one octet, then the packet.
         * The sequence number counts every packet, sent compressed or not. */
        static const uint8_t proto1[1] = { PPP_PROTO_IP };

        h[0] = (uint8_t)(p->tx_seq >> 8);
        h[1] = (uint8_t)p->tx_seq;
        p->tx_seq++;
        /* compressed only if that is shorter, sequence number included
         * (RFC 1979 section 2, "Data Expansion"); then it also fits the
         * peer's MRU, since the packet itself does */
        cn = ppp_deflate_compress(&p->cenc.d, proto1, 1, pkt, len, p->cbuf_tx, len > 3 ? len - 3 : 0);
        if (cn) {
            r = tx_frame(p, PPP_PROTO_COMP, h, 2, p->cbuf_tx, cn, NULL, 0, PPP_TX_RESERVE);
            sent = cn + 2;
        } else {
            r = tx_frame(p, PPP_PROTO_IP, NULL, 0, pkt, len, NULL, 0, PPP_TX_RESERVE);
            sent = len;
            p->cnt.comp_tx_native++;
        }
    } else {
        /* RFC 2118 3.1: the Protocol field (two octets here), then the
         * packet. A compressed packet may be at most one octet longer
         * than the packet was (beyond that it has expanded, section 3)
         * and must fit the peer's MRU with its two-octet header. */
        static const uint8_t proto2[2] = { 0x00, PPP_PROTO_IP };
        size_t max = len + 1;
        unsigned bits;

        if (max > (size_t)p->peer_mru - 2)
            max = (size_t)p->peer_mru - 2;
        cn = ppp_mppc_compress(&p->cenc.m, proto2, 2, pkt, len, p->cbuf_tx, max, &bits);
        h[0] = (uint8_t)((bits | p->tx_seq) >> 8);
        h[1] = (uint8_t)p->tx_seq;
        if (cn) {
            r = tx_frame(p, PPP_PROTO_COMP, h, 2, p->cbuf_tx, cn, NULL, 0, PPP_TX_RESERVE);
            sent = cn + 2;
            p->tx_seq = (p->tx_seq + 1) & PPP_MPPC_COUNT_MASK;
        } else if (len + 4 <= p->peer_mru) {
            /* "the original data is sent as an uncompressed MPPC packet" */
            h[2] = proto2[0];
            h[3] = proto2[1];
            r = tx_frame(p, PPP_PROTO_COMP, h, 4, pkt, len, NULL, 0, PPP_TX_RESERVE);
            sent = len + 4;
            p->tx_seq = (p->tx_seq + 1) & PPP_MPPC_COUNT_MASK;
            p->cnt.comp_tx_native++;
        } else {
            /* that would be longer than the peer's MRU: in its standard
             * form (RFC 1962 2.1), which MPPC does not count */
            r = tx_frame(p, PPP_PROTO_IP, NULL, 0, pkt, len, NULL, 0, PPP_TX_RESERVE);
            sent = len;
            p->cnt.comp_tx_native++;
        }
    }
    if (r != 0) {
        /* not reached: the room was checked. If it were, the peer would
         * see a gap in the sequence and ask for a reset. */
        p->cnt.tx_dropped++;
        return PPP_ERR_FULL;
    }
    p->cnt.comp_tx_in += (uint32_t)len;
    p->cnt.comp_tx_out += (uint32_t)sent;
    p->cnt.tx_ip++;
    return 0;
}

void ppp_set_comp_queue(ppp_t *p, size_t octets)
{
    p->comp_queue = octets;
}

int ppp_send_ip(ppp_t *p, const uint8_t *pkt, size_t len)
{
    if (p->phase != PPP_PHASE_NETWORK || p->ipcp.state != PPP_FSM_OPENED)
        return PPP_ERR_DOWN;
    if (len > p->peer_mru)
        return PPP_ERR_SIZE;
    /* LCP, IPCP and CCP packets never come this way: only IP is compressed */
    if (p->tx_alg != PPP_COMP_NONE && len > 0)
        return send_compressed(p, pkt, len);
    if (tx_frame(p, PPP_PROTO_IP, NULL, 0, pkt, len, NULL, 0, PPP_TX_RESERVE) != 0)
        return PPP_ERR_FULL;
    p->cnt.tx_ip++;
    return 0;
}

void ppp_tick(ppp_t *p, uint32_t ms)
{
    if (p->phase == PPP_PHASE_DEAD)
        return;
    p->uptime_ms += ms;
    ppp_fsm_tick(&p->lcp, ms);
    ppp_fsm_tick(&p->ipcp, ms);
    ppp_fsm_tick(&p->ccp, ms);
    ccp_tick(p, ms);
    auth_tick(p, ms);
    keepalive_tick(p, ms);
    run_pending(p);
}

void ppp_get_status(const ppp_t *p, ppp_status_t *st)
{
    int lcp_open = p->lcp.state == PPP_FSM_OPENED;

    memset(st, 0, sizeof *st);
    st->phase = p->phase;
    st->end_reason = p->end_reason;
    st->lcp_state = p->lcp.state;
    st->ipcp_state = p->ipcp.state;
    st->ccp_state = p->ccp.state;
    st->comp_tx = p->tx_alg;
    st->comp_rx = p->rx_alg;
    st->auth = p->auth_proto;
    st->authenticated = p->auth_done && p->auth_ok;
    memcpy(st->peer_name, p->peer_name, sizeof st->peer_name);
    st->ip_up = p->phase == PPP_PHASE_NETWORK && p->ipcp.state == PPP_FSM_OPENED;
    st->our_ip = p->our_ip;
    st->peer_ip = st->ip_up ? p->peer_ip : 0;
    st->dns1 = p->cfg.dns1;
    st->dns2 = p->cfg.dns2;
    st->our_mru = lcp_open ? p->mru : PPP_MAX_MRU;
    st->peer_mru = p->peer_mru;
    st->tx_accm = p->tx_accm;
    st->rx_accm = p->rx.rx_accm;
    st->our_magic = p->w_magic ? p->magic : 0;
    st->peer_magic = p->peer_magic;
    st->counters = p->cnt;
    st->counters.rx_frames = p->rx.frames_ok;
    st->counters.rx_bad_fcs = p->rx.bad_fcs;
    st->counters.rx_runts = p->rx.runts;
    st->counters.rx_overlong = p->rx.overlong;
    st->counters.rx_aborts = p->rx.aborts;
}
