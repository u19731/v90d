/* Test-side PPP client. See pppc.h. */
#include <string.h>
#include "pppc.h"
#include "ppp_md5.h"

#define P_IP    0x0021
#define P_COMP  0x00fd
#define P_CCP   0x80fd
#define P_IPCP  0x8021
#define P_LCP   0xc021
#define P_PAP   0xc023
#define P_CHAP  0xc223

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* ---- transmit ---- */
static void c_frame(pppc_t *c, uint16_t proto, const uint8_t *h, size_t hn,
                    const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    ppp_hdlc_tx_t tx;
    uint8_t hdr[4];
    size_t hl = 0, n;
    uint32_t accm = 0xffffffffu;

    if (proto == P_LCP) {
        hdr[hl++] = 0xff; hdr[hl++] = 0x03;
        hdr[hl++] = (uint8_t)(proto >> 8); hdr[hl++] = (uint8_t)proto;
    } else {
        accm = c->tx_accm;
        if (!c->tx_acfc) { hdr[hl++] = 0xff; hdr[hl++] = 0x03; }
        if (!(c->tx_pfc && proto < 0x100)) hdr[hl++] = (uint8_t)(proto >> 8);
        hdr[hl++] = (uint8_t)proto;
    }
    ppp_hdlc_tx_begin(&tx, c->tx + c->tx_n, sizeof c->tx - c->tx_n, accm, 1);
    ppp_hdlc_tx_add(&tx, hdr, hl);
    ppp_hdlc_tx_add(&tx, h, hn);
    ppp_hdlc_tx_add(&tx, a, an);
    ppp_hdlc_tx_add(&tx, b, bn);
    n = ppp_hdlc_tx_end(&tx);
    c->tx_n += n;
}

static void c_cp(pppc_t *c, uint16_t proto, uint8_t code, uint8_t id,
                 const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    uint8_t h[4];
    size_t len = 4 + an + bn;
    h[0] = code; h[1] = id; h[2] = (uint8_t)(len >> 8); h[3] = (uint8_t)len;
    c_frame(c, proto, h, 4, a, an, b, bn);
}

static void c_send(ppp_fsm_t *f, uint8_t code, uint8_t id,
                   const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c_cp(c, f == &c->lcp ? P_LCP : f == &c->ipcp ? P_IPCP : P_CCP, code, id, a, an, b, bn);
}

/* ---- LCP ---- */
static void l_reset(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->w_accm = (uint8_t)c->cfg.send_accm;
    c->w_pfc = (uint8_t)c->cfg.pfc;
    c->w_acfc = (uint8_t)c->cfg.acfc;
    c->w_mru = c->cfg.mru != 0;
    c->w_magic = c->cfg.magic != 0;
}

static size_t l_build(ppp_fsm_t *f, uint8_t *o, size_t max)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t n = 0;
    (void)max;
    if (c->w_mru) { o[n++] = 1; o[n++] = 4; o[n++] = (uint8_t)(c->cfg.mru >> 8); o[n++] = (uint8_t)c->cfg.mru; }
    if (c->w_accm) { o[n++] = 2; o[n++] = 6; wr32(o + n, c->cfg.accm); n += 4; }
    if (c->w_magic) { o[n++] = 5; o[n++] = 6; wr32(o + n, c->cfg.magic); n += 4; }
    if (c->w_pfc) { o[n++] = 7; o[n++] = 2; }
    if (c->w_acfc) { o[n++] = 8; o[n++] = 2; }
    return n;
}

/* the server's request: we take everything except an authentication
 * method we were told not to accept */
static int l_rcr(ppp_fsm_t *f, const uint8_t *opts, size_t len,
                 uint8_t *out, size_t max, size_t *outlen)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    (void)max;

    c->pend_auth = 0;
    c->pend_accm = 0xffffffffu;
    c->pend_mru = 1500;
    c->pend_pfc = c->pend_acfc = 0;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        switch (type) {
        case 1: c->pend_mru = (uint16_t)((val[0] << 8) | val[1]); break;
        case 2: c->pend_accm = rd32(val); break;
        case 3: {
            unsigned asked = (vlen == 2 && val[0] == 0xc0 && val[1] == 0x23) ? PPPC_AUTH_PAP
                           : (vlen == 3 && val[0] == 0xc2 && val[1] == 0x23 && val[2] == 5) ? PPPC_AUTH_CHAP
                           : (vlen == 3 && val[0] == 0xc2 && val[1] == 0x23 && val[2] == 0x81) ? PPPC_AUTH_MSCHAPV2
                           : 0;
            if (asked && (asked & c->cfg.accept_auth)) {
                c->pend_auth = asked;
            } else if (c->cfg.accept_auth & PPPC_AUTH_PAP) {
                static const uint8_t pap[] = { 3, 4, 0xc0, 0x23 };
                memcpy(out, pap, 4); *outlen = 4;
                return PPP_CONF_NAK;
            } else if (c->cfg.accept_auth & PPPC_AUTH_CHAP) {
                static const uint8_t chap[] = { 3, 5, 0xc2, 0x23, 5 };
                memcpy(out, chap, 5); *outlen = 5;
                return PPP_CONF_NAK;
            } else {
                memcpy(out, val - 2, vlen + 2); *outlen = vlen + 2;
                return PPP_CONF_REJ;
            }
            break;
        }
        case 5: break;
        case 7: c->pend_pfc = 1; break;
        case 8: c->pend_acfc = 1; break;
        default:
            memcpy(out, val - 2, vlen + 2); *outlen = vlen + 2;
            return PPP_CONF_REJ;
        }
    }
    return PPP_CONF_ACK;
}

static void l_ack(ppp_fsm_t *f, const uint8_t *o, size_t n) { (void)f; (void)o; (void)n; }
static void l_nak(ppp_fsm_t *f, const uint8_t *o, size_t n) { (void)f; (void)o; (void)n; }
static void l_rej(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type == 1) c->w_mru = 0;
        if (type == 2) c->w_accm = 0;
        if (type == 5) c->w_magic = 0;
        if (type == 7) c->w_pfc = 0;
        if (type == 8) c->w_acfc = 0;
    }
}

static void pap_send(pppc_t *c)
{
    uint8_t d[160];
    size_t ul = strlen(c->cfg.user), pl = strlen(c->cfg.pass);
    d[0] = (uint8_t)ul;
    memcpy(d + 1, c->cfg.user, ul);
    d[1 + ul] = (uint8_t)pl;
    memcpy(d + 2 + ul, c->cfg.pass, pl);
    c_cp(c, P_PAP, 1, ++c->pap_id, d, 2 + ul + pl, NULL, 0);
    c->auth_timer = c->lcp.restart_ms;
}

static void net_start(pppc_t *c)
{
    ppp_fsm_open(&c->ipcp);
    ppp_fsm_up(&c->ipcp);
    if (c->cfg.ccp) {
        ppp_fsm_open(&c->ccp);
        ppp_fsm_up(&c->ccp);
    }
}

static void l_up(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->lcp_is_up = 1;
    c->auth = c->pend_auth;
    c->tx_accm = c->pend_accm;
    c->peer_mru = c->pend_mru;
    c->tx_pfc = c->pend_pfc;
    c->tx_acfc = c->pend_acfc;
    c->rx.rx_accm = c->w_accm ? c->cfg.accm : 0xffffffffu;
    c->rx_pfc = c->w_pfc;
    c->rx_acfc = c->w_acfc;
    c->auth_ok = c->auth_failed = 0;
    c->chap_answered = 0;
    if (c->auth == PPPC_AUTH_PAP)
        pap_send(c);
    else if (c->auth == 0)
        net_start(c);
    /* CHAP: wait for the Challenge */
}

static void l_down(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->lcp_is_up = 0;
    c->ip_up = 0;
    ppp_fsm_down(&c->ipcp);
    ppp_fsm_close(&c->ipcp);
    ppp_fsm_down(&c->ccp);
    ppp_fsm_close(&c->ccp);
    c->tx_accm = 0xffffffffu;
    c->rx.rx_accm = 0xffffffffu;
    c->tx_pfc = c->tx_acfc = c->rx_pfc = c->rx_acfc = 0;
}

static void l_finished(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->terminated = 1;
}

static int l_ext(ppp_fsm_t *f, uint8_t code, uint8_t id, const uint8_t *d, size_t n)
{
    pppc_t *c = (pppc_t *)f->ctx;
    uint8_t m[4];
    switch (code) {
    case 8:
        c->proto_rejects++;
        return PPP_FSM_EXT_RXJ_GOOD;
    case 9:
        c->echo_requests++;
        if (f->state == PPP_FSM_OPENED && n >= 4 && !c->cfg.no_echo_reply) {
            wr32(m, c->w_magic ? c->cfg.magic : 0);
            c_cp(c, P_LCP, 10, id, m, 4, d + 4, n - 4);
        }
        return PPP_FSM_EXT_RXR;
    case 10:
    case 11:
        return PPP_FSM_EXT_RXR;
    default:
        return PPP_FSM_EXT_RUC;
    }
}

static const ppp_fsm_ops_t l_ops = {
    c_send, l_reset, l_build, l_rcr, l_ack, l_nak, l_rej,
    l_up, l_down, NULL, l_finished, l_ext
};

/* ---- IPCP (client: ask for an address and DNS) ---- */
static void i_reset(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->w_vj = (uint8_t)c->cfg.want_vj;
    c->w_dns1 = c->w_dns2 = (uint8_t)c->cfg.want_dns;
    c->my_ip = c->dns1 = c->dns2 = 0;
}

static size_t i_build(ppp_fsm_t *f, uint8_t *o, size_t max)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t n = 0;
    (void)max;
    if (c->w_vj) {
        static const uint8_t vj[] = { 2, 6, 0x00, 0x2d, 0x0f, 0x01 };
        memcpy(o + n, vj, 6); n += 6;
    }
    o[n++] = 3; o[n++] = 6; wr32(o + n, c->my_ip); n += 4;
    if (c->w_dns1) { o[n++] = 129; o[n++] = 6; wr32(o + n, c->dns1); n += 4; }
    if (c->w_dns2) { o[n++] = 131; o[n++] = 6; wr32(o + n, c->dns2); n += 4; }
    return n;
}

static int i_rcr(ppp_fsm_t *f, const uint8_t *opts, size_t len,
                 uint8_t *out, size_t max, size_t *outlen)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    (void)max;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type == 3 && vlen == 4) {
            c->server_ip = rd32(val);
        } else {
            memcpy(out, val - 2, vlen + 2); *outlen = vlen + 2;
            return PPP_CONF_REJ;
        }
    }
    return PPP_CONF_ACK;
}

static void i_ack(ppp_fsm_t *f, const uint8_t *o, size_t n) { (void)f; (void)o; (void)n; }
static void i_nak(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (vlen != 4) continue;
        if (type == 3) c->my_ip = rd32(val);
        if (type == 129) c->dns1 = rd32(val);
        if (type == 131) c->dns2 = rd32(val);
    }
}
static void i_rej(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type == 2) { c->w_vj = 0; c->vj_rejected = 1; }
        if (type == 129) c->w_dns1 = 0;
        if (type == 131) c->w_dns2 = 0;
    }
}
static void i_up(ppp_fsm_t *f) { ((pppc_t *)f->ctx)->ip_up = 1; }
static void i_down(ppp_fsm_t *f) { ((pppc_t *)f->ctx)->ip_up = 0; }

static const ppp_fsm_ops_t i_ops = {
    c_send, i_reset, i_build, i_rcr, i_ack, i_nak, i_rej,
    i_up, i_down, NULL, NULL, NULL
};

/* ---- CCP, the caller's side ---- */
/* The transmit buffer is whole frames between flags. Like the server (see
 * ppp.c), the client lets a reset pass what is waiting: index just behind
 * the frame going out now. */
static size_t c_cut(const pppc_t *c)
{
    size_t i = 0;
    while (i < c->tx_n && c->tx[i] != PPP_FLAG) i++;
    return i < c->tx_n ? i + 1 : c->tx_n;
}

static void cc_reset(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    int pppd = c->cfg.ccp == PPPC_CCP_PPPD;
    c->cw26 = (uint8_t)(pppd && !c->cfg.ccp_draft_only);
    c->cw24 = c->cw21 = (uint8_t)pppd;
    c->cw18 = (uint8_t)!pppd;
    c->cw_w = (uint8_t)(c->cfg.ccp_wbits ? c->cfg.ccp_wbits : 15);
    /* MPPC, 40-bit and 128-bit encryption, stateless mode (RFC 3078 2.1) */
    c->cw_bits = c->cfg.ccp == PPPC_CCP_WINDOWS_MPPE ? 0x01000061u : 1u;
}

static size_t cc_build(ppp_fsm_t *f, uint8_t *o, size_t max)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t n = 0;
    (void)max;
    if (c->cw26) { o[n++] = 26; o[n++] = 4; o[n++] = (uint8_t)((c->cw_w - 8) << 4 | 8); o[n++] = 0; }
    if (c->cw24) { o[n++] = 24; o[n++] = 4; o[n++] = (uint8_t)((c->cw_w - 8) << 4 | 8); o[n++] = 0; }
    if (c->cw21) { o[n++] = 21; o[n++] = 3; o[n++] = 0x2f; }       /* BSD-Compress, version 1, 15 bits */
    if (c->cw18) { o[n++] = 18; o[n++] = 6; wr32(o + n, c->cw_bits); n += 4; }
    return n;
}

/* the server's request names what it will decompress: what we compress with */
static int cc_rcr(ppp_fsm_t *f, const uint8_t *opts, size_t len,
                  uint8_t *out, size_t max, size_t *outlen)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen, n = 0;
    uint8_t type;
    const uint8_t *val;
    int pppd = c->cfg.ccp == PPPC_CCP_PPPD;
    (void)max;

    c->cp_opt = 0;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (pppd && (type == 26 || type == 24) && vlen == 2 && (val[0] & 15) == 8 && val[1] == 0 && !c->cp_opt) {
            c->cp_opt = type; c->cp_w = (uint8_t)((val[0] >> 4) + 8);
        } else if (!pppd && type == 18 && vlen == 4 && rd32(val) == 1 && !c->cp_opt) {
            c->cp_opt = 18;
        } else {
            memcpy(out + n, val - 2, vlen + 2); n += vlen + 2;
        }
    }
    *outlen = n;
    return n ? PPP_CONF_REJ : PPP_CONF_ACK;
}

static void cc_ack(ppp_fsm_t *f, const uint8_t *o, size_t n) { (void)f; (void)o; (void)n; }
static void cc_nak(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if ((type == 26 || type == 24) && vlen == 2) c->cw_w = (uint8_t)((val[0] >> 4) + 8);
        if (type == 18 && vlen == 4) c->cw_bits = rd32(val);
    }
}
static void cc_rej(ppp_fsm_t *f, const uint8_t *opts, size_t len)
{
    pppc_t *c = (pppc_t *)f->ctx;
    size_t pos = 0, vlen;
    uint8_t type;
    const uint8_t *val;
    while (ppp_fsm_next_option(opts, len, &pos, &type, &val, &vlen)) {
        if (type == 26) c->cw26 = 0;
        if (type == 24) c->cw24 = 0;
        if (type == 21) c->cw21 = 0;
        if (type == 18) c->cw18 = 0;
    }
}

static void cc_up(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->ccp_ups++;
    c->tx_alg = c->cp_opt == 18 ? PPPC_ALG_MPPC : c->cp_opt ? PPPC_ALG_DEFLATE : 0;
    /* several algorithms acked at once would leave open which one is meant;
     * like pppd, the first in the request counts */
    c->rx_alg = c->cw26 || c->cw24 ? PPPC_ALG_DEFLATE : c->cw18 && c->cw_bits == 1 ? PPPC_ALG_MPPC : 0;
    c->tx_w = c->cp_w; c->rx_w = c->cw_w;
    c->tx_seq = c->rx_seq = 0;
    c->rx_wait = 0;
    if (c->tx_alg == PPPC_ALG_DEFLATE) ppp_deflate_enc_init(&c->denc, c->cp_w, NULL);
    if (c->tx_alg == PPPC_ALG_MPPC) ppp_mppc_enc_init(&c->menc);
    if (c->rx_alg == PPPC_ALG_DEFLATE) ppp_deflate_dec_init(&c->ddec);
    if (c->rx_alg == PPPC_ALG_MPPC) ppp_mppc_dec_init(&c->mdec);
}

static void cc_down(ppp_fsm_t *f)
{
    pppc_t *c = (pppc_t *)f->ctx;
    c->tx_alg = c->rx_alg = 0;
    c->rx_wait = 0;
}

static int cc_ext(ppp_fsm_t *f, uint8_t code, uint8_t id, const uint8_t *d, size_t n)
{
    pppc_t *c = (pppc_t *)f->ctx;
    (void)d; (void)n;
    if (code == 14) {
        c->resets_rcvd++;
        if (c->cfg.ccp == 0 || c->ignore_reset_req || f->state != PPP_FSM_OPENED) return PPP_FSM_EXT_NONE;
        if (c->tx_alg == PPPC_ALG_DEFLATE) { ppp_deflate_enc_reset(&c->denc); c->tx_seq = 0; }
        if (c->tx_alg == PPPC_ALG_MPPC) ppp_mppc_enc_flush(&c->menc);
        /* what waits behind the frame in transmission is of no use to the
         * server now (a real stack's queue is its own affair; this one
         * simply drops it, control frames included) */
        c->tx_n = c_cut(c);
        c_cp(c, P_CCP, 15, id, NULL, 0, NULL, 0);
        return PPP_FSM_EXT_NONE;
    }
    if (code == 15) {
        c->reset_acks_rcvd++;
        if (c->rx_wait && id == c->rr_id && c->rx_alg == PPPC_ALG_DEFLATE) {
            ppp_deflate_dec_reset(&c->ddec); c->rx_seq = 0; c->rx_wait = 0;
        }
        return PPP_FSM_EXT_NONE;
    }
    return PPP_FSM_EXT_RUC;
}

static const ppp_fsm_ops_t cc_ops = {
    c_send, cc_reset, cc_build, cc_rcr, cc_ack, cc_nak, cc_rej,
    cc_up, cc_down, NULL, NULL, cc_ext
};

/* a Reset-Request, put in front of the frames that are waiting */
static void cc_reset_req(pppc_t *c)
{
    uint8_t tmp[40];
    size_t start = c->tx_n, cut = c_cut(c), n;

    c->resets_sent++;
    c->rr_ms = 0;
    c_cp(c, P_CCP, 14, c->rr_id, NULL, 0, NULL, 0);
    n = c->tx_n - start;
    if (n == 0 || n > sizeof tmp || cut >= start) return;
    memcpy(tmp, c->tx + start, n);
    memmove(c->tx + cut + n, c->tx + cut, start - cut);
    memcpy(c->tx + cut, tmp, n);
}

static void cc_error(pppc_t *c)
{
    c->comp_rx_bad++;
    c->rx_wait = 1;
    c->rr_id = ppp_fsm_new_id(&c->ccp);
    cc_reset_req(c);
}

static void c_deliver(pppc_t *c, const uint8_t *ip, size_t n)
{
    if (c->ip_up && n <= sizeof c->ip_last) {
        c->ip_count++;
        c->ip_len = n;
        memcpy(c->ip_last, ip, n);
    }
}

/* a compressed datagram from the server */
static void cc_input(pppc_t *c, const uint8_t *info, size_t n)
{
    static uint8_t out[1600];
    const uint8_t *d = out;
    unsigned hdr;
    int r;

    if (c->drop_rx_comp > 0) { c->drop_rx_comp--; return; }
    if (n < 3) return;
    c->comp_rx_octets += n;
    hdr = (unsigned)info[0] << 8 | info[1];
    c->last_rx_hdr = (uint16_t)hdr;
    if (c->rx_alg == PPPC_ALG_DEFLATE) {
        if (c->rx_wait) { c->comp_rx_dropped++; return; }
        r = hdr == c->rx_seq ? ppp_deflate_decompress(&c->ddec, info + 2, n - 2, out, sizeof out) : -1;
        if (r < 1) { cc_error(c); return; }
        c->rx_seq++;
    } else if (c->rx_alg == PPPC_ALG_MPPC) {
        if (hdr & PPP_MPPC_FLUSHED) { ppp_mppc_dec_flush(&c->mdec); c->rx_seq = hdr & 0xfff; c->rx_wait = 0; }
        else if (c->rx_wait) {
            /* MPPC: asked again only when a packet shows the need */
            c->comp_rx_dropped++;
            if (c->rr_ms >= (c->cfg.ccp_reset_ms ? c->cfg.ccp_reset_ms : c->ccp.restart_ms)) cc_reset_req(c);
            return;
        }
        if ((hdr & 0xfff) != c->rx_seq) { cc_error(c); return; }
        c->rx_seq = (c->rx_seq + 1) & 0xfff;
        if (hdr & PPP_MPPC_COMPRESSED) {
            r = ppp_mppc_decompress(&c->mdec, (hdr & PPP_MPPC_AT_FRONT) != 0, info + 2, n - 2, out, sizeof out);
            if (r < 1) { cc_error(c); return; }
        } else { d = info + 2; r = (int)n - 2; }
    } else {
        return;
    }
    c->comp_rx_ok++;
    if (d[0] == 0x21) c_deliver(c, d + 1, (size_t)r - 1);
    else if (r >= 2 && d[0] == 0 && d[1] == 0x21) c_deliver(c, d + 2, (size_t)r - 2);
}

/* ---- authentication, peer side ---- */
static void auth_input(pppc_t *c, uint16_t proto, const uint8_t *p, size_t n)
{
    size_t len;
    if (n < 4) return;
    len = ((size_t)p[2] << 8) | p[3];
    if (len < 4 || len > n) return;

    if (proto == P_PAP && c->auth == PPPC_AUTH_PAP) {
        if (p[0] == 2 && !c->auth_ok) {
            c->auth_ok = 1;
            net_start(c);
        } else if (p[0] == 3) {
            c->auth_failed = 1;
        }
    } else if (proto == P_CHAP && (c->auth == PPPC_AUTH_CHAP || c->auth == PPPC_AUTH_MSCHAPV2)) {
        if (p[0] == 1 && len >= 5 && (size_t)p[4] + 5 <= len) {
            size_t ulen = strlen(c->cfg.user), plen = strlen(c->cfg.pass);
            c->chap_id = p[1];
            if (c->auth == PPPC_AUTH_MSCHAPV2 && p[4] == 16) {
                /* a fixed peer challenge is fine for a test; the NT-Response
                 * is over the server's 16-octet authenticator challenge */
                static const uint8_t peer[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
                c->chap_rsp[0] = 49;
                memcpy(c->chap_rsp + 1, peer, 16);
                memset(c->chap_rsp + 1 + 16, 0, 8);
                ppp_mschap2_nt_response(p + 5, peer, (const uint8_t *)c->cfg.user, ulen,
                                        (const uint8_t *)c->cfg.pass, plen, c->chap_rsp + 1 + 24);
                c->chap_rsp[1 + 48] = 0;
                c->chap_answered = 1;
                c_cp(c, P_CHAP, 2, c->chap_id, c->chap_rsp, 50, (const uint8_t *)c->cfg.user, ulen);
            } else {
                ppp_md5_t m;
                c->chap_rsp[0] = 16;
                ppp_md5_init(&m);
                ppp_md5_update(&m, &p[1], 1);
                ppp_md5_update(&m, (const uint8_t *)c->cfg.pass, plen);
                ppp_md5_update(&m, p + 5, p[4]);
                ppp_md5_final(&m, c->chap_rsp + 1);
                c->chap_answered = 1;
                c_cp(c, P_CHAP, 2, c->chap_id, c->chap_rsp, 17, (const uint8_t *)c->cfg.user, ulen);
            }
            c->auth_timer = c->lcp.restart_ms;
        } else if (p[0] == 3 && !c->auth_ok) {
            size_t ml = len - 4 < sizeof c->auth_msg - 1 ? len - 4 : sizeof c->auth_msg - 1;
            memcpy(c->auth_msg, p + 4, ml);
            c->auth_msg[ml] = 0;
            c->auth_ok = 1;
            net_start(c);
        } else if (p[0] == 4) {
            c->auth_failed = 1;
        }
    }
}

/* ---- public ---- */
void pppc_init(pppc_t *c, const pppc_config_t *cfg)
{
    memset(c, 0, sizeof *c);
    c->cfg = *cfg;
    ppp_fsm_init(&c->lcp, &l_ops, c, c->scratch, sizeof c->scratch);
    ppp_fsm_init(&c->ipcp, &i_ops, c, c->scratch, sizeof c->scratch);
    ppp_fsm_init(&c->ccp, &cc_ops, c, c->scratch, sizeof c->scratch);
    if (cfg->restart_ms) {
        c->lcp.restart_ms = cfg->restart_ms;
        c->ipcp.restart_ms = cfg->restart_ms;
        c->ccp.restart_ms = cfg->restart_ms;
    }
    ppp_hdlc_rx_init(&c->rx, PPP_HDLC_BUF);
    c->tx_accm = 0xffffffffu;
    c->peer_mru = 1500;
}

void pppc_start(pppc_t *c)
{
    ppp_fsm_open(&c->lcp);
    ppp_fsm_up(&c->lcp);
}

void pppc_close(pppc_t *c)
{
    ppp_fsm_close(&c->lcp);
}

static void c_handle(pppc_t *c)
{
    uint16_t proto;
    size_t off, n;
    const uint8_t *info;

    if (ppp_hdlc_parse(c->rx.buf, c->rx.len, c->rx_acfc, c->rx_pfc, &proto, &off) != 0)
        return;
    info = c->rx.buf + off;
    n = c->rx.len - off;
    if (proto == P_LCP) {
        ppp_fsm_input(&c->lcp, info, n);
        return;
    }
    if (c->lcp.state != PPP_FSM_OPENED)
        return;
    if (proto == P_PAP || proto == P_CHAP) {
        auth_input(c, proto, info, n);
    } else if (proto == P_IPCP) {
        if (c->auth == 0 || c->auth_ok)
            ppp_fsm_input(&c->ipcp, info, n);
    } else if (proto == P_CCP) {
        if (c->auth != 0 && !c->auth_ok) return;
        if (c->cfg.ccp) {
            ppp_fsm_input(&c->ccp, info, n);
        } else {
            /* a peer without CCP: LCP Protocol-Reject */
            uint8_t pr[2] = { 0x80, 0xfd };
            c_cp(c, P_LCP, 8, ppp_fsm_new_id(&c->lcp), pr, 2, info, n);
        }
    } else if (proto == P_COMP) {
        if (c->ccp.state == PPP_FSM_OPENED && c->rx_alg) cc_input(c, info, n);
    } else if (proto == P_IP) {
        /* RFC 1979 section 2: a packet sent as it was still counts */
        if (c->rx_alg == PPPC_ALG_DEFLATE && !c->rx_wait) {
            static const uint8_t pf[1] = { 0x21 };
            ppp_deflate_dec_add(&c->ddec, pf, 1, info, n);
            c->rx_seq++;
        }
        if (c->rx_alg) c->native_rx++;
        c_deliver(c, info, n);
    }
}

void pppc_input(pppc_t *c, const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (ppp_hdlc_rx_byte(&c->rx, buf[i]))
            c_handle(c);
}

size_t pppc_output(pppc_t *c, uint8_t *buf, size_t max)
{
    size_t n = c->tx_n < max ? c->tx_n : max;
    memcpy(buf, c->tx, n);
    memmove(c->tx, c->tx + n, c->tx_n - n);
    c->tx_n -= n;
    return n;
}

void pppc_tick(pppc_t *c, uint32_t ms)
{
    ppp_fsm_tick(&c->lcp, ms);
    ppp_fsm_tick(&c->ipcp, ms);
    ppp_fsm_tick(&c->ccp, ms);
    /* RFC 1962 3.1: a Reset-Request that brought nothing is sent again */
    if (c->rx_wait && c->ccp.state == PPP_FSM_OPENED && (c->rr_ms += ms) >= (c->cfg.ccp_reset_ms ? c->cfg.ccp_reset_ms : c->ccp.restart_ms) &&
        c->rx_alg == PPPC_ALG_DEFLATE)
        cc_reset_req(c);
    /* repeat our credentials until the server answers */
    if (c->lcp.state == PPP_FSM_OPENED && c->auth && !c->auth_ok && !c->auth_failed) {
        if (c->auth_timer > ms) {
            c->auth_timer -= ms;
        } else if (c->auth == PPPC_AUTH_PAP) {
            pap_send(c);
        } else if (c->chap_answered) {
            c_cp(c, P_CHAP, 2, c->chap_id, c->chap_rsp, 17,
                 (const uint8_t *)c->cfg.user, strlen(c->cfg.user));
            c->auth_timer = c->lcp.restart_ms;
        }
    }
}

int pppc_send_ip(pppc_t *c, const uint8_t *pkt, size_t len)
{
    static uint8_t out[1600];
    uint8_t h[4];
    size_t cn;

    if (!c->ip_up || len > c->peer_mru)
        return -1;
    if (c->tx_alg == PPPC_ALG_DEFLATE) {
        static const uint8_t pf[1] = { 0x21 };
        h[0] = (uint8_t)(c->tx_seq >> 8); h[1] = (uint8_t)c->tx_seq;
        c->tx_seq++;
        cn = ppp_deflate_compress(&c->denc, pf, 1, pkt, len, out, len > 3 ? len - 3 : 0);
        if (c->skip_tx > 0) { c->skip_tx--; return 0; }
        if (cn) { c->comp_tx++; c_frame(c, P_COMP, h, 2, out, cn, NULL, 0); }
        else { c->native_tx++; c_frame(c, P_IP, NULL, 0, pkt, len, NULL, 0); }
        return 0;
    }
    if (c->tx_alg == PPPC_ALG_MPPC) {
        static const uint8_t pf[2] = { 0x00, 0x21 };
        size_t pl = c->cfg.ccp_inner_pfc ? 1 : 2, max = len + pl - 1;
        unsigned bits;
        if (max > (size_t)c->peer_mru - 2) max = (size_t)c->peer_mru - 2;
        cn = ppp_mppc_compress(&c->menc, pf + 2 - pl, pl, pkt, len, out, max, &bits);
        h[0] = (uint8_t)((bits | c->tx_seq) >> 8); h[1] = (uint8_t)c->tx_seq;
        if (cn || len + 2 + pl <= c->peer_mru) c->tx_seq = (c->tx_seq + 1) & 0xfff;
        if (c->skip_tx > 0) { c->skip_tx--; return 0; }
        if (cn) { c->comp_tx++; c_frame(c, P_COMP, h, 2, out, cn, NULL, 0); }
        else if (len + 2 + pl <= c->peer_mru) { c->native_tx++; memcpy(h + 2, pf + 2 - pl, pl); c_frame(c, P_COMP, h, 2 + pl, pkt, len, NULL, 0); }
        else { c->native_tx++; c_frame(c, P_IP, NULL, 0, pkt, len, NULL, 0); }
        return 0;
    }
    c_frame(c, P_IP, NULL, 0, pkt, len, NULL, 0);
    return 0;
}

void pppc_send_raw(pppc_t *c, uint16_t proto, const uint8_t *d, size_t n)
{
    c_frame(c, proto, NULL, 0, d, n, NULL, 0);
}
