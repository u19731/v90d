/* Test-side PPP CLIENT (the calling peer). Not part of the library and
 * never shipped: it exists so the server can be exercised end to end.
 * It reuses the library's framing and automaton, but has its own option
 * handling, authentication (as the authenticatee) and IPCP client logic. */
#ifndef V90D_PPPC_H
#define V90D_PPPC_H
#include <stddef.h>
#include <stdint.h>
#include "ppp_fsm.h"
#include "ppp_hdlc.h"
#include "ppp_deflate.h"
#include "ppp_mppc.h"
#include "ppp_crypto.h"

#define PPPC_AUTH_PAP   1u
#define PPPC_AUTH_CHAP  2u
#define PPPC_AUTH_MSCHAPV2 4u

/* How the client speaks CCP (pppc_config_t.ccp):
 *   NONE     it has no CCP and Protocol-Rejects it
 *   PPPD     like pppd on a kernel with ppp_deflate and bsd_comp: its
 *            request offers Deflate, Deflate under the draft number and
 *            BSD-Compress (which it then cannot use here: the server
 *            rejects it); it compresses with Deflate if the server asks
 *   WINDOWS  like Windows dial-up networking with "software compression":
 *            MPPC both ways, nothing else
 *   WINDOWS_MPPE  the same, first asking for encryption bits as well and
 *            giving in when the server Naks them */
#define PPPC_CCP_NONE          0
#define PPPC_CCP_PPPD          1
#define PPPC_CCP_WINDOWS       2
#define PPPC_CCP_WINDOWS_MPPE  3
#define PPPC_ALG_DEFLATE       1
#define PPPC_ALG_MPPC          2

typedef struct {
    const char *user, *pass;
    unsigned accept_auth;     /* methods the client agrees to */
    uint32_t accm;            /* what the server must escape towards us */
    int      send_accm;       /* include the ACCM option */
    int      pfc, acfc;       /* request the compressions */
    uint16_t mru;             /* 0: do not send the option */
    uint32_t magic;
    int      want_vj;         /* ask for Van Jacobson compression */
    int      want_dns;        /* ask for both DNS addresses */
    int      no_echo_reply;   /* play dead towards Echo-Requests */
    uint32_t restart_ms;      /* 0 = 3000 */
    int      ccp;             /* PPPC_CCP_* */
    int      ccp_wbits;       /* Deflate window offered, 0 = 15 */
    int      ccp_draft_only;  /* PPPD: only the draft number, as old pppd versions */
    uint32_t ccp_reset_ms;    /* before a Reset-Request is repeated, 0 = restart */
    int      ccp_inner_pfc;   /* WINDOWS: one-octet Protocol field inside MPPC packets */
} pppc_config_t;

typedef struct pppc {
    pppc_config_t cfg;
    ppp_fsm_t lcp, ipcp;
    uint8_t   scratch[256];
    ppp_hdlc_rx_t rx;
    uint8_t   tx[16384];
    size_t    tx_n;

    /* LCP */
    uint8_t   w_accm, w_pfc, w_acfc, w_mru, w_magic;
    unsigned  pend_auth;
    uint32_t  pend_accm;
    uint16_t  pend_mru;
    uint8_t   pend_pfc, pend_acfc;
    unsigned  auth;           /* method agreed, 0 = none */
    uint32_t  tx_accm;
    uint16_t  peer_mru;
    uint8_t   tx_pfc, tx_acfc, rx_pfc, rx_acfc;
    int       lcp_is_up;
    int       terminated;     /* LCP reached This-Layer-Finished */
    int       echo_requests;  /* Echo-Requests seen */
    int       proto_rejects;  /* Protocol-Rejects received */

    /* authentication */
    int       auth_ok, auth_failed;
    uint8_t   pap_id;
    uint32_t  auth_timer;
    uint8_t   chap_rsp[1 + 49];     /* MD5 is 1+16; MS-CHAPv2 is 1+49 */
    uint8_t   chap_id;
    int       chap_answered;
    char      auth_msg[64];

    /* IPCP */
    uint8_t   w_vj, w_dns1, w_dns2;
    int       vj_rejected;
    uint32_t  my_ip, dns1, dns2, server_ip;
    int       ip_up;

    /* CCP */
    ppp_fsm_t ccp;
    uint8_t   cw26, cw24, cw21, cw18;   /* options still in our request */
    uint8_t   cw_w;
    uint32_t  cw_bits;                  /* MPPC supported bits we ask for */
    uint8_t   cp_opt, cp_w;             /* the server's request, as acked */
    int       tx_alg, rx_alg, tx_w, rx_w;   /* PPPC_ALG_* in force, Deflate windows */
    int       ccp_ups;
    uint16_t  tx_seq, rx_seq;
    int       rx_wait;
    uint8_t   rr_id;
    uint32_t  rr_ms;                    /* since the last Reset-Request */
    ppp_deflate_enc_t denc;
    ppp_deflate_dec_t ddec;
    ppp_mppc_enc_t    menc;
    ppp_mppc_dec_t    mdec;
    /* what happened */
    int       comp_rx_ok, comp_rx_bad, comp_rx_dropped, native_rx;
    int       comp_tx, native_tx;
    int       resets_sent, resets_rcvd, reset_acks_rcvd;
    unsigned long comp_rx_octets;       /* information octets of compressed frames received */
    uint16_t  last_rx_hdr;              /* first two octets of the last compressed frame */
    /* faults */
    int       drop_rx_comp;             /* lose this many compressed frames on the way in */
    int       skip_tx;                  /* compress this many packets and lose them on the way out */
    int       ignore_reset_req;         /* do not answer Reset-Requests */

    /* IP received */
    int       ip_count;
    size_t    ip_len;
    uint8_t   ip_last[1600];
} pppc_t;

void pppc_init(pppc_t *c, const pppc_config_t *cfg);
void pppc_start(pppc_t *c);                 /* line is up: begin LCP */
void pppc_close(pppc_t *c);                 /* graceful Terminate */
void pppc_input(pppc_t *c, const uint8_t *buf, size_t n);
size_t pppc_output(pppc_t *c, uint8_t *buf, size_t max);
void pppc_tick(pppc_t *c, uint32_t ms);
int pppc_send_ip(pppc_t *c, const uint8_t *pkt, size_t len);
/* send an arbitrary frame (for protocols the server does not know) */
void pppc_send_raw(pppc_t *c, uint16_t proto, const uint8_t *d, size_t n);

#endif
