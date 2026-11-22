/* The hashes and ciphers that MS-CHAPv2 (RFC 2759) and MPPE (RFC 3078,
 * RFC 3079) need, and the MS-CHAPv2 / MPPE-key helpers built on them.
 *
 * Written from the RFCs' own descriptions and checked against their test
 * vectors (RFC 2759 section 9.2, RFC 3079 section 3.5); no other code.
 * CHAP-MD5 keeps using ppp_md5; this is only for the Microsoft methods.
 *
 * Portable C99, integer only, no allocation, no OS calls. */
#ifndef V90D_PPP_CRYPTO_H
#define V90D_PPP_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

/* longest secret the MS-CHAPv2 helpers convert to UTF-16LE */
#define PPP_CRYPTO_PASS_MAX 64

/* ---- primitives ---- */

/* MD4 (RFC 1320), one shot. */
void ppp_md4(const uint8_t *data, size_t len, uint8_t out[16]);

/* SHA-1 (RFC 3174). A context so callers can feed concatenated fields. */
typedef struct {
    uint32_t h[5];
    uint32_t len_lo, len_hi;   /* message length in bytes */
    uint8_t  block[64];
    size_t   have;
} ppp_sha1_t;
void ppp_sha1_init(ppp_sha1_t *s);
void ppp_sha1_update(ppp_sha1_t *s, const uint8_t *data, size_t len);
void ppp_sha1_final(ppp_sha1_t *s, uint8_t out[20]);
void ppp_sha1(const uint8_t *data, size_t len, uint8_t out[20]);   /* one shot */

/* DES, one 64-bit block, ECB (RFC 2759's ChallengeResponse). key is 8
 * octets with the parity bits already in place (see ppp_des_key_from_7). */
void ppp_des_encrypt(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);
/* Spread a 7-octet value over 8 octets, one left-justified 7-bit group per
 * octet; the low bit of each is a parity bit (odd parity), as MS-CHAP keys
 * are formed (RFC 2759 section 8.6). */
void ppp_des_key_from_7(const uint8_t in7[7], uint8_t out8[8]);

/* RC4 (used by MPPE). */
typedef struct { uint8_t s[256]; uint8_t i, j; } ppp_rc4_t;
void ppp_rc4_init(ppp_rc4_t *r, const uint8_t *key, size_t len);
void ppp_rc4(ppp_rc4_t *r, const uint8_t *in, uint8_t *out, size_t len);

/* ---- MS-CHAPv2 (RFC 2759), server side ---- */

/* The NT password hash: MD4 of the password in UTF-16LE (no terminator).
 * pass is the plain ASCII secret; only code points < 256 are represented. */
void ppp_nt_password_hash(const uint8_t *pass, size_t plen, uint8_t out[16]);

/* The expected 24-octet NT-Response for these challenges and this secret
 * (RFC 2759 GenerateNTResponse). The server compares it with the peer's. */
void ppp_mschap2_nt_response(const uint8_t auth_chal[16], const uint8_t peer_chal[16],
                             const uint8_t *user, size_t ulen,
                             const uint8_t *pass, size_t plen, uint8_t out[24]);

/* The 42-octet authenticator response string ("S=" + 40 uppercase hex),
 * RFC 2759 GenerateAuthenticatorResponse. out is not NUL-terminated. */
void ppp_mschap2_auth_response(const uint8_t *pass, size_t plen, const uint8_t nt_response[24],
                               const uint8_t peer_chal[16], const uint8_t auth_chal[16],
                               const uint8_t *user, size_t ulen, uint8_t out[42]);

/* ---- MPPE key derivation (RFC 3079), server side ---- */

/* The master send and receive START keys (before the per-session key
 * change). keylen is 8 (for 40- or 56-bit) or 16 (for 128-bit). The
 * send/receive assignment is the server's (RFC 3079 section 3.3). */
void ppp_mppe_master_keys(const uint8_t *pass, size_t plen, const uint8_t nt_response[24],
                          size_t keylen, uint8_t send_start[16], uint8_t recv_start[16]);

/* One key change (RFC 3078 section 7.3 / RFC 3079 Get_Key): from the start
 * key and the current session key to the next session key, in place in
 * `session`. keylen is 8 or 16; for 8 the result's leading octets are forced
 * (40-bit: D1 26 9E; 56-bit: D1) when force40 / force56 is set. On the first
 * call the caller sets session = start. */
enum { PPP_MPPE_FORCE_NONE = 0, PPP_MPPE_FORCE_40 = 1, PPP_MPPE_FORCE_56 = 2 };
void ppp_mppe_new_key(const uint8_t *start, uint8_t *session, size_t keylen, int force);

#endif
