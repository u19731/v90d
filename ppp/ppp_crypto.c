/* See ppp_crypto.h. Written from the algorithm descriptions in RFC 1320
 * (MD4), RFC 3174 (SHA-1), FIPS 46-3 (DES), RFC 2759 (MS-CHAPv2) and
 * RFC 3078 / RFC 3079 (MPPE), checked against the RFCs' test vectors. */
#include "ppp_crypto.h"
#include <string.h>

static uint32_t rol32(uint32_t v, unsigned n) { return (v << n) | (v >> (32 - n)); }

/* ---- MD4 (RFC 1320) ---- little-endian ---- */

static uint32_t rd32le(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

static void md4_block(uint32_t st[4], const uint8_t *p)
{
    uint32_t x[16], a = st[0], b = st[1], c = st[2], d = st[3];
    unsigned j;
    for (j = 0; j < 16; j++) x[j] = rd32le(p + j * 4);
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define R1(a, b, c, d, k, s) a = rol32(a + F(b, c, d) + x[k], s)
#define R2(a, b, c, d, k, s) a = rol32(a + G(b, c, d) + x[k] + 0x5a827999u, s)
#define R3(a, b, c, d, k, s) a = rol32(a + H(b, c, d) + x[k] + 0x6ed9eba1u, s)
    R1(a,b,c,d,0,3);  R1(d,a,b,c,1,7);  R1(c,d,a,b,2,11);  R1(b,c,d,a,3,19);
    R1(a,b,c,d,4,3);  R1(d,a,b,c,5,7);  R1(c,d,a,b,6,11);  R1(b,c,d,a,7,19);
    R1(a,b,c,d,8,3);  R1(d,a,b,c,9,7);  R1(c,d,a,b,10,11); R1(b,c,d,a,11,19);
    R1(a,b,c,d,12,3); R1(d,a,b,c,13,7); R1(c,d,a,b,14,11); R1(b,c,d,a,15,19);
    R2(a,b,c,d,0,3);  R2(d,a,b,c,4,5);  R2(c,d,a,b,8,9);   R2(b,c,d,a,12,13);
    R2(a,b,c,d,1,3);  R2(d,a,b,c,5,5);  R2(c,d,a,b,9,9);   R2(b,c,d,a,13,13);
    R2(a,b,c,d,2,3);  R2(d,a,b,c,6,5);  R2(c,d,a,b,10,9);  R2(b,c,d,a,14,13);
    R2(a,b,c,d,3,3);  R2(d,a,b,c,7,5);  R2(c,d,a,b,11,9);  R2(b,c,d,a,15,13);
    R3(a,b,c,d,0,3);  R3(d,a,b,c,8,9);  R3(c,d,a,b,4,11);  R3(b,c,d,a,12,15);
    R3(a,b,c,d,2,3);  R3(d,a,b,c,10,9); R3(c,d,a,b,6,11);  R3(b,c,d,a,14,15);
    R3(a,b,c,d,1,3);  R3(d,a,b,c,9,9);  R3(c,d,a,b,5,11);  R3(b,c,d,a,13,15);
    R3(a,b,c,d,3,3);  R3(d,a,b,c,11,9); R3(c,d,a,b,7,11);  R3(b,c,d,a,15,15);
#undef F
#undef G
#undef H
#undef R1
#undef R2
#undef R3
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

void ppp_md4(const uint8_t *data, size_t len, uint8_t out[16])
{
    uint32_t st[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    uint8_t blk[64];
    uint64_t bits = (uint64_t)len * 8;
    size_t i, off = 0, rem;

    while (len - off >= 64) { md4_block(st, data + off); off += 64; }
    rem = len - off;
    memset(blk, 0, 64);
    memcpy(blk, data + off, rem);
    blk[rem] = 0x80;
    if (rem >= 56) { md4_block(st, blk); memset(blk, 0, 64); }
    for (i = 0; i < 8; i++) blk[56 + i] = (uint8_t)(bits >> (8 * i));
    md4_block(st, blk);
    for (i = 0; i < 4; i++) {
        out[i]      = (uint8_t)(st[0] >> (8 * i));
        out[4 + i]  = (uint8_t)(st[1] >> (8 * i));
        out[8 + i]  = (uint8_t)(st[2] >> (8 * i));
        out[12 + i] = (uint8_t)(st[3] >> (8 * i));
    }
}

/* ---- SHA-1 (RFC 3174) ---- big-endian ---- */

static void sha1_block(ppp_sha1_t *s, const uint8_t *p)
{
    uint32_t w[80], a, b, c, d, e, f, k, t;
    unsigned i;
    for (i = 0; i < 16; i++) w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (i = 16; i < 80; i++) w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;         k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;         k = 0xca62c1d6; }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}

void ppp_sha1_init(ppp_sha1_t *s)
{
    s->h[0] = 0x67452301; s->h[1] = 0xefcdab89; s->h[2] = 0x98badcfe;
    s->h[3] = 0x10325476; s->h[4] = 0xc3d2e1f0;
    s->len_lo = s->len_hi = 0; s->have = 0;
}

void ppp_sha1_update(ppp_sha1_t *s, const uint8_t *data, size_t len)
{
    uint32_t add = (uint32_t)len;
    if ((s->len_lo += add) < add) s->len_hi++;
    while (len) {
        size_t take = 64 - s->have;
        if (take > len) take = len;
        memcpy(s->block + s->have, data, take);
        s->have += take; data += take; len -= take;
        if (s->have == 64) { sha1_block(s, s->block); s->have = 0; }
    }
}

void ppp_sha1_final(ppp_sha1_t *s, uint8_t out[20])
{
    uint64_t bits = ((uint64_t)s->len_hi << 32 | s->len_lo) * 8;
    uint8_t pad = 0x80;
    unsigned i;
    ppp_sha1_update(s, &pad, 1);
    pad = 0;
    while (s->have != 56) ppp_sha1_update(s, &pad, 1);
    for (i = 0; i < 8; i++) { uint8_t b = (uint8_t)(bits >> (56 - 8 * i)); ppp_sha1_update(s, &b, 1); }
    for (i = 0; i < 5; i++) { out[i*4] = (uint8_t)(s->h[i] >> 24); out[i*4+1] = (uint8_t)(s->h[i] >> 16); out[i*4+2] = (uint8_t)(s->h[i] >> 8); out[i*4+3] = (uint8_t)s->h[i]; }
}

void ppp_sha1(const uint8_t *data, size_t len, uint8_t out[20])
{
    ppp_sha1_t s; ppp_sha1_init(&s); ppp_sha1_update(&s, data, len); ppp_sha1_final(&s, out);
}

/* ---- DES (FIPS 46-3), one ECB block, via bit arrays ---- */

static const uint8_t IP[64] = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7 };
static const uint8_t FP[64] = {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25 };
static const uint8_t E[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1 };
static const uint8_t P[32] = {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25 };
static const uint8_t PC1[56] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4 };
static const uint8_t PC2[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32 };
static const uint8_t SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
static const uint8_t SBOX[8][64] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} };

static void permute(const uint8_t *in, uint8_t *out, const uint8_t *tab, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++) out[i] = in[tab[i] - 1];
}

void ppp_des_encrypt(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    uint8_t kb[64], ib[64], ip[64], c[28], d[28], sub[16][48];
    uint8_t l[32], r[32], er[48], sb[32], pf[32], fp[64];
    unsigned i, j, round;

    for (i = 0; i < 64; i++) kb[i] = (key[i / 8] >> (7 - i % 8)) & 1;
    for (i = 0; i < 64; i++) ib[i] = (in[i / 8] >> (7 - i % 8)) & 1;

    /* key schedule */
    {
        uint8_t pc1[56];
        permute(kb, pc1, PC1, 56);
        memcpy(c, pc1, 28); memcpy(d, pc1 + 28, 28);
        for (round = 0; round < 16; round++) {
            uint8_t cd[56], t;
            unsigned s;
            for (s = 0; s < SHIFTS[round]; s++) {
                t = c[0]; memmove(c, c + 1, 27); c[27] = t;
                t = d[0]; memmove(d, d + 1, 27); d[27] = t;
            }
            memcpy(cd, c, 28); memcpy(cd + 28, d, 28);
            permute(cd, sub[round], PC2, 48);
        }
    }

    permute(ib, ip, IP, 64);
    memcpy(l, ip, 32); memcpy(r, ip + 32, 32);
    for (round = 0; round < 16; round++) {
        uint8_t nl[32];
        permute(r, er, E, 48);
        for (i = 0; i < 48; i++) er[i] ^= sub[round][i];
        for (j = 0; j < 8; j++) {
            unsigned row = (unsigned)(er[j*6] << 1) | er[j*6+5];
            unsigned col = (unsigned)(er[j*6+1] << 3) | (er[j*6+2] << 2) | (er[j*6+3] << 1) | er[j*6+4];
            uint8_t v = SBOX[j][row * 16 + col];
            sb[j*4] = (v >> 3) & 1; sb[j*4+1] = (v >> 2) & 1; sb[j*4+2] = (v >> 1) & 1; sb[j*4+3] = v & 1;
        }
        permute(sb, pf, P, 32);
        memcpy(nl, r, 32);
        for (i = 0; i < 32; i++) r[i] = l[i] ^ pf[i];
        memcpy(l, nl, 32);
    }
    /* preoutput is R16 L16 (swap) */
    {
        uint8_t pre[64];
        memcpy(pre, r, 32); memcpy(pre + 32, l, 32);
        permute(pre, fp, FP, 64);
    }
    for (i = 0; i < 8; i++) {
        uint8_t v = 0;
        for (j = 0; j < 8; j++) v = (uint8_t)((v << 1) | fp[i*8 + j]);
        out[i] = v;
    }
}

void ppp_des_key_from_7(const uint8_t in7[7], uint8_t out8[8])
{
    /* left-justify 7 bits per octet; low bit is odd parity */
    uint8_t bits[56];
    unsigned i, j;
    for (i = 0; i < 56; i++) bits[i] = (in7[i / 8] >> (7 - i % 8)) & 1;
    for (i = 0; i < 8; i++) {
        unsigned ones = 0;
        uint8_t v = 0;
        for (j = 0; j < 7; j++) { uint8_t bit = bits[i*7 + j]; v = (uint8_t)((v << 1) | bit); ones += bit; }
        v = (uint8_t)(v << 1);
        out8[i] = (uint8_t)(v | ((ones & 1) ? 0 : 1));   /* odd parity */
    }
}

/* ---- RC4 ---- */

void ppp_rc4_init(ppp_rc4_t *r, const uint8_t *key, size_t len)
{
    unsigned i, j = 0;
    for (i = 0; i < 256; i++) r->s[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        uint8_t t;
        j = (j + r->s[i] + key[i % len]) & 0xff;
        t = r->s[i]; r->s[i] = r->s[j]; r->s[j] = t;
    }
    r->i = r->j = 0;
}

void ppp_rc4(ppp_rc4_t *r, const uint8_t *in, uint8_t *out, size_t len)
{
    size_t k;
    for (k = 0; k < len; k++) {
        uint8_t t;
        r->i = (uint8_t)(r->i + 1);
        r->j = (uint8_t)(r->j + r->s[r->i]);
        t = r->s[r->i]; r->s[r->i] = r->s[r->j]; r->s[r->j] = t;
        out[k] = in[k] ^ r->s[(uint8_t)(r->s[r->i] + r->s[r->j])];
    }
}

/* ---- MS-CHAPv2 (RFC 2759) ---- */

void ppp_nt_password_hash(const uint8_t *pass, size_t plen, uint8_t out[16])
{
    uint8_t uni[2 * PPP_CRYPTO_PASS_MAX];
    size_t i;
    if (plen > PPP_CRYPTO_PASS_MAX) plen = PPP_CRYPTO_PASS_MAX;
    for (i = 0; i < plen; i++) { uni[2*i] = pass[i]; uni[2*i+1] = 0; }
    ppp_md4(uni, 2 * plen, out);
    memset(uni, 0, sizeof uni);
}

static void challenge_hash(const uint8_t peer[16], const uint8_t auth[16],
                           const uint8_t *user, size_t ulen, uint8_t out8[8])
{
    ppp_sha1_t s; uint8_t d[20];
    ppp_sha1_init(&s);
    ppp_sha1_update(&s, peer, 16);
    ppp_sha1_update(&s, auth, 16);
    ppp_sha1_update(&s, user, ulen);
    ppp_sha1_final(&s, d);
    memcpy(out8, d, 8);
}

static void challenge_response(const uint8_t chal8[8], const uint8_t pwhash[16], uint8_t out24[24])
{
    uint8_t z[21], k[8];
    memcpy(z, pwhash, 16); memset(z + 16, 0, 5);
    ppp_des_key_from_7(z + 0,  k); ppp_des_encrypt(k, chal8, out24 + 0);
    ppp_des_key_from_7(z + 7,  k); ppp_des_encrypt(k, chal8, out24 + 8);
    ppp_des_key_from_7(z + 14, k); ppp_des_encrypt(k, chal8, out24 + 16);
    memset(z, 0, sizeof z);
}

void ppp_mschap2_nt_response(const uint8_t auth_chal[16], const uint8_t peer_chal[16],
                             const uint8_t *user, size_t ulen,
                             const uint8_t *pass, size_t plen, uint8_t out[24])
{
    uint8_t chal[8], pwhash[16];
    challenge_hash(peer_chal, auth_chal, user, ulen, chal);
    ppp_nt_password_hash(pass, plen, pwhash);
    challenge_response(chal, pwhash, out);
    memset(pwhash, 0, sizeof pwhash);
}

static const char MAGIC1[] = "Magic server to client signing constant";
static const char MAGIC2[] = "Pad to make it do more than one iteration";

void ppp_mschap2_auth_response(const uint8_t *pass, size_t plen, const uint8_t nt_response[24],
                               const uint8_t peer_chal[16], const uint8_t auth_chal[16],
                               const uint8_t *user, size_t ulen, uint8_t out[42])
{
    uint8_t pwhash[16], pwhh[16], chal[8], d1[20], d2[20];
    ppp_sha1_t s;
    size_t i;
    static const char hex[] = "0123456789ABCDEF";

    ppp_nt_password_hash(pass, plen, pwhash);
    ppp_md4(pwhash, 16, pwhh);
    ppp_sha1_init(&s);
    ppp_sha1_update(&s, pwhh, 16);
    ppp_sha1_update(&s, nt_response, 24);
    ppp_sha1_update(&s, (const uint8_t *)MAGIC1, sizeof MAGIC1 - 1);
    ppp_sha1_final(&s, d1);
    challenge_hash(peer_chal, auth_chal, user, ulen, chal);
    ppp_sha1_init(&s);
    ppp_sha1_update(&s, d1, 20);
    ppp_sha1_update(&s, chal, 8);
    ppp_sha1_update(&s, (const uint8_t *)MAGIC2, sizeof MAGIC2 - 1);
    ppp_sha1_final(&s, d2);
    out[0] = 'S'; out[1] = '=';
    for (i = 0; i < 20; i++) { out[2 + 2*i] = (uint8_t)hex[d2[i] >> 4]; out[3 + 2*i] = (uint8_t)hex[d2[i] & 15]; }
    memset(pwhash, 0, sizeof pwhash); memset(pwhh, 0, sizeof pwhh);
}

/* ---- MPPE keys (RFC 3079) ---- */

static const char MMK[]   = "This is the MPPE Master Key";
static const char MSEND[] = "On the client side, this is the receive key; on the server side, it is the send key.";
static const char MRECV[] = "On the client side, this is the send key; on the server side, it is the receive key.";
static const uint8_t SHSPAD1[40] = { 0 };
static const uint8_t SHSPAD2[40] = {
    0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,
    0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2 };

static void asym_start_key(const uint8_t mk[16], size_t keylen, const char *magic, uint8_t out[16])
{
    ppp_sha1_t s; uint8_t d[20];
    ppp_sha1_init(&s);
    ppp_sha1_update(&s, mk, 16);
    ppp_sha1_update(&s, SHSPAD1, 40);
    ppp_sha1_update(&s, (const uint8_t *)magic, 84);
    ppp_sha1_update(&s, SHSPAD2, 40);
    ppp_sha1_final(&s, d);
    memcpy(out, d, keylen);
}

void ppp_mppe_master_keys(const uint8_t *pass, size_t plen, const uint8_t nt_response[24],
                          size_t keylen, uint8_t send_start[16], uint8_t recv_start[16])
{
    uint8_t pwhash[16], pwhh[16], mk[20];
    ppp_sha1_t s;
    ppp_nt_password_hash(pass, plen, pwhash);
    ppp_md4(pwhash, 16, pwhh);
    ppp_sha1_init(&s);
    ppp_sha1_update(&s, pwhh, 16);
    ppp_sha1_update(&s, nt_response, 24);
    ppp_sha1_update(&s, (const uint8_t *)MMK, sizeof MMK - 1);
    ppp_sha1_final(&s, mk);                 /* first 16 octets are the master key */
    asym_start_key(mk, keylen, MSEND, send_start);
    asym_start_key(mk, keylen, MRECV, recv_start);
    memset(pwhash, 0, sizeof pwhash); memset(pwhh, 0, sizeof pwhh); memset(mk, 0, sizeof mk);
}

void ppp_mppe_new_key(const uint8_t *start, uint8_t *session, size_t keylen, int force)
{
    ppp_sha1_t s; uint8_t d[20];
    /* SHA-1 over StartKey, pad1, the current session key, pad2; the first
     * keylen octets are the next session key (RFC 3078 7.3 / RFC 3079 3.5
     * test vectors). The leading octets are then forced for the short keys. */
    ppp_sha1_init(&s);
    ppp_sha1_update(&s, start, keylen);
    ppp_sha1_update(&s, SHSPAD1, 40);
    ppp_sha1_update(&s, session, keylen);
    ppp_sha1_update(&s, SHSPAD2, 40);
    ppp_sha1_final(&s, d);
    memcpy(session, d, keylen);
    if (force == PPP_MPPE_FORCE_40) { session[0] = 0xd1; session[1] = 0x26; session[2] = 0x9e; }
    else if (force == PPP_MPPE_FORCE_56) { session[0] = 0xd1; }
}
