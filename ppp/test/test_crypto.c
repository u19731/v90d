/* ppp_crypto.c against the vectors in the specs it implements:
 * RFC 1320 (MD4), RFC 3174 (SHA-1), RFC 2759 (MS-CHAPv2, section 9.2 and
 * the DES-key example of 9.3) and RFC 3079 (MPPE keys, section 3.5). */
#include <string.h>
#include <stdio.h>
#include "test.h"
#include "ppp_crypto.h"

static int eq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n) == 0; }

static void test_md4(void)
{
    uint8_t d[16];
    static const uint8_t empty[16] = { 0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0 };
    static const uint8_t abc[16]   = { 0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d };
    static const uint8_t msg[16]   = { 0xd9,0x13,0x0a,0x81,0x64,0x54,0x9f,0xe8,0x18,0x87,0x48,0x06,0xe1,0xc7,0x01,0x4b };
    ppp_md4((const uint8_t *)"", 0, d);                         CHECK(eq(d, empty, 16));
    ppp_md4((const uint8_t *)"abc", 3, d);                      CHECK(eq(d, abc, 16));
    ppp_md4((const uint8_t *)"message digest", 14, d);          CHECK(eq(d, msg, 16));
}

static void test_sha1(void)
{
    uint8_t d[20];
    static const uint8_t empty[20] = { 0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09 };
    static const uint8_t abc[20]   = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
    /* RFC 3174: the 448-bit message, which spans two blocks */
    static const uint8_t two[20]   = { 0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1 };
    ppp_sha1((const uint8_t *)"", 0, d);     CHECK(eq(d, empty, 20));
    ppp_sha1((const uint8_t *)"abc", 3, d);  CHECK(eq(d, abc, 20));
    ppp_sha1((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    CHECK(eq(d, two, 20));
}

/* RFC 2759 section 9.3: the DES key example (checks parity insertion and the
 * NT hash of a known password) */
static void test_des_keys(void)
{
    uint8_t h[16], k[8];
    static const uint8_t mypw_hash[16] = { 0xFC,0x15,0x6A,0xF7,0xED,0xCD,0x6C,0x0E,0xDD,0xE3,0x33,0x7D,0x42,0x7F,0x4E,0xAC };
    static const uint8_t key1[8]       = { 0xFD,0x0B,0x5B,0x5E,0x7F,0x6E,0x34,0xD9 };
    static const uint8_t key2[8]       = { 0x0E,0x6E,0x79,0x67,0x37,0xEA,0x08,0xFE };
    ppp_nt_password_hash((const uint8_t *)"MyPw", 4, h);
    CHECK(eq(h, mypw_hash, 16));
    ppp_des_key_from_7(h + 0, k);  CHECK(eq(k, key1, 8));
    ppp_des_key_from_7(h + 7, k);  CHECK(eq(k, key2, 8));
}

/* RFC 2759 section 9.2: the full MS-CHAPv2 worked example */
static const uint8_t AUTH_CHAL[16] = { 0x5B,0x5D,0x7C,0x7D,0x7B,0x3F,0x2F,0x3E,0x3C,0x2C,0x60,0x21,0x32,0x26,0x26,0x28 };
static const uint8_t PEER_CHAL[16] = { 0x21,0x40,0x23,0x24,0x25,0x5E,0x26,0x2A,0x28,0x29,0x5F,0x2B,0x3A,0x33,0x7C,0x7E };
static const uint8_t NT_RESP[24]   = { 0x82,0x30,0x9E,0xCD,0x8D,0x70,0x8B,0x5E,0xA0,0x8F,0xAA,0x39,0x81,0xCD,0x83,0x54,0x42,0x33,0x11,0x4A,0x3D,0x85,0xD6,0xDF };

static void test_mschap2(void)
{
    uint8_t h[16], nt[24], s[42];
    static const uint8_t pwhash[16] = { 0x44,0xEB,0xBA,0x8D,0x53,0x12,0xB8,0xD6,0x11,0x47,0x44,0x11,0xF5,0x69,0x89,0xAE };
    static const char *resp = "S=407A5589115FD0D6209F510FE9C04566932CDA56";

    ppp_nt_password_hash((const uint8_t *)"clientPass", 10, h);
    CHECK(eq(h, pwhash, 16));
    ppp_mschap2_nt_response(AUTH_CHAL, PEER_CHAL, (const uint8_t *)"User", 4,
                            (const uint8_t *)"clientPass", 10, nt);
    CHECK(eq(nt, NT_RESP, 24));
    ppp_mschap2_auth_response((const uint8_t *)"clientPass", 10, NT_RESP, PEER_CHAL, AUTH_CHAL,
                              (const uint8_t *)"User", 4, s);
    CHECK(memcmp(s, resp, 42) == 0);
}

/* RFC 3079 section 3.5: the MPPE key vectors (server side, "clientPass") */
static void test_rc4(void)
{
    /* well-known vector: RC4("Key", "Plaintext") = BB F3 16 E8 D9 40 AF 0A D3 */
    ppp_rc4_t r; uint8_t out[9];
    static const uint8_t want[9] = { 0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3 };
    ppp_rc4_init(&r, (const uint8_t *)"Key", 3);
    ppp_rc4(&r, (const uint8_t *)"Plaintext", out, 9);
    CHECK(eq(out, want, 9));
}

static void test_mppe_keys(void)
{
    uint8_t send[16], recv[16], sk[16];
    unsigned dbg;
    static const uint8_t send128[16] = { 0x8B,0x7C,0xDC,0x14,0x9B,0x99,0x3A,0x1B,0xA1,0x18,0xCB,0x15,0x3F,0x56,0xDC,0xCB };
    static const uint8_t sess128[16] = { 0x40,0x5C,0xB2,0x24,0x7A,0x79,0x56,0xE6,0xE2,0x11,0x00,0x7A,0xE2,0x7B,0x22,0xD4 };
    static const uint8_t send8[8]    = { 0x8B,0x7C,0xDC,0x14,0x9B,0x99,0x3A,0x1B };
    static const uint8_t sess40[8]   = { 0xD1,0x26,0x9E,0xC4,0x9F,0xA6,0x2E,0x3E };
    static const uint8_t sess56[8]   = { 0xD1,0x5C,0x00,0xC4,0x9F,0xA6,0x2E,0x3E };

    /* the RC4 of "test message" under each session key (RFC 3079 3.5): the
     * end-to-end proof that our key is the one that actually keys the data
     * cipher, so we interoperate with Windows */
    static const uint8_t msg_in[12] = { 't','e','s','t',' ','m','e','s','s','a','g','e' };
    static const uint8_t ct128[12] = { 0x81,0x84,0x83,0x17,0xDF,0x68,0x84,0x62,0x72,0xFB,0x5A,0xBE };
    static const uint8_t ct40[12]  = { 0x92,0x91,0x37,0x91,0x7E,0x58,0x03,0xD6,0x68,0xD7,0x58,0x98 };
    /* RFC 3079's 56-bit RC4 sample is not checked: that line of 3.5.2 names
     * SendSessionKey40 as its key and its ciphertext matches neither the 40-
     * nor the 56-bit key under our (40- and 128-bit-verified) RC4, an RFC
     * inconsistency. The 56-bit session KEY is checked against its vector. */
    uint8_t ct[12]; ppp_rc4_t r;
    (void)dbg;

    /* 128-bit */
    ppp_mppe_master_keys((const uint8_t *)"clientPass", 10, NT_RESP, 16, send, recv);
    CHECK(eq(send, send128, 16));
    memcpy(sk, send, 16);
    ppp_mppe_new_key(send, sk, 16, PPP_MPPE_FORCE_NONE);
    CHECK(eq(sk, sess128, 16));
    ppp_rc4_init(&r, sk, 16); ppp_rc4(&r, msg_in, ct, 12); CHECK(eq(ct, ct128, 12));

    /* 40-bit: same 8-octet start key, session forced to D1 26 9E ... */
    ppp_mppe_master_keys((const uint8_t *)"clientPass", 10, NT_RESP, 8, send, recv);
    CHECK(eq(send, send8, 8));
    memcpy(sk, send, 8);
    ppp_mppe_new_key(send, sk, 8, PPP_MPPE_FORCE_40);
    CHECK(eq(sk, sess40, 8));
    ppp_rc4_init(&r, sk, 8); ppp_rc4(&r, msg_in, ct, 12); CHECK(eq(ct, ct40, 12));

    /* 56-bit: first octet forced to D1 (key checked; see the note above) */
    memcpy(sk, send, 8);
    ppp_mppe_new_key(send, sk, 8, PPP_MPPE_FORCE_56);
    CHECK(eq(sk, sess56, 8));
}

int main(void)
{
    test_md4();
    test_sha1();
    test_des_keys();
    test_rc4();
    test_mschap2();
    test_mppe_keys();
    T_REPORT("crypto");
}
