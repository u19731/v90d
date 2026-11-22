#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "../qspi.h"
#include "qspisim.h"

static qspisim S; static qspi_io IO; static qspi_t Q; static uint8_t *before;
static void fresh(void)
{
    if (S.mem) qspisim_free(&S);
    qspisim_init(&S); qspisim_io(&S, &IO);
    if (!before) before = malloc(QSPI_SIZE);
    memcpy(before, S.mem, QSPI_SIZE);
}
/* the flash differs from what it was only inside [lo, hi) */
static int untouched_outside(uint32_t lo, uint32_t hi)
{
    return memcmp(S.mem, before, lo) == 0 && memcmp(S.mem + hi, before + hi, QSPI_SIZE - hi) == 0;
}

static void test_init(void)
{
    uint8_t b[16];
    /* as the stock system leaves it */
    fresh(); CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK); CHECK_EQ_I(S.qpi, 1); CHECK_EQ_I((int)S.bad, 0);
    CHECK_EQ_I(qspi_read(&Q, 0x123456, b, 16), QSPI_OK); CHECK(memcmp(b, S.mem + 0x123456, 16) == 0);
    CHECK_EQ_I((int)S.reg[0x10 / 4], 0);                /* polled: no interrupt left enabled */
    /* as U-Boot leaves it: the chip back in single-line mode */
    fresh(); qspisim_after_uboot(&S);
    CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK); CHECK_EQ_I(S.qpi, 1); CHECK_EQ_I((int)S.bad, 0);
    CHECK_EQ_I(qspi_read(&Q, 0xFBE000, b, 16), QSPI_OK); CHECK(memcmp(b, S.mem + 0xFBE000, 16) == 0);
    CHECK_EQ_I((int)S.status_writes, 0);
    /* a chip we do not carry: hands off (0xC84018 GD25Q128 is now supported,
     * so use a Macronix id the driver does not know) */
    fresh(); S.id[0] = 0xC2; S.id[1] = 0x20;
    CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_E_ID);
    CHECK_EQ_I(qspi_read(&Q, 0, b, 16), QSPI_E_ID);
    /* a controller that never becomes idle ends in an error, not a hang */
    fresh(); S.stuck = 1; CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_E_TIMEOUT);
    CHECK(untouched_outside(0, 0));
}

static void test_ranges(void)
{
    uint8_t b[64]; memset(b, 0, sizeof b);
    fresh(); CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK);
    /* nothing is allowed until said so */
    CHECK_EQ_I(qspi_erase(&Q, 0xFBE000, 0x2000), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_write(&Q, 0xFBE000, b, 64), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_allow(&Q, 0xFBE000, 0xFC0000), QSPI_OK);
    CHECK_EQ_I(qspi_allow(&Q, 0x8E0000, 0xC1F000), QSPI_OK);
    CHECK_EQ_I(qspi_allow(&Q, 0x8E0100, 0xC1F000), QSPI_E_RANGE);          /* not on sector boundaries */
    CHECK_EQ_I(qspi_allow(&Q, 0xC1F000, 0x8E0000), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_allow(&Q, 0xFF0000, 0x1001000), QSPI_E_RANGE);
    /* one byte over either edge refuses the whole operation */
    CHECK_EQ_I(qspi_erase(&Q, 0xFBD000, 0x2000), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_erase(&Q, 0xFBF000, 0x2000), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_write(&Q, 0xFBFFF0, b, 17), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_write(&Q, 0xFBDFFF, b, 2), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_write(&Q, 0x020000, b, 64), QSPI_E_RANGE);              /* U-Boot */
    /* the list has room for what the device tree of the box names, and an end */
    {
        unsigned i;
        for (i = 2; i < QSPI_MAX_ALLOW; i++) CHECK_EQ_I(qspi_allow(&Q, 0x100000 + i * 0x2000, 0x101000 + i * 0x2000), QSPI_OK);
        CHECK(QSPI_MAX_ALLOW >= 7);
        CHECK_EQ_I(qspi_allow(&Q, 0x200000, 0x201000), QSPI_E_RANGE);
        CHECK_EQ_I(qspi_write(&Q, 0x200000, b, 4), QSPI_E_RANGE);
    }
    CHECK_EQ_I(qspi_erase(&Q, 0, 0x1000), QSPI_E_RANGE);                    /* the first-stage loader */
    CHECK_EQ_I(qspi_erase(&Q, 0xFBE000, 0x1800), QSPI_E_RANGE);             /* not whole sectors */
    CHECK_EQ_I(qspi_erase(&Q, 0xFBE800, 0x1000), QSPI_E_RANGE);
    CHECK_EQ_I(qspi_read(&Q, 0xFFFFF0, b, 17), QSPI_E_RANGE);               /* past the end */
    CHECK_EQ_I(qspi_erase(&Q, 0xFFF000, 0xFFFFF000ul), QSPI_E_RANGE);       /* length that wraps */
    CHECK_EQ_I((int)S.erases, 0); CHECK_EQ_I((int)S.programs, 0); CHECK(untouched_outside(0, 0));
    CHECK_EQ_I((int)S.bad, 0);
}

static void test_erase_write(void)
{
    static uint8_t data[5000], back[5000]; uint32_t i;
    for (i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 31 + 5);
    fresh(); CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK);
    CHECK_EQ_I(qspi_allow(&Q, 0xFBE000, 0xFC0000), QSPI_OK);
    CHECK_EQ_I(qspi_erase(&Q, 0xFBE000, 0x2000), QSPI_OK);
    CHECK_EQ_I((int)S.erases, 2);
    for (i = 0; i < 0x2000; i++) if (S.mem[0xFBE000 + i] != 0xFF) break;
    CHECK_EQ_I((int)i, 0x2000);
    CHECK(untouched_outside(0xFBE000, 0xFC0000));
    /* an odd start, an odd length, many pages */
    CHECK_EQ_I(qspi_write(&Q, 0xFBE003, data, 5000), QSPI_OK);
    CHECK(memcmp(S.mem + 0xFBE003, data, 5000) == 0);
    CHECK_EQ_I(S.mem[0xFBE002], 0xFF); CHECK_EQ_I(S.mem[0xFBE003 + 5000], 0xFF);
    CHECK(untouched_outside(0xFBE000, 0xFC0000));
    CHECK_EQ_I(qspi_read(&Q, 0xFBE003, back, 5000), QSPI_OK); CHECK(memcmp(back, data, 5000) == 0);
    CHECK_EQ_I((int)S.bad, 0); CHECK_EQ_I(S.wel, 0);
    /* writing over what is not erased cannot give the data: reported */
    CHECK_EQ_I(qspi_write(&Q, 0xFBE003, back + 1, 100), QSPI_E_VERIFY);
    CHECK(untouched_outside(0xFBE000, 0xFC0000));
}

static void test_cut_program(void)
{
    static uint8_t data[600]; uint32_t i;
    for (i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 3 + 1);
    /* a page program that ends early is done again */
    fresh(); CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK); CHECK_EQ_I(qspi_allow(&Q, 0x8E0000, 0x8E2000), QSPI_OK);
    CHECK_EQ_I(qspi_erase(&Q, 0x8E0000, 0x1000), QSPI_OK);
    S.cut_bursts = 2;
    CHECK_EQ_I(qspi_write(&Q, 0x8E0010, data, 600), QSPI_OK);
    CHECK(memcmp(S.mem + 0x8E0010, data, 600) == 0); CHECK_EQ_I((int)Q.retries, 2);
    /* seen on the unit: a page program the chip never starts, which leaves
     * its write enable latch set, after which the controller programs
     * nothing more until it has been reset. Reset, set up, done again. */
    CHECK_EQ_I(qspi_erase(&Q, 0x8E0000, 0x1000), QSPI_OK);
    S.lost_bursts = 2; Q.retries = 0; S.resets = 0;
    CHECK_EQ_I(qspi_write(&Q, 0x8E0010, data, 600), QSPI_OK);
    CHECK(memcmp(S.mem + 0x8E0010, data, 600) == 0); CHECK_EQ_I((int)Q.retries, 2);
    CHECK_EQ_I((int)S.resets, 2); CHECK_EQ_I((int)S.bad, 0);
    /* and when it never completes: an error after a few tries */
    CHECK_EQ_I(qspi_erase(&Q, 0x8E0000, 0x1000), QSPI_OK);
    S.cut_bursts = 1000; S.programs = 0;
    CHECK_EQ_I(qspi_write(&Q, 0x8E0010, data, 600), QSPI_E_VERIFY);
    CHECK(S.programs < 10);
    S.cut_bursts = 0; S.lost_bursts = 1000;
    CHECK_EQ_I(qspi_erase(&Q, 0x8E0000, 0x1000), QSPI_OK);
    CHECK_EQ_I(qspi_write(&Q, 0x8E0010, data, 600), QSPI_E_VERIFY);
    CHECK_EQ_I(S.wel, 0); S.lost_bursts = 0;
    CHECK(untouched_outside(0x8E0000, 0x8E2000)); CHECK_EQ_I((int)S.bad, 0);
}

static void test_slow_chip(void)
{
    uint8_t b[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    /* a chip that stays busy for a long time is waited for */
    fresh(); S.busy_polls = 5000;
    CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK); CHECK_EQ_I(qspi_allow(&Q, 0xFBE000, 0xFC0000), QSPI_OK);
    CHECK_EQ_I(qspi_erase(&Q, 0xFBE000, 0x1000), QSPI_OK);
    CHECK_EQ_I(qspi_write(&Q, 0xFBE000, b, 8), QSPI_OK); CHECK(memcmp(S.mem + 0xFBE000, b, 8) == 0);
    CHECK_EQ_I((int)S.bad, 0);
    /* one that never finishes: an error */
    fresh(); S.busy_polls = 2000000000;
    CHECK_EQ_I(qspi_init(&Q, &IO), QSPI_OK); CHECK_EQ_I(qspi_allow(&Q, 0xFBE000, 0xFC0000), QSPI_OK);
    CHECK_EQ_I(qspi_erase(&Q, 0xFBE000, 0x2000), QSPI_E_TIMEOUT);
    CHECK_EQ_I((int)S.erases, 1);
}

int main(void)
{
    test_init(); test_ranges(); test_erase_write(); test_cut_program(); test_slow_chip();
    T_REPORT("qspi");
}
