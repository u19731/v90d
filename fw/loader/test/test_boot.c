/* The loader's decisions, run on the host against the model of the flash
 * controller and chip that the flash driver's own tests use (fw/drv/test). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "../boot.h"
#include "qspisim.h"

static qspisim S; static uint8_t *before, *ram;
static ld_env E; static ld_result R;
#define RAM_MAX 0x400000u

static void put32be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void put32le(uint8_t *p, uint32_t v) { p[3] = (uint8_t)(v >> 24); p[2] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[0] = (uint8_t)v; }

/* a legacy U-Boot image at flash offset `at` */
static void put_uimage(uint32_t at, const char *name, uint32_t load, uint32_t n, uint8_t seed)
{
    uint8_t *h = S.mem + at, *d = h + 64; uint32_t i;
    for (i = 0; i < n; i++) d[i] = (uint8_t)(seed + i * 31 + (i >> 8));
    memset(h, 0, 64);
    put32be(h, 0x27051956); put32be(h + 12, n); put32be(h + 16, load); put32be(h + 20, load);
    put32be(h + 24, ld_crc32(0, d, n));
    h[28] = 5; h[29] = 2; h[30] = 2; h[31] = 0;
    strncpy((char *)h + 32, name, 31);
    put32be(h + 4, ld_crc32(0, h, 64));
}
/* the stock partition header in front of a payload of n octets */
static void put_gs(uint32_t at, uint32_t n, uint32_t counter)
{
    uint8_t *h = S.mem + at;
    memset(h, 0, 0x200);
    put32le(h, 0x23C97AF9); put32le(h + 12, n); put32le(h + 0x30, counter);
}
/* one set as the stock upgrade leaves it: loader in core, system in base,
 * the rest of both partitions erased */
static void install(int set, uint32_t image_len, uint8_t seed)
{
    uint32_t core = set ? LD_CORE_B : LD_CORE_A, base = set ? LD_BASE_B : LD_BASE_A;
    memset(S.mem + core, 0xFF, 0x140000); memset(S.mem + base, 0xFF, 0x300000);
    put_gs(core, 64 + 3000, 5); put_uimage(core + 0x200, "v90d-loader", 0xC9000000ul, 3000, 9);
    put_gs(base, 64 + image_len, 5); put_uimage(base + 0x200, "v90d", LD_LOAD, image_len, seed);
}
/* a device tree as the boot loader hands it over, for the set it started */
static uint8_t fdt_a[256], fdt_b[256];
static void make_fdt(uint8_t *f, int set)
{
    memset(f, 0, 256);
    put32be(f, 0xD00DFEED); put32be(f + 4, 256);
    sprintf((char *)f + 80, "gxp_console=0 root=/dev/mtdblock%d bootpartition=%d partgeneration=1 mtdparts=qspi:16k(bootastic)", 6 + set, set);
}
static void fresh(void)
{
    if (S.mem) qspisim_free(&S);
    qspisim_init(&S); qspisim_after_uboot(&S);
    memcpy(S.mem + LD_BOARD_OFF, "9610003725A", 12);
    if (!before) before = malloc(QSPI_SIZE);
    if (!ram) ram = malloc(RAM_MAX);
    memset(ram, 0xEE, RAM_MAX);
    make_fdt(fdt_a, 0); make_fdt(fdt_b, 1);
    memset(&E, 0, sizeof E);
    qspisim_io(&S, &E.io);
    E.ram = ram; E.ram_max = RAM_MAX; E.fdt = fdt_a; E.fdt_max = sizeof fdt_a;
}
static void keep(void) { memcpy(before, S.mem, QSPI_SIZE); }
static int same(uint32_t lo, uint32_t hi) { return memcmp(S.mem + lo, before + lo, hi - lo) == 0; }
/* the flash differs from what it was only inside [lo, hi) */
static int untouched_outside(uint32_t lo, uint32_t hi) { return same(0, lo) && same(hi, QSPI_SIZE); }
static uint32_t word(uint32_t at) { const uint8_t *p = S.mem + at; return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

static void test_pieces(void)
{
    uint8_t f[128];
    CHECK_EQ_I(ld_crc32(0, (const uint8_t *)"123456789", 9) == 0xCBF43926ul, 1);
    CHECK_EQ_I(ld_crc32(ld_crc32(0, (const uint8_t *)"1234", 4), (const uint8_t *)"56789", 5) == 0xCBF43926ul, 1);
    make_fdt(fdt_a, 0); make_fdt(fdt_b, 1);
    CHECK_EQ_I(ld_set_from_fdt(fdt_a, 256), 0);
    CHECK_EQ_I(ld_set_from_fdt(fdt_b, 256), 1);
    CHECK_EQ_I(ld_set_from_fdt(0, 256), -1);
    CHECK_EQ_I(ld_set_from_fdt(fdt_b, 90), -1);                 /* the word lies beyond what may be read */
    memcpy(f, fdt_b, 128); f[0] = 0;                            /* not a device tree */
    CHECK_EQ_I(ld_set_from_fdt(f, 128), -1);
    memcpy(f, fdt_b, 128); put32be(f + 4, 100);                 /* the tree says it ends before the word */
    CHECK_EQ_I(ld_set_from_fdt(f, 128), -1);
    memset(f, 0, 128); put32be(f, 0xD00DFEED); put32be(f + 4, 128);
    CHECK_EQ_I(ld_set_from_fdt(f, 128), -1);
    strcpy((char *)f + 40, "bootpartition=7");                  /* not a set we know */
    CHECK_EQ_I(ld_set_from_fdt(f, 128), -1);
    strcpy((char *)f + 113, "bootpartition=");                  /* cut off at the end */
    CHECK_EQ_I(ld_set_from_fdt(f, 128), -1);
    CHECK_EQ_I(ld_tries(0xFFFFFFFFul), 0);
    CHECK_EQ_I(ld_tries(0xFFFFFFFEul), 1);
    CHECK_EQ_I(ld_tries(0xFFFFFFF8ul), 3);
    CHECK_EQ_I(ld_tries(0), 32);
}

static void test_boots(int set)
{
    uint32_t core = set ? LD_CORE_B : LD_CORE_A, base = set ? LD_BASE_B : LD_BASE_A, n = 2161190;
    fresh(); install(set, n, 3); E.fdt = set ? fdt_b : fdt_a; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.why, LD_W_OK); CHECK_EQ_I(R.set, set); CHECK_EQ_I(R.image_set, set);
    CHECK_EQ_I(R.size, n); CHECK_EQ_I(R.tries, 1);
    CHECK(memcmp(ram, S.mem + base + 0x200 + 64, n) == 0);
    CHECK_EQ_I(ram[n], 0xEE);                                   /* not a byte more */
    CHECK(untouched_outside(core + LD_STATE_OFF, core + LD_STATE_OFF + 4));
    CHECK_EQ_I(word(core + LD_STATE_OFF) == 0xFFFFFFFEul, 1);
    CHECK_EQ_I((int)S.bad, 0); CHECK_EQ_I((int)S.erases, 0);
}

static void test_three_starts_then_stock(void)
{
    int i;
    fresh(); install(1, 50000, 4); E.fdt = fdt_b; keep();
    for (i = 1; i <= LD_MAX_TRIES; i++) {
        qspisim_after_uboot(&S);
        ld_run(&E, &R);
        CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.tries, i);
    }
    CHECK(untouched_outside(LD_CORE_B + LD_STATE_OFF, LD_CORE_B + LD_STATE_OFF + 4));
    qspisim_after_uboot(&S);
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_TRIES);
    /* our own header is no longer one; done by programming, never by erasing */
    CHECK_EQ_I(word(LD_CORE_B) == 0, 1); CHECK_EQ_I((int)S.erases, 0);
    CHECK(same(LD_CORE_B + 4, LD_CORE_B + LD_STATE_OFF));
    CHECK(untouched_outside(LD_CORE_B, LD_CORE_B + LD_STATE_OFF + 4));
    CHECK_EQ_I((int)S.bad, 0);
    /* a state word that is rubbish counts as used up */
    fresh(); install(0, 50000, 4); memset(S.mem + LD_CORE_A + LD_STATE_OFF, 0, 4); keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_TRIES); CHECK_EQ_I(word(LD_CORE_A) == 0, 1);
    CHECK(untouched_outside(LD_CORE_A, LD_CORE_A + 4));
}

static void test_bad_image(void)
{
    /* one bit wrong in the system image: back to stock */
    fresh(); install(0, 70000, 5); S.mem[LD_BASE_A + 0x200 + 64 + 12345] ^= 4; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_NOIMAGE); CHECK_EQ_I(word(LD_CORE_A) == 0, 1);
    CHECK(untouched_outside(LD_CORE_A, LD_CORE_A + 4)); CHECK_EQ_I((int)S.bad, 0);
    /* a header that lies about the size must not send the copy over the RAM we were given */
    fresh(); install(0, 70000, 5); put32be(S.mem + LD_BASE_A + 0x200 + 12, 0x7FFFFFF0ul);
    put32be(S.mem + LD_BASE_A + 0x200 + 4, 0); put32be(S.mem + LD_BASE_A + 0x200 + 4, ld_crc32(0, S.mem + LD_BASE_A + 0x200, 64)); keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_NOIMAGE); CHECK_EQ_I(ram[0], 0xEE);
    /* nor an honest one that is larger than the room it was given */
    fresh(); install(0, 70000, 5); E.ram_max = 69999; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_NOIMAGE); CHECK_EQ_I(ram[0], 0xEE);
    /* an image built for another address, or one that is not ours, is not started */
    fresh(); install(0, 70000, 5); put_uimage(LD_BASE_A + 0x200, "v90d", 0xC8000000ul, 70000, 5); keep();
    ld_run(&E, &R); CHECK_EQ_I(R.why, LD_W_NOIMAGE);
    fresh(); install(0, 70000, 5); put_uimage(LD_BASE_A + 0x200, "Linux-3.4.20", LD_LOAD, 70000, 5); keep();
    ld_run(&E, &R); CHECK_EQ_I(R.why, LD_W_NOIMAGE);
    fresh(); install(0, 70000, 5); put_uimage(LD_BASE_A + 0x200, "v90d-loader", LD_LOAD, 70000, 5); keep();
    ld_run(&E, &R); CHECK_EQ_I(R.why, LD_W_NOIMAGE);
    /* our own set's image bad, the other set holds a good one of ours: that one */
    fresh(); install(0, 70000, 5); install(1, 60000, 6); S.mem[LD_BASE_A + 0x200 + 64 + 100] ^= 1; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.set, 0); CHECK_EQ_I(R.image_set, 1); CHECK_EQ_I(R.size, 60000);
    CHECK(memcmp(ram, S.mem + LD_BASE_B + 0x200 + 64, 60000) == 0);
    CHECK(untouched_outside(LD_CORE_A + LD_STATE_OFF, LD_CORE_A + LD_STATE_OFF + 4));
    /* both good: our own set's */
    fresh(); install(0, 70000, 5); install(1, 60000, 6); E.fdt = fdt_b; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.set, 1); CHECK_EQ_I(R.image_set, 1); CHECK_EQ_I(R.size, 60000);
}

static void test_other_hardware(void)
{
    /* a board we never tried: no start, back to stock, no attempt counted */
    fresh(); install(0, 50000, 7); memcpy(S.mem + LD_BOARD_OFF, "9610003713B", 12); keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_BOARD); CHECK_EQ_I(word(LD_CORE_A) == 0, 1);
    CHECK(untouched_outside(LD_CORE_A, LD_CORE_A + 4)); CHECK_EQ_I(ram[0], 0xEE);
    /* a longer name that only starts like ours is another board */
    fresh(); install(0, 50000, 7); memcpy(S.mem + LD_BOARD_OFF, "9610003725AB", 13); keep();
    ld_run(&E, &R); CHECK_EQ_I(R.why, LD_W_BOARD);
    /* the one-port box (HT801), in the two revisions whose flash was read */
    fresh(); install(0, 50000, 7); memcpy(S.mem + LD_BOARD_OFF, "9611003610A", 12); keep();
    ld_run(&E, &R); CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.size, 50000);
    fresh(); install(0, 50000, 7); memcpy(S.mem + LD_BOARD_OFF, "9610003611C", 12); keep();
    ld_run(&E, &R); CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.size, 50000);
    /* a Winbond W25Q128FV flash (issue #4's HT802 V1.6A, board 9610003716A):
     * the loader must set the quad-enable bit and enter QPI itself, then boot */
    fresh(); install(0, 50000, 7); memcpy(S.mem + LD_BOARD_OFF, "9610003716A", 12);
    S.id[0] = 0xEF; S.id[1] = 0x40; S.id[2] = 0x18; S.need_qe = 1; S.sr2 = 0; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.size, 50000); CHECK_EQ_I((int)S.bad, 0);
    CHECK_EQ_I(S.qpi, 1); CHECK_EQ_I((S.sr2 & 0x02) != 0, 1);
    /* a GigaDevice GD25Q128 flash (also quad-enabled in SR2): boots too */
    fresh(); install(0, 50000, 7); memcpy(S.mem + LD_BOARD_OFF, "9610003716A", 12);
    S.id[0] = 0xC8; S.id[1] = 0x40; S.id[2] = 0x18; S.need_qe = 1; S.sr2 = 0; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.size, 50000); CHECK_EQ_I((int)S.bad, 0);
    /* a flash chip the driver does not know: it stays in single-line mode,
     * our header's sector is erased with plain commands, nothing else */
    fresh(); install(1, 50000, 7); E.fdt = fdt_b; S.id[0] = 0xC2; S.id[1] = 0x20; keep();   /* Macronix: a chip we do not carry */
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_FLASH);
    CHECK_EQ_I((int)S.erases, 1); CHECK_EQ_I(S.last_erase == LD_CORE_B, 1); CHECK_EQ_I(S.qpi, 0);
    CHECK_EQ_I(word(LD_CORE_B) == 0xFFFFFFFFul, 1);
    CHECK(untouched_outside(LD_CORE_B, LD_CORE_B + 0x1000)); CHECK_EQ_I((int)S.bad, 0);
    /* the same, but nothing says which set we are: hands off */
    fresh(); install(1, 50000, 7); E.fdt = 0; S.id[0] = 0xC2; S.id[1] = 0x20; keep();   /* Macronix: a chip we do not carry */
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_FLASH); CHECK(untouched_outside(0, 0));
    /* a controller that never answers ends in a reset, not a hang */
    fresh(); install(0, 50000, 7); S.stuck = 1; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_FLASH); CHECK(untouched_outside(0, 0));
}

static void test_flash_trouble(void)
{
    /* a page program the chip never got (seen on the unit): done again */
    fresh(); install(0, 50000, 8); S.lost_bursts = 1; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(word(LD_CORE_A + LD_STATE_OFF) == 0xFFFFFFFEul, 1);
    CHECK_EQ_I((int)S.resets, 1);
    /* programming does not work at all: an attempt that cannot be counted
     * is not made; the header goes by erasing, the last resort */
    fresh(); install(0, 50000, 8); S.lost_bursts = 1000; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_RECORD);
    CHECK_EQ_I((int)S.erases, 1); CHECK_EQ_I(S.last_erase == LD_CORE_A, 1);
    CHECK(untouched_outside(LD_CORE_A, LD_CORE_A + 0x1000));
}

static void test_not_from_flash(void)
{
    /* started from RAM during bring-up: no device tree from the boot
     * loader, no loader of ours in either core. The image is found (here
     * at the place the bring-up build keeps it, the very start of base A)
     * and started; the flash is not written. */
    fresh(); E.fdt = 0;
    put_uimage(LD_BASE_A, "v90d", LD_LOAD, 80000, 1); keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.set, -1); CHECK_EQ_I(R.image_set, 0); CHECK_EQ_I(R.tries, 0);
    CHECK(memcmp(ram, S.mem + LD_BASE_A + 64, 80000) == 0);
    CHECK(untouched_outside(0, 0)); CHECK_EQ_I((int)S.bad, 0);
    /* nothing to start and nothing of ours to give up: reset, flash as it was */
    fresh(); E.fdt = 0; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_NOIMAGE); CHECK(untouched_outside(0, 0));
    /* no device tree, but one core holds our loader: that is our set */
    fresh(); install(1, 50000, 2); E.fdt = 0; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_BOOT); CHECK_EQ_I(R.set, 1); CHECK_EQ_I(R.tries, 1);
    /* the boot loader names a set whose core is not ours (the stock
     * kernel's place): never written, whatever happens */
    fresh(); install(1, 50000, 2); E.fdt = fdt_a;
    put_gs(LD_CORE_A, 64 + 4000, 9); put_uimage(LD_CORE_A + 0x200, "Linux-3.4.20", LD_LOAD, 4000, 1);
    S.mem[LD_BASE_B + 0x200 + 64 + 9] ^= 1; keep();
    ld_run(&E, &R);
    CHECK_EQ_I(R.action, LD_RESET); CHECK_EQ_I(R.why, LD_W_NOIMAGE); CHECK(untouched_outside(0, 0));
}

int main(void)
{
    test_pieces(); test_boots(0); test_boots(1); test_three_starts_then_stock(); test_bad_image();
    test_other_hardware(); test_flash_trouble(); test_not_from_flash();
    T_REPORT("loader");
}
