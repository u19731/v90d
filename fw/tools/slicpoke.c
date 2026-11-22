/* v90d bring-up tool: talk to a SLIC of the HT802 from user space, through
 * /dev/mem, with our own polled use of the SoC's SPI block. For use on a
 * quiet bus only (the stock driver touches the bus on telephone events).
 *
 *   slicpoke [-c 0|1] regs            all direct registers
 *   slicpoke [-c 0|1] reg N [VALUE]   read, or write, one (decimal N, hex VALUE)
 *   slicpoke [-c 0|1] ram A [COUNT]   read RAM words (user mode is entered
 *                                     and left again for 1024 and up)
 *   slicpoke [-c 0|1] wram A VALUE    write one RAM word (hex VALUE)
 *   slicpoke [-c 0|1] reset           pulse the part's reset line
 *   slicpoke [-c 0|1] init [alaw|ulaw|linear [SLOT]]   reset and bring the port up (drv/slic.c)
 *   slicpoke [-c 0|1] hook | down     hook state and battery; line open and converter off
 *
 * While our kernel driver (v90line) runs, the bus is its own: the commands
 * above would cut into its accesses. These go through the driver instead
 * (its slic / slic2 attribute; the port's thread does the access between two
 * looks at the hook), at run time, during a call if need be:
 *
 *   slicpoke [-c 0|1] kreg N [VALUE]  a register
 *   slicpoke [-c 0|1] kram A [COUNT]  RAM words
 *   slicpoke [-c 0|1] kwram A VALUE   write one RAM word
 *   slicpoke [-c 0|1] gains           the AC path: gains, equalisers, hybrid,
 *                                     next to what drv/slic.c loads
 *   slicpoke [-c 0|1] dac DB          gain of the PCM-to-line path (what we
 *                                     send), in dB against drv/slic.c's value,
 *                                     tenths allowed (-6, -2.5, 1.5)
 *   slicpoke [-c 0|1] adc DB          the same for the line-to-PCM path (what
 *                                     we receive)
 *
 * dac / adc place the change where the part's own gain routine is described
 * to (refs/si3217x-map.md 4.4): D/A attenuation in RXACGAIN (545, and its
 * copy 906), D/A gain in the RXACEQ coefficients (546..549); A/D gain in
 * TXACGAIN (544), A/D attenuation in the TXACEQ coefficients (540..543). The
 * other member of each pair is put back to drv/slic.c's value. A restart of
 * the port by the driver loads drv/slic.c's values again.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <glob.h>
#include "../drv/slic.h"

#define SPI_BASE  0x05E00000ul
#define GPIO_BASE 0x05000000ul
#define BANK_D    (3 * 0x60)
enum { GLOBAL = 0x00, CON = 0x04, FRM = 0x08, IER = 0x0C, STAT = 0x10, DAT = 0x14 };
enum { ST_BUSY = 0x40, ST_RX_EMPTY = 0x08, ST_TX_EMPTY = 0x01 };
#define CON_MODE3_8BIT 0x0F81
#define CON_SHIFT_OFF  0x2000

static volatile uint8_t *spi, *gpio;
static unsigned cs_pin = 16;

static uint16_t r16(unsigned o) { return *(volatile uint16_t *)(spi + o); }
static void w16(unsigned o, uint16_t v) { *(volatile uint16_t *)(spi + o) = v; }
static void gw(unsigned o, uint32_t v) { *(volatile uint32_t *)(gpio + o) = v; }

static void nap(long ns) { struct timespec t = { 0, ns }; nanosleep(&t, 0); }
static void spin(int n) { volatile int i; for (i = 0; i < n; i++) ; }

static int wait_clear(unsigned reg, uint16_t mask)
{
    int i;
    for (i = 0; i < 200000; i++) if (!(r16(reg) & mask)) return 0;
    return -1;
}

static uint8_t xfer(void *ctx, uint8_t out)
{
    static int reading;         /* 0 control, 1 address, 2 data of a register access */
    static uint8_t ctl;
    uint8_t in = 0xFF;
    int rd;
    (void)ctx;
    rd = reading == 2 && (ctl & 0x40);
    if (reading == 0) ctl = out;
    reading = reading == 2 ? 0 : reading + 1;

    w16(GLOBAL, 0x04);                          /* FIFO pointers */
    if (wait_clear(GLOBAL, 0xFFFF)) { fprintf(stderr, "slicpoke: SPI block does not come out of FIFO reset\n"); exit(1); }
    spin(200);
    w16(CON, CON_MODE3_8BIT);
    w16(IER, 0);
    gw(BANK_D + 0x08, 1ul << cs_pin);           /* chip select low */
    spin(200);
    if (!rd) {
        w16(FRM, 0);
        w16(DAT, out);
        spin(100);
        if (wait_clear(STAT, ST_BUSY)) { fprintf(stderr, "slicpoke: SPI busy for ever\n"); exit(1); }
        spin(2000);                             /* a 1 MHz octet is 8 us */
        wait_clear(STAT, ST_BUSY);
    } else {
        uint16_t st0, st1;
        (void)r16(DAT);                         /* the dummy read starts the clock */
        w16(CON, CON_MODE3_8BIT | CON_SHIFT_OFF);
        st0 = r16(STAT);
        spin(3000);                             /* a 1 MHz octet is 8 us */
        if (wait_clear(STAT, ST_BUSY)) { fprintf(stderr, "slicpoke: SPI busy for ever\n"); exit(1); }
        st1 = r16(STAT);
        in = (uint8_t)r16(DAT);
        if (getenv("SLICPOKE_DEBUG")) fprintf(stderr, "rx: stat %04x -> %04x, frm %04x, dat %02x, stat after %04x\n", st0, st1, r16(FRM), in, r16(STAT));
    }
    spin(200);
    gw(BANK_D + 0x04, 1ul << cs_pin);           /* chip select high */
    spin(400);
    return in;
}
static void msleep_(void *ctx, unsigned ms) { (void)ctx; while (ms--) nap(1000000); }

/* ---- through the kernel driver ---- */

static char kpath[300];

static int kfind(void)
{
    glob_t g;
    const char *pat = cs_pin == 17 ? "/sys/bus/platform/drivers/v90line/*/slic2" : "/sys/bus/platform/drivers/v90line/*/slic";
    const char *env = getenv("SLICPOKE_ATTR");          /* for tests: the attribute file itself */
    if (env) { snprintf(kpath, sizeof kpath, "%s", env); return 0; }
    if (glob(pat, 0, 0, &g) != 0 || g.gl_pathc < 1) { fprintf(stderr, "slicpoke: no %s (is the v90line driver running?)\n", pat); return -1; }
    snprintf(kpath, sizeof kpath, "%s", g.gl_pathv[0]);
    globfree(&g);
    return 0;
}

/* one request ("r 544", "w 544 0a5db3a8", "R 11", "W 11 13"); the value
 * the part holds afterwards */
static int kdo(const char *req, uint32_t *val)
{
    char line[64]; ssize_t n; unsigned a; unsigned long v; int fd;
    if (!kpath[0] && kfind()) return -1;
    fd = open(kpath, O_WRONLY);
    if (fd < 0 || write(fd, req, strlen(req)) != (ssize_t)strlen(req)) { perror(kpath); if (fd >= 0) close(fd); return -1; }
    close(fd);
    fd = open(kpath, O_RDONLY);
    n = fd < 0 ? -1 : read(fd, line, sizeof line - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) { perror(kpath); return -1; }
    line[n] = 0;
    if (sscanf(line, "%*s %u = %lx", &a, &v) != 2) { fprintf(stderr, "slicpoke: driver said \"%s\"\n", line); return -1; }
    *val = (uint32_t)v;
    return 0;
}
static int kram(unsigned a, uint32_t *v) { char r[32]; snprintf(r, sizeof r, "r %u", a); return kdo(r, v); }
static int kwram(unsigned a, uint32_t w, uint32_t *v) { char r[40]; snprintf(r, sizeof r, "w %u %lx", a, (unsigned long)w); return kdo(r, v); }

/* "-2.5" -> -25 (tenths of a dB) */
static int db10_of(const char *s)
{
    int neg = *s == '-', whole = 0, tenth = 0;
    if (*s == '-' || *s == '+') s++;
    while (*s >= '0' && *s <= '9') whole = whole * 10 + (*s++ - '0');
    if (*s == '.' && s[1] >= '0' && s[1] <= '9') tenth = s[1] - '0';
    return neg ? -(whole * 10 + tenth) : whole * 10 + tenth;
}

static double word_q27(uint32_t v) { return (double)((v & 0x10000000ul) ? (long)v - 0x20000000l : (long)v) / 134217728.0; }

static int kgains(void)
{
    static const struct { unsigned a; const char *n; } t[] = {
        { 540, "TXACEQ_C0" }, { 541, "TXACEQ_C1" }, { 542, "TXACEQ_C2" }, { 543, "TXACEQ_C3" },
        { 544, "TXACGAIN  (A/D path gain)" }, { 545, "RXACGAIN  (D/A path gain)" }, { 906, "RXACGAIN_SAVE" },
        { 546, "RXACEQ_C0" }, { 547, "RXACEQ_C1" }, { 548, "RXACEQ_C2" }, { 549, "RXACEQ_C3" },
        { 563, "ECFIR_C2" }, { 564, "ECFIR_C3" }, { 565, "ECFIR_C4" }, { 566, "ECFIR_C5" },
        { 567, "ECFIR_C6" }, { 568, "ECFIR_C7" }, { 569, "ECFIR_C8" }, { 570, "ECFIR_C9" },
        { 571, "ECIIR_B0" }, { 572, "ECIIR_B1" }, { 573, "ECIIR_A1" }, { 574, "ECIIR_A2" },
        { 1002, "LINEAR_OS" },
    };
    unsigned i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        uint32_t v, d = 0; int has = slic_default_ram(t[i].a, &d);
        if (kram(t[i].a, &v)) return 1;
        printf("ram %4u = %08lx  %+9.6f", t[i].a, (unsigned long)v, word_q27(v));
        if (has) printf("  drv/slic.c %08lx%s", (unsigned long)d, v == d ? "" : "  CHANGED");
        printf("  %s\n", t[i].n);
    }
    return 0;
}

/* gain_addr takes the change when it is of sign `gain_sign`, else the four
 * equaliser coefficients from eq0 do; the others go back to drv/slic.c's */
static int kgain(int db10, int gain_sign, unsigned gain_addr, unsigned save_addr, unsigned eq0)
{
    int in_gain = db10 == 0 || (db10 > 0) == (gain_sign > 0), k;
    uint32_t base, v;
    if (!slic_default_ram(gain_addr, &base)) return 1;
    v = slic_gain_scale(base, in_gain ? db10 : 0);
    if (in_gain && db10 > 0 && v == 0x0FFFFFFFul) { fprintf(stderr, "slicpoke: %d.%d dB does not fit the gain word\n", db10 / 10, db10 % 10); return 1; }
    for (k = 0; k < 4; k++) {
        uint32_t c, w;
        if (!slic_default_ram(eq0 + (unsigned)k, &c)) return 1;
        w = slic_gain_scale(c, in_gain ? 0 : db10);
        if (kwram(eq0 + (unsigned)k, w, &c)) return 1;
        printf("ram %4u = %08lx\n", eq0 + (unsigned)k, (unsigned long)c);
    }
    if (save_addr) { uint32_t c; if (kwram(save_addr, v, &c)) return 1; printf("ram %4u = %08lx\n", save_addr, (unsigned long)c); }
    if (kwram(gain_addr, v, &base)) return 1;
    printf("ram %4u = %08lx\n", gain_addr, (unsigned long)base);
    return 0;
}

static int kmain(int argc, char **argv, int a)
{
    uint32_t v;
    if (!strcmp(argv[a], "kreg") && argc > a + 1) {
        char r[40];
        if (argc > a + 2) snprintf(r, sizeof r, "W %d %lx", atoi(argv[a + 1]), strtoul(argv[a + 2], 0, 16));
        else snprintf(r, sizeof r, "R %d", atoi(argv[a + 1]));
        if (kdo(r, &v)) return 1;
        printf("reg %3d = %02lx\n", atoi(argv[a + 1]), (unsigned long)v);
        return 0;
    }
    if (!strcmp(argv[a], "kram") && argc > a + 1) {
        unsigned A = (unsigned)atoi(argv[a + 1]), n = argc > a + 2 ? (unsigned)atoi(argv[a + 2]) : 1, i;
        for (i = 0; i < n; i++) { if (kram(A + i, &v)) return 1; printf("ram %4u = %08lx\n", A + i, (unsigned long)v); }
        return 0;
    }
    if (!strcmp(argv[a], "kwram") && argc > a + 2) {
        if (kwram((unsigned)atoi(argv[a + 1]), (uint32_t)strtoul(argv[a + 2], 0, 16), &v)) return 1;
        printf("ram %4u = %08lx\n", (unsigned)atoi(argv[a + 1]), (unsigned long)v);
        return 0;
    }
    if (!strcmp(argv[a], "gains")) return kgains();
    /* D/A path: attenuation in RXACGAIN (and its copy), gain in RXACEQ */
    if (!strcmp(argv[a], "dac") && argc > a + 1) return kgain(db10_of(argv[a + 1]), -1, SLIC_RXACGAIN, SLIC_RXACGAIN_SAVE, SLIC_RXACEQ_C0);
    /* A/D path: gain in TXACGAIN, attenuation in TXACEQ */
    if (!strcmp(argv[a], "adc") && argc > a + 1) return kgain(db10_of(argv[a + 1]), 1, SLIC_TXACGAIN, 0, SLIC_TXACEQ_C0);
    return -1;
}

int main(int argc, char **argv)
{
    ps_bus b = { xfer, msleep_, 0 };
    int a = 1, fd;
    if (argc > 2 && !strcmp(argv[1], "-c")) { cs_pin = atoi(argv[2]) ? 17 : 16; a = 3; }
    if (argc <= a) { fprintf(stderr, "usage: slicpoke [-c 0|1] regs | reg N [V] | ram A [COUNT] | wram A V | reset | init | hook | down\n"
                                     "       through the running driver: kreg N [V] | kram A [COUNT] | kwram A V | gains | dac DB | adc DB\n"); return 2; }
    {
        int r = kmain(argc, argv, a);
        if (r >= 0) return r;
    }
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) { perror("/dev/mem"); return 1; }
    spi = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)SPI_BASE);
    gpio = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)GPIO_BASE);
    if (spi == MAP_FAILED || gpio == MAP_FAILED) { perror("mmap"); return 1; }

    if (!strcmp(argv[a], "regs")) {
        int r;
        for (r = 0; r < 128; r++) printf("reg %3d = %02x\n", r, ps_rd(&b, (uint8_t)r));
    } else if (!strcmp(argv[a], "reg") && argc > a + 1) {
        int r = atoi(argv[a + 1]);
        if (argc > a + 2) ps_wr(&b, (uint8_t)r, (uint8_t)strtoul(argv[a + 2], 0, 16));
        printf("reg %3d = %02x\n", r, ps_rd(&b, (uint8_t)r));
    } else if (!strcmp(argv[a], "ram") && argc > a + 1) {
        unsigned A = (unsigned)atoi(argv[a + 1]), n = argc > a + 2 ? (unsigned)atoi(argv[a + 2]) : 1, i;
        int was = ps_rd(&b, PS_TEST_CNTL) & 1, need = A + n > PS_RAM_USER;
        if (need && !was && ps_user_mode(&b, 1)) { fprintf(stderr, "slicpoke: no user mode\n"); return 1; }
        for (i = 0; i < n; i++) {
            uint32_t v, v2; int tries = 0;
            /* from user space an interrupt can land inside an octet: take
             * a value only when two readings agree */
            do {
                if (ps_ram_rd(&b, A + i, &v) || ps_ram_rd(&b, A + i, &v2)) { printf("ram %4u = (not ready)\n", A + i); return 1; }
            } while (v != v2 && ++tries < 8);
            if (v != v2) { printf("ram %4u = (unstable)\n", A + i); continue; }
            printf("ram %4u = %08lx\n", A + i, (unsigned long)v);
        }
        if (need && !was) ps_user_mode(&b, 0);
    } else if (!strcmp(argv[a], "wram") && argc > a + 2) {
        unsigned A = (unsigned)atoi(argv[a + 1]);
        int was = ps_rd(&b, PS_TEST_CNTL) & 1, need = A >= PS_RAM_USER;
        uint32_t v = 0;
        if (need && !was && ps_user_mode(&b, 1)) { fprintf(stderr, "slicpoke: no user mode\n"); return 1; }
        if (ps_ram_wr(&b, A, (uint32_t)strtoul(argv[a + 2], 0, 16)) || ps_ram_rd(&b, A, &v)) { fprintf(stderr, "slicpoke: not ready\n"); return 1; }
        printf("ram %4u = %08lx\n", A, (unsigned long)v);
        if (need && !was) ps_user_mode(&b, 0);
    } else if (!strcmp(argv[a], "reset")) {
        /* the part's reset line: EGPIO21 (port 1) or EGPIO19 (port 2), low = reset */
        uint32_t bit = 1ul << (cs_pin == 16 ? 21 : 19);
        gw(4 * 0x60 + 0x08, bit); msleep_(0, 10);
        gw(4 * 0x60 + 0x04, bit); msleep_(0, 100);
        printf("reg   0 = %02x\n", ps_rd(&b, PS_ID));
    } else if (!strcmp(argv[a], "init")) {
        /* our own bring-up of the port: reset, then drv/slic.c */
        slic_cfg cfg = { SLIC_PCM_LINEAR, 0, 0 }; slic_info info; int r;
        uint32_t bit = 1ul << (cs_pin == 16 ? 21 : 19);
        if (argc > a + 1) cfg.pcm_format = !strcmp(argv[a + 1], "alaw") ? SLIC_PCM_ALAW : !strcmp(argv[a + 1], "ulaw") ? SLIC_PCM_ULAW : SLIC_PCM_LINEAR;
        if (argc > a + 2) cfg.slot = (uint16_t)atoi(argv[a + 2]);
        gw(4 * 0x60 + 0x08, bit); msleep_(0, 10);
        gw(4 * 0x60 + 0x04, bit); msleep_(0, 250);
        r = slic_init(&b, &cfg, &info);
        printf("slic_init: %d (stage %d), id %02x, battery %ld mV\n", r, info.stage, info.id, info.vbat_mv);
        return r ? 1 : 0;
    } else if (!strcmp(argv[a], "hook")) {
        printf("hook %d, battery %ld mV, linefeed %02x\n", slic_offhook(&b), slic_vbat_mv(&b), ps_rd(&b, PS_LINEFEED));
    } else if (!strcmp(argv[a], "down")) {
        slic_shutdown(&b);
        printf("line open, converter off; battery %ld mV\n", slic_vbat_mv(&b));
    } else { fprintf(stderr, "slicpoke: what?\n"); return 2; }
    return 0;
}
