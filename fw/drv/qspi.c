/* See qspi.h. */
#include "qspi.h"

/* controller registers */
enum { R_CFG = 0x000, R_STS = 0x008, R_ISR = 0x00C, R_IER = 0x010, R_ICR = 0x014, R_FWD = 0x020, R_FRD = 0x040,
       R_RDTRSTP = 0x13C, R_RDCMD = 0x140, R_PPTRSTP = 0x144, R_PPCMD = 0x148, R_MEMADD = 0x154,
       R_TRSTP = 0x300, R_CMD = 0x304, R_ADD = 0x308, R_CSTIMING = 0x408 };
#define STS_BUSY    0x80000000ul
#define STS_IDLE    0x00000001ul
#define INT_DONE    0x40u               /* a register-driven transfer has ended */
#define TR_HAS_OP   (1ul << 19)
#define TR_ADDR3    (1ul << 10)
#define TR_QUAD     0x28Aul             /* opcode, address, data out and data in on four lines */
#define TR_SINGLE   0ul
#define CMD_START   0x80000000ul
#define CMD_IN      (1ul << 13)
#define CMD_RDID    (0x9Ful | (9ul << 8) | CMD_IN)
#define CMD_RDSR    (0x05ul | (5ul << 8) | CMD_IN)
#define CMD_WREN    (0x06ul | (9ul << 8))
#define CMD_WRDI    (0x04ul | (9ul << 8))
#define CMD_QPI     (0x38ul | (9ul << 8))
#define CMD_SE      (0x20ul | (0ul << 8))
#define CMD_OUT     (1ul << 14)             /* the data phase is a write */
/* chip bring-up commands, single line until QPI is on (refs/qspi-chips.md) */
#define CMD_RDSR2   (0x35ul | (5ul << 8) | CMD_IN)      /* read status register 2 */
#define CMD_WRSR2   (0x31ul | (6ul << 8) | CMD_OUT)     /* write status register 2 */
#define CMD_VWREN   (0x50ul | (9ul << 8))               /* volatile status write enable (Winbond) */
#define CMD_SETRD   (0xC0ul | (9ul << 8) | CMD_OUT)     /* Winbond set read parameters (in QPI) */
#define QE_SR2      0x02u                                /* quad enable: bit 1 of status register 2 */
/* Micron N25Q: quad and dummy live in the (enhanced) volatile config registers */
#define CMD_WRSR    (0x01ul | (6ul << 8) | CMD_OUT)
#define CMD_RDVCR   (0x85ul | (5ul << 8) | CMD_IN)
#define CMD_WRVCR   (0x81ul | (6ul << 8) | CMD_OUT)
#define CMD_RDEVCR  (0x65ul | (5ul << 8) | CMD_IN)
#define CMD_WREVCR  (0x61ul | (6ul << 8) | CMD_OUT)
#define SR_BUSY     0x01u
#define SR_WEL      0x02u
/* the values the unit's own software runs the chip with (read from it) */
#define V_CFG       0x00010009ul
#define V_CSTIMING  0x00000300ul
#define V_RDTRSTP   0x0008362Aul        /* fast read 0x0B, all on four lines, 6 dummy clocks */
#define V_RDTRSTP_GD 0x0008262Aul       /* same, 4 dummy clocks (GD25Q128) */
#define V_RDCMD     0x0000000Bul
#define V_PPTRSTP   0x0008048Aul        /* page program 0x02, all on four lines */
#define V_PPCMD     0x00000002ul
#define V_MEMADD    0xFFFF0000ul

#define IDLE_POLLS  100000u             /* x 10 us: 1 s */
#define CHIP_POLLS  40000u              /* x 100 us: 4 s; a sector erase takes 0.4 s at most */
#define TRIES       4

#define RD(q, r)      ((q)->io.rd((q)->io.ctx, (r)))
#define WR(q, r, v)   ((q)->io.wr((q)->io.ctx, (r), (v)))

/* one register-driven command: opcode, perhaps an address, perhaps up to 32
 * octets in. The data buffers are filled from the end backwards. */
static int aux(qspi_t *q, uint32_t lines, uint32_t cmd, int with_addr, uint32_t addr, uint8_t *in, unsigned n)
{
    unsigned i;
    for (i = 0; ; i++) {
        uint32_t s = RD(q, R_STS);
        if (!(s & STS_BUSY) && (s & STS_IDLE)) break;
        if (i >= IDLE_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 10);
    }
    WR(q, R_TRSTP, lines | TR_HAS_OP | ((uint32_t)n << 20) | (with_addr ? TR_ADDR3 : 0));
    if (with_addr) WR(q, R_ADD, addr);
    WR(q, R_CMD, cmd | CMD_START);
    for (i = 0; !(RD(q, R_ISR) & INT_DONE); i++) {
        if (i >= IDLE_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 10);
    }
    WR(q, R_ICR, INT_DONE);             /* not self-clearing */
    for (i = 0; RD(q, R_ISR) & INT_DONE; i++) {
        if (i >= IDLE_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 10);
    }
    WR(q, R_ICR, 0);
    for (i = 0; i < n; i++) {
        unsigned at = 31 - i;
        in[i] = (uint8_t)(RD(q, R_FRD + (at & ~3u)) >> (8 * (at & 3)));
    }
    return QSPI_OK;
}

/* a register-driven command that writes up to 32 octets out; the FIFO is
 * filled from the end, the way the read path (aux) reads it */
static int aux_out(qspi_t *q, uint32_t lines, uint32_t cmd, const uint8_t *out, unsigned n)
{
    uint32_t w[8];
    unsigned i;
    for (i = 0; i < 8; i++) w[i] = 0;
    for (i = 0; i < n; i++) { unsigned at = 31 - i; w[at >> 2] |= (uint32_t)out[i] << (8 * (at & 3)); }
    for (i = 0; ; i++) {
        uint32_t s = RD(q, R_STS);
        if (!(s & STS_BUSY) && (s & STS_IDLE)) break;
        if (i >= IDLE_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 10);
    }
    for (i = 0; i < 8; i++) WR(q, R_FWD + i * 4, w[i]);
    WR(q, R_TRSTP, lines | TR_HAS_OP | ((uint32_t)n << 20));
    WR(q, R_CMD, cmd | CMD_START);
    for (i = 0; !(RD(q, R_ISR) & INT_DONE); i++) {
        if (i >= IDLE_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 10);
    }
    WR(q, R_ICR, INT_DONE);
    for (i = 0; RD(q, R_ISR) & INT_DONE; i++) {
        if (i >= IDLE_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 10);
    }
    WR(q, R_ICR, 0);
    return QSPI_OK;
}

/* the chips we know, by JEDEC id; all 16 MiB, read 0x0B in QPI (refs/qspi-chips.md) */
static const struct { uint8_t id[3]; int chip; uint32_t rdtrstp; } CHIPS[] = {
    { { 0x1C, 0x71, 0x18 }, QSPI_CHIP_EON,     V_RDTRSTP },     /* EN25QX128A */
    { { 0xEF, 0x40, 0x18 }, QSPI_CHIP_WINBOND, V_RDTRSTP },     /* W25Q128FV */
    { { 0xEF, 0x60, 0x18 }, QSPI_CHIP_WINBOND, V_RDTRSTP },     /* W25Q128FV (QPI id) */
    { { 0xC8, 0x40, 0x18 }, QSPI_CHIP_GD,      V_RDTRSTP_GD },  /* GD25Q128 */
    { { 0x20, 0xBA, 0x18 }, QSPI_CHIP_N25Q,    V_RDTRSTP }      /* N25Q128A */
};

/* read the JEDEC id on `lines` and set q->chip / q->rdtrstp; QSPI_CHIP_NONE
 * when we do not know it (not an error: the caller may be asking in the mode
 * the chip is not in) */
static int identify(qspi_t *q, uint32_t lines)
{
    uint8_t id[3];
    unsigned i;
    int r = aux(q, lines, CMD_RDID, 0, 0, id, 3);
    if (r != QSPI_OK) return r;
    for (i = 0; i < sizeof CHIPS / sizeof CHIPS[0]; i++)
        if (id[0] == CHIPS[i].id[0] && id[1] == CHIPS[i].id[1] && id[2] == CHIPS[i].id[2]) {
            q->chip = CHIPS[i].chip; q->rdtrstp = CHIPS[i].rdtrstp;
            return QSPI_OK;
        }
    q->chip = QSPI_CHIP_NONE;
    return QSPI_OK;
}

/* wait until the status register, under mask, reads want */
static int chip_wait(qspi_t *q, uint8_t mask, uint8_t want, unsigned polls)
{
    unsigned i;
    for (i = 0; ; i++) {
        uint8_t s;
        int r = aux(q, TR_QUAD, CMD_RDSR, 0, 0, &s, 1);
        if (r) return r;
        if ((s & mask) == want) return QSPI_OK;
        if (i >= polls) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 100);
    }
}

static int write_enable(qspi_t *q)
{
    int r = aux(q, TR_QUAD, CMD_WREN, 0, 0, 0, 0);
    return r ? r : chip_wait(q, SR_WEL, SR_WEL, 1000);
}

/* everything the controller needs to know; the window settings are for the
 * chip in QPI and mean nothing before qspi_init() has put it there */
static void controller_setup(qspi_t *q)
{
    WR(q, R_IER, 0);                    /* polled */
    WR(q, R_CFG, V_CFG);
    WR(q, R_CSTIMING, V_CSTIMING);
    WR(q, R_RDTRSTP, q->rdtrstp); WR(q, R_RDCMD, V_RDCMD);
    WR(q, R_PPTRSTP, V_PPTRSTP); WR(q, R_PPCMD, V_PPCMD);
    WR(q, R_MEMADD, V_MEMADD);
}

/* poll the status register on one line until the chip is not busy */
static int wait_ready_single(qspi_t *q)
{
    unsigned i;
    for (i = 0; ; i++) {
        uint8_t s;
        int r = aux(q, TR_SINGLE, CMD_RDSR, 0, 0, &s, 1);
        if (r != QSPI_OK) return r;
        if (!(s & SR_BUSY)) return QSPI_OK;
        if (i >= CHIP_POLLS) return QSPI_E_TIMEOUT;
        q->io.udelay(q->io.ctx, 100);
    }
}

/* put the identified chip into QPI with window reads. The chip is on one
 * line here; the sequence is this chip's (refs/qspi-chips.md). */
static int chip_enable(qspi_t *q)
{
    uint8_t v;
    int r;
    switch (q->chip) {
    case QSPI_CHIP_EON:
        /* the 0x38 command alone switches it; no quad-enable bit */
        return aux(q, TR_SINGLE, CMD_QPI, 0, 0, 0, 0);
    case QSPI_CHIP_WINBOND:
        if ((r = aux(q, TR_SINGLE, CMD_RDSR2, 0, 0, &v, 1)) != QSPI_OK) return r;
        v |= QE_SR2;
        if ((r = aux(q, TR_SINGLE, CMD_VWREN, 0, 0, 0, 0)) != QSPI_OK) return r;
        if ((r = aux_out(q, TR_SINGLE, CMD_WRSR2, &v, 1)) != QSPI_OK) return r;
        if ((r = aux(q, TR_SINGLE, CMD_QPI, 0, 0, 0, 0)) != QSPI_OK) return r;
        v = 0x2u << 4;                          /* 6 dummy clocks, set once in QPI */
        return aux_out(q, TR_QUAD, CMD_SETRD, &v, 1);
    case QSPI_CHIP_GD:
        if ((r = aux(q, TR_SINGLE, CMD_RDSR2, 0, 0, &v, 1)) != QSPI_OK) return r;
        if (!(v & QE_SR2)) {
            if ((r = aux(q, TR_SINGLE, CMD_WREN, 0, 0, 0, 0)) != QSPI_OK) return r;
            v = QE_SR2;
            if ((r = aux_out(q, TR_SINGLE, CMD_WRSR2, &v, 1)) != QSPI_OK) return r;
            if ((r = wait_ready_single(q)) != QSPI_OK) return r;
        }
        return aux(q, TR_SINGLE, CMD_QPI, 0, 0, 0, 0);
    case QSPI_CHIP_N25Q:
        if ((r = aux(q, TR_SINGLE, CMD_RDSR, 0, 0, &v, 1)) != QSPI_OK) return r;
        v = (uint8_t)(v & ~0x5Cu);              /* clear block protection */
        if ((r = aux(q, TR_SINGLE, CMD_WREN, 0, 0, 0, 0)) != QSPI_OK) return r;
        if ((r = aux_out(q, TR_SINGLE, CMD_WRSR, &v, 1)) != QSPI_OK) return r;
        if ((r = wait_ready_single(q)) != QSPI_OK) return r;
        if ((r = aux(q, TR_SINGLE, CMD_RDVCR, 0, 0, &v, 1)) != QSPI_OK) return r;
        v = (uint8_t)((v & ~0xF0u) | (6u << 4));    /* 6 dummy clocks */
        if ((r = aux(q, TR_SINGLE, CMD_WREN, 0, 0, 0, 0)) != QSPI_OK) return r;
        if ((r = aux_out(q, TR_SINGLE, CMD_WRVCR, &v, 1)) != QSPI_OK) return r;
        if ((r = wait_ready_single(q)) != QSPI_OK) return r;
        if ((r = aux(q, TR_SINGLE, CMD_RDEVCR, 0, 0, &v, 1)) != QSPI_OK) return r;
        v = (uint8_t)((v & ~(1u << 7)) | (1u << 6));  /* quad on (bit 7 = 0), dual off (bit 6 = 1): now QPI */
        if ((r = aux(q, TR_SINGLE, CMD_WREN, 0, 0, 0, 0)) != QSPI_OK) return r;
        return aux_out(q, TR_SINGLE, CMD_WREVCR, &v, 1);
    }
    return QSPI_E_ID;
}

int qspi_init(qspi_t *q, const qspi_io *io)
{
    int r;
    q->io = *io; q->ready = 0; q->nallow = 0; q->retries = 0;
    q->chip = QSPI_CHIP_NONE; q->rdtrstp = V_RDTRSTP;   /* defaults until identified */
    controller_setup(q);
    /* After U-Boot the chip listens on one line; after the stock system (a
     * RAM boot) on four. Ask on one line first and, if we know it, turn on
     * QPI the way that chip needs. If the one-line id is unknown the chip may
     * already be in QPI from a stock RAM boot: the four-line id below catches
     * that (aux reads the id whatever the window read shape is). */
    if ((r = identify(q, TR_SINGLE)) != QSPI_OK) return r;
    if (q->chip != QSPI_CHIP_NONE)
        if ((r = chip_enable(q)) != QSPI_OK) return r;
    if ((r = identify(q, TR_QUAD)) != QSPI_OK) return r;
    if (q->chip == QSPI_CHIP_NONE) return QSPI_E_ID;
    controller_setup(q);        /* apply this chip's read shape for window reads */
    q->ready = 1;
    return QSPI_OK;
}

static int in_chip(uint32_t off, uint32_t n) { return n <= QSPI_SIZE && off <= QSPI_SIZE - n; }

static int allowed(const qspi_t *q, uint32_t off, uint32_t n)
{
    unsigned i;
    if (!in_chip(off, n)) return 0;
    for (i = 0; i < q->nallow; i++) if (off >= q->allow[i].lo && off + n <= q->allow[i].hi) return 1;
    return 0;
}

int qspi_allow(qspi_t *q, uint32_t lo, uint32_t hi)
{
    if (lo >= hi || hi > QSPI_SIZE || (lo % QSPI_SECTOR) || (hi % QSPI_SECTOR) || q->nallow >= QSPI_MAX_ALLOW) return QSPI_E_RANGE;
    q->allow[q->nallow].lo = lo; q->allow[q->nallow].hi = hi; q->nallow++;
    return QSPI_OK;
}

int qspi_read(qspi_t *q, uint32_t off, uint8_t *buf, uint32_t n)
{
    if (!q->ready) return QSPI_E_ID;
    if (!in_chip(off, n)) return QSPI_E_RANGE;
    q->io.win_read(q->io.ctx, off, buf, n);
    return QSPI_OK;
}

int qspi_erase(qspi_t *q, uint32_t off, uint32_t n)
{
    int r;
    if (!q->ready) return QSPI_E_ID;
    if (n == 0 || (off % QSPI_SECTOR) || (n % QSPI_SECTOR) || !allowed(q, off, n)) return QSPI_E_RANGE;
    for (; n; off += QSPI_SECTOR, n -= QSPI_SECTOR) {
        if ((r = write_enable(q)) != QSPI_OK) return r;
        if ((r = aux(q, TR_QUAD, CMD_SE, 1, off, 0, 0)) != QSPI_OK) return r;
        if ((r = chip_wait(q, SR_BUSY | SR_WEL, 0, CHIP_POLLS)) != QSPI_OK) return r;
    }
    return QSPI_OK;
}

/* one stretch inside a page: programmed as whole words, the octets around
 * ours as 0xFF, which leaves what is there as it is */
static int program(qspi_t *q, uint32_t off, const uint8_t *buf, unsigned n)
{
    uint32_t w[QSPI_PAGE / 4], a = off & ~3ul;
    uint8_t back[QSPI_PAGE];
    unsigned words = (unsigned)((off + n + 3 - a) / 4), i, t;
    int r;
    for (i = 0; i < words; i++) w[i] = 0xFFFFFFFFul;
    for (i = 0; i < n; i++) {
        unsigned at = (unsigned)(off - a) + i;
        w[at / 4] &= ~(0xFFul << (8 * (at & 3)));
        w[at / 4] |= (uint32_t)buf[i] << (8 * (at & 3));
    }
    for (t = 0; t < TRIES; t++) {
        if (t) {
            /* Seen on the unit: now and then (one page in a few hundred)
             * the chip never gets the program, and from then on the
             * controller programs nothing at all until it has been reset.
             * The chip keeps its mode through that. */
            q->retries++;
            q->io.reset(q->io.ctx);
            controller_setup(q);
        }
        if ((r = write_enable(q)) != QSPI_OK) return r;
        q->io.win_burst(q->io.ctx, a, w, words);
        /* Busy only: a burst the chip did not take as a program (seen on
         * the unit, about one page in 350) leaves the write enable latch
         * set for ever. The read-back below decides. */
        if ((r = chip_wait(q, SR_BUSY, 0, CHIP_POLLS)) != QSPI_OK) return r;
        q->io.win_read(q->io.ctx, off, back, n);
        for (i = 0; i < n && back[i] == buf[i]; i++) ;
        if (i == n) return QSPI_OK;
    }
    (void)aux(q, TR_QUAD, CMD_WRDI, 0, 0, 0, 0);       /* no latch left set behind us */
    return QSPI_E_VERIFY;
}

int qspi_write(qspi_t *q, uint32_t off, const uint8_t *buf, uint32_t n)
{
    if (!q->ready) return QSPI_E_ID;
    if (n == 0 || !allowed(q, off, n)) return QSPI_E_RANGE;
    while (n) {
        unsigned k = QSPI_PAGE - (unsigned)(off % QSPI_PAGE);
        int r;
        if (k > n) k = (unsigned)n;
        if ((r = program(q, off, buf, k)) != QSPI_OK) return r;
        off += k; buf += k; n -= k;
    }
    return QSPI_OK;
}
