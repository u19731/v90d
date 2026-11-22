#include <stdlib.h>
#include <string.h>
#include "qspisim.h"

enum { R_CFG = 0x000, R_STS = 0x008, R_ISR = 0x00C, R_IER = 0x010, R_ICR = 0x014, R_FWD = 0x020, R_FRD = 0x040,
       R_RDTRSTP = 0x13C, R_RDCMD = 0x140, R_PPTRSTP = 0x144, R_PPCMD = 0x148, R_MEMADD = 0x154,
       R_TRSTP = 0x300, R_CMD = 0x304, R_ADD = 0x308, R_CSTIMING = 0x408 };
#define REG(s, r) ((s)->reg[(r) / 4])

void qspisim_init(qspisim *s)
{
    uint32_t i;
    memset(s, 0, sizeof *s);
    s->mem = malloc(QSPI_SIZE);
    for (i = 0; i < QSPI_SIZE; i++) s->mem[i] = (uint8_t)(i * 7 + (i >> 9) * 13 + (i >> 16));
    s->qpi = 1; s->busy_polls = 2;
    s->id[0] = 0x1C; s->id[1] = 0x71; s->id[2] = 0x18;
    REG(s, R_CFG) = 0x10009; REG(s, R_IER) = 0x40; REG(s, R_CSTIMING) = 0x300;
    REG(s, R_RDTRSTP) = 0x0008362A; REG(s, R_RDCMD) = 0x0B; REG(s, R_PPTRSTP) = 0x0008048A; REG(s, R_PPCMD) = 0x02;
    REG(s, R_MEMADD) = 0xFFFF0000;
}
void qspisim_after_uboot(qspisim *s) { s->qpi = 0; s->wel = 0; }
void qspisim_free(qspisim *s) { free(s->mem); s->mem = 0; }

/* buffers are filled from the end backwards: first byte on the wire at +31 */
static uint8_t buf_get(qspisim *s, unsigned base, unsigned i)
{
    unsigned at = 31 - i;
    return (uint8_t)(s->reg[(base + (at & ~3u)) / 4] >> (8 * (at & 3)));
}
static void buf_put(qspisim *s, unsigned base, unsigned i, uint8_t v)
{
    unsigned at = 31 - i; uint32_t *w = &s->reg[(base + (at & ~3u)) / 4];
    *w = (*w & ~(0xFFul << (8 * (at & 3)))) | ((uint32_t)v << (8 * (at & 3)));
}

static uint8_t status(qspisim *s)
{
    uint8_t v = (uint8_t)((s->busy > 0 ? 1 : 0) | (s->wel ? 2 : 0));
    if (s->busy > 0 && --s->busy == 0) s->wel = 0;      /* the chip drops WEL when the operation ends */
    return v;
}

static void aux(qspisim *s, uint32_t cmd)
{
    uint32_t t = REG(s, R_TRSTP);
    unsigned op = cmd & 0xFF, type = (cmd >> 8) & 0x1F, n = (t >> 20) & 0x3F, i;
    int quad = (t & 3) == 2;                /* the opcode's lines decide whether the chip understands */
    if (REG(s, R_CFG) != 0x10009) { s->bad++; return; }
    s->isr_pending = 1;
    if (!(t & (1ul << 19)) || (cmd & (1ul << 30))) { s->bad++; return; }
    if (quad != s->qpi) {                   /* the chip hears noise: reads give rubbish */
        for (i = 0; i < n; i++) buf_put(s, R_FRD, i, (uint8_t)(0xA5 ^ i));
        return;
    }
    /* in QPI everything travels on four lines */
    if (s->qpi && ((n && (cmd & (1ul << 13)) && ((t >> 8) & 3) != 2) || (n && (cmd & (1ul << 14)) && ((t >> 6) & 3) != 2))) { s->bad++; return; }
    if (s->busy > 0 && op != 0x05) { s->bad++; return; }   /* only status may be read while busy */
    switch (op) {
    case 0x9F: if (type != 9 || !(cmd & (1ul << 13))) s->bad++; for (i = 0; i < n; i++) buf_put(s, R_FRD, i, i < 3 ? s->id[i] : 0); break;
    case 0x05: if (type != 5) s->bad++; buf_put(s, R_FRD, 0, status(s)); break;
    case 0x06: if (type != 9) s->bad++; s->wel = 1; break;
    case 0x04: if (type != 9) s->bad++; s->wel = 0; break;
    case 0x38: if (type != 9) s->bad++; if (!s->need_qe || (s->sr2 & 0x02)) s->qpi = 1; break;   /* QPI only once QE is set, on chips that need it */
    case 0x35: if (type != 5 || !(cmd & (1ul << 13))) s->bad++; buf_put(s, R_FRD, 0, s->sr2); break;   /* read status register 2 */
    case 0x50: if (type != 9) s->bad++; break;      /* volatile status write enable */
    case 0xC0: if (type != 9 || !(cmd & (1ul << 14))) s->bad++; break;   /* set read parameters (in QPI) */
    case 0x01: case 0x31: s->status_writes++; if (op == 0x31) s->sr2 = buf_get(s, R_FWD, 0); s->wel = 0; break;
    case 0x20:
        if (type != 0 || ((t >> 10) & 3) != 1 || (s->qpi && ((t >> 2) & 3) != 2)) { s->bad++; break; }
        if (!s->wel) { s->bad++; break; }
        s->last_erase = REG(s, R_ADD) & ~(QSPI_SECTOR - 1) & (QSPI_SIZE - 1);
        memset(s->mem + s->last_erase, 0xFF, QSPI_SECTOR);
        s->erases++; s->busy = s->busy_polls + 1;
        break;
    default: s->bad++;
    }
}

static uint32_t sim_rd(void *ctx, unsigned reg)
{
    qspisim *s = ctx;
    if (reg == R_STS) return s->stuck ? 0x80000000ul : 1;
    if (reg == R_ISR) return s->isr_pending ? 0x40 : 0;
    return s->reg[reg / 4];
}
static void sim_wr(void *ctx, unsigned reg, uint32_t v)
{
    qspisim *s = ctx;
    if (reg == R_ICR) { if (v & 0x40) s->isr_pending = 0; s->reg[reg / 4] = v; return; }
    s->reg[reg / 4] = v;
    if (reg == R_CMD && (v & 0x80000000ul)) { if (s->stuck) return; aux(s, v); }
}
static int window_reads(qspisim *s)
{
    return s->qpi ? ((REG(s, R_RDTRSTP) == 0x0008362A || REG(s, R_RDTRSTP) == 0x0008262A) && REG(s, R_RDCMD) == 0x0B) : 0;
}
static void sim_win_read(void *ctx, uint32_t off, uint8_t *buf, uint32_t n)
{
    qspisim *s = ctx; uint32_t i;
    if (s->busy > 0 || !window_reads(s)) { for (i = 0; i < n; i++) buf[i] = 0x5A; s->bad += s->busy > 0; return; }
    memcpy(buf, s->mem + off, n);
}
static void sim_win_burst(void *ctx, uint32_t off, const uint32_t *w, unsigned n)
{
    qspisim *s = ctx; unsigned i, k;
    if (!s->qpi || REG(s, R_PPTRSTP) != 0x0008048A || REG(s, R_PPCMD) != 0x02 || (off & 3) || !s->wel || s->busy > 0 ||
        n == 0 || (off / QSPI_PAGE) != ((off + 4 * n - 1) / QSPI_PAGE)) { s->bad++; return; }
    if (s->pp_stuck) return;
    if (s->lost_bursts > 0) { s->lost_bursts--; s->pp_stuck = 1; return; }
    if (s->cut_bursts > 0) { s->cut_bursts--; n = 1; }
    for (i = 0; i < n; i++) for (k = 0; k < 4; k++) s->mem[off + 4 * i + k] &= (uint8_t)(w[i] >> (8 * k));
    s->programs++; s->busy = s->busy_polls + 1;
}
static void sim_udelay(void *ctx, unsigned us) { (void)ctx; (void)us; }
static void sim_reset(void *ctx)
{
    qspisim *s = ctx;
    memset(s->reg, 0, sizeof s->reg); s->pp_stuck = 0; s->isr_pending = 0; s->resets++;
}

void qspisim_io(qspisim *s, qspi_io *io)
{
    io->rd = sim_rd; io->wr = sim_wr; io->win_read = sim_win_read; io->win_burst = sim_win_burst; io->udelay = sim_udelay; io->reset = sim_reset; io->ctx = s;
}
