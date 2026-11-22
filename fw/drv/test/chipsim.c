#include <string.h>
#include "chipsim.h"

void chipsim_init(chipsim *c) { memset(c, 0, sizeof *c); c->reg[0] = 0xB2; c->reg[126] = 0; }

static void reg_write(chipsim *c, uint8_t r, uint8_t v)
{
    static const uint8_t key[4] = { 2, 8, 0xE, 0 };
    if (r == 126) {
        if (v == key[c->key]) { if (++c->key == 4) { c->key = 0; c->user = !c->user; } }
        else c->key = v == key[0] ? 1 : 0;
        c->reg[126] = (uint8_t)((v & 0xFE) | (c->user ? 1 : 0));
        return;
    }
    if (r == 4) return;                                 /* status: read only */
    if (r >= 5 && r <= 10 && c->busy) c->bad++;         /* touched while busy */
    c->reg[r] = v;
    if (r == 6) c->reg[6] = v & 0xF8;
    if (r >= 6 && r <= 9) { c->loaded = 1; }          /* data loaded: the next address write is a write */
    if (r == 10) {
        unsigned a = ((unsigned)(c->reg[5] & 0xE0) << 3) | v;
        if (c->loaded) {                              /* write */
            uint32_t w = ((uint32_t)c->reg[6] >> 3) | ((uint32_t)c->reg[7] << 5) | ((uint32_t)c->reg[8] << 13) | ((uint32_t)c->reg[9] << 21);
            if (a < PS_RAM_USER || c->user) { c->ram[a] = w; if (c->on_ram) c->on_ram(c, a, w); }
        } else {                                        /* read */
            uint32_t w = c->ram[a];
            if (a >= PS_RAM_USER && !c->user) w = 0;
            c->reg[6] = (uint8_t)(w << 3); c->reg[7] = (uint8_t)(w >> 5); c->reg[8] = (uint8_t)(w >> 13); c->reg[9] = (uint8_t)(w >> 21);
        }
        c->loaded = 0;
        c->busy = c->busy_polls;
    }
    if (c->on_write) c->on_write(c, r, v);
}

static uint8_t reg_read(chipsim *c, uint8_t r)
{
    if (r == 4) {
        if (c->dead) return 1;
        if (c->busy) { c->busy--; return 1; }
        return 0;
    }
    if (r >= 6 && r <= 9 && c->busy) c->bad++;
    return c->reg[r];
}

static uint8_t xfer(void *ctx, uint8_t out)
{
    chipsim *c = ctx; uint8_t in = 0xFF;
    c->frames++;
    switch (c->phase) {
    case 0:
        /* register access, channel 0 (0x20/0x60) or channel 1 (0x30/0x70):
         * bit 6 = read, bit 4 = CID, the rest fixed */
        if ((out & 0xAF) != 0x20) c->bad++;
        c->ch = (out >> 4) & 1;
        c->ctl = out; c->phase = 1; break;
    case 1:
        if (out > 127) c->bad++;
        c->addr = out & 127; c->phase = 2; break;
    default:
        if (c->ctl & 0x40) in = reg_read(c, c->addr); else reg_write(c, c->addr, out);
        c->phase = 0; break;
    }
    return in;
}
static void sleep_ms(void *ctx, unsigned ms) { chipsim *c = ctx; c->ms += ms; if (c->on_sleep) c->on_sleep(c, ms); }

void chipsim_bus(chipsim *c, ps_bus *b) { b->xfer = xfer; b->msleep = sleep_ms; b->ctx = c; }
