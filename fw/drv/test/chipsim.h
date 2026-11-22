/* A ProSLIC as the SPI bus sees it, for the driver's tests: the protocol of
 * refs/si3226x-facts.md sections 1 and 3, registers, RAM, user mode. Not a
 * model of the analogue side beyond what each test sets up. */
#ifndef CHIPSIM_H
#define CHIPSIM_H
#include <stdint.h>
#include "../proslic.h"

typedef struct chipsim chipsim;
struct chipsim {
    uint8_t  reg[128];
    uint32_t ram[2048];
    int      phase;             /* 0 control, 1 address, 2 data */
    uint8_t  ctl, addr;
    int      ch;                /* channel (CID) of the last control octet: 0, or 1 for a dual part's second channel */
    int      user, key;         /* user mode; place in the key sequence */
    int      busy_polls;        /* RAMSTAT says busy for this many reads after an access */
    int      busy, loaded;
    int      dead;              /* never ready */
    unsigned long frames, ms;   /* octets moved; time slept */
    int      bad;               /* protocol violations seen */
    /* hooks for tests that model behaviour */
    void (*on_write)(chipsim *c, uint8_t reg, uint8_t v);
    void (*on_ram)(chipsim *c, unsigned addr, uint32_t v);
    void (*on_sleep)(chipsim *c, unsigned ms);
    void *user_ctx;
};
void chipsim_init(chipsim *c);
void chipsim_bus(chipsim *c, ps_bus *b);
#endif
