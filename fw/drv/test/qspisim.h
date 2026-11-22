/* The QSPI controller and the flash chip behind it, as the driver's
 * register and window accesses see them (refs/dvf99-core-facts.md 7). */
#ifndef QSPISIM_H
#define QSPISIM_H
#include <stdint.h>
#include "../qspi.h"

typedef struct {
    uint8_t  *mem;              /* 16 MiB */
    uint32_t reg[0x500 / 4];
    int      qpi;               /* chip mode */
    int      wel;
    int      busy_polls;        /* status says busy for this many reads after erase/program */
    int      busy;
    uint8_t  id[3];
    int      need_qe;           /* Winbond/GD: 0x38 enters QPI only once the QE bit (SR2 bit 1) is set */
    uint8_t  sr2;               /* status register 2 (the QE bit lives here) */
    int      stuck;             /* controller never idle */
    int      cut_bursts;        /* this many page programs end after the first word */
    int      lost_bursts;       /* this many are not taken at all: write enable stays set,
                                 * and the controller takes no more until it is reset */
    int      pp_stuck;
    unsigned long resets;
    int      isr_pending;
    /* what happened */
    unsigned long erases, programs, status_writes, bad;
    uint32_t last_erase;
} qspisim;
void qspisim_init(qspisim *s);              /* as the stock system leaves it: QPI */
void qspisim_after_uboot(qspisim *s);       /* chip reset to single line, controller still set for QPI */
void qspisim_io(qspisim *s, qspi_io *io);
void qspisim_free(qspisim *s);
#endif
