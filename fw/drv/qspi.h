/* The serial flash of the HT802 (EON EN25QX128A, 16 MiB, on this unit) behind the
 * SoC's QSPI controller: read, erase 4 KiB sectors, program, and nothing
 * outside the address ranges the caller has allowed.
 *
 * Written from the facts in refs/dvf99-core-facts.md section 7 and the
 * register values read from the running unit (HARDWARE.md); no vendor code.
 * The chip is used the way the unit's own boot loader and stock system use
 * it: QPI mode, reads through the controller's memory window.
 *
 * Why the allow list: the same chip holds the boot loaders and the stock
 * firmware that is this box's only way back without a serial cable. A bug
 * above this layer must not be able to reach them.
 *
 * No allocation, no floating point; builds in the kernel and on the host. */
#ifndef V90D_FW_QSPI_H
#define V90D_FW_QSPI_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define QSPI_SIZE     0x1000000ul
#define QSPI_SECTOR   4096u
#define QSPI_PAGE     256u
#define QSPI_MAX_ALLOW 8        /* the kernel's list has seven (dvf99-ht802.dts) */

typedef struct {
    uint32_t (*rd)(void *ctx, unsigned reg);            /* controller registers */
    void     (*wr)(void *ctx, unsigned reg, uint32_t v);
    /* the memory window of chip select 0 */
    void     (*win_read)(void *ctx, uint32_t off, uint8_t *buf, uint32_t n);
    /* n words to consecutive window addresses from off (a multiple of 4),
     * with nothing in between: the controller ends the page program when
     * its FIFO runs dry. The kernel does this with interrupts off. */
    void     (*win_burst)(void *ctx, uint32_t off, const uint32_t *w, unsigned n);
    void     (*udelay)(void *ctx, unsigned us);
    /* pulse the controller's reset line (its registers go back to zero;
     * the chip is not touched) */
    void     (*reset)(void *ctx);
    void     *ctx;
} qspi_io;

/* the flash chip families the controller is set up for (refs/qspi-chips.md).
 * All are 16 MiB and read with opcode 0x0B in QPI; they differ in how quad
 * mode is turned on and in the read dummy length. */
enum {
    QSPI_CHIP_NONE = 0,
    QSPI_CHIP_EON,              /* EN25QX128A: QPI by the 0x38 command alone */
    QSPI_CHIP_WINBOND,          /* W25Q128FV: quad-enable in SR2, then 0x38, then set read params */
    QSPI_CHIP_GD,               /* GD25Q128: quad-enable in SR2, then 0x38 */
    QSPI_CHIP_N25Q              /* Micron N25Q128: quad and dummy in the (enhanced) volatile config registers */
};

typedef struct {
    qspi_io  io;
    int      ready;
    int      chip;              /* QSPI_CHIP_*, found by qspi_init */
    uint32_t rdtrstp;           /* the window read shape for this chip (dummy length differs) */
    unsigned nallow;
    struct { uint32_t lo, hi; } allow[QSPI_MAX_ALLOW];
    unsigned long retries;      /* page programs done again after a failed check */
} qspi_t;

enum {
    QSPI_OK = 0,
    QSPI_E_ID = -1,             /* not the chip we know, in either mode */
    QSPI_E_TIMEOUT = -2,        /* controller or chip never became ready */
    QSPI_E_RANGE = -3,          /* outside the chip, misaligned, or not allowed */
    QSPI_E_VERIFY = -4          /* what was written does not read back */
};

/* Find the chip in whichever mode the previous owner left it, put it and
 * the controller into QPI with window reads. Nothing is allowed yet. */
int qspi_init(qspi_t *q, const qspi_io *io);
/* [lo, hi) may be erased and written; both multiples of the sector size */
int qspi_allow(qspi_t *q, uint32_t lo, uint32_t hi);
int qspi_read(qspi_t *q, uint32_t off, uint8_t *buf, uint32_t n);
int qspi_erase(qspi_t *q, uint32_t off, uint32_t n);        /* whole sectors */
int qspi_write(qspi_t *q, uint32_t off, const uint8_t *buf, uint32_t n);    /* programmed and read back */

#endif
