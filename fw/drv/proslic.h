/* Register and RAM access to a ProSLIC (Si3217x on the HT802: one
 * single-channel part per FXS port, each on its own chip select).
 *
 * Written from the facts in refs/si3226x-facts.md (protocol as described in
 * the public data sheet and observed on the board); no vendor code.
 *
 * The bus is whatever moves one octet in one chip-select frame: the part
 * wants chip select released between octets. No allocation, no floating
 * point; builds in the kernel, in a /dev/mem tool and on the host. */
#ifndef V90D_FW_PROSLIC_H
#define V90D_FW_PROSLIC_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

typedef struct {
    /* chip select low, shift `out` while reading one octet, chip select high */
    uint8_t (*xfer)(void *ctx, uint8_t out);
    void    (*msleep)(void *ctx, unsigned ms);
    void    *ctx;
    /* which channel of the part this bus talks to: 0, or 1 for the second
     * channel of a dual part (Si3226x) that shares one chip select. It goes
     * into the SPI control octet as the CID; 0 for the single-channel parts.
     * A zeroed ps_bus is channel 0, so existing callers need no change. */
    uint8_t  cid;
} ps_bus;

/* direct registers 0..127 */
enum {
    PS_ID = 0, PS_RESET = 1, PS_RAMSTAT = 4, PS_RAM_ADDR_HI = 5, PS_RAM_DATA_B0 = 6,
    PS_RAM_ADDR_LO = 10, PS_PCMMODE = 11, PS_PCMTXLO = 12, PS_PCMTXHI = 13,
    PS_PCMRXLO = 14, PS_PCMRXHI = 15, PS_IRQ1 = 18, PS_IRQEN1 = 22, PS_CALR0 = 26,
    PS_CALR3 = 29, PS_LINEFEED = 30, PS_LCRRTP = 34, PS_RINGCON = 38, PS_LOOPBACK = 43,
    PS_DIGCON = 44, PS_ZCAL_EN = 46, PS_ENHANCE = 47, PS_AUTO = 80, PS_JMPEN = 81,
    PS_PDN = 98, PS_TEST_CNTL = 126
};
#define PS_RAM_MAX   2047u
#define PS_RAM_USER  1024u          /* from here up: only in user mode */
#define PS_RAM_MASK  0x1FFFFFFFul   /* RAM words are 29 bits */

uint8_t ps_rd(const ps_bus *b, uint8_t reg);
void    ps_wr(const ps_bus *b, uint8_t reg, uint8_t v);
/* 0, or -1: the part never became ready (nothing was read or written) */
int     ps_ram_rd(const ps_bus *b, unsigned addr, uint32_t *v);
int     ps_ram_wr(const ps_bus *b, unsigned addr, uint32_t v);
/* user mode on or off (needed for RAM from PS_RAM_USER up); 0, or -1 when
 * the part does not follow */
int     ps_user_mode(const ps_bus *b, int on);

#endif
