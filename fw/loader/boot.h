/* The v90d loader: what the stock boot loader starts from our "core"
 * partition, in place of a kernel. It finds our system image in "base",
 * checks it, copies it to where it runs and starts it; and it is what gets
 * the box back to the stock firmware, without anybody's help, when our
 * system does not come up.
 *
 * Why it exists: the stock boot loader (`gsboot`, HARDWARE.md) only starts
 * what is in "core", 1280 KiB, and our kernel with its system inside is
 * larger. And `gsboot` has no way back from an image that passes its
 * checksum and then hangs.
 *
 * This file is the deciding part, plain C99 with no library, tested on the
 * host (test/test_boot.c) against the same flash model as the flash driver.
 * start.S and hw.c are the parts that only exist on the box.
 *
 * Flash layout it relies on (physical offsets, both sets of the stock
 * layout; the stock upgrade installs into whichever set is not running):
 *
 *   set A: core 0x060000, base 0x2E0000      set B: core 0x1A0000, base 0x5E0000
 *
 *   core + 0x00000   stock partition header, then the loader as a U-Boot image
 *   core + 0x10000   the state word: one bit cleared per start attempt,
 *                    all ones again (sector erased) once our system is up
 *   base + 0x00000   stock partition header
 *   base + 0x00200   our system: U-Boot image header, zImage with device tree
 *
 * Giving up means: the first word of our own "core" (the signature the
 * stock boot loader looks for) is programmed to zero, then a reset. With our
 * set no longer valid `gsboot` starts the stock set, which we never write.
 * Programming, not erasing: a program that is cut short leaves the
 * signature either good or bad, while a sector erase cut short could leave
 * a good signature in front of a length field of rubbish, and `gsboot`
 * adds up the checksum over whatever length it finds there.
 *
 * Written for the v90d project; no vendor code. */
#ifndef V90D_LOADER_BOOT_H
#define V90D_LOADER_BOOT_H
#include <stdint.h>
#include "qspi.h"

#define LD_CORE_A     0x060000ul
#define LD_CORE_B     0x1A0000ul
#define LD_BASE_A     0x2E0000ul
#define LD_BASE_B     0x5E0000ul
#define LD_BASE_SIZE  0x300000ul
#define LD_GS_HDR     0x200u            /* the stock partition header */
#define LD_STATE_OFF  0x10000ul         /* in our core: the state word's sector */
#define LD_MAX_TRIES  3                 /* starts without a confirmation before we give up */
#define LD_LOAD       0xC8008000ul      /* where the system image runs (its U-Boot header must say so) */
#define LD_BOARD_OFF  0x4020ul          /* the board's part number, text, in "factory" */
#define LD_LOADER_NAME "v90d-loader"    /* image name of the loader in core */
#define LD_SYSTEM_NAME "v90d"           /* image name of the system in base */
/* boards this has run on: the part number as the factory wrote it into
 * "factory" (also what the running system's flash tool goes by) */
#define LD_BOARDS     { "9610003725A",  /* HT802 V2.5A: the unit this was made on */ \
                        "9611003610A",  /* HT801 V1.0A: from a flash dump, not tried on a unit */ \
                        "9610003611C",  /* HT801 V1.1C: the same */ \
                        "9610003716A" } /* HT802 V1.6A: issue #4, not tried on a unit */
/* how many at the head of LD_BOARDS a unit has run: on the others a start
 * is confirmed only once the network has been heard (fw/rcS) */
#define LD_BOARDS_TRIED 1

typedef struct {
    qspi_io        io;          /* the flash controller and its memory window */
    const uint8_t *fdt;         /* the device tree the boot loader handed over, or 0 */
    uint32_t       fdt_max;     /* how many octets of it may be read */
    uint8_t       *ram;         /* where address LD_LOAD is */
    uint32_t       ram_max;     /* how much may be written there */
} ld_env;

enum { LD_RESET = 0, LD_BOOT = 1 };
enum {
    LD_W_OK = 0,
    LD_W_FLASH,                 /* controller dead, or a flash chip we do not know */
    LD_W_BOARD,                 /* a board we never tried */
    LD_W_TRIES,                 /* started LD_MAX_TRIES times and never confirmed */
    LD_W_NOIMAGE,               /* no system image of ours that checks */
    LD_W_RECORD                 /* the attempt could not be written down */
};
typedef struct {
    int      action;            /* LD_BOOT: the image is at LD_LOAD, start it. LD_RESET: reset the box */
    int      why;
    int      set;               /* the set we were started from: 0 = A, 1 = B, -1 = not known */
    int      image_set;         /* the set whose base the image came from */
    uint32_t size;              /* octets at LD_LOAD */
    int      tries;             /* attempts counted, this one included */
} ld_result;

void ld_run(const ld_env *e, ld_result *r);

/* the pieces, for the tests */
uint32_t ld_crc32(uint32_t crc, const uint8_t *p, uint32_t n);     /* as zlib's: start with 0, feed on */
int      ld_set_from_fdt(const uint8_t *fdt, uint32_t max);        /* "bootpartition=N" in it: 0, 1, or -1 */
int      ld_tries(uint32_t state_word);

#endif
