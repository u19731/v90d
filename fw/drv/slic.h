/* Bring-up and use of one FXS port of the HT80x, without the vendor's RAM
 * patch. Two ProSLIC parts are handled, both rev C, sharing the rev-C RAM
 * address map and differing only in the ID revision code and a handful of
 * DC-DC / battery init values: the Si3217x (one channel each; HT802 V2.5A and
 * the HT801s) and the Si3226x (two channels per package; the V1.x boards, e.g.
 * the Si32260 on the issue #4 HT802 V1.6A). Si3226x is experimental, patch-free
 * like the Si3217x, confirmed on hardware per board.
 *
 * Sequence and constants: refs/si3217x-map.md and refs/si3226x-facts.md (the
 * public description of the parts' start-up, studied from the Silicon Labs
 * ProSLIC API; no vendor code) and the values read back from this board while
 * its stock firmware ran (recon/out/slic0_stock_state.txt).
 *
 * The caller has pulsed the part's reset line and has the PCM clocks running.
 * slic_init() takes about half a second on a healthy part and sleeps through
 * the bus's msleep. */
#ifndef V90D_FW_SLIC_H
#define V90D_FW_SLIC_H
#include "proslic.h"

enum { SLIC_PCM_ALAW = 0, SLIC_PCM_ULAW = 1, SLIC_PCM_LINEAR = 3 };

/* the ProSLIC family, from the ID register's revision code (Si3217x rev C = 2,
 * Si3226x rev C = 3); they share the rev-C RAM map, so only a few init values
 * and the gate differ */
enum { SLIC_FAM_3217X = 0, SLIC_FAM_3226X = 1 };

typedef struct {
    uint8_t  pcm_format;        /* SLIC_PCM_* */
    uint16_t slot;              /* start of our samples, in bit clocks from frame sync */
    int      defer_service;     /* 1: leave the line open at the end of slic_init,
                                   to be put in service later with slic_service().
                                   On a dual part both channels must be calibrated
                                   with their lines open before either goes in
                                   service, or the second channel's calibration
                                   disturbs the first. 0: in service as before. */
} slic_cfg;

enum {
    SLIC_OK = 0,
    SLIC_E_ID = -1,             /* not a supported ProSLIC rev C (Si3217x or Si3226x) */
    SLIC_E_BUS = -2,            /* a register did not read back / RAM never ready */
    SLIC_E_CAL = -3,            /* a calibration did not finish */
    SLIC_E_SHORT = -4,          /* battery under half its target 50 ms after start: converter stopped */
    SLIC_E_VBAT = -5            /* battery did not come up in 2 s: converter stopped */
};

typedef struct {
    uint8_t id;                 /* register 0 */
    int     family;             /* SLIC_FAM_* */
    int     stage;              /* how far slic_init() got (for the log) */
    long    vbat_mv;            /* battery voltage when it returned */
} slic_info;

/* 1 if a ProSLIC answers on this chip select (out of reset 250 ms or more),
 * 0 if nothing does: the second port of a one-port board. Changes nothing
 * in the part. */
int  slic_present(const ps_bus *b);
/* the ProSLIC family on this bus from its ID (SLIC_FAM_*), or -1 if none/not
 * one we know; the part must be out of reset. Used to tell a dual part
 * (Si3226x, two ports on one chip select) from the single-channel boards. */
int  slic_family(const ps_bus *b);
int  slic_init(const ps_bus *b, const slic_cfg *cfg, slic_info *info);
/* The three phases of slic_init, for bringing up the two channels of a dual
 * part in the right order: set up both, start both converters, then finish
 * (calibrate / line / PCM) both -- so the second converter's start-up does not
 * trip the first. slic_init runs all three in turn for a single channel.
 * slic_setup must run before slic_converter, and both before slic_finish. */
int  slic_setup(const ps_bus *b, slic_info *info);
int  slic_converter(const ps_bus *b, slic_info *info);
int  slic_finish(const ps_bus *b, const slic_cfg *cfg, slic_info *info);
/* Put a line that was brought up with cfg->defer_service into service (forward
 * active). The converter and calibration are already done by slic_finish. */
void slic_service(const ps_bus *b);
int  slic_offhook(const ps_bus *b);             /* 1 off hook, 0 on hook */
long slic_vbat_mv(const ps_bus *b);
void slic_shutdown(const ps_bus *b);            /* line open, converter off */

/* The AC path of the part (HARDWARE.md, "Linear PCM and the gain knobs"):
 * RAM locations, and what slic_init() loads into them (1, or 0 for an
 * address that is not in its impedance set). The part's names: TX is line to
 * PCM (its A/D, what we receive), RX is PCM to line (its D/A, what we send). */
enum {
    SLIC_TXACEQ_C0 = 540,       /* ..C3 = 543: equaliser of the A/D path */
    SLIC_TXACGAIN = 544,        /* gain of the A/D path */
    SLIC_RXACGAIN = 545,        /* gain of the D/A path */
    SLIC_RXACEQ_C0 = 546,       /* ..C3 = 549: equaliser of the D/A path */
    SLIC_ECFIR_C2 = 563,        /* ..C9 = 570: hybrid balance, FIR part */
    SLIC_ECIIR_B0 = 571,        /* B1 572, A1 573, A2 574: its IIR part */
    SLIC_RXACGAIN_SAVE = 906,   /* written with the same value as RXACGAIN */
    SLIC_LINEAR_OS = 1002       /* rev C; name only in our notes, see HARDWARE.md */
};
int  slic_default_ram(unsigned addr, uint32_t *val);
/* base scaled by 10^(db10 / 200), db10 in tenths of a dB, on 29-bit two's
 * complement RAM words (sign kept; saturates at the largest magnitude) */
uint32_t slic_gain_scale(uint32_t base, int db10);

#endif
