/* See slic.h. */
#include "slic.h"

/* RAM locations (Si3217x rev C numbering, refs/si3217x-map.md 1.2) */
enum {
    R_MADC_VBAT = 3, R_ILOOPLPF = 513, R_ILONGLPF = 514, R_VDIFFLPF = 516, R_VCMLPF = 517,
    R_TXACHPF_A1_1 = 533, R_CM_SPEEDUP_TIMER = 708, R_VCM_TH = 709, R_VCM_HYST = 750,
    R_P_TH_HVIC = 756, R_COEF_P_HVIC = 759, R_BAT_HYST = 764, R_VBATH_EXPECT = 767,
    R_VBATR_EXPECT = 768, R_AC_ADC_GAIN = 880, R_PWRSAVE_TIMER = 915, R_OFFHOOK_THRESH = 916,
    R_VBAT_TRACK_MIN = 919, R_VBAT_TRACK_MIN_RNG = 920, R_SCALE_KAUDIO = 967, R_THERM_DBI = 970,
    R_VOV_DCDC_SLOPE = 973, R_VOV_DCDC_OS = 974, R_VOV_RING_BAT_MAX = 975, R_DCDC_VERR = 1004,
    R_DCDC_VERR_HYST = 1005, R_DCDC_OITHRESH_LO = 1006, R_DCDC_OITHRESH_HI = 1007,
    R_PD_BIAS = 1413, R_PD_HVIC = 1430, R_CAL_TRNRD_DACT = 1458, R_CAL_TRNRD_DACR = 1459,
    R_CMDAC_FWD = 1476, R_CMDAC_RVS = 1477, R_PD_DCDC = 1538, R_PD_UVLO = 1540, R_PD_OVLO = 1541,
    R_PD_OCLO = 1542, R_PD_SWDRV = 1543, R_DCDC_UVHYST = 1545, R_DCDC_UVTHRESH = 1546,
    R_DCDC_OVTHRESH = 1547, R_DCDC_OITHRESH = 1548, R_DCDC_STATUS = 1551, R_DCDC_SWDRV_POL = 1553,
    R_DCDC_UVPOL = 1554, R_DCDC_CPUMP = 1555, R_DCDC_VREF_CTRL = 1558, R_DCDC_RNGTYPE = 1560,
    R_PD_REF_OSC = 1571, R_PWRSAVE_CTRL_LO = 1575, R_DCDC_ANA_TOFF = 1586,
    R_DCDC_ANA_TONMIN = 1587, R_DCDC_ANA_TONMAX = 1588, R_DCDC_LIFT_EN = 1635
};

/* converter states written to PD_DCDC */
#define DCDC_ARM        0x700000ul      /* clear an earlier over/under-voltage stop */
#define DCDC_START      0x600000ul      /* digital start, over-voltage clamp and shutdown */
#define DCDC_RUN        0x400000ul      /* analogue loop */
#define DCDC_OFF_SHORT  0x300000ul
#define DCDC_OFF        0x900000ul

#define COUNTS_PER_MV   1074l           /* monitor ADC and the *_EXPECT targets */
#define FIVE_VOLTS      0x51EB82l

typedef struct { uint16_t addr; uint32_t val; } ram_val;

/* The general parameters of this board's converter (tracking supply, "LCQCUK"
 * topology, no gate driver, 0.2 ohm current sense) and line interface. The
 * numbers are the published ones for that topology; where the board's stock
 * firmware uses another value (seen in the RAM of the working part) it is
 * noted. Written in this order before anything is calibrated. */
static const ram_val general[] = {
    { R_P_TH_HVIC, 0x0048D15B }, { R_COEF_P_HVIC, 0x07FEB800 }, { R_BAT_HYST, 0x00083120 },
    { R_VBATH_EXPECT, 0x03D70A20 },                 /* 60 V battery */
    { R_VBATR_EXPECT, 0x053DDE47 },                 /* ringing battery: stock value, 82 V (published 110 V) */
    { R_PWRSAVE_TIMER, 0x0FFF0000 }, { R_OFFHOOK_THRESH, 0x01999A00 },
    { R_VBAT_TRACK_MIN, 0x00F00000 }, { R_VBAT_TRACK_MIN_RNG, 0x00F00000 },
    { R_THERM_DBI, 0x00800000 }, { R_VOV_DCDC_SLOPE, 0x00FFFFFF }, { R_VOV_DCDC_OS, 0x00A18937 },
    { R_VOV_RING_BAT_MAX, 0x00E49BA5 }, { R_DCDC_VERR, 0x01018900 }, { R_DCDC_VERR_HYST, 0x0080C480 },
    { R_PD_UVLO, 0x00400000 }, { R_PD_OVLO, 0x00400000 }, { R_PD_OCLO, 0x00200000 }, { R_PD_SWDRV, 0x00400000 },
    { R_DCDC_UVPOL, 0 }, { R_DCDC_RNGTYPE, 0x00200000 },
    { R_DCDC_ANA_TOFF, 0x00300000 }, { R_DCDC_ANA_TONMIN, 0x00100000 }, { R_DCDC_ANA_TONMAX, 0x00FFC000 },
    { R_DCDC_OITHRESH, 0x01C00000 },                /* 1850 mA through 0.2 ohm */
    { R_DCDC_OITHRESH_LO, 0x00900000 }, { R_DCDC_OITHRESH_HI, 0x01C00000 },
    { R_DCDC_OVTHRESH, 0x01300000 },                /* 128 V */
    { R_DCDC_UVTHRESH, 0x00500000 }, { R_DCDC_UVHYST, 0x00900000 },
    { R_SCALE_KAUDIO, 0x03A2E8BA }, { R_AC_ADC_GAIN, 0x0099999A },
};
/* fixed settings that follow them */
static const ram_val general2[] = {
    { R_TXACHPF_A1_1, 0x071EB851 }, { R_PD_REF_OSC, 0x00200000 },
    { R_ILOOPLPF, 0x004EDDB9 }, { R_ILONGLPF, 0x000806D6 }, { R_VDIFFLPF, 0x0010038D },
    { R_DCDC_VREF_CTRL, 0 }, { R_VCM_TH, 0x00106240 }, { R_VCMLPF, 0x0010059F },
    { R_CM_SPEEDUP_TIMER, 0x000F0000 }, { R_VCM_HYST, 0x00206280 },
};

/* Si3226x LCQCUK general parameters (refs/si3226x-facts.md and the Silicon
 * Labs Si3226x LCQCUK constants, our own code): the same fields the Si3217x
 * `general` table sets, at the shared rev-C RAM addresses, carrying the
 * Si3226x values where they differ (line-driver power, battery hysteresis,
 * ringing battery, and the DC-DC error, over/under-voltage and over-current
 * thresholds). The VOV overhead and AC-ADC gain are left to the part's
 * defaults and the ring preset, as the Si3226x general configuration does.
 * Experimental, patch-free like the Si3217x; to be confirmed on hardware. */
static const ram_val general_3226x[] = {
    { R_P_TH_HVIC, 0x005B05B2 }, { R_COEF_P_HVIC, 0x07FEB800 }, { R_BAT_HYST, 0x000AD000 },
    { R_VBATH_EXPECT, 0x03D70A20 },                 /* 60 V talk battery (same as Si3217x) */
    { R_VBATR_EXPECT, 0x051EB82A },                 /* 80 V ringing battery */
    { R_PWRSAVE_TIMER, 0x0FFF0000 }, { R_OFFHOOK_THRESH, 0x01999A00 },
    { R_VBAT_TRACK_MIN, 0x00F00000 }, { R_VBAT_TRACK_MIN_RNG, 0x00F00000 },
    { R_THERM_DBI, 0x00800000 }, { R_DCDC_VERR, 0x00F18900 }, { R_DCDC_VERR_HYST, 0x00809D80 },
    { R_PD_UVLO, 0x00400000 }, { R_PD_OVLO, 0x00400000 }, { R_PD_OCLO, 0x00200000 }, { R_PD_SWDRV, 0x00400000 },
    { R_DCDC_UVPOL, 0 }, { R_DCDC_RNGTYPE, 0x00200000 },
    { R_DCDC_ANA_TOFF, 0x00300000 }, { R_DCDC_ANA_TONMIN, 0x00100000 }, { R_DCDC_ANA_TONMAX, 0x00FFC000 },
    { R_DCDC_OITHRESH, 0x00800000 },
    { R_DCDC_OITHRESH_LO, 0x00000000 }, { R_DCDC_OITHRESH_HI, 0x01C00000 },
    { R_DCDC_OVTHRESH, 0x00500000 },
    { R_DCDC_UVTHRESH, 0x00000000 }, { R_DCDC_UVHYST, 0x00500000 },
    { R_SCALE_KAUDIO, 0x03A2E8BA },
};

/* Longitudinal balance trim. These are the results the stock firmware holds
 * for THIS unit (it reloads them instead of calibrating at every start); a
 * different unit should run the calibration instead. User-mode locations. */
static const ram_val balance[] = {
    { R_CMDAC_FWD, 0x02210000 }, { R_CMDAC_RVS, 0x02590000 },
    { R_CAL_TRNRD_DACT, 0x000E0000 }, { R_CAL_TRNRD_DACR, 0x00120000 },
};

/* DC feed as the stock firmware has it on this port: 48 V open circuit,
 * constant current about 35 mA (stock) off hook; hook thresholds 10/12 mA. */
static const ram_val dcfeed[] = {
    { 634, 0x18D363B9 }, { 635, 0x1F909679 }, { 636, 0x0040A0E0 }, { 638, 0x1ED0198F },
    { 639, 0x1EEC3D1F }, { 640, 0x05A38633 }, { 641, 0x050D2839 }, { 642, 0x03FE7F0F },
    { 643, 0x00FABF7F }, { 644, 0x00A2DB62 }, { 645, 0x002D8D96 }, { 853, 0x005B0AFB },
    { 852, 0x006D4060 }, { 701, 0x00008000 }, { 858, 0x0048D595 }, { 859, 0x003FBAE2 },
    { 702, 0x00008000 }, { 854, 0x00080000 }, { 855, 0x00080000 }, { 856, 0x00080000 },
    { 857, 0x00140000 }, { 748, 0x01BA5E35 }, { 752, 0x0051EB85 }, { 751, 0x00418937 },
};

/* Two-wire impedance and hybrid as the stock firmware has them on this port
 * (its default line setting): equalisers, echo FIR/IIR, impedance synthesis,
 * gains, receive high-pass. */
#define IMPEDANCE_RA 0x75
static const ram_val impedance[] = {
    { 540, 0x07F53B40 }, { 541, 0x000DD6F8 }, { 542, 0x000105B8 }, { 543, 0x1FFDB9F8 },
    { 546, 0x07EE0B68 }, { 547, 0x0012CC80 }, { 548, 0x1FFE61F0 }, { 549, 0x1FFCBFF8 },
    { 563, 0x001E4E80 }, { 564, 0x1FB8F500 }, { 565, 0x01F8E080 }, { 566, 0x0024BB80 },
    { 567, 0x021DEF00 }, { 568, 0x1F249180 }, { 569, 0x006C7580 }, { 570, 0x1FD9A500 },
    { 571, 0x0008B200 }, { 572, 0x1FF2A680 }, { 573, 0x02577380 }, { 574, 0x0558D480 },
    { 656, 0x0FF66D00 }, { 657, 0x18099280 }, { 654, 0x1F01CE80 }, { 653, 0x007F8C00 }, { 655, 0x007EA600 },
};
static const ram_val impedance2[] = {
    { 544, 0x0A5DB3A8 }, { 906, 0x018AC298 }, { 545, 0x018AC298 },
    { 658, 0x07B49980 }, { 659, 0x184B6700 }, { 660, 0x07693380 },
};

#define N(a) (sizeof(a) / sizeof((a)[0]))

static int load(const ps_bus *b, const ram_val *t, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++) if (ps_ram_wr(b, t[i].addr, t[i].val)) return SLIC_E_BUS;
    return 0;
}

static long sext29(uint32_t v) { return (v & 0x10000000ul) ? (long)v - 0x20000000l : (long)v; }

int slic_default_ram(unsigned addr, uint32_t *val)
{
    unsigned i;
    for (i = 0; i < N(impedance); i++) if (impedance[i].addr == addr) { *val = impedance[i].val; return 1; }
    for (i = 0; i < N(impedance2); i++) if (impedance2[i].addr == addr) { *val = impedance2[i].val; return 1; }
    return 0;
}

uint32_t slic_gain_scale(uint32_t base, int db10)
{
    /* 10^(0.1 / 20) and its inverse, Q30 */
    const uint64_t up = 1086175168ull, down = 1061450803ull;
    long v = sext29(base & 0x1FFFFFFFul);
    int neg = v < 0, n = db10 < 0 ? -db10 : db10;
    uint64_t m = (uint64_t)(neg ? -v : v);
    if (n > 600) n = 600;
    while (n-- > 0) {
        m = (m * (db10 < 0 ? down : up) + (1ull << 29)) >> 30;
        if (m > 0x0FFFFFFFull) { m = 0x0FFFFFFFull; break; }
    }
    return (uint32_t)(neg ? 0x20000000ul - (uint32_t)m : (uint32_t)m) & 0x1FFFFFFFul;
}

static int vbat_counts(const ps_bus *b, long *v)
{
    uint32_t w;
    if (ps_ram_rd(b, R_MADC_VBAT, &w)) return SLIC_E_BUS;
    *v = sext29(w);
    return 0;
}

long slic_vbat_mv(const ps_bus *b)
{
    long v;
    if (vbat_counts(b, &v)) return 0;
    return v / COUNTS_PER_MV;
}

int slic_offhook(const ps_bus *b) { return (ps_rd(b, PS_LCRRTP) & 0x02) ? 1 : 0; }

/* start a calibration and wait for the part to finish it */
static int calibrate(const ps_bus *b, uint8_t c0, uint8_t c1, uint8_t c2, unsigned step_ms, unsigned limit_ms)
{
    unsigned t;
    ps_wr(b, PS_CALR0, c0); ps_wr(b, PS_CALR0 + 1, c1); ps_wr(b, PS_CALR0 + 2, c2); ps_wr(b, PS_CALR3, 0x80);
    for (t = 0; t < limit_ms; t += step_ms) {
        b->msleep(b->ctx, step_ms);
        if (!(ps_rd(b, PS_CALR3) & 0x80)) return 0;
    }
    return SLIC_E_CAL;
}

static void converter_off(const ps_bus *b, uint32_t how)
{
    ps_wr(b, PS_LINEFEED, 0);
    ps_ram_wr(b, R_PD_DCDC, how);
}

/* The battery converter. The line is open while it starts. If the battery
 * is under half its target after 50 ms something is shorted: stop at once.
 * If it is not within 5 V of the target after 2 s: stop. */
static int converter_up(const ps_bus *b)
{
    uint32_t target, pd; long v; uint8_t enhance; unsigned t;

    /* On a dual part (Si3226x) the two channels share one converter: whichever
     * channel starts it first brings it up, and the other finds PD_DCDC bit 20
     * already clear and leaves it running rather than re-arming it, which would
     * disturb the channel already in service (refs/si3226x-facts.md section 4
     * step 9). A part with a converter of its own per channel reads its own
     * bit 20 still set here and starts it, so this is right for both. */
    if (!ps_ram_rd(b, R_PD_DCDC, &pd) && !(pd & 0x100000)) return 0;

    ps_wr(b, PS_LINEFEED, 0);
    enhance = ps_rd(b, PS_ENHANCE);
    ps_wr(b, PS_ENHANCE, enhance & 0x07);
    if (ps_ram_wr(b, R_PD_DCDC, DCDC_ARM)) return SLIC_E_BUS;
    /* this topology without a gate driver: switch drive not inverted, charge pump on */
    if (ps_ram_wr(b, R_DCDC_LIFT_EN, 0) || ps_ram_wr(b, R_DCDC_SWDRV_POL, 0) || ps_ram_wr(b, R_DCDC_CPUMP, 0x100000)) return SLIC_E_BUS;
    b->msleep(b->ctx, 20);
    if (ps_ram_rd(b, R_VBATH_EXPECT, &target)) return SLIC_E_BUS;

    if (ps_ram_wr(b, R_PD_DCDC, DCDC_START)) return SLIC_E_BUS;
    ps_ram_wr(b, R_PD_BIAS, 0x200000);
    ps_ram_wr(b, R_PD_HVIC, 0x200000);
    b->msleep(b->ctx, 50);
    if (vbat_counts(b, &v) || v < (long)target / 2) { converter_off(b, DCDC_OFF_SHORT); return SLIC_E_SHORT; }

    ps_ram_wr(b, R_DCDC_STATUS, 0);
    ps_ram_wr(b, R_PD_DCDC, DCDC_RUN);
    ps_wr(b, PS_ENHANCE, enhance);
    b->msleep(b->ctx, 50);
    for (t = 0; t < 2000; t += 10) {
        if (vbat_counts(b, &v)) break;
        if (v >= (long)target - FIVE_VOLTS) return 0;
        b->msleep(b->ctx, 10);
    }
    converter_off(b, DCDC_OFF);
    return SLIC_E_VBAT;
}

void slic_shutdown(const ps_bus *b)
{
    ps_user_mode(b, 1);
    ps_wr(b, PS_LINEFEED, 0);
    b->msleep(b->ctx, 50);
    ps_ram_wr(b, R_PD_DCDC, DCDC_OFF);
}

int slic_family(const ps_bus *b)
{
    uint8_t id = ps_rd(b, PS_ID);
    if (id == 0xFF || !(id & 0x80)) return -1;
    if ((id & 0x07) == 2) return SLIC_FAM_3217X;
    if ((id & 0x07) == 3) return SLIC_FAM_3226X;
    return -1;
}

int slic_present(const ps_bus *b)
{
    uint8_t id = ps_rd(b, PS_ID), was;
    int ok;

    if (id == 0xFF || !(id & 0x80) || ps_rd(b, PS_ID) != id) return 0;
    /* an identity alone can be a floating bus: a part also keeps what is
     * written to it */
    was = ps_rd(b, PS_PCMRXLO);
    ps_wr(b, PS_PCMRXLO, 0x5A); ok = ps_rd(b, PS_PCMRXLO) == 0x5A;
    ps_wr(b, PS_PCMRXLO, 0xA5); ok = ok && ps_rd(b, PS_PCMRXLO) == 0xA5;
    ps_wr(b, PS_PCMRXLO, was);
    return ok;
}

/* Stages 1-2: identify the part, load the general parameters, calibrate the
 * monitor ADC. The converter is left off and the line open. On a dual part
 * this runs for both channels before either converter is started. */
int slic_setup(const ps_bus *b, slic_info *info)
{
    uint32_t w; int r;

    info->stage = 0; info->vbat_mv = 0;
    info->id = ps_rd(b, PS_ID);
    /* a ProSLIC (bit 7), not a line-side device; the revision code names the
     * family at rev C: 2 = Si3217x, 3 = Si3226x (refs/si3226x-facts.md). They
     * share the rev-C RAM map, so only the general values and a couple of
     * bring-up steps differ. */
    if (info->id == 0xFF || !(info->id & 0x80)) return SLIC_E_ID;
    if ((info->id & 0x07) == 2) info->family = SLIC_FAM_3217X;
    else if ((info->id & 0x07) == 3) info->family = SLIC_FAM_3226X;
    else return SLIC_E_ID;
    ps_wr(b, PS_PCMRXLO, 0x5A);
    if (ps_rd(b, PS_PCMRXLO) != 0x5A) return SLIC_E_BUS;
    ps_wr(b, PS_PCMRXLO, 0);
    if (ps_user_mode(b, 1)) return SLIC_E_BUS;

    /* 1: general parameters. Power saving and automatic transitions off
     * while the part is brought up. No patch: the jump table stays off. */
    info->stage = 1;
    ps_wr(b, PS_ENHANCE, 0x00);
    ps_wr(b, PS_AUTO, 0x2F);
    if (info->family == SLIC_FAM_3226X) { if ((r = load(b, general_3226x, N(general_3226x))) != 0) return r; }
    else if ((r = load(b, general, N(general))) != 0) return r;
    ps_wr(b, 68, (uint8_t)((ps_rd(b, 68) & 0xF9) | 0x60));    /* GPIO1/2: analogue sense inputs */
    ps_wr(b, PS_PDN, 0x80);                                    /* monitor ADC stays on with the line open */
    if ((r = load(b, general2, N(general2))) != 0) return r;
    if (ps_ram_rd(b, R_PWRSAVE_CTRL_LO, &w) || ps_ram_wr(b, R_PWRSAVE_CTRL_LO, w & 0x07FFFFFFul)) return SLIC_E_BUS;

    /* 2: monitor ADC offset calibration */
    info->stage = 2;
    if ((r = calibrate(b, 0x00, 0x00, 0x01, 10, 1000)) != 0) return r;
    return SLIC_OK;
}

/* Stage 3: start the battery converter. slic_setup must have run. On a dual
 * part the converters of both channels are started back to back, between the
 * setup of both and any line calibration, so the second converter's start-up
 * inrush does not trip the first off the shared VDC input (the parts have a
 * converter each, but they share the board's DC input). */
int slic_converter(const ps_bus *b, slic_info *info)
{
    int r;
    info->stage = 3;
    r = converter_up(b);
    info->vbat_mv = slic_vbat_mv(b);
    return r;
}

/* Stages 4-7: the remaining calibrations, line parameters, PCM, and (unless
 * cfg->defer_service) the line in service. slic_setup and slic_converter must
 * have run. On a dual part both lines are left open (defer_service) until both
 * channels have finished, then slic_service() puts each in service. */
int slic_finish(const ps_bus *b, const slic_cfg *cfg, slic_info *info)
{
    int r;

    /* 4: the remaining calibrations */
    info->stage = 4;
    if ((r = calibrate(b, 0x00, 0xC0, 0x18, 10, 3000)) != 0) { converter_off(b, DCDC_OFF); return r; }
    ps_wr(b, PS_ENHANCE, 0x00);         /* no power saving */
    ps_wr(b, PS_AUTO, 0x3E);            /* automatic tracking; never go to "open" on its own */
    ps_wr(b, PS_ZCAL_EN, 0x04);

    /* 5: line parameters, with the line open */
    info->stage = 5;
    ps_wr(b, PS_LINEFEED, 0);
    /* balance[] are the Si3217x reference unit's own longitudinal-balance
     * calibration results, reloaded in place of calibrating. They do not
     * apply to the Si3226x (a different part and board), which calibrates
     * instead (the stage-5 calibrate below). */
    if (info->family == SLIC_FAM_3217X && (r = load(b, balance, N(balance))) != 0) { converter_off(b, DCDC_OFF); return r; }
    if ((r = load(b, dcfeed, N(dcfeed))) != 0 ||
        (r = load(b, impedance, N(impedance))) != 0) { converter_off(b, DCDC_OFF); return r; }
    ps_wr(b, 45, IMPEDANCE_RA);
    if ((r = load(b, impedance2, N(impedance2))) != 0) { converter_off(b, DCDC_OFF); return r; }
    if ((r = calibrate(b, 0x00, 0x40, 0x00, 1, 500)) != 0) { converter_off(b, DCDC_OFF); return r; }

    /* 6: PCM. The band filters are right as the part resets them. High-pass
     * filters off, as the stock firmware has them. */
    info->stage = 6;
    ps_wr(b, PS_DIGCON, (uint8_t)(ps_rd(b, PS_DIGCON) | 0x0C));
    ps_wr(b, PS_PCMMODE, cfg->pcm_format & 0x03);
    ps_wr(b, PS_PCMTXLO, (uint8_t)cfg->slot); ps_wr(b, PS_PCMTXHI, (uint8_t)((cfg->slot >> 8) & 0x03));
    ps_wr(b, PS_PCMRXLO, (uint8_t)cfg->slot); ps_wr(b, PS_PCMRXHI, (uint8_t)((cfg->slot >> 8) & 0x03));
    ps_wr(b, PS_PCMMODE, (uint8_t)((cfg->pcm_format & 0x03) | 0x10));

    /* 7: no interrupts (the driver polls the hook state), clear what is latched */
    info->stage = 7;
    ps_wr(b, PS_IRQEN1, 0); ps_wr(b, PS_IRQEN1 + 1, 0); ps_wr(b, PS_IRQEN1 + 2, 0); ps_wr(b, PS_IRQEN1 + 3, 0);
    (void)ps_rd(b, PS_IRQ1); (void)ps_rd(b, PS_IRQ1 + 1); (void)ps_rd(b, PS_IRQ1 + 2); (void)ps_rd(b, PS_IRQ1 + 3);
    if (!cfg->defer_service) ps_wr(b, PS_LINEFEED, 1);
    info->vbat_mv = slic_vbat_mv(b);
    return SLIC_OK;
}

int slic_init(const ps_bus *b, const slic_cfg *cfg, slic_info *info)
{
    int r;
    if ((r = slic_setup(b, info)) != 0) return r;
    if ((r = slic_converter(b, info)) != 0) return r;
    return slic_finish(b, cfg, info);
}

void slic_service(const ps_bus *b)
{
    ps_wr(b, PS_LINEFEED, 1);       /* forward active */
}
