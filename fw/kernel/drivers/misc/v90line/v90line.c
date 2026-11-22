// SPDX-License-Identifier: GPL-2.0
/*
 * v90d telephone lines of the Grandstream HT802: the two FXS ports as
 * character devices, /dev/v90line (port 1) and /dev/v90line2 (port 2), for
 * the dial-up daemon (srv/line.h, "dev:"). Each of them:
 *
 *   read   the hook state (0 on hook, 1 off hook) and the next 80 samples
 *          from the line; blocks until they are there. Companded receive:
 *          81 octets, the samples are G.711 codewords. Linear receive: 161
 *          octets, the samples are 16-bit values, little endian. The reader
 *          gives room for 161 and tells the format by the length it gets.
 *   write  80 codewords: the answer to the block just read (in both
 *          formats: V.90 and V.92 need exact G.711 levels on the line)
 *   write  1 octet: 'u' or 'a', the law of the codewords from now on;
 *          'l' or 'c', linear or companded receive from now on
 *
 * The SoC's TDM block is master of the PCM highway (4 slots of 16 bits at
 * 8 kHz); each port has its own SLIC, a Si3217x, port 1 on slot 0 and port 2
 * on slot 1. The part's PCM format is one setting for both directions:
 *   companded (as started): a codeword is the top octet of a FIFO word in
 *     both directions and nothing is converted here;
 *   linear: a received sample is the 16 bits of the slot, and every codeword
 *     to send goes out as the exact linear value of that codeword in the
 *     port's law (pump_lin16), so the levels on the line are the G.711
 *     levels, while what we receive is not companded: the echo of our own
 *     transmitter no longer drags the receive quantiser's steps up.
 * A change of law or format restarts the port's pump (do it on hook). The
 * statistics carry a level meter of the received samples as linear values
 * in either format, and the attributes slic / slic2 give the bench access
 * to the part's registers and RAM through the port's own thread
 * (HARDWARE.md, "Linear PCM and the gain knobs"). An interrupt every
 * 8 frames moves codewords between the FIFOs and each port's pump
 * (fw/drv/pump.c); one thread per port brings its SLIC up without any vendor
 * patch (fw/drv/slic.c) and watches the hook. The ports share the SPI block
 * (one chip select each) and nothing else: a port whose SLIC does not start
 * leaves the other alone.
 *
 * Facts about the hardware: HARDWARE.md, "Register-level facts for our own
 * drivers", and refs/. Written for this project; no vendor code.
 */
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_data/dvf99-cmu.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "pump.h"
#include "slic.h"

/* TDM block */
#define T_ENABLE	0x00
#define T_CONFIG1	0x04
#define T_CONFIG2	0x08
#define T_FSYNC		0x10
#define T_FSYNC_DUR	0x14
#define T_FIFO_WM	0x18
#define T_INT_EN	0x20
#define T_INT_CLR	0x28
#define T_INT_STATUS	0x2c
#define T_TX		0x38
#define T_RX		0x3c
#define T_FDA		0x1800
#define T_INT_RX_WM	BIT(2)
#define T_ST_TX_UNDER	BIT(1)
#define T_ST_RX_OVER	BIT(3)

#define SLOTS		4	/* FIFO words per frame */
#define CHUNK		8	/* frames per interrupt: 1 ms */
#define PREFILL		24	/* frames queued to send at start: we may be 2 ms late */
#define LATENCY		240	/* codewords from a block read to its answer on the wire:
				 * the daemon may be 20 ms late with one (10 ms was not
				 * enough on the unit: one late block in a first call) */

/* SPI block (16-bit registers) */
#define S_GLOBAL	0x00
#define S_CON		0x04
#define S_FRM		0x08
#define S_IER		0x0c
#define S_STAT		0x10
#define S_DAT		0x14
#define S_ST_BUSY	0x40
#define S_CON_MODE3_8	0x0f81
#define S_CON_SHIFT_OFF	0x2000

/*
 * The 8 kHz clock. PLL3 multiplies the 25 MHz crystal; the TDM divider
 * makes the bit clock (512 kHz for 4 slots of 16 bits) from it.
 *   ours:  25 MHz / 2 * 29 = 362.5 MHz, / 708 = 511 994.35 Hz: 8 kHz - 11 ppm
 *   stock: 25 MHz / 2 * 73 / 2 = 456.25 MHz, / 891: 8 kHz + 127 ppm
 * (no setting inside the PLL's stated limits is exact). PLL field layout:
 * [4:0] pre-divider - 1, [11:5] multiplier - 1, [13:12] post-divider shift,
 * bit 14 VCO above 600 MHz, bits 15 and 16 power down, bit 18 locked.
 */
#define PLL3_OURS	0x0381
#define TDMDIV_OURS	708
#define PLL3_STOCK	0x5901
#define TDMDIV_STOCK	891
#define PLL3_SETTING	0x7fff
#define PLL3_DOWN	0x18000
#define PLL3_LOCKED	BIT(18)
#define CLKSW_AUD_PLL3	BIT(2)
#define CLKSW_TDM1_MASK	(3u << 19)
#define CLKSW_TDM1_AUD	(1u << 19)

#define PORTS		2

struct v90line;

struct v90port {
	struct v90line *l;
	int idx;			/* 0 = port 1: the logical port (PCM slot, device name) */
	int cs_idx;			/* which chip select / reset line this port drives; = idx,
					   except a dual part's second channel shares the first's (0) */
	int shares;			/* 1: the second channel of a dual part on a shared chip
					   select -- do not reset the chip, follow the owner port */
	struct miscdevice misc;
	struct task_struct *thr;
	ps_bus bus;
	int spi_phase;			/* 0 control, 1 address, 2 data octet */
	u8 spi_ctl;

	/* under the line's lock */
	pump_t pump;
	int hook;
	int fresh;			/* pump restarted, no block read since */
	wait_queue_head_t wq;

	unsigned long busy;		/* bit 0: the device is open */
	int law, want_law;		/* 0 mu-law, 1 A-law */
	int lin, want_lin;		/* 1: the codec runs 16-bit linear */
	pump_meter meter;		/* received level, linear values */
	int up;				/* the SLIC is initialised */
	int slic_ready;			/* a shared second channel: set by the owner once it has
					   brought this channel's SLIC up and in service */

	/* bench access to the part, carried out by the port's thread */
	struct mutex dbg_lock;
	struct completion dbg_done;
	int dbg_op;			/* 0 none, 'r' 'w' RAM, 'R' 'W' register */
	unsigned int dbg_addr;
	u32 dbg_val;
	int dbg_res;
	char dbg_text[40];

	/* for the stats attribute */
	unsigned long inits, stale;
	long vbat_mv;
	int last_err, last_stage;
};

struct v90line {
	struct device *dev;
	void __iomem *tdm, *spi;
	struct gpio_desc *cs[PORTS], *rst[PORTS];
	spinlock_t lock;		/* the pumps and what goes with them */
	int dual;			/* 1: one dual-channel part serves both ports on chip select 0 */
	struct v90port port[PORTS];
	s16 lin16[2][256];		/* codeword to linear, per law */

	/* for the stats attributes */
	unsigned long frames, tdm_under, tdm_over, spi_errors;
	unsigned int tdm_div;
};

static inline u8 idle_of(int alaw) { return alaw ? 0xd5 : 0xff; }
static inline u8 pcmmode_of(int alaw, int lin)
{
	return lin ? SLIC_PCM_LINEAR : alaw ? SLIC_PCM_ALAW : SLIC_PCM_ULAW;
}

/* ---- SPI: one octet in one chip-select frame, polled ---- */

static int spi_wait_clear(struct v90line *l, unsigned int reg, u16 mask)
{
	int i;

	for (i = 0; i < 2000; i++) {
		if (!(readw(l->spi + reg) & mask))
			return 0;
		udelay(1);
	}
	return -1;
}

/*
 * Both ports' threads come through here. An access to a SLIC register is
 * three octets, each in a chip-select frame of its own with interrupts off,
 * so the two threads can only interleave between frames, and a part sees
 * nothing of the frames of the other.
 */
static uint8_t line_xfer(void *ctx, uint8_t out)
{
	struct v90port *p = ctx;
	struct v90line *l = p->l;
	unsigned long flags;
	u8 in = 0xff;
	int rd, bad = 0;

	/* the third octet of an access with the read bit is the one to receive */
	rd = p->spi_phase == 2 && (p->spi_ctl & 0x40);
	if (p->spi_phase == 0)
		p->spi_ctl = out;
	p->spi_phase = p->spi_phase == 2 ? 0 : p->spi_phase + 1;

	/* An interrupt between the steps of an octet spoils it: 40 us with
	 * interrupts off, against a TDM margin of 2 ms. */
	local_irq_save(flags);
	writew(0x04, l->spi + S_GLOBAL);		/* FIFO pointers */
	bad |= spi_wait_clear(l, S_GLOBAL, 0xffff);
	writew(S_CON_MODE3_8, l->spi + S_CON);
	writew(0, l->spi + S_IER);
	gpiod_set_raw_value(l->cs[p->cs_idx], 0);
	udelay(1);
	if (!rd) {
		writew(0, l->spi + S_FRM);
		writew(out, l->spi + S_DAT);
		udelay(10);				/* an octet at 1 MHz is 8 us */
		bad |= spi_wait_clear(l, S_STAT, S_ST_BUSY);
	} else {
		(void)readw(l->spi + S_DAT);		/* the dummy read starts the clock */
		writew(S_CON_MODE3_8 | S_CON_SHIFT_OFF, l->spi + S_CON);
		udelay(10);
		bad |= spi_wait_clear(l, S_STAT, S_ST_BUSY);
		in = (u8)readw(l->spi + S_DAT);
	}
	udelay(1);
	gpiod_set_raw_value(l->cs[p->cs_idx], 1);
	udelay(2);
	local_irq_restore(flags);
	if (bad)
		l->spi_errors++;
	return in;
}

static void line_msleep(void *ctx, unsigned int ms)
{
	msleep(ms);
}

/* ---- clock and TDM ---- */

static int pll3_set(u32 setting)
{
	int i;

	dvf99_cmu_update(DVF99_CMU_PLL3, PLL3_DOWN, PLL3_DOWN);
	dvf99_cmu_update(DVF99_CMU_PLL3, PLL3_SETTING, setting);
	udelay(1);
	dvf99_cmu_update(DVF99_CMU_PLL3, PLL3_DOWN, 0);
	for (i = 0; i < 50; i++) {
		if (dvf99_cmu_read(DVF99_CMU_PLL3) & PLL3_LOCKED)
			return 0;
		usleep_range(1000, 2000);
	}
	return -EIO;
}

/* TDM clock gated when called; the SLICs in reset */
static int line_clock(struct v90line *l)
{
	u32 pll = dvf99_cmu_read(DVF99_CMU_PLL3);

	l->tdm_div = TDMDIV_OURS;
	if ((pll & (PLL3_SETTING | PLL3_DOWN)) != PLL3_OURS || !(pll & PLL3_LOCKED)) {
		if (pll3_set(PLL3_OURS)) {
			dev_warn(l->dev, "PLL3 does not lock at 362.5 MHz, using the stock 456.25 MHz (+127 ppm)\n");
			l->tdm_div = TDMDIV_STOCK;
			if (pll3_set(PLL3_STOCK)) {
				dev_err(l->dev, "PLL3 does not lock: no PCM clock\n");
				return -EIO;
			}
		}
	}
	dvf99_cmu_update(DVF99_CMU_CLKSW, CLKSW_AUD_PLL3 | CLKSW_TDM1_MASK, CLKSW_AUD_PLL3 | CLKSW_TDM1_AUD);
	dvf99_cmu_update(DVF99_CMU_CLKDIV4, 0xfff, l->tdm_div - 1);
	return 0;
}

static void tdm_start(struct v90line *l)
{
	int i;

	writel(0, l->tdm + T_ENABLE);
	dvf99_cmu_gate(DVF99_GATE_TDM1, false);		/* configured with its clock off */
	udelay(20);
	dvf99_cmu_reset(DVF99_GATE_TDM1, true);
	udelay(2);
	dvf99_cmu_reset(DVF99_GATE_TDM1, false);
	for (i = 0; i < SLOTS; i++)
		writel((i << 8) | 0xc0 | 16, l->tdm + T_FDA + 4 * i);
	writel(0x1a03, l->tdm + T_CONFIG1);
	writel(0x0301, l->tdm + T_CONFIG2);
	writel(0, l->tdm + T_FSYNC);
	writel(0, l->tdm + T_FSYNC_DUR);
	writel(((CHUNK - 1) << 8) | (CHUNK - 1), l->tdm + T_FIFO_WM);
	writel(0, l->tdm + T_INT_EN);
	dvf99_cmu_gate(DVF99_GATE_TDM1, true);
	for (i = 0; i < 32 * SLOTS; i++)
		(void)readl(l->tdm + T_RX);
	for (i = 0; i < PREFILL * SLOTS; i++) {
		struct v90port *p = &l->port[i % SLOTS < PORTS ? i % SLOTS : 0];

		writel(i % SLOTS < PORTS ? pump_tx_word(p->lin ? l->lin16[p->law] : NULL, idle_of(p->law)) : 0,
		       l->tdm + T_TX);
	}
	writel(0xfffff, l->tdm + T_INT_CLR);
	writel(1, l->tdm + T_ENABLE);
	writel(T_INT_RX_WM, l->tdm + T_INT_EN);
}

/*
 * The receive FIFO holds CHUNK frames or more (the interrupt is level
 * type): take CHUNK, give CHUNK. Sent and received frames stay paired, so
 * the two FIFO levels always add up to PREFILL.
 *
 * That only holds while we are in time. When interrupts stay off for
 * milliseconds (a line of kernel log on the serial console does it), the
 * transmit FIFO runs empty or the receive FIFO runs over, the two levels no
 * longer add up to PREFILL, and from then on part of every chunk we send is
 * lost: tones still go out, but chopped at 1 kHz, and no modem trains on
 * them (seen on the unit: three log lines, and the next call fails; the
 * state lasts until the highway is started again). So an underrun or an
 * overrun is not just counted: the highway is started afresh, empty and
 * with its prefill, which costs the line a few milliseconds of silence.
 */
static irqreturn_t line_irq(int irq, void *data)
{
	struct v90line *l = data;
	u32 raw[PORTS][CHUNK];
	s16 rx[CHUNK];
	u8 tx[PORTS][CHUNK];
	const s16 *tab[PORTS];
	u32 st = readl(l->tdm + T_INT_STATUS);
	int i, j, ready[PORTS];

	if (st & (T_ST_TX_UNDER | T_ST_RX_OVER)) {
		if (st & T_ST_TX_UNDER)
			l->tdm_under++;
		if (st & T_ST_RX_OVER)
			l->tdm_over++;
		tdm_start(l);
		return IRQ_HANDLED;
	}
	for (i = 0; i < CHUNK; i++) {
		for (j = 0; j < PORTS; j++)
			raw[j][i] = readl(l->tdm + T_RX);
		for (; j < SLOTS; j++)
			(void)readl(l->tdm + T_RX);
	}
	spin_lock(&l->lock);
	for (j = 0; j < PORTS; j++) {
		struct v90port *p = &l->port[j];

		/* format and law change only under this lock */
		tab[j] = p->lin ? l->lin16[p->law] : NULL;
		for (i = 0; i < CHUNK; i++) {
			rx[i] = pump_rx_sample(p->lin, raw[j][i]);
			pump_meter_add(&p->meter, p->lin ? rx[i] : l->lin16[p->law][rx[i] & 0xff]);
		}
		pump_tick(&p->pump, rx, tx[j], CHUNK);
		ready[j] = pump_ready(&p->pump);
	}
	spin_unlock(&l->lock);
	for (i = 0; i < CHUNK; i++) {
		for (j = 0; j < PORTS; j++)
			writel(pump_tx_word(tab[j], tx[j][i]), l->tdm + T_TX);
		for (; j < SLOTS; j++)
			writel(0, l->tdm + T_TX);
	}
	l->frames += CHUNK;
	for (j = 0; j < PORTS; j++)
		if (ready[j])
			wake_up_interruptible(&l->port[j].wq);
	return IRQ_HANDLED;
}

/* ---- the SLIC ---- */

static void pump_restart(struct v90port *p, int hook)
{
	unsigned long flags;

	spin_lock_irqsave(&p->l->lock, flags);
	p->hook = hook;
	pump_start(&p->pump, idle_of(p->law), LATENCY);
	p->fresh = 1;
	spin_unlock_irqrestore(&p->l->lock, flags);
}

/* law and format of the port from now on, with a fresh pump */
static void port_format(struct v90port *p, int law, int lin)
{
	unsigned long flags;

	spin_lock_irqsave(&p->l->lock, flags);
	p->law = law;
	p->lin = lin;
	pump_start(&p->pump, idle_of(law), LATENCY);
	p->fresh = 1;
	spin_unlock_irqrestore(&p->l->lock, flags);
}

/* a request from the slic / slic2 attribute, in the port's thread */
static void slic_debug(struct v90port *p)
{
	u32 v = p->dbg_val;
	int r = 0;

	switch (p->dbg_op) {
	case 'w':
		r = ps_ram_wr(&p->bus, p->dbg_addr, v & PS_RAM_MASK);
		fallthrough;
	case 'r':
		if (!r)
			r = ps_ram_rd(&p->bus, p->dbg_addr, &v);
		snprintf(p->dbg_text, sizeof(p->dbg_text), "ram %4u = %08x\n", p->dbg_addr, v);
		break;
	case 'W':
		ps_wr(&p->bus, (u8)p->dbg_addr, (u8)v);
		fallthrough;
	default:
		snprintf(p->dbg_text, sizeof(p->dbg_text), "reg %3u = %02x\n", p->dbg_addr,
			 ps_rd(&p->bus, (u8)p->dbg_addr));
		break;
	}
	p->dbg_res = r ? -EIO : 0;
	p->dbg_op = 0;
	complete(&p->dbg_done);
}

/* record a channel's bring-up result: stats and a log line */
static int chan_report(struct v90port *p, int r, const slic_info *info)
{
	p->inits++;
	p->last_err = r;
	p->last_stage = info->stage;
	p->vbat_mv = info->vbat_mv;
	if (r)
		dev_err(p->l->dev, "port %d: SLIC start failed: %d at stage %d (id %02x, battery %ld mV)\n",
			p->idx + 1, r, info->stage, info->id, info->vbat_mv);
	else
		dev_info(p->l->dev, "port %d: SLIC id %02x up, battery %ld mV, %s, %s receive\n", p->idx + 1,
			 info->id, info->vbat_mv, p->law ? "A-law" : "mu-law", p->lin ? "linear" : "companded");
	return r;
}

/* a single-channel part, straight through to in service (defer = 0) */
static int chan_up(struct v90port *p, int defer)
{
	slic_cfg cfg = { pcmmode_of(p->law, p->lin), (uint16_t)(16 * p->idx), defer };
	slic_info info = { 0 };

	p->spi_phase = 0;
	return chan_report(p, slic_init(&p->bus, &cfg, &info), &info);
}

/* Both channels of a dual part, in the chip's order: set up both, start both
 * converters back to back, calibrate/configure both, then put both lines in
 * service. Starting the converters together -- before either channel draws
 * line current or runs its line calibrations -- keeps the second converter's
 * start-up inrush from tripping the first off the shared VDC input. Returns
 * the owner channel's result (channel 0); channel 1 comes up on its own
 * result, flagged in p2->slic_ready for its thread. */
static int dual_up(struct v90port *p, struct v90port *p2)
{
	slic_cfg c0 = { pcmmode_of(p->law, p->lin), 0, 1 };
	slic_cfg c1 = { pcmmode_of(p2->law, p2->lin), 16, 1 };
	slic_info i0 = { 0 }, i1 = { 0 };
	int r0, r1;

	WRITE_ONCE(p2->slic_ready, 0);
	p->spi_phase = 0;
	p2->spi_phase = 0;

	r0 = slic_setup(&p->bus, &i0);
	r1 = slic_setup(&p2->bus, &i1);
	if (!r0) r0 = slic_converter(&p->bus, &i0);
	if (!r1) r1 = slic_converter(&p2->bus, &i1);
	if (!r0) r0 = slic_finish(&p->bus, &c0, &i0);
	if (!r1) r1 = slic_finish(&p2->bus, &c1, &i1);
	if (!r0) slic_service(&p->bus);
	if (!r1) slic_service(&p2->bus);

	chan_report(p, r0, &i0);
	chan_report(p2, r1, &i1);
	WRITE_ONCE(p2->slic_ready, r1 == 0);
	return r0;
}

static int slic_up(struct v90port *p)
{
	struct v90line *l = p->l;
	int r;

	/* Reset the part. A shared second channel never does this: it would reset
	 * the whole part and drop the other channel. (Only the owner reaches here
	 * on a dual board; the shared channel is brought up inside this call.) */
	if (!p->shares) {
		gpiod_set_raw_value(l->rst[p->cs_idx], 0);
		msleep(10);
		gpiod_set_raw_value(l->rst[p->cs_idx], 1);
		msleep(250);
	}

	if (l->dual && p->idx == 0) {
		r = dual_up(p, &l->port[1]);
		if (r)
			gpiod_set_raw_value(l->rst[0], 0);	/* owner failed: converter off, retry */
		return r;
	}

	r = chan_up(p, 0);					/* single channel, straight into service */
	if (r && !p->shares)
		gpiod_set_raw_value(l->rst[p->cs_idx], 0);	/* converter off (own chip only) */
	return r;
}

/* Is there a part on this port's chip select? The one-port board (HT801)
 * is this board without its second SLIC. Three tries, so that one spoiled
 * access does not take a port away; the part is left in reset. */
static bool port_there(struct v90port *p)
{
	int i, r = 0;

	for (i = 0; i < 3 && !r; i++) {
		gpiod_set_raw_value(p->l->rst[p->cs_idx], 0);
		msleep(10);
		gpiod_set_raw_value(p->l->rst[p->cs_idx], 1);
		msleep(250);
		p->spi_phase = 0;
		r = slic_present(&p->bus);
	}
	gpiod_set_raw_value(p->l->rst[p->cs_idx], 0);
	return r;
}

static int line_thread(void *data)
{
	struct v90port *p = data;
	int seen = 0, run = 0, tick = 0, fails = 0;

	while (!kthread_should_stop()) {
		int h, want, want_lin;

		/* A shared second channel does not drive its own SLIC: the owner
		 * (same chip) brings both channels up together, in the right order.
		 * This thread only runs its own PCM/hook loop, mirroring the owner --
		 * it comes up once the owner has readied this channel and falls with
		 * the owner so it re-initialises if the owner resets the part. */
		if (p->shares) {
			if (!READ_ONCE(p->l->port[p->cs_idx].up) || !READ_ONCE(p->slic_ready)) {
				p->up = 0;
				msleep_interruptible(200);
				continue;
			}
			if (!p->up) {
				p->up = 1;
				seen = run = 0;
				pump_restart(p, 0);
			}
		} else if (!p->up) {
			if (slic_up(p)) {
				/* a shorted or missing line: try again, slowly */
				fails++;
				msleep_interruptible(fails < 5 ? 5000 : 60000);
				continue;
			}
			fails = 0;
			p->up = 1;
			seen = run = 0;
			pump_restart(p, 0);
		}
		want = READ_ONCE(p->want_law);
		want_lin = READ_ONCE(p->want_lin);
		if (want != p->law || want_lin != p->lin) {
			/* the part first, then our side of it: for the few
			 * frames in between the samples mean nothing */
			ps_wr(&p->bus, PS_PCMMODE, 0x10 | pcmmode_of(want, want_lin));
			port_format(p, want, want_lin);
			dev_info(p->l->dev, "port %d: %s, %s receive\n", p->idx + 1, want ? "A-law" : "mu-law",
				 want_lin ? "linear" : "companded");
		}
		if (p->dbg_op)
			slic_debug(p);
		/* the hook, believed when it reads the same three times running */
		h = slic_offhook(&p->bus);
		if (h == seen) {
			if (run < 3 && ++run == 3 && h != p->hook)
				pump_restart(p, h);
		} else {
			seen = h;
			run = 1;
		}
		if (++tick >= 100) {
			tick = 0;
			p->vbat_mv = slic_vbat_mv(&p->bus);
			/* the part resets itself on a fault it cannot ride out */
			if (ps_rd(&p->bus, PS_PCMMODE) != (0x10 | pcmmode_of(p->law, p->lin))) {
				dev_warn(p->l->dev, "port %d: SLIC lost its settings, starting it again\n", p->idx + 1);
				p->up = 0;
				pump_restart(p, 0);
			}
		}
		schedule_timeout_idle(msecs_to_jiffies(10));	/* idle: not in the load average */
	}
	return 0;
}

/* ---- the character device ---- */

static struct v90port *line_of(struct file *f)
{
	return container_of(f->private_data, struct v90port, misc);
}

static int line_open(struct inode *inode, struct file *f)
{
	struct v90port *p = line_of(f);

	if (test_and_set_bit(0, &p->busy))
		return -EBUSY;
	return stream_open(inode, f);
}

static int line_release(struct inode *inode, struct file *f)
{
	clear_bit(0, &line_of(f)->busy);
	return 0;
}

static ssize_t line_read(struct file *f, char __user *buf, size_t n, loff_t *off)
{
	struct v90port *p = line_of(f);
	u8 blk[PUMP_READ_LINEAR];
	s16 smp[PUMP_BLOCK];
	unsigned long flags;
	unsigned int len = 0;
	int got;

	if (n < PUMP_READ_COMPANDED)
		return -EINVAL;
	for (;;) {
		spin_lock_irqsave(&p->l->lock, flags);
		/* a reader with room for the companded block only gets no
		 * linear one (and loses none: it stays queued) */
		if (p->lin && n < PUMP_READ_LINEAR) {
			spin_unlock_irqrestore(&p->l->lock, flags);
			return -EINVAL;
		}
		got = pump_read(&p->pump, smp);
		if (got) {
			len = pump_block_out(p->hook, p->lin, smp, blk);
			p->fresh = 0;
		}
		spin_unlock_irqrestore(&p->l->lock, flags);
		if (got)
			break;
		if (f->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(p->wq, pump_ready(&p->pump)))
			return -ERESTARTSYS;
	}
	if (copy_to_user(buf, blk, len))
		return -EFAULT;
	return len;
}

static ssize_t line_write(struct file *f, const char __user *buf, size_t n, loff_t *off)
{
	struct v90port *p = line_of(f);
	u8 blk[PUMP_BLOCK];
	unsigned long flags;

	if (n != 1 && n != PUMP_BLOCK)
		return -EINVAL;
	if (copy_from_user(blk, buf, n))
		return -EFAULT;
	if (n == 1) {
		if (blk[0] == 'u' || blk[0] == 'a')
			WRITE_ONCE(p->want_law, blk[0] == 'a');
		else if (blk[0] == 'l' || blk[0] == 'c')
			WRITE_ONCE(p->want_lin, blk[0] == 'l');
		else
			return -EINVAL;
		return 1;
	}
	spin_lock_irqsave(&p->l->lock, flags);
	/* an answer to a block read before the pump was restarted has no
	 * place in the new timing */
	if (p->fresh || pump_write(&p->pump, blk))
		p->stale++;
	spin_unlock_irqrestore(&p->l->lock, flags);
	return n;
}

static __poll_t line_poll(struct file *f, poll_table *pt)
{
	struct v90port *p = line_of(f);

	poll_wait(f, &p->wq, pt);
	return EPOLLOUT | EPOLLWRNORM | (pump_ready(&p->pump) ? EPOLLIN | EPOLLRDNORM : 0);
}

static const struct file_operations line_fops = {
	.owner = THIS_MODULE,
	.open = line_open,
	.release = line_release,
	.read = line_read,
	.write = line_write,
	.poll = line_poll,
	.llseek = no_llseek,
};

static ssize_t port_stats(struct device *dev, char *buf, int idx)
{
	struct v90line *l = dev_get_drvdata(dev);
	struct v90port *p = &l->port[idx];

	return sysfs_emit(buf,
		"frames %lu\nbit_clock_divider %u\nslic_up %d\nslic_inits %lu\nslic_last_error %d\n"
		"slic_last_stage %d\nbattery_mv %ld\nhook %d\nlaw %s\ntdm_underruns %lu\ntdm_overruns %lu\n"
		"pump_underruns %lu\npump_overruns %lu\nstale_writes %lu\nspi_errors %lu\n"
		"rx_format %s\nrx_dc %ld\nrx_peak %u\nrx_mean_square %lu\n",
		l->frames, l->tdm_div, p->up, p->inits, p->last_err, p->last_stage, p->vbat_mv,
		p->hook, p->law ? "alaw" : "ulaw", l->tdm_under, l->tdm_over,
		p->pump.underruns, p->pump.overruns, p->stale, l->spi_errors,
		p->lin ? "linear" : "companded", p->meter.dc, p->meter.last_peak, p->meter.ms);
}

/*
 * Bench access to a port's SLIC: write "r ADDR" or "w ADDR HEX" for a RAM
 * word, "R N" or "W N HEX" for a register (decimal ADDR and N); the write
 * returns when the port's thread has done it, and a read of the attribute
 * gives the result ("ram  544 = 0a5db3a8"). fw/tools/slicpoke uses it
 * (kram, kwram, kreg) while this driver owns the SPI bus.
 */
static ssize_t slic_store_port(struct device *dev, const char *buf, size_t n, int idx)
{
	struct v90line *l = dev_get_drvdata(dev);
	struct v90port *p = &l->port[idx];
	unsigned int addr, val = 0;
	char op;
	int got, r;

	got = sscanf(buf, " %c %u %x", &op, &addr, &val);
	if (got < 2 || (op != 'r' && op != 'w' && op != 'R' && op != 'W'))
		return -EINVAL;
	if ((op == 'w' || op == 'W') && got < 3)
		return -EINVAL;
	if ((op == 'r' || op == 'w') ? addr > PS_RAM_MAX : addr > 127)
		return -EINVAL;
	if (mutex_lock_interruptible(&p->dbg_lock))
		return -ERESTARTSYS;
	reinit_completion(&p->dbg_done);
	p->dbg_addr = addr;
	p->dbg_val = val;
	p->dbg_text[0] = 0;
	WRITE_ONCE(p->dbg_op, op);
	if (!p->up || !wait_for_completion_timeout(&p->dbg_done, msecs_to_jiffies(2000))) {
		WRITE_ONCE(p->dbg_op, 0);
		r = -ETIMEDOUT;
	} else {
		r = p->dbg_res;
	}
	mutex_unlock(&p->dbg_lock);
	return r ? r : n;
}

static ssize_t slic_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct v90line *l = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%s", l->port[0].dbg_text);
}

static ssize_t slic_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t n)
{
	return slic_store_port(dev, buf, n, 0);
}
static DEVICE_ATTR_ADMIN_RW(slic);

static ssize_t slic2_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct v90line *l = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%s", l->port[1].dbg_text);
}

static ssize_t slic2_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t n)
{
	return slic_store_port(dev, buf, n, 1);
}
static DEVICE_ATTR_ADMIN_RW(slic2);

/* port 1 and port 2; the counters of the highway and of the SPI bus are
 * the same in both */
static ssize_t stats_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return port_stats(dev, buf, 0);
}
static DEVICE_ATTR_RO(stats);

static ssize_t stats2_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return port_stats(dev, buf, 1);
}
static DEVICE_ATTR_RO(stats2);

static struct attribute *line_attrs[] = {
	&dev_attr_stats.attr, &dev_attr_stats2.attr, &dev_attr_slic.attr, &dev_attr_slic2.attr, NULL
};
ATTRIBUTE_GROUPS(line);

static int line_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct v90line *l;
	int i, irq, r;

	l = devm_kzalloc(dev, sizeof(*l), GFP_KERNEL);
	if (!l)
		return -ENOMEM;
	l->dev = dev;
	spin_lock_init(&l->lock);
	platform_set_drvdata(pdev, l);
	pump_lin16_table(0, l->lin16[0]);
	pump_lin16_table(1, l->lin16[1]);

	l->tdm = devm_platform_ioremap_resource_byname(pdev, "tdm");
	if (IS_ERR(l->tdm))
		return PTR_ERR(l->tdm);
	l->spi = devm_platform_ioremap_resource_byname(pdev, "spi");
	if (IS_ERR(l->spi))
		return PTR_ERR(l->spi);
	for (i = 0; i < PORTS; i++) {
		/* chip selects idle high; both parts held in reset (low) */
		l->cs[i] = devm_gpiod_get_index(dev, "cs", i, GPIOD_OUT_HIGH);
		if (IS_ERR(l->cs[i]))
			return dev_err_probe(dev, PTR_ERR(l->cs[i]), "chip select %d\n", i);
		l->rst[i] = devm_gpiod_get_index(dev, "reset", i, GPIOD_OUT_LOW);
		if (IS_ERR(l->rst[i]))
			return dev_err_probe(dev, PTR_ERR(l->rst[i]), "reset line %d\n", i);
	}
	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	for (i = 0; i < PORTS; i++) {
		struct v90port *p = &l->port[i];

		p->l = l;
		p->idx = i;
		p->cs_idx = i;			/* its own chip select, unless the probe below shares one */
		init_waitqueue_head(&p->wq);
		mutex_init(&p->dbg_lock);
		init_completion(&p->dbg_done);
		p->bus.xfer = line_xfer;
		p->bus.msleep = line_msleep;
		p->bus.ctx = p;
		pump_start(&p->pump, idle_of(0), LATENCY);
	}

	dvf99_cmu_gate(DVF99_GATE_SPI2, true);
	dvf99_cmu_reset(DVF99_GATE_SPI2, false);
	writel(0, l->tdm + T_ENABLE);
	writel(0, l->tdm + T_INT_EN);
	dvf99_cmu_gate(DVF99_GATE_TDM1, false);
	r = line_clock(l);
	if (r)
		return r;
	r = devm_request_irq(dev, irq, line_irq, 0, "v90line", l);
	if (r)
		return r;
	tdm_start(l);

	/* Which board this is. The V1.x HT802 carries one dual-channel Si3226x:
	 * port 1 is its channel 0 and port 2 its channel 1, both on chip select 0.
	 * The other boards carry a single-channel part per port on its own chip
	 * select. Bring the first part out of reset and read which it is; if it is
	 * the dual part, point port 2 at its second channel on the same select. */
	if (PORTS > 1) {
		struct v90port *p0 = &l->port[0];

		gpiod_set_raw_value(l->rst[0], 0);
		msleep(10);
		gpiod_set_raw_value(l->rst[0], 1);
		msleep(250);
		p0->spi_phase = 0;
		if (slic_family(&p0->bus) == SLIC_FAM_3226X) {
			l->dual = 1;
			l->port[1].cs_idx = 0;
			l->port[1].shares = 1;
			l->port[1].bus.cid = 1;
			dev_info(dev, "dual-channel SLIC on chip select 0: port 2 is its second channel\n");
		}
		gpiod_set_raw_value(l->rst[0], 0);	/* back to reset; the port thread starts it */
	}

	for (i = 0; i < PORTS; i++) {
		struct v90port *p = &l->port[i];

		if (i && !l->dual && !port_there(p)) {
			dev_info(dev, "port %d: no SLIC answers, this is a one-port board\n", i + 1);
			continue;
		}
		p->misc.minor = MISC_DYNAMIC_MINOR;
		p->misc.name = i ? "v90line2" : "v90line";
		p->misc.fops = &line_fops;
		p->misc.parent = dev;
		r = misc_register(&p->misc);
		if (r)
			goto undo;
		p->thr = kthread_run(line_thread, p, "%s", p->misc.name);
		if (IS_ERR(p->thr)) {
			r = PTR_ERR(p->thr);
			p->thr = NULL;
			misc_deregister(&p->misc);
			goto undo;
		}
	}
	dev_info(dev, "PCM highway running, bit clock = PLL3 / %u\n", l->tdm_div);
	return 0;
undo:
	while (i-- > 0) {
		if (!l->port[i].thr)
			continue;
		kthread_stop(l->port[i].thr);
		l->port[i].thr = NULL;
		misc_deregister(&l->port[i].misc);
		gpiod_set_raw_value(l->rst[i], 0);
	}
	writel(0, l->tdm + T_INT_EN);
	return r;
}

/* on the way down: no battery voltage left on the line */
static void line_shutdown(struct platform_device *pdev)
{
	struct v90line *l = platform_get_drvdata(pdev);

	int i;

	if (!l)
		return;
	for (i = 0; i < PORTS; i++)
		if (l->port[i].thr)
			kthread_stop(l->port[i].thr);
	writel(0, l->tdm + T_INT_EN);
	for (i = 0; i < PORTS; i++)
		gpiod_set_raw_value(l->rst[i], 0);
}

static const struct of_device_id line_of_match[] = {
	{ .compatible = "v90d,ht802-line" },
	{ }
};

static struct platform_driver line_driver = {
	.probe = line_probe,
	.shutdown = line_shutdown,
	.driver = {
		.name = "v90line",
		.of_match_table = line_of_match,
		.dev_groups = line_groups,
		/* there is no remove(): an unbind through sysfs, with the
		 * ports open and their threads running, took the kernel down */
		.suppress_bind_attrs = true,
	},
};
builtin_platform_driver(line_driver);

MODULE_DESCRIPTION("v90d telephone lines of the HT802");
MODULE_LICENSE("GPL");
