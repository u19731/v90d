# Supported boards

v90d is a Grandstream HT80x firmware. This lists the boards it is known or
expected to run on, and what "supported" means for each.

v90d will not start on a board it does not recognise, **by design**. The
loader reads the board's part number from the stock `factory` partition and
runs v90d only if that number is in its built-in list; on any other board it
hands control straight back to the stock firmware. So an unlisted board is
never left running v90d and cannot be bricked by trying one: it simply boots
stock as before.

## Boards

| Board | Hardware | Part number | SoC | FXS ports | SLIC | Status |
|---|---|---|---|---|---|---|
| HT802 | V2.5A | `9610003725A` | DSPG DVF9918 | 2 | 2 × Si3217x | **Tested** |
| HT802 | V1.6A | `9610003716A` | DVF99 (same device tree) | 2 | 1 × Si3226x (Si32260, dual-channel) | **Tested** (issue #4) |
| HT802 | other V2.x | not yet known | DVF9918 (expected) | 2 | 2 × Si3217x (expected) | **Expected, untested** |
| HT801 | V1.0A | `9611003610A` | DVF99 (same device tree) | 1 | 1 × Si3217x (factory data) | **Accepted by the loader, untested** |
| HT801 | V1.1C | `9610003611C` | DVF99 (same device tree) | 1 | 1 × Si3217x (factory data) | **Accepted by the loader, untested** |
| HT801 | V2.x | not yet known | DVF9918 (expected) | 1 | 1 × Si3217x (expected) | **Expected, untested** |
| HT802V2 | V2.0A | `9610009420A` | Rockchip RK3308H | 2 | Si32283 ProSLIC | **Rockchip; under investigation** |

## What the status words mean

- **Tested** — v90d has been installed on a real unit of this board and a
  dial-up call made through it. This is the reference unit, from stock
  firmware 1.0.65; its facts are in `HARDWARE.md`.
- **Expected, untested** — Grandstream ships one firmware for the HT801 and
  HT802 (the stock image branches on the model for the number of ports
  only), and the stock board tables give these boards the same DSPG DVF9918
  SoC and the same Si3217x SLIC family as the tested unit. So the code is
  expected to work: the modem, PPP, web interface, loader and flash tooling
  are all SoC-level and unchanged, and a single FXS port is already a
  first-class mode in the daemon, the settings and the web pages. But no
  such unit has been tried, and **the loader does not yet carry its part
  number, so it will not start there** until a board is added (below).

- **Accepted by the loader, untested**: the part number is in the loader's
  list, so v90d starts on this board, and the line driver brings up one port
  when no second SLIC answers. Nobody has run it there. See the HT801 section
  below for what is known and what can go wrong.

- **Rockchip; under investigation**: this board is a Rockchip RK3308 platform
  (not the DVF9918) running signed firmware. The stock upgrader refuses v90d
  because the image is not signed, so the normal install path is closed.
  Whether v90d can still be booted another way (over the RK3308 MaskROM, or by
  writing kernel and rootfs under the signed U-Boot) is an open question
  (below), not yet decided either way.

## The HT802V2 (Rockchip RK3308, signed firmware)

The **HT802V2** is a newer product than the HT802 this firmware was built on,
not a hardware revision of it, and it is a completely different platform. From
a board photo (silkscreen `HT802_V2_MB_V1.0A`, 2025-06-12) the parts are:

- **SoC: Rockchip RK3308H** (quad Cortex-A35, ARMv8). Not the DSPG DVF9918.
- **SLIC: Si32283-FM** (Silicon Labs / Skyworks Si3228x ProSLIC, dual-channel
  FXS). The same ProSLIC family v90d already targets (`refs/si3226x-facts.md`):
  raw PCM to the host, no closed voice DSP.
- **Flash: XT26Q01CWSIG** (XTX), a 1 Gbit (128 MB) SPI NAND.
- **Ethernet PHY: RTL8201F** (Realtek 10/100).
- A **`DEBUG` header at `J404`**, almost certainly the UART console.

It runs a signed firmware generation (issue #1): stock 1.0.15.x, dropbear SSH
into a restricted "HT802V2 Command Shell" with no shell escape, lighttpd, and
a `status` that reports `Certificate Type: ECDSA+SHA384` and `SecureStatus: 3`.

### The stock upgrader will not install v90d on it

The v90d install path depends on the stock upgrader accepting an unsigned,
repacked image: on the generation this project targets the flasher checks only
the container magic, a 16-bit checksum and version/generation/hardware
compatibility, with no public-key signature (`HARDWARE.md`, "Firmware image
format"). The stock `ht80xv2fw.bin` (1.0.15.x) was downloaded and read with
`mkgsfw.py`. It keeps the same base format (magic `0x23C97AF9`, same
32-character header key, model key still `0xFD21`) with three changes from
1.0.65:

- a 256-octet high-entropy block (a signature / certificate) in front of the
  container magic, which now sits at file offset `0x100`;
- a slimmed directory that carries only the magic and the four partition
  names, with no sizes or versions;
- the file header beyond offset `0x20` and the whole payload are now encrypted
  under a key the old body-key derivation does not produce (in 1.0.65 the
  header past `0x20`, including the CPU field, was plaintext). Only the first
  32 octets of each 512-octet partition header still decrypt with the stock
  key, which is enough to read the version, size and image id.

The four partitions (genuine 1.0.15.x, versions matching a running unit):

| partition | version | payload | flash capacity |
|---|---|---|---|
| `ht80xv2boot` | 1.0.15.2 | 676 KB | 1 MB |
| `ht80xv2core` (kernel) | 1.0.15.2 | 2.9 MB | 5 MB |
| `ht80xv2base` (rootfs) | 1.0.15.3 | 9.1 MB | 15 MB |
| `ht80xv2prog` (app) | 1.0.15.3 | 5.2 MB | 26 MB |

Because one universal file installs on every unit, the payload key is not
device-unique: it is a new fixed key inside the upgrader or a new derivation,
and the binary that holds it is inside the encrypted rootfs. So the firmware
file yields the layout but not the boot images: U-Boot, the kernel and the
rootfs cannot be extracted from it, and the SoC cannot be confirmed from it
(the RK3308 identification is from the board, not the file). `mkgsfw.py` also
cannot forge the 256-octet signature, so a repacked image is refused.
Uploading through the stock page is a dead end.

### Whether v90d can run at all, in Rockchip terms (assume OTP burned)

The RK3308 enforces secure boot only if a hash of the signing key is burned
into on-chip OTP, and on this SoC that burn is done by the signed firmware
itself: Rockchip's secure-boot note says the loader writes the key hash to OTP
during startup and enables secure boot. So any unit that has ever booted
Grandstream's signed firmware has almost certainly already burned its OTP, and
`SecureStatus: 3` is consistent with that. We therefore **assume OTP is
burned** on any field unit. The unburned state, in which MaskROM would accept
our own loader, would exist only on a factory-fresh board that had never
booted, which is not a realistic unit to obtain.

Two consequences of assuming OTP burned:

- **MaskROM is not a route for us.** With OTP burned, the BootROM verifies the
  loader even in USB download mode, so `rkdeveloptool` will not run our own
  DDR-init or U-Boot, and MaskROM cannot be used to dump the NAND either: it is
  signature-gated. (The "RK3308 DDR security issue" Grandstream patched in
  firmware 1.0.9.3 is not a bypass. It most likely refers to enabling DDR data
  scrambling, a hardening feature, not a hole. No public CVE or exploit maps
  to it.)
- **The one live route is kernel and rootfs replacement under the genuine
  signed U-Boot.** The BootROM forces a genuine U-Boot, but that U-Boot may or
  may not verify the kernel it boots. If it does not, we write only the core
  (kernel) and rootfs partitions, leave the signed U-Boot in place, and it
  boots v90d, exactly as v90d already installs on the DVF9918. Safety rule:
  never rewrite the loader, so the genuine signed U-Boot always comes up and
  can re-flash.

Unlike the DVF9918, the RK3308 is a fully documented, open SoC: mainline
U-Boot and Linux, and a public TRM. A v90d port would be a real ARMv8 port
(new kernel config and device tree, a Si32283 driver, RK3308 audio / TDM
routing, a new boot story), but every piece is supported upstream, and the
modem, V.42, V.90, V.92, PPP and web stack is SoC-agnostic C that moves across
unchanged.

### What a UART log from J404 decides

The log answers two questions, and the pair gives four outcomes:

- **Q1: can autoboot be interrupted to a U-Boot console?** (a "hit a key"
  prompt, versus `bootdelay=0` blowing straight through, as on the OBi302).
- **Q2: does the signed U-Boot verify the kernel?** (a verify step and a
  refusal, versus loading and jumping).

1. **Console yes, no kernel verify (the win).** RAM-boot v90d first, writing
   nothing: load kernel and rootfs over the console (ymodem, or TFTP if U-Boot
   brings up the network) and `bootm`. If it runs, write only kernel and
   rootfs to NAND from U-Boot and leave the signed U-Boot. Recovery is the
   signed U-Boot re-flashing stock.
2. **Console yes, kernel verified.** The signed U-Boot refuses our kernel.
   Narrow: look for an unverified boot path (some builds verify the flash boot
   partition but `bootm` a RAM or TFTP image without checking, or have a
   recovery mode that skips verify). If the verify is airtight, closed short of
   a signing key or a U-Boot bug.
3. **No console, no kernel verify.** Use an external SPI-NAND programmer on the
   `XT26Q01`: dump it, disassemble the stock U-Boot to confirm it does not
   verify the kernel, then write kernel and rootfs back with the programmer.
   Riskier (no RAM-boot dry run) but recoverable by reprogramming stock.
4. **No console and kernel verified.** Closed, short of fault injection on the
   BootROM.

Either way the log also hands us the port's boot parameters: the U-Boot
version, DDR and load addresses, kernel command line, console baud, and the
NAND/mtd partition map. A NAND dump (for the real images and the stock device
tree) now means an external programmer on the `XT26Q01`, not MaskROM, since
MaskROM is signature-gated once OTP is burned.

### What the first UART log shows

A power-on capture from `J404` (115200 8N1) gives the Rockchip boot chain up to
U-Boot: the DDR init blob (64 MB DDR2), ARM Trusted Firmware (`BL31 v1.3`, built
Oct 2021, no OP-TEE), then the hand-off to U-Boot at `0x600000`. Two facts fall
out of it:

- **The normal world is 32-bit.** The log says `Next images boot on AArch32
  mode` and `SPSR = 0x1d3` (AArch32, SVC, ARM state, little-endian), and
  `0x600000` is the usual RK3308 32-bit U-Boot base. So U-Boot and the kernel
  are built ARMv7, not ARM64. v90d's userspace is already 32-bit ARM, so a port
  keeps the same ABI for the daemon, modem, PPP and web stack: it is a new
  kernel, device tree and SLIC driver, not a word-size change.
- **U-Boot is silent.** Every stage up to BL31 prints on the pad, then U-Boot
  (now running at `0x600000`) prints nothing: no banner, no autoboot prompt. The
  Rockchip stages share one debug UART, so this is almost certainly a suppressed
  production console (`silent=1` / `CONFIG_SILENT_CONSOLE`), not a different
  port. A silenced console usually still reads the line, so it may still be
  interruptible.

So Q1 and Q2 are still open, and the **RX line is the next thing to confirm**: a
working RX lets us try to break into the console as BL31 hands off, and, if the
console is silent end to end, lets us read whether the kernel prints a command
line and mtd map later. The ATF vintage (v1.3, Oct 2021) pins this to the RK3308
Linux SDK whose U-Boot is 2017.09, which verifies the kernel only when a signed
FIT image was shipped with `FIT_SIGNATURE` turned on; a plain kernel boot is not
verified. That leans toward Q2 being favourable, but it is unproven.

A later test settled both questions, and closed the on-device route. RX works,
the console does not break in (tried repeatedly), and nothing prints for five
minutes after `SPSR = 0x1d3`. So the signed U-Boot is silent end to end and
gives no console and no kernel output: RAM-boot and writing kernel and rootfs
under the signed U-Boot are both out, short of an external SPI-NAND programmer.

### The practical path: v90d off the box, over a SIP ATA

Because the modem is SoC-agnostic DSP on 8 kHz samples, it does not have to run
on the box at all. The HT802V2 stays on stock firmware as a plain SIP ATA; a PBX
(Asterisk) bridges the call to the v90d modem over its AudioSocket interface, and
v90d answers on Linux. The caller's hardware modem dials the ATA as before. This
runs today, on any ATA or PBX, and sidesteps the signed firmware entirely.

The target is **V.34**, not V.90: V.90 and V.92 need the answering side to place
exact PCM codewords on a clean digital path, which a transcoding SIP leg does not
give; V.34 (up to 33600 both ways) is analogue and survives. It needs G.711 end
to end (no lossy codec such as G.729 or Opus), echo cancellation and any
fax/modem DSP off, and a fixed or absent jitter buffer (an adaptive one forces
retrains). AudioSocket carries 8 kHz 16-bit linear, which libv90modem already
accepts (`rx_linear`), so no G.711 round-trip is needed on our side. First tried
by willsowerbutts against the HT802V2 on stock firmware, and it works.

## The HT801, from two flash dumps

Two complete flash dumps of HT801 units are public
([crvallance/Grandstream-hax](https://github.com/crvallance/Grandstream-hax)).
Read as facts, compared with the tested HT802:

- Part numbers `9611003610A` and `9610003611C` (hardware V1.0A and V1.1C).
  In these numbers `36` is the HT801, `37` the HT802, and the last three
  characters the hardware version.
- The two HT801 device trees are identical to each other, and differ from
  the HT802's only in the second SLIC: one chip select (the HT802's port 1),
  one reset line, one interrupt line.
- The flash layout is the HT802's, partition for partition.
- The factory data gives the same SLIC family, converter type and
  protection setting as the HT802, with one SLIC device instead of two.

What v90d does with that: the loader accepts both part numbers, and the line
driver asks the second chip select whether a SLIC is there before it makes
the second port. On an HT801 the daemon then runs with one line and the web
pages show one port. On the tested HT802 this was checked: both ports found,
a call made through port 2.

What is not known, and matters before anyone flashes one:

1. **Ethernet.** The firmware does not name the PHY: the device tree says
   only RMII at 100 Mb (the same words in all three), the factory data has
   no record that differs for it, and the stock kernel asks the chip for
   its identity when it runs. V1.x boards are reported to carry a KSZ8081,
   the tested V2.5A unit a YT8512H. That should not matter to v90d: the
   box's own boot loader, which v90d leaves in place, resets the PHY and
   sets its clock on every start, and our kernel then talks to it with the
   generic driver at MDIO address 0, which is where the vendor's published
   source puts the KSZ8081. It is not proven until seen on a unit, so on
   these boards a start is confirmed only once the network port has
   received something: a box whose Ethernet does not work goes back to the
   stock firmware by itself after three starts. (So does one that is
   started three times in a row with no cable in.)
2. **SLIC revision.** The driver starts a Si3217x of revision C only. Another
   revision is refused cleanly (no battery voltage, a line in the log), and
   the port stays dead.
3. **V2.x HT801 units** have a part number that is not in the list yet.

Whoever can should make the first start on an HT801 from RAM
(`fw/tools/ramboot.sh`, which writes nothing) with a serial console
attached. Installing from the stock web page is expected to be safe as
well, for the reason in point 1, with the network cable plugged in.

## Flash chips and Ethernet PHYs

HT80x boards ship with different parts for the 16 MiB QSPI flash and the
Ethernet PHY. The loader and kernel now handle the ones the stock firmware
does (its chip table and PHY set, studied from the vendor GPL kernel; our own
clean code, `refs/qspi-chips.md`):

- **Flash (16 MiB, the only size the A/B layout fits):** EON EN25QX128A
  (the reference unit, tested), Winbond W25Q128FV (`ef4018`/`ef6018`),
  GigaDevice GD25Q128 (`c84018`), Micron N25Q128 (`20ba18`). The loader reads
  the JEDEC id and drives each one's quad mode; a flash chip it does not know
  is handled like an unknown board (hands back to stock, no brick).
- **Ethernet PHY:** the stock kernel uses the generic/fixed PHY path, so most
  IEEE PHYs work without a chip-specific driver; we keep that and also build
  the drivers for the parts seen in the field (Motorcomm YT8512H on the HT802
  V2.5A, Micrel KSZ8081 on V1.x) plus a few common 10/100 parts.

The **SLIC** is the exception: the vendor's line bring-up and its RAM patch are
in closed userspace, not in the GPL, so v90d's SLIC support is written from the
Silicon Labs Si3217x documentation and confirmed on the bench, per revision. It
drives Si3217x **rev C** (patch-free, the reference unit). Another revision is a
separate bring-up: it needs that revision's data and a unit to measure battery
and ring voltage on, and it fails safe until then (the port stays dead, logged).

## Adding a board

The code that is specific to a board is small and in three places, so
bringing up a compatible board is mostly reading values off a unit, not
writing new code:

1. **Part number** — read it from the unit (the label, or flash offset
   `0x4020` in the `factory` partition) and add it to `LD_BOARDS` in
   `fw/loader/boot.h`.
2. **SLIC wiring** — the reset, chip-select and interrupt GPIOs and the pin
   mux, in `fw/kernel/arch/arm/boot/dts/dspg/dvf99-ht802.dts` (and the
   `v90line` driver). On the HT801 only one SLIC is populated; its pins are
   likely the HT802's port-1 SLIC, to be confirmed from the board's own
   device tree. The driver finds out by itself whether the second SLIC is
   there.
3. **Flash layout** — the set A/B core and base offsets in
   `fw/loader/boot.h`. The HT801 and HT802 use the same 16 MiB flash and the
   same stock firmware, so these are almost certainly identical; confirm
   with `/proc/mtd` on the unit.

Then, before ever writing flash, RAM-boot the image on the unit with
`fw/tools/ramboot.sh` (it writes nothing) and confirm the FXS port(s), the
SLIC DC-DC ringing supply (`fw/tools/slicpoke`) and the flash map. Only once
the no-serial recovery path is proven on the board does it move from
"expected" to "tested". See `HARDWARE.md` for the HT802 facts and the
starting points for the HT801 and other HT802 revisions.

## The one electrical risk

The Si3217x needs the right DC-DC converter configuration loaded at init
(the stock board table carries a DC-DC type per model). If a board's ringing
supply differs from the tested HT802's, those init values need matching
before ringing is trusted. This is the same risk that was cleared on the
HT802 and is checkable on the bench without writing flash.
