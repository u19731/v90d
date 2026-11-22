# QSPI flash chips on the HT80x (DSPG DVF9918), for fw/drv/qspi.c

Hardware facts extracted by **studying** the vendor GPL kernel driver
`linux-3.4.20/drivers/mtd/devices/dspg-qspic.c` (Grandstream ht8xx_gpl.tar.gz,
2017) and U-Boot `drivers/mtd/spi/{winbond,eon}.c`. No vendor code is copied;
these are the register-level facts our own clean driver is written from, the
same way qspi.c's EON support was written from the running unit. The stock
driver prints `CS%d: jedecid: 0x%06x` and sets the chip up per this table.

## The DVF9918 QSPI controller (as fw/drv/qspi.c already uses it)

Reads go through a memory window configured by RDTRSTP (transfer shape) +
RDCMD (opcode). RDTRSTP fields (vendor macros, confirmed against our working
EON value `V_RDTRSTP = 0x0008362A`):

    OPCODE lines  bits 0-1    ADD lines     bits 2-3
    DUMMY lines   bits 4-5    DIN lines     bits 8-9
    ADDMODE       bits 10-11  (1 = 3-byte, 2 = 4-byte)
    DUMMY_SIZE    bits 12-15  (in BYTES; QPI = 2 bits/line/clock -> N bytes = 4N dummy clocks)
    HAS_OPCODE    bit 19

Full QPI read (all phases on 4 lines), 3-byte address, opcode 0x0B:
`0x0008362A | (DUMMY_SIZE differs per chip)`. Our EON value has DUMMY_SIZE=3
(6 clocks). Program: PPTRSTP `0x0008048A`, opcode 0x02, all-quad. aux commands
once in QPI: all-quad (TR_QUAD = 0x28A). Data bytes in FRD/FWD are stored
end-first (byte i at offset 31-i), which qspi.c's read path already handles;
the write path (QE / config bytes) must mirror it.

## The 128 Mbit (16 MB) chips that fit the HT80x A/B layout

| name | JEDEC id | RDTRSTP (read 0x0B) | enable sequence |
|---|---|---|---|
| EON EN25QX128A | `1c 71 18` | `0x0008362A` (6 clk) | enter QPI `0x38` alone; no quad-enable bit |
| Winbond W25Q128FV | `ef 40 18`, `ef 60 18` | `0x0008362A` (6 clk) | below |
| GigaDevice GD25Q128 | `c8 40 18` | `0x0008262A` (4 clk) | below |
| Micron N25Q128A | `20 ba 18` | `0x0008362A` (6 clk) | below |

Command encoding (opcode | type<<8 | dir): type 5 = read-status, 6 =
write-status, 9 = other; dir bit 13 = read, bit 14 = write.

**Winbond `ef4018`/`ef6018`** (single-line until the 0x38, then QPI):
1. read SR2: opcode `0x35`, type 5, read -> sr2
2. sr2 |= 1<<1 (QE)
3. volatile SR write-enable: opcode `0x50`, type 9
4. write SR2: opcode `0x31`, type 6, write, 1 byte sr2
5. enter QPI: opcode `0x38`, type 9
6. (QPI now) set read parameters: opcode `0xC0`, type 9, write, 1 byte = `0x2<<4` (6 dummy clocks)

**GigaDevice `c84018`** (single-line until 0x38):
1. read SR2: opcode `0x35`, type 5 -> sr2 (QE = bit 1)
2. if QE clear: WREN `0x06`(type 9); write SR2 `0x31`(type 6, write) = `0x02`; poll SR0 (`0x05`) until BUSY(bit0) clears
3. enter QPI: opcode `0x38`, type 9
   (DUMMY_SIZE = 2 bytes / 4 clocks, so RDTRSTP = `0x0008262A`)

**Micron N25Q `20ba18`** (no 0x38; quad via config registers):
1. read SR `0x05`, clear protect bits (`& ~0x5c`), WREN, write SR `0x01` (write), wait
2. read Volatile Config `0x85`; set dummy = 6 (`(v & ~0xf0) | (6<<4)`); WREN; write VCR `0x81` (write); wait
3. read Enhanced Volatile Config `0x65`; clear bit 7 (quad enable) and set bit 6 (disable dual); WREN; write EVCR `0x61` (write); wait

Smaller/larger Winbond (`ef4015` 16Mb, `ef4017` 64Mb, `ef4019` 256Mb), SST26VF,
Atmel AT25DQ321 exist in the vendor table but do not match the 16 MB A/B
partition layout, so they are not relevant to booting v90d on an HT80x.

## Verification status

- EON: the reference unit (tested).
- Winbond W25Q128FV: issue #4 reporter's board (a Zoom-less HT802 V1.6A,
  `9610003716A`); to be confirmed by that unit.
- GD25Q128, N25Q128: added from these vendor facts, NOT yet seen on a unit.
