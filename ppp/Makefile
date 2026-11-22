# v90d/ppp - PPP server library: host tests, ARM cross tests under qemu,
# and an optional host-only interop run against the system pppd.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
BUILD   := build

# Cross toolchain for the ARM926 target (same one the top-level Makefile uses).
ARM_CC  ?= $(wildcard $(CURDIR)/../toolchain/*/bin/arm-linux-gcc)
QEMU    ?= qemu-arm-static

INC     := -I. -I../test
LIB_SRC := ppp_md5.c ppp_crypto.c ppp_hdlc.c ppp_fsm.c ppp_deflate.c ppp_mppc.c ppp.c
LIB_HDR := ppp_md5.h ppp_crypto.h ppp_hdlc.h ppp_fsm.h ppp_deflate.h ppp_mppc.h ppp.h
SUP_SRC := test/pppc.c
SUP_HDR := test/pppc.h test/gen.h ../test/test.h
TESTS   := test_md5 test_crypto test_hdlc test_fsm test_ppp test_e2e test_deflate test_mppc test_ccp

# under qemu the long sequences of test_deflate and test_mppc are cut short
# (ARM_ARGS= for all of them; the other tests take no arguments)
ARM_ARGS ?= quick
COMP_SRC := ppp_deflate.c ppp_mppc.c
COMP_HDR := ppp_deflate.h ppp_mppc.h test/gen.h

.PHONY: all test test-arm test-interop bench clean
all: test

$(BUILD):
	@mkdir -p $(BUILD)

# each test_X links test/test_X.c with the library and the test-side client
$(BUILD)/test_%: test/test_%.c $(LIB_SRC) $(LIB_HDR) $(SUP_SRC) $(SUP_HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_SRC) $(SUP_SRC)

# The two compressors alone, for the check against zlib and for the figures:
#   comp_tool   packets in, packets out on its standard streams, driven by
#               test/zlib_check.py (Python's zlib module as the independent
#               implementation of RFC 1951; left out where there is no python3)
#   comp_bench  ratios on a file cut into packets, and runs for instruction
#               counts under qemu (make bench FILE=...)
$(BUILD)/comp_%: test/comp_%.c $(COMP_SRC) $(COMP_HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(INC) -Itest -o $@ $< $(COMP_SRC)
$(BUILD)/arm_comp_%: test/comp_%.c $(COMP_SRC) $(COMP_HDR) | $(BUILD)
	$(ARM_CC) $(CFLAGS) $(INC) -Itest -static -o $@ $< $(COMP_SRC)

test: $(addprefix $(BUILD)/,$(TESTS)) $(BUILD)/comp_tool
	@echo "== running host tests =="
	@fail=0; for t in $(TESTS); do ./$(BUILD)/$$t || fail=1; done; \
	 if command -v python3 >/dev/null 2>&1; then python3 test/zlib_check.py ./$(BUILD)/comp_tool || fail=1; \
	 else echo "  (no python3: the check of Deflate against zlib is left out)"; fi; \
	 if [ $$fail -eq 0 ]; then echo "ALL TESTS PASS"; else echo "TESTS FAILED"; exit 1; fi

bench: $(BUILD)/comp_bench $(BUILD)/arm_comp_bench
	@test -n "$(FILE)" || { echo "usage: make bench FILE=some-file"; exit 2; }
	./$(BUILD)/comp_bench $(FILE)

# cross-build the same tests for the ARM926 target and run under qemu
$(BUILD)/arm_test_%: test/test_%.c $(LIB_SRC) $(LIB_HDR) $(SUP_SRC) $(SUP_HDR) | $(BUILD)
	$(ARM_CC) $(CFLAGS) $(INC) -static -o $@ $< $(LIB_SRC) $(SUP_SRC)

test-arm: $(addprefix $(BUILD)/arm_,$(TESTS)) $(BUILD)/arm_comp_tool
	@echo "== running ARM tests under $(QEMU) =="
	@fail=0; for t in $(TESTS); do echo "[arm] $$t"; $(QEMU) ./$(BUILD)/arm_$$t $(ARM_ARGS) || fail=1; done; \
	 if command -v python3 >/dev/null 2>&1; then echo "[arm] comp_tool against zlib"; \
	   python3 test/zlib_check.py -q $(QEMU) ./$(BUILD)/arm_comp_tool || fail=1; \
	 else echo "  (no python3: the check of Deflate against zlib is left out)"; fi; \
	 if [ $$fail -eq 0 ]; then echo "ALL ARM TESTS PASS"; else echo "ARM TESTS FAILED"; exit 1; fi

# Interop against independent implementations from the system ppp package
# (host only, never shipped; nothing is installed, no root needed):
#   - pppdump checks our HDLC framing and FCS;
#   - pppd runs as the calling peer, in a user namespace, with the kernel
#     side of /dev/ppp replaced by test/pppd_shim.c (see that file).
$(BUILD)/pppd_shim.so: test/pppd_shim.c | $(BUILD)
	$(CC) -O2 -Wall -Wextra -shared -fPIC -o $@ $< -ldl

$(BUILD)/interop_pppd: test/interop_pppd.c $(LIB_SRC) $(LIB_HDR) $(SUP_SRC) $(SUP_HDR) | $(BUILD)
	$(CC) $(CFLAGS) -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE $(INC) -o $@ $< $(LIB_SRC) $(SUP_SRC)

test-interop: $(BUILD)/interop_pppd $(BUILD)/pppd_shim.so
	@echo "== running interop against pppdump and pppd =="
	./$(BUILD)/interop_pppd $(BUILD)

clean:
	rm -rf $(BUILD)
