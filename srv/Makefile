# v90d/srv - the server core (telephony + call + status + configuration) and
# the Linux daemon around it.
#   make test       whole calls against the simulated caller, on the host
#   make test-arm   the same cross-built, under qemu
#   make v90d       the daemon for the host;  make v90d-arm  for the box
CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
LDLIBS  ?= -lm
BUILD   := build
ARM_CC  ?= $(wildcard $(CURDIR)/../toolchain/*/bin/arm-linux-gcc)
QEMU    ?= qemu-arm-static

# -D options in CFLAGS (the bench experiments of live/*.sh) reach the modem too
LIBV90M_DEFS ?= $(filter-out -D_POSIX_C_SOURCE%,$(filter -D%,$(CFLAGS)))
include ../libv90m.mk

# the daemon sees the library's public header only; the tests see its internals
DAEMON_INC := -I. -I../tel -I../dce -I../cfg -I../ppp $(LIBV90M_INC)
INC := -I. -I../tel -I../dce -I../dce/test -I../cfg -I../test -I../ppp -I../ppp/test $(LIBV90M_DEV_INC)
PPP_SRC := $(addprefix ../ppp/,ppp_md5.c ppp_crypto.c ppp_hdlc.c ppp_fsm.c ppp_deflate.c ppp_mppc.c ppp.c)
CFG_SRC := ../cfg/config.c ../cfg/status.c
# everything portable that goes into the daemon
# (the modem and V.42: libv90modem)
CORE_SRC := srv.c console.c dclist.c dcnow.c upnp.c saturn.c stun.c bbs.c telnet.c bbsdial.c line.c ../tel/tel.c ../dce/dce.c $(PPP_SRC) $(CFG_SRC)
# test side: the calling DCE and PPP client; the simulated line and caller
# are in the library's dev archive (linked last, after the sources)
SIM_SRC := ../dce/test/caller.c ../ppp/test/pppc.c $(LIBV90M_DEV)
SIM_SRC_ARM := ../dce/test/caller.c ../ppp/test/pppc.c $(LIBV90M_DEV_ARM)
HDRS := $(wildcard *.h ../tel/*.h ../dce/*.h ../dce/test/*.h ../cfg/*.h ../ppp/*.h) $(LIBV90M)/include/v90modem.h

DAEMON_SRC := main.c satlink.c bbslink.c update.c netsvc.c tun.c nat.c ../cfg/httpd.c ../cfg/settings.c ../cfg/firmware.c ../cfg/vpn.c $(CORE_SRC)
# the firmware's version, shown on the pages: one place, fw/VERSION
VERSION := $(shell cat ../fw/VERSION 2>/dev/null || echo dev)
DAEMON_DEF := -DV90D_VERSION='"$(VERSION)"'
NS_SRC := test/ns_call.c tun.c $(filter-out srv.c ../tel/tel.c ../dce/dce.c,$(CORE_SRC)) $(SIM_SRC)

RIG_SRC := ../rig/pppcall.c $(filter-out srv.c ../tel/tel.c $(CFG_SRC),$(CORE_SRC)) $(SIM_SRC)
RIG_SRC_ARM := ../rig/pppcall.c $(filter-out srv.c ../tel/tel.c $(CFG_SRC),$(CORE_SRC)) $(SIM_SRC_ARM)
$(BUILD)/test_rig: test/test_rig.c $(RIG_SRC) $(HDRS) ../rig/pppcall.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -I../rig -o $@ test/test_rig.c $(RIG_SRC) $(LDLIBS)
$(BUILD)/arm_test_rig: test/test_rig.c $(RIG_SRC_ARM) $(HDRS) ../rig/pppcall.h
	@mkdir -p $(BUILD)
	$(ARM_CC) $(CFLAGS) $(INC) -I../rig -static -o $@ test/test_rig.c $(RIG_SRC_ARM) $(LDLIBS)

.PHONY: test test-arm test-ns test-ns-nat test-ns-upnp test-ns-pppd v90d v90d-arm clean
v90d: $(BUILD)/v90d
v90d-arm: $(BUILD)/v90d-arm
$(BUILD)/v90d: $(DAEMON_SRC) $(HDRS) ../fw/VERSION $(LIBV90M_A)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DAEMON_DEF) $(DAEMON_INC) -o $@ $(DAEMON_SRC) $(LIBV90M_A) $(LDLIBS)
$(BUILD)/v90d-arm: $(DAEMON_SRC) $(HDRS) ../fw/VERSION $(LIBV90M_A_ARM)
	@mkdir -p $(BUILD)
	$(ARM_CC) $(CFLAGS) $(DAEMON_DEF) $(DAEMON_INC) -static -Os -o $@ $(DAEMON_SRC) $(LIBV90M_A_ARM) $(LDLIBS)
	$(dir $(ARM_CC))arm-linux-strip $@
# The real daemon in a private network namespace (needs unprivileged user
# namespaces): TUN device, NAT rule, HTTP listener, a whole call.
$(BUILD)/ns_call: $(NS_SRC) $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ $(NS_SRC) $(LDLIBS)
# The real daemon against the real pppd (test/ns_pppd.c): PPP compression
# with a peer that was not written here. pppd needs /dev/ppp and the
# kernel's ppp_deflate, so this part runs as root (sudo -n) in namespaces of
# its own, and is left out, with a line that says so, where there is no
# pppd, no password-less sudo or no ppp_deflate module.
NSP_SRC := test/ns_pppd.c $(filter-out srv.c ../tel/tel.c ../dce/dce.c,$(CORE_SRC)) $(SIM_SRC)
$(BUILD)/ns_pppd: $(NSP_SRC) $(HDRS) ../ppp/test/gen.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ $(NSP_SRC) $(LDLIBS)
test-ns-pppd: $(BUILD)/v90d $(BUILD)/ns_pppd
	@if ! command -v pppd >/dev/null 2>&1; then echo "  (no pppd here: the call with the real pppd is not tried)"; \
	 elif ! sudo -n true 2>/dev/null; then echo "  (no sudo without a password: the call with the real pppd is not tried)"; \
	 elif ! sudo -n modprobe ppp_deflate 2>/dev/null; then echo "  (no ppp_deflate module in this kernel: the call with the real pppd is not tried)"; \
	 else d=$$(mktemp -d) && { sudo -n unshare -n -m ./$(BUILD)/ns_pppd ./$(BUILD)/v90d $$d; rc=$$?; rm -rf $$d; exit $$rc; }; fi

# The Firmware page end to end takes the image's flash tool built for the
# host and a file that stands for the flash (fw/tools); without python3 or
# fw/ that part is left out.
FW_NV := ../fw/tools/v90nv.host
$(BUILD)/ns_nat: test/ns_nat.c nat.c nat.h tun.c tun.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ test/ns_nat.c nat.c tun.c
test-ns-nat: $(BUILD)/ns_nat
	unshare -Urn ./$(BUILD)/ns_nat
$(BUILD)/ns_upnp: test/ns_upnp.c upnp.c upnp.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ test/ns_upnp.c upnp.c
test-ns-upnp: $(BUILD)/ns_upnp
	unshare -Urn ./$(BUILD)/ns_upnp $(BUILD)

test-ns: $(BUILD)/v90d $(BUILD)/ns_call test-ns-nat test-ns-upnp
	@$(MAKE) -s -C ../fw tools/v90nv.host && python3 ../fw/tools/test_v90nv_boot.py --make-flash $(BUILD)/ns_flash.bin $(BUILD)/ns_new.uimage \
	  || echo "  (no flash tool or no python3: the Firmware page is not tried)"
	unshare -Urn ./$(BUILD)/ns_call ./$(BUILD)/v90d $(BUILD) $$(test -f $(BUILD)/ns_flash.bin && test -x $(FW_NV) && echo $(FW_NV) $(BUILD)/ns_flash.bin $(BUILD)/ns_new.uimage)
	@rm -f $(BUILD)/ns_flash.bin
	@$(MAKE) -s test-ns-pppd

test: $(BUILD)/test_srv $(BUILD)/test_rig $(BUILD)/test_orig $(BUILD)/test_update
	./$(BUILD)/test_srv
	./$(BUILD)/test_update
	./$(BUILD)/test_rig
	./$(BUILD)/test_orig
test-arm: $(BUILD)/arm_test_srv $(BUILD)/arm_test_rig $(BUILD)/arm_test_orig $(BUILD)/arm_test_update
	$(QEMU) ./$(BUILD)/arm_test_srv
	$(QEMU) ./$(BUILD)/arm_test_update
	$(QEMU) ./$(BUILD)/arm_test_rig
	$(QEMU) ./$(BUILD)/arm_test_orig
$(BUILD)/test_orig: test/test_orig.c $(CORE_SRC) $(SIM_SRC) $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ test/test_orig.c $(CORE_SRC) $(SIM_SRC) $(LDLIBS)
$(BUILD)/arm_test_orig: test/test_orig.c $(CORE_SRC) $(SIM_SRC_ARM) $(HDRS)
	@mkdir -p $(BUILD)
	$(ARM_CC) $(CFLAGS) $(INC) -static -o $@ test/test_orig.c $(CORE_SRC) $(SIM_SRC_ARM) $(LDLIBS)

$(BUILD)/test_update: test/test_update.c update.c update.h $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ test/test_update.c update.c $(LDLIBS)
$(BUILD)/arm_test_update: test/test_update.c update.c update.h $(HDRS) | $(BUILD)
	$(ARM_CC) $(CFLAGS) $(INC) -static -o $@ test/test_update.c update.c $(LDLIBS)
$(BUILD)/test_srv: test/test_srv.c $(CORE_SRC) $(SIM_SRC) $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ test/test_srv.c $(CORE_SRC) $(SIM_SRC) $(LDLIBS)
$(BUILD)/arm_test_srv: test/test_srv.c $(CORE_SRC) $(SIM_SRC_ARM) $(HDRS)
	@mkdir -p $(BUILD)
	$(ARM_CC) $(CFLAGS) $(INC) -static -o $@ test/test_srv.c $(CORE_SRC) $(SIM_SRC_ARM) $(LDLIBS)
clean:
	rm -rf $(BUILD)
