# sct-guard — syscall table integrity detection harness (spec v2.0 §9-§12)

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc
UNAME_R ?= $(shell uname -r)
KDIR    ?= /lib/modules/$(UNAME_R)/build
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/;s/i.86/x86/')

BPFOBJ  := build/sct_detect.bpf.o
SKEL    := build/sct_detect.skel.h
VMLINUX := src/bpf/vmlinux.h

CFLAGS  := -g -O2 -Wall -Icommon -Ibuild
LDLIBS  := -lbpf -lelf -lz

SYSCTBL ?= syscall_64.tbl

.PHONY: all module clean distclean baseline test

all: build/sct_guard module

$(VMLINUX):
	@mkdir -p $(dir $@)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

build:
	@mkdir -p build

$(BPFOBJ): src/bpf/sct_detect.bpf.c $(VMLINUX) | build
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Isrc/bpf -c $< -o $@

$(SKEL): $(BPFOBJ)
	$(BPFTOOL) gen skeleton $< > $@

build/sct_guard: src/loader/sct_guard.c $(SKEL) common/baseline.h | build
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src/kernel modules

baseline:
	@mkdir -p build
	python3 tools/baseline_gen.py \
	    --map /boot/System.map-$(UNAME_R) \
	    --syscalls $(SYSCTBL) -o build/baseline.txt

test: all baseline
	sudo bash tests/selftest.sh

clean:
	rm -rf build
	-$(MAKE) -C $(KDIR) M=$(CURDIR)/src/kernel clean

distclean: clean
	rm -f $(VMLINUX)
