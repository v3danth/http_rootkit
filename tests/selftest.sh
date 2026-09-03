#!/usr/bin/env bash
# Validates the detection pipeline WITHOUT any rootkit present:
#   pass 1: clean run for 10 s — expects zero alerts
#   pass 2: --selftest injects a wrong EXPECTED value into the eBPF map;
#           the sampler must fire. The actual table is never touched —
#           kernel-side full scans stay clean in both passes, which also
#           proves the layers are independent.
set -u
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
[ -x build/sct_guard ]     || { echo "run: make" >&2; exit 1; }
[ -f build/baseline.txt ]  || { echo "run: make baseline SYSCTBL=..." >&2; exit 1; }

echo "== pass 1: clean baseline, 10 s (expect no alerts) =="
timeout 10 ./build/sct_guard -b build/baseline.txt --no-module || true

echo "== pass 2: injected mismatch must alert =="
./build/sct_guard -b build/baseline.txt --no-module --selftest
