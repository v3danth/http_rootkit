#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""baseline_gen.py — build the trusted-anchor baseline for sct-guard.

Maps System.map-$(uname -r) (link-time, pre-KASLR addresses of the ON-DISK
kernel) to syscall numbers via arch/x86/entry/syscall_64.tbl.

Trust model (spec §9.1 / F-32): System.map is the anchor because it is a
file on disk shipped with the kernel build, not runtime state. Verify the
map matches the RUNNING kernel before trusting it (readelf -n on
/boot/vmlinuz-$(uname -r), distro source provenance). The loader adds its
own safety nets: 2 MiB-aligned KASLR slide + per-symbol consistency.

Output format (consumed by sct_guard):
    # anchor _text 0xffffffff81000000
    0 __x64_sys_read 0xffffffff8125f6f0
"""
import argparse
import sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=True,
                    help="/boot/System.map-<uname -r>")
    ap.add_argument("--syscalls", required=True,
                    help="arch/x86/entry/syscall_64.tbl from kernel source "
                         "of the SAME version")
    ap.add_argument("--anchor", default="_text")
    ap.add_argument("-o", "--output", default="build/baseline.txt")
    args = ap.parse_args()

    symbols = {}
    with open(args.map) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                symbols.setdefault(parts[2], int(parts[0], 16))

    if args.anchor not in symbols:
        sys.exit(f"anchor {args.anchor} not in {args.map}")

    out = [f"# anchor {args.anchor} {symbols[args.anchor]:#x}"]
    n = skipped = 0

    with open(args.syscalls) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            cols = line.split()
            if len(cols) < 4 or not cols[0].isdigit():
                continue
            nr, abi, sym = int(cols[0]), cols[1], cols[3]
            if abi not in ("common", "64"):
                continue                    # skip x32 (spec §5.6, F-40)
            # tbl may carry plain 'sys_read' (older) or the full
            # '__x64_sys_read' (newer); normalize to the table symbol.
            full = sym if sym.startswith("__x64_") else "__x64_" + sym
            if full not in symbols:
                print(f"warn: {full} not in System.map, skipping",
                      file=sys.stderr)
                skipped += 1
                continue
            out.append(f"{nr} {full} {symbols[full]:#x}")
            n += 1

    if n < 300:
        sys.exit(f"suspiciously few entries ({n}) — wrong tbl or map?")

    with open(args.output, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {args.output}: {n} entries, {skipped} skipped, "
          f"anchor={args.anchor}")

if __name__ == "__main__":
    main()
