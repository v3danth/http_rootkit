# sct-guard

Read-only syscall-table integrity detection harness for Linux x86_64.

## Build

Requires clang with BPF support, bpftool, libbpf, libelf, zlib, matching Linux headers, and a matching `System.map` plus `syscall_64.tbl`.

```bash
make
make baseline SYSCTBL=/path/to/syscall_64.tbl
```

The build generates `src/bpf/vmlinux.h` from the running kernel's BTF. The baseline generator writes `build/baseline.txt` using the on-disk `System.map` as the trusted anchor.

## Run

```bash
sudo insmod src/kernel/sct_monitor.ko
sudo ./build/sct_guard -b build/baseline.txt
```

Use `--no-module` to run userspace-only monitoring, and `--selftest` to validate the eBPF alert path without modifying the syscall table.

```bash
sudo ./build/sct_guard -b build/baseline.txt --no-module --selftest
```

This project is detection-only: it does not modify the syscall table or disable kernel write protection.
