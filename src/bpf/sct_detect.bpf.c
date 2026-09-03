// SPDX-License-Identifier: GPL-2.0
/* sct_detect.bpf.c — syscall table integrity sampler.
 *
 * Attaches to the raw tracepoint sys_enter. Its TP_ARGS
 * (struct pt_regs *regs, long id) are stable, unlike do_syscall_64's
 * signature which changed in 4.17 — this is why we do NOT kprobe it.
 *
 * SCT address and expected handlers arrive at load time via maps
 * (KASLR changes addresses every boot; compile-time constants are dead).
 * Expected values come from the System.map trusted anchor, never from
 * live /proc/kallsyms of the host under test (F-32).
 *
 * Sampling 1/4096: a full probe on every syscall is pure overhead. The
 * loader's /proc/kcore path and the kernel module do periodic FULL scans;
 * this program catches anomalies in traffic between scans.
 *
 * Note on compat callers: 32-bit processes also hit this tracepoint with
 * i386 syscall numbers, but we always compare "table slot N" against
 * "expected for slot N" of the same 64-bit table — caller semantics are
 * irrelevant, so compat traffic cannot produce false positives. x32
 * (nr >= 512) is filtered: separate entries per spec §5.6 / F-40.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SAMPLE_MASK 4095

struct alert {
    __u32 nr;
    __u32 pid;
    __u64 actual;
    __u64 expected;
    __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} alerts SEC(".maps");

/* index 0 = live sys_call_table address (set by loader, per boot) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sct_addr SEC(".maps");

/* syscall nr -> expected (KASLR-adjusted) handler, from trusted anchor */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, __u64);
} expected_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("raw_tp/sys_enter")
int BPF_RAW_TRACEPOINT(sys_enter, struct pt_regs *regs, long id)
{
    __u32 nr = (__u32)id;
    __u32 zero = 0;
    __u64 *table_p, *exp_p, actual = 0;
    struct alert *a;

    if (nr >= 512)                          /* x32 ABI range: excluded */
        return 0;

    if (bpf_get_prandom_u32() & SAMPLE_MASK)/* sample 1/4096 */
        return 0;

    table_p = bpf_map_lookup_elem(&sct_addr, &zero);
    if (!table_p || !*table_p)
        return 0;

    exp_p = bpf_map_lookup_elem(&expected_map, &nr);
    if (!exp_p)
        return 0;

    if (bpf_probe_read_kernel(&actual, sizeof(actual),
            (void *)(*table_p + (__u64)nr * sizeof(void *))))
        return 0;

    if (actual != *exp_p) {
        a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
        if (a) {
            a->nr = nr;
            a->pid = bpf_get_current_pid_tgid() >> 32;
            a->actual = actual;
            a->expected = *exp_p;
            a->ts = bpf_ktime_get_ns();
            bpf_ringbuf_submit(a, 0);
        }
    }
    return 0;
}
