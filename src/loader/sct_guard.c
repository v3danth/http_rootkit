// SPDX-License-Identifier: GPL-2.0
/* sct_guard — userspace monitor for syscall table integrity.
 *
 * Layers implemented here (spec v2.0 §9.1, F-32/F-34):
 *   1. Trusted anchor: System.map-$(uname -r) (on-disk, link-time
 *      addresses) + syscall_64.tbl -> expected handler per nr.
 *      NOT runtime /proc/kallsyms, which is attacker-tamperable.
 *   2. KASLR slide derived from one anchor symbol; validated 2 MiB
 *      aligned (CONFIG_PHYSICAL_ALIGN) and re-validated against every
 *      baseline symbol — a wrong System.map or tampered kallsyms is
 *      caught, not silently trusted.
 *   3. Kallsyms consistency: hidden symbols and name<->addr
 *      substitution are themselves IOCs (F-34).
 *   4. Full table scans via /proc/kcore (root, read-only) — no kernel
 *      module needed, catches diffs the 1/4096 sampler may miss.
 *   5. eBPF sampler attach + ringbuf polling.
 *
 * Requires root (kallsyms with real addresses, BPF, kcore).
 * x86_64 only (matches the spec's lab target, 5.15-era kernel).
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "baseline.h"
#include "sct_detect.skel.h"

#define ANCHOR_DEFAULT "_text"
#define RECHECK_TICKS  30          /* seconds between full rechecks */

struct bl {
    unsigned     nr;
    char         name[96];
    unsigned long abs;             /* System.map link-time address */
    unsigned long expected;        /* abs + slide (anchor-derived) */
};

static struct bl bl_tab[SCTG_MAX_NR];
static int bl_n;
static unsigned long anchor_abs, anchor_live, slide, sct_addr;
static char anchor_name[96] = ANCHOR_DEFAULT;

static struct sct_detect_bpf *skel;
static struct ring_buffer *rb;
static struct bpf_link *tp_link;
static volatile sig_atomic_t exiting;
static int selftest_hit;

/* ---- tiny helpers ---- */

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static void ioc(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("IOC: ");
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

/* ---- baseline file ---- */

static void load_baseline(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];

    if (!f)
        die("open baseline %s: %m", path);

    while (fgets(line, sizeof line, f)) {
        char name[96];
        unsigned long a;
        unsigned nr;

        if (line[0] == '#') {
            char an[96];
            if (sscanf(line, "# anchor %95s %lx", an, &a) == 2) {
                snprintf(anchor_name, sizeof anchor_name, "%s", an);
                anchor_abs = a;
            }
            continue;
        }
        if (sscanf(line, "%u %95s %lx", &nr, name, &a) == 3 &&
            bl_n < SCTG_MAX_NR) {
            bl_tab[bl_n].nr = nr;
            snprintf(bl_tab[bl_n].name, sizeof bl_tab[0].name, "%s", name);
            bl_tab[bl_n].abs = a;
            bl_n++;
        }
    }
    fclose(f);
    if (!bl_n || !anchor_abs)
        die("baseline %s malformed (need '# anchor' line and nr sym addr lines)", path);
}

/* ---- kallsyms parse (wanted-symbol extraction only) ---- */

struct ref {
    char         name[96];
    unsigned long addr;
    int          found;
};

static struct ref *refs;
static int refs_n;

static int ref_cmp(const void *a, const void *b)
{
    return strcmp(((const struct ref *)a)->name, ((const struct ref *)b)->name);
}

static struct ref *find_ref(const char *name)
{
    struct ref key = {{0}};
    snprintf(key.name, sizeof key.name, "%s", name);
    return bsearch(&key, refs, refs_n, sizeof *refs, ref_cmp);
}

static void build_refs(void)
{
    int i;

    refs_n = bl_n + 2;
    refs = realloc(refs, refs_n * sizeof *refs);
    if (!refs)
        die("realloc");
    memset(refs, 0, refs_n * sizeof *refs);
    snprintf(refs[0].name, sizeof refs[0].name, "sys_call_table");
    snprintf(refs[1].name, sizeof refs[1].name, "%s", anchor_name);
    for (i = 0; i < bl_n; i++)
        snprintf(refs[i + 2].name, sizeof refs[0].name, "%s", bl_tab[i].name);
    qsort(refs, refs_n, sizeof *refs, ref_cmp);
}

static void parse_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[1024], name[256], type[8];
    unsigned long a;
    int zero_seen = 0, i;

    if (!f)
        die("open /proc/kallsyms: %m");

    for (i = 0; i < refs_n; i++) {          /* reset for recheck passes */
        refs[i].addr = 0;
        refs[i].found = 0;
    }

    while (fgets(line, sizeof line, f)) {
        struct ref *r;
        struct ref key = {{0}};

        if (sscanf(line, "%lx %7s %255s", &a, type, name) != 3)
            continue;
        if (!a)
            zero_seen = 1;
        snprintf(key.name, sizeof key.name, "%s", name);
        r = bsearch(&key, refs, refs_n, sizeof *refs, ref_cmp);
        if (r) {
            r->addr = a;
            r->found = 1;
        }
    }
    fclose(f);

    if (zero_seen) {
        struct ref *r = find_ref("sys_call_table");
        if (!r || !r->found || !r->addr)
            die("kallsyms shows zero addresses: run as root with "
                "CAP_SYSLOG, or set kernel.kptr_restrict=0");
    }
}

/* ---- slide computation + per-symbol consistency (F-32/F-34) ---- */

static void compute_slide(void)
{
    struct ref *r = find_ref(anchor_name);

    if (!r || !r->found || !r->addr)
        die("anchor %s not visible in /proc/kallsyms "
            "(hiding IOC, or wrong System.map)", anchor_name);

    anchor_live = r->addr;
    slide = anchor_live - anchor_abs;

    /* KASLR slide is 2 MiB-aligned on x86_64. A misaligned slide means
     * the System.map does not describe the running kernel. */
    if (slide & 0x1fffffUL)
        die("slide 0x%lx not 2MiB-aligned: System.map/kernel mismatch", slide);
}

static void verify_entries(void)
{
    int i;

    for (i = 0; i < bl_n; i++) {
        struct ref *r = find_ref(bl_tab[i].name);

        if (!r || !r->found) {
            ioc("symbol %s absent from kallsyms (hiding)", bl_tab[i].name);
            bl_tab[i].expected = bl_tab[i].abs + slide;
        } else if (r->addr != bl_tab[i].abs + slide) {
            /* Live kallsyms disagrees with the anchor: either a
             * substituted address (F-34) or a wrong map. Anchor wins. */
            ioc("kallsyms mismatch %s: live=0x%lx anchor=0x%lx",
                bl_tab[i].name, r->addr, bl_tab[i].abs + slide);
            bl_tab[i].expected = bl_tab[i].abs + slide;
        } else {
            bl_tab[i].expected = r->addr;
        }
    }
}

/* ---- full table scan via /proc/kcore (read-only, no module needed) ---- */

static int kcore_full_scan(int verbose)
{
    int fd, i, bad = 0;
    Elf64_Ehdr eh;
    Elf64_Phdr *ph = NULL;
    unsigned long maxnr = 0, span;
    uint64_t *tab = NULL;
    int covered = 0;

    for (i = 0; i < bl_n; i++)
        if (bl_tab[i].nr > maxnr)
            maxnr = bl_tab[i].nr;
    span = (maxnr + 1) * sizeof(uint64_t);

    fd = open("/proc/kcore", O_RDONLY);
    if (fd < 0) {
        if (verbose)
            printf("note: /proc/kcore unavailable (%m) — "
                   "userspace full scans disabled, relying on BPF/module\n");
        return -1;
    }
    if (read(fd, &eh, sizeof eh) != sizeof eh)
        goto out;
    ph = calloc(eh.e_phnum, sizeof *ph);
    tab = malloc(span);
    if (!ph || !tab)
        goto out;
    if (pread(fd, ph, eh.e_phnum * sizeof *ph, eh.e_phoff) !=
        (ssize_t)(eh.e_phnum * sizeof *ph))
        goto out;

    for (i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        if (sct_addr >= ph[i].p_vaddr &&
            sct_addr + span <= ph[i].p_vaddr + ph[i].p_filesz) {
            off_t off = ph[i].p_offset + (off_t)(sct_addr - ph[i].p_vaddr);
            if (pread(fd, tab, span, off) == (ssize_t)span)
                covered = 1;
            break;
        }
    }
    if (!covered) {
        if (verbose)
            printf("note: kcore has no PT_LOAD covering the table\n");
        bad = -2;
        goto out;
    }

    for (i = 0; i < bl_n; i++) {
        uint64_t actual = tab[bl_tab[i].nr];
        if (actual != bl_tab[i].expected) {
            bad++;
            printf("ALERT (full scan): syscall %u handler=0x%llx "
                   "expected=0x%llx\n",
                   bl_tab[i].nr,
                   (unsigned long long)actual,
                   (unsigned long long)bl_tab[i].expected);
        }
    }
    if (!bad && verbose)
        printf("full scan clean (%d entries)\n", bl_n);
out:
    free(ph);
    free(tab);
    close(fd);
    return bad;
}

/* ---- eBPF wiring ---- */

static int on_alert(void *ctx, void *data, size_t size)
{
    struct alert { uint32_t nr, pid; uint64_t actual, expected, ts; } *a = data;

    printf("ALERT (sampler): syscall=%u pid=%u actual=0x%llx expected=0x%llx\n",
           a->nr, a->pid,
           (unsigned long long)a->actual,
           (unsigned long long)a->expected);
    if (a->nr == (uint32_t)SYS_getpid)
        selftest_hit = 1;
    return 0;
}

static void populate_maps(void)
{
    int sct_fd = bpf_map__fd(skel->maps.sct_addr);
    int exp_fd = bpf_map__fd(skel->maps.expected_map);
    uint32_t zero = 0, nr;
    uint64_t v = sct_addr;
    int i;

    if (bpf_map_update_elem(sct_fd, &zero, &v, BPF_ANY))
        die("update sct_addr map: %m");
    for (i = 0; i < bl_n; i++) {
        nr = bl_tab[i].nr;
        v = bl_tab[i].expected;
        if (bpf_map_update_elem(exp_fd, &nr, &v, BPF_ANY))
            die("update expected_map: %m");
    }
}

/* ---- handoff to the kernel monitor module (optional) ---- */

static void handoff_module(void)
{
    const char *path = "/sys/kernel/debug/sctguard/baseline";
    size_t sz = sizeof(struct sctg_hdr) + sizeof(struct sctg_entry) * bl_n;
    struct sctg_hdr *h;
    struct sctg_entry *e;
    void *blob = malloc(sz);
    int fd, i;

    if (!blob)
        return;
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        printf("note: sct_monitor module not loaded — BPF-only mode\n");
        free(blob);
        return;
    }
    h = blob;
    h->magic = SCTG_MAGIC;
    h->count = bl_n;
    h->sct_addr = sct_addr;
    e = blob + sizeof(*h);
    for (i = 0; i < bl_n; i++) {
        e[i].nr = bl_tab[i].nr;
        e[i].reserved = 0;
        e[i].expected = bl_tab[i].expected;   /* anchor-derived truth */
    }
    if (write(fd, blob, sz) != (ssize_t)sz)
        fprintf(stderr, "warn: module handoff write failed: %m\n");
    else
        printf("kernel monitor armed (%d entries)\n", bl_n);
    close(fd);
    free(blob);
}

/* ---- periodic recheck: kallsyms drift + full rescan ---- */

static void recheck(void)
{
    parse_kallsyms();

    {
        struct ref *r = find_ref(anchor_name);
        if (!r || !r->found || r->addr != anchor_live)
            ioc("CRITICAL: kallsyms anchor %s moved/hidden "
                "(was 0x%lx)", anchor_name, anchor_live);
    }
    {
        struct ref *r = find_ref("sys_call_table");
        if (!r || !r->found || !r->addr)
            ioc("sys_call_table symbol hidden from kallsyms");
        else if (r->addr != sct_addr)
            ioc("sys_call_table symbol retargeted: 0x%lx -> 0x%lx",
                sct_addr, r->addr);
    }
    verify_entries();
    kcore_full_scan(0);
}

/* ---- selftest: corrupt EXPECTED data (never the table) and prove
 *      the detector fires. The kernel-side scans remain clean —
 *      only the BPF comparison data is wrong.                    ---- */

static int do_selftest(void)
{
    int exp_fd = bpf_map__fd(skel->maps.expected_map);
    uint32_t nr = (uint32_t)SYS_getpid;
    uint64_t wrong = 0xdeadbeefdeadbeefULL;
    int round, i;

    printf("selftest: corrupting expected handler for getpid (nr %u)\n", nr);
    if (bpf_map_update_elem(exp_fd, &nr, &wrong, BPF_ANY))
        die("selftest map update: %m");

    for (round = 0; round < 400 && !selftest_hit && !exiting; round++) {
        ring_buffer__poll(rb, 25);
        for (i = 0; i < 100000; i++)     /* ~40M sampled syscalls max */
            syscall(SYS_getpid);
    }
    if (selftest_hit) {
        printf("SELFTEST PASS: detection pipeline fired end-to-end\n");
        return 0;
    }
    printf("SELFTEST FAIL: no alert after 40M syscalls\n");
    return 1;
}

static void on_sigint(int sig) { exiting = 1; }

static void usage(int code)
{
    fprintf(stderr,
        "usage: sct_guard [-b baseline.txt] [--selftest] [--no-module]\n"
        "  -b FILE       baseline file (default build/baseline.txt)\n"
        "  --selftest    inject a wrong expected value and verify alerting\n"
        "  --no-module   skip sct_monitor handoff\n");
    exit(code);
}

int main(int argc, char **argv)
{
    const char *bfile = "build/baseline.txt";
    int selftest = 0, use_module = 1, i, tick = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b") && i + 1 < argc) bfile = argv[++i];
        else if (!strcmp(argv[i], "--selftest"))    selftest = 1;
        else if (!strcmp(argv[i], "--no-module"))   use_module = 0;
        else if (!strcmp(argv[i], "-h"))            usage(0);
        else                                        usage(1);
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    load_baseline(bfile);
    build_refs();
    parse_kallsyms();
    compute_slide();
    verify_entries();

    {
        struct ref *r = find_ref("sys_call_table");
        if (!r || !r->found || !r->addr)
            die("sys_call_table not resolvable in kallsyms");
        sct_addr = r->addr;
    }
    printf("monitoring: sct=0x%lx slide=0x%lx entries=%d\n",
           sct_addr, slide, bl_n);

    kcore_full_scan(1);                    /* immediate full scan */

    skel = sct_detect_bpf__open_and_load();
    if (!skel)
        die("BPF open/load failed");
    populate_maps();

    rb = ring_buffer__new(bpf_map__fd(skel->maps.alerts),
                          on_alert, NULL, NULL);
    if (!rb)
        die("ringbuf create failed");

    tp_link = bpf_program__attach_raw_tracepoint(
        skel->progs.sys_enter, "sys_enter");
    if (!tp_link)
        die("attach raw_tp/sys_enter failed");

    if (use_module)
        handoff_module();

    if (selftest) {
        int rc = do_selftest();
        bpf_link__destroy(tp_link);
        ring_buffer__free(rb);
        sct_detect_bpf__destroy(skel);
        return rc;
    }

    while (!exiting) {
        ring_buffer__poll(rb, 1000);
        if (++tick >= RECHECK_TICKS) {
            tick = 0;
            recheck();
        }
    }

    printf("\nshutting down\n");
    bpf_link__destroy(tp_link);
    ring_buffer__free(rb);
    sct_detect_bpf__destroy(skel);
    free(refs);
    return 0;
}
