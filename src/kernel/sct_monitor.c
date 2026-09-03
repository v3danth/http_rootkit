// SPDX-License-Identifier: GPL-2.0
/*
 * sct_monitor — read-only syscall table integrity monitor (spec §10.2).
 *
 *   - periodic FULL scan of sys_call_table[] against the baseline handed
 *     in by the loader (trusted-anchor derived; F-32)
 *   - CR0.WP sampling (F-30: kprobing write_cr0 cannot see inline-asm
 *     CR0 writes, so we poll instead — per-CPU sampling, honest caveat)
 *   - watches for third-party kprobe registrations on
 *     kallsyms_lookup_name (the >=5.7 resolution trick; F-02 / §11.1)
 *
 * Deliberately does NOT: write the table, write CR0, resolve symbols
 * (the SCT address arrives from the loader), hide anything.
 *
 * The SCT address is root-provided input; table reads go through
 * copy_from_kernel_nofault() so a bad address alerts instead of oopsing.
 */

#define pr_fmt(fmt) "sctguard: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <asm/special_insns.h>
#include <asm/processor.h>

#include "baseline.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#  define sctg_kread copy_from_kernel_nofault
#else
#  define sctg_kread probe_kernel_read
#endif

static int scan_interval = 30;              /* seconds */
module_param(scan_interval, int, 0644);
MODULE_PARM_DESC(scan_interval, "seconds between full table scans");

static DEFINE_MUTEX(state_lock);
static DEFINE_SPINLOCK(alert_lock);

static struct dentry *sctg_dir;
static struct sctg_hdr hdr;
static struct sctg_entry *entries;
static bool armed;
static struct task_struct *mon;

static atomic64_t n_scans, n_mismatch, n_kln_kprobe, n_cr0_bad;
static char last_alert[128];

static void record_alert(const char *fmt, ...)
{
    unsigned long flags;
    va_list ap;

    spin_lock_irqsave(&alert_lock, flags);
    va_start(ap, fmt);
    vsnprintf(last_alert, sizeof(last_alert), fmt, ap);
    va_end(ap);
    spin_unlock_irqrestore(&alert_lock, flags);
}

/* ---- CR0.WP sampling (F-30) ---- */

static void cr0_check(void)
{
    if (!(native_read_cr0() & X86_CR0_WP)) {
        atomic64_inc(&n_cr0_bad);
        record_alert("CR0.WP cleared (cpu=%d)", task_cpu(current));
        pr_emerg_ratelimited("CR0.WP CLEARED — write-protection bypass "
                             "in progress on cpu %d\n", task_cpu(current));
    }
}

/* ---- full table scan ---- */

static void do_scan(void)
{
    int i;

    atomic64_inc(&n_scans);
    for (i = 0; i < hdr.count; i++) {
        unsigned long actual = 0;
        const void *slot = (const void __force *)
            (hdr.sct_addr + (u64)entries[i].nr * sizeof(void *));

        if (sctg_kread(&actual, slot, sizeof(actual))) {
            atomic64_inc(&n_mismatch);
            record_alert("nr=%u READ FAULT at slot", entries[i].nr);
            pr_emerg_ratelimited("read fault at slot nr=%u "
                                 "(bad sct_addr?)\n", entries[i].nr);
            continue;
        }
        if (actual != (unsigned long)entries[i].expected) {
            atomic64_inc(&n_mismatch);
            record_alert("nr=%u actual=%px expected=%px",
                         entries[i].nr, (void *)actual,
                         (void *)(unsigned long)entries[i].expected);
            pr_emerg_ratelimited("SYSCALL TABLE MISMATCH: %s\n",
                                 last_alert);
        }
    }
}

/* ---- kprobe-registration watch (F-02 IOC) ---- */

static int regk_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct kprobe *incoming = (struct kprobe *)regs->di;

    /* register_kprobe(p): arg1 is the kprobe being registered.
     * Callers pass initialized structs by contract; keep the sanity
     * check anyway. Handler runs in atomic context: no sleeping here. */
    if ((unsigned long)incoming < PAGE_OFFSET)
        return 0;
    if (incoming->symbol_name &&
        !strncmp(incoming->symbol_name, "kallsyms_lookup_name",
                 KSYM_NAME_LEN)) {
        atomic64_inc(&n_kln_kprobe);
        record_alert("kprobe on kallsyms_lookup_name pid=%d comm=%s",
                     task_pid_nr(current), current->comm);
        pr_warn_ratelimited("kprobe registered on kallsyms_lookup_name "
                            "by pid %d (%s) — IOC\n",
                            task_pid_nr(current), current->comm);
    }
    return 0;
}

static struct kprobe regk_kp = {
    .symbol_name = "register_kprobe",
    .pre_handler = regk_pre,
};

/* ---- monitor thread ---- */

static int mon_thread(void *unused)
{
    unsigned long next = jiffies + HZ * (unsigned long)scan_interval;

    while (!kthread_should_stop()) {
        cr0_check();                        /* every second */
        if (armed && time_after_eq(jiffies, next)) {
            mutex_lock(&state_lock);
            if (armed)
                do_scan();
            mutex_unlock(&state_lock);
            next = jiffies + HZ * (unsigned long)scan_interval;
        }
        schedule_timeout_interruptible(HZ);
    }
    return 0;
}

/* ---- debugfs interface ---- */

static ssize_t baseline_write(struct file *f, const char __user *buf,
                              size_t len, loff_t *off)
{
    struct sctg_hdr h;
    struct sctg_entry *e;
    size_t need;
    int i;

    if (len < sizeof(h))
        return -EINVAL;
    if (copy_from_user(&h, buf, sizeof(h)))
        return -EFAULT;
    if (h.magic != SCTG_MAGIC || !h.count || h.count > SCTG_MAX_NR)
        return -EINVAL;
    need = sizeof(h) + (size_t)h.count * sizeof(*e);
    if (len < need)
        return -EINVAL;
    if ((unsigned long)h.sct_addr < PAGE_OFFSET)
        return -EINVAL;

    e = kmalloc_array(h.count, sizeof(*e), GFP_KERNEL);
    if (!e)
        return -ENOMEM;
    if (copy_from_user(e, buf + sizeof(h),
                       (size_t)h.count * sizeof(*e))) {
        kfree(e);
        return -EFAULT;
    }
    for (i = 0; i < h.count; i++) {
        if (e[i].nr >= SCTG_MAX_NR || e[i].reserved) {
            kfree(e);
            return -EINVAL;
        }
    }

    mutex_lock(&state_lock);
    kfree(entries);
    entries = e;
    hdr = h;
    armed = true;
    do_scan();                              /* immediate first scan */
    mutex_unlock(&state_lock);

    pr_info("armed with %u entries, table=%px\n", h.count,
            (void *)(unsigned long)h.sct_addr);
    return len;
}

static ssize_t scan_write(struct file *f, const char __user *buf,
                          size_t len, loff_t *off)
{
    mutex_lock(&state_lock);
    if (armed)
        do_scan();
    mutex_unlock(&state_lock);
    return len;
}

static int status_show(struct seq_file *m, void *v)
{
    seq_printf(m, "armed:                 %d\n", armed);
    seq_printf(m, "sct_addr:              %px\n",
               (void *)(unsigned long)hdr.sct_addr);
    seq_printf(m, "entries:               %u\n", hdr.count);
    seq_printf(m, "scans:                 %lld\n",
               (long long)atomic64_read(&n_scans));
    seq_printf(m, "mismatches:            %lld\n",
               (long long)atomic64_read(&n_mismatch));
    seq_printf(m, "kallsyms_lookup kprobes: %lld\n",
               (long long)atomic64_read(&n_kln_kprobe));
    seq_printf(m, "cr0_bad:               %lld\n",
               (long long)atomic64_read(&n_cr0_bad));
    seq_printf(m, "last_alert:            %s\n", last_alert);
    return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
    return single_open(file, status_show, NULL);
}

static const struct file_operations baseline_fops = {
    .owner  = THIS_MODULE,
    .write  = baseline_write,
};

static const struct file_operations scan_fops = {
    .owner  = THIS_MODULE,
    .write  = scan_write,
};

static const struct file_operations status_fops = {
    .owner   = THIS_MODULE,
    .open    = status_open,
    .read    = seq_read,
    .release = single_release,
};

/* ---- module lifecycle ---- */

static int __init sctg_init(void)
{
    int ret;

    sctg_dir = debugfs_create_dir("sctguard", NULL);
    if (IS_ERR(sctg_dir) || !sctg_dir)
        return sctg_dir ? PTR_ERR(sctg_dir) : -ENODEV;

    debugfs_create_file("baseline", 0200, sctg_dir, NULL, &baseline_fops);
    debugfs_create_file("status",   0400, sctg_dir, NULL, &status_fops);
    debugfs_create_file("scan",     0200, sctg_dir, NULL, &scan_fops);

    ret = register_kprobe(&regk_kp);
    if (ret)
        pr_warn("register_kprobe watch unavailable (%d); "
                "continuing without it\n", ret);

    mon = kthread_run(mon_thread, NULL, "sctguard");
    if (IS_ERR(mon)) {
        ret = PTR_ERR(mon);
        unregister_kprobe(&regk_kp);
        debugfs_remove_recursive(sctg_dir);
        return ret;
    }

    pr_info("loaded (scan_interval=%ds)\n", scan_interval);
    return 0;
}

static void __exit sctg_exit(void)
{
    kthread_stop(mon);
    unregister_kprobe(&regk_kp);
    debugfs_remove_recursive(sctg_dir);
    mutex_lock(&state_lock);
    kfree(entries);
    entries = NULL;
    armed = false;
    mutex_unlock(&state_lock);
    pr_info("unloaded\n");
}

module_init(sctg_init);
module_exit(sctg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only syscall table integrity monitor (detection)");
MODULE_AUTHOR("sct-guard");
