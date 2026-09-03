/* SPDX-License-Identifier: GPL-2.0 */
/* ABI shared between the userspace loader and the sct_monitor module.*/
/* Natural alignment, byte-identical layout on both sides. */

#ifndef SCTG_BASELINE_H
#define SCTG_BASELINE_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  define SCTG_U32 __u32
#  define SCTG_U64 __u64
#else
#  include <stdint.h>
#  define SCTG_U32 uint32_t
#  define SCTG_U64 uint64_t
#endif

#define SCTG_MAGIC   0x53435447u   /* "SCTG" */
#define SCTG_MAX_NR  512

struct sctg_hdr {
    SCTG_U32 magic;
    SCTG_U32 count;
    SCTG_U64 sct_addr;    /* live (post-KASLR) sys_call_table address */
};

struct sctg_entry {
    SCTG_U32 nr;
    SCTG_U32 reserved;    /* must be 0 */
    SCTG_U64 expected;    /* anchor-derived, KASLR-adjusted handler */
};

#endif /* SCTG_BASELINE_H */
