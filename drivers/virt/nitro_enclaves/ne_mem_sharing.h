/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * NIE Guest.Share / Guest.Unshare interface for enclave memory sharing.
 */

#ifndef _NE_MEM_SHARING_H
#define _NE_MEM_SHARING_H

#include <linux/bits.h>
#include <linux/types.h>

struct ne_enclave;
struct ne_pci_dev;

/* Permission encoding (2 bits, matches NIE HVC). */
#define NE_PERM_NOACCESS	0
#define NE_PERM_RO		1
#define NE_PERM_WO		2
#define NE_PERM_RW		3

/* Guest.Share flags (X3). */
#define NE_SHARE_HYP		BIT(0)
#define NE_SHARE_VM		BIT(1)
/*
 * Consent to the host hypervisor taking the range away. This grants nobody
 * access, so it is not a kind of sharing and is orthogonal to the two intents
 * above: on its own NIE maps nothing and leaves the page state alone, and the
 * range stays ours to use until the secure monitor actually withdraws it.
 *
 * Combining it with NE_SHARE_HYP and/or NE_SHARE_VM is meaningful and is what a
 * range we both share and expect to lose must ask for: the range is mapped and
 * retagged exactly as those bits say, and stays usable until the withdrawal.
 * NIE requires this flag for that withdrawal: sharing read-write says nothing
 * about consenting to lose the range, so consent has to be stated rather than
 * inferred from a combination of NE_SHARE_* bits.
 *
 * The parent permission must be NE_PERM_RW, the access we in fact keep: a
 * DONATE leaves our stage 2 untouched, so a narrower value would record a
 * restriction that is never applied.
 */
#define NE_SHARE_DONATE		BIT(4)

/**
 * ne_share_perms_pack() - Pack parent/hyp/target perms into one u64.
 * bits[0:1] parent, bits[2:3] hyp, bits[4:5] target.
 */
static inline u64 ne_share_perms_pack(u8 parent, u8 hyp, u8 target)
{
	return ((u64)parent & 3) |
	       (((u64)hyp & 3) << 2) |
	       (((u64)target & 3) << 4);
}

/**
 * struct ne_mem_sharing_ops - NIE memory sharing operations.
 * @share:   Guest.Share, make region visible to hypervisor/enclave.
 * @unshare: Guest.Unshare, revoke sharing after teardown.
 */
struct ne_mem_sharing_ops {
	int (*share)(struct ne_enclave *enc, phys_addr_t gpa, size_t size,
		     u64 flags, u64 perms, u64 smid);
	int (*unshare)(struct ne_enclave *enc, phys_addr_t gpa, size_t size);
};

/**
 * ne_init_mem_sharing() - Return the NIE sharing ops if NIE is active.
 * @ne_pci_dev: PCI device with nie_enabled read at probe.
 *
 * Returns the NIE ops on arm64 when nie_enabled, NULL otherwise.
 */
const struct ne_mem_sharing_ops *ne_init_mem_sharing(struct ne_pci_dev *ne_pci_dev);

#endif /* _NE_MEM_SHARING_H */
