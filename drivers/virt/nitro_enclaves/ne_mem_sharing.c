// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * NIE Guest.Share / Guest.Unshare HVC backend.
 */

#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/sizes.h>

#include "ne_mem_sharing.h"
#include "ne_misc_dev.h"

/* NIE HVC expects 2 MiB aligned base and size for optimal operation.
 * Sub-2 MiB requests are not rejected but may trigger a warning. */
#define NIE_SHARE_ALIGNMENT	SZ_2M

#ifdef CONFIG_ARM64

#include <linux/arm-smccc.h>

/* HVC function IDs for guest-initiated NIE sharing. */
#define NIE_GUEST_SHARE_FN_ID		0xC600816E
#define NIE_GUEST_UNSHARE_FN_ID		0xC6008170

static_assert(NIE_SHARE_ALIGNMENT >= SZ_2M,
	      "NIE Guest.Share/Unshare expect at least 2 MiB alignment");

static int nie_share(struct ne_enclave *enc, phys_addr_t gpa,
		     size_t size, u64 flags, u64 perms, u64 smid)
{
	struct arm_smccc_res res;

	if (!IS_ALIGNED(gpa, NIE_SHARE_ALIGNMENT) ||
	    !IS_ALIGNED(size, NIE_SHARE_ALIGNMENT))
		pr_warn_ratelimited("ne: Guest.Share: misaligned gpa=0x%llx size=0x%zx\n",
				    (u64)gpa, size);

	arm_smccc_1_1_hvc(NIE_GUEST_SHARE_FN_ID, gpa, size, flags, perms,
			  smid, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_err("ne: Guest.Share failed: gpa=0x%llx size=0x%zx flags=0x%llx perms=0x%llx smid=0x%llx rc=%ld\n",
		       (u64)gpa, size, flags, perms, smid, (long)res.a0);
		return -EIO;
	}

	return 0;
}

static int nie_unshare(struct ne_enclave *enc, phys_addr_t gpa, size_t size)
{
	struct arm_smccc_res res;

	if (!IS_ALIGNED(gpa, NIE_SHARE_ALIGNMENT) ||
	    !IS_ALIGNED(size, NIE_SHARE_ALIGNMENT))
		pr_warn_ratelimited("ne: Guest.Unshare: misaligned gpa=0x%llx size=0x%zx\n",
				    (u64)gpa, size);

	arm_smccc_1_1_hvc(NIE_GUEST_UNSHARE_FN_ID, gpa, size, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_err("ne: Guest.Unshare failed: gpa=0x%llx size=0x%zx rc=%ld\n",
		       (u64)gpa, size, (long)res.a0);
		return -EIO;
	}

	return 0;
}

static const struct ne_mem_sharing_ops nie_ops = {
	.share   = nie_share,
	.unshare = nie_unshare,
};

#else /* !CONFIG_ARM64 */

/* Non-arm64: no-op backend that validates 2 MiB alignment. */

static int noop_share(struct ne_enclave *enc, phys_addr_t gpa,
		      size_t size, u64 flags, u64 perms, u64 smid)
{
	if (!IS_ALIGNED(gpa, NIE_SHARE_ALIGNMENT) ||
	    !IS_ALIGNED(size, NIE_SHARE_ALIGNMENT))
		pr_warn_ratelimited("ne: share noop: misaligned gpa=0x%llx size=0x%zx\n",
				    (u64)gpa, size);
	return 0;
}

static int noop_unshare(struct ne_enclave *enc, phys_addr_t gpa, size_t size)
{
	if (!IS_ALIGNED(gpa, NIE_SHARE_ALIGNMENT) ||
	    !IS_ALIGNED(size, NIE_SHARE_ALIGNMENT))
		pr_warn_ratelimited("ne: unshare noop: misaligned gpa=0x%llx size=0x%zx\n",
				    (u64)gpa, size);
	return 0;
}

static const struct ne_mem_sharing_ops noop_ops = {
	.share   = noop_share,
	.unshare = noop_unshare,
};

#endif /* CONFIG_ARM64 */

const struct ne_mem_sharing_ops *ne_init_mem_sharing(struct ne_pci_dev *ne_pci_dev)
{
	if (ne_pci_dev->nie_enabled) {
#ifdef CONFIG_ARM64
		return &nie_ops;
#else
		return &noop_ops;
#endif
	}
	return NULL;
}
