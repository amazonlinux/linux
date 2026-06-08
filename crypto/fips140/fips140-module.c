// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Kernel Cryptographic Module
 *
 * This file is the module entry point for fips140.ko, which is linked with previously built-in cryptos
 * to generate the fips140.ko module.
 * At load time, this module plugs the previously built-in implementations contained within itself back to the kernel.
 * It also runs self-tests on these algorithms and verifies the integrity of its code and data.
 * If either of these steps fails, the kernel will panic.
 */

#include "fips140-module.h"

#define FIPS140_MODULE_NAME "FIPS 140 Kernel Cryptographic Module"
#define FIPS140_MODULE_VERSION "1.0.0"

#define CRYPTO_INTERNAL "CRYPTO_INTERNAL"

static const u8 fips140_integ_hmac_key[] = CONFIG_CRYPTO_FIPS140_HMAC_KEY;

static int verify_integrity(void)
{
	extern const u8 *_binary_crypto_ko_start;
	extern const u8 *_binary_crypto_ko_end;
	extern const u8 *_binary_crypto_hmac_start;
	
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	u8 digest[SHA256_DIGEST_SIZE];
	int err;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		panic("FIPS 140: failed to allocate hmac tfm (%ld)\n", PTR_ERR(tfm));

	desc->tfm = tfm;

	err = crypto_shash_setkey(tfm, fips140_integ_hmac_key, sizeof(fips140_integ_hmac_key) - 1);
	if (err)
		panic("FIPS 140: crypto_shash_setkey() failed: %d\n", err);

	err = crypto_shash_init(desc);
	if (err)
		panic("FIPS 140: crypto_shash_init() failed: %d\n", err);

	err = crypto_shash_update(desc, _binary_crypto_ko_start, _binary_crypto_ko_end - _binary_crypto_ko_start);
	if (err)
		panic("FIPS 140: crypto_shash_update() failed: %d\n", err);

	err = crypto_shash_final(desc, digest);
	if (err)
		panic("FIPS 140: crypto_shash_final() failed: %d\n", err);

	shash_desc_zero(desc);

	if (memcmp(digest, _binary_crypto_hmac_start, sizeof(digest))) {
		memzero_explicit(digest, sizeof(digest));
		panic("FIPS 140: failed integrity check\n");
	}

	pr_info("FIPS 140: integrity verification passed\n");

	crypto_free_shash(tfm);
	memzero_explicit(digest, sizeof(digest));

	return 0;
}

/*
 * Run FIPS module initcalls level by level, synchronizing with the
 * kernel's initcall progression.
 *
 * At each level, the FIPS module runs first (via linker-section barriers
 * in the kernel), then the kernel's initcalls run. This ensures crypto
 * algorithms are registered and tested before kernel code uses them.
 *
 * Sections use kernel initcall level numbers directly:
 *   Level 4 (.fips_initcall4/4s) <- subsys_initcall / subsys_initcall_sync
 *   Level 5 (.fips_initcall5/5s) <- fs_initcall / fs_initcall_sync / rootfs_initcall
 *   Level 6 (.fips_initcall6/6s) <- module_init / device_initcall / device_initcall_sync
 *   Level 7 (.fips_initcall7/7s) <- late_initcall / late_initcall_sync
 */

#define FIPS_LOADER_LEVEL 3
#define FIPS_FIRST_LEVEL 4
#define FIPS_LAST_LEVEL  7
#define FIPS_ROOTFS_LEVEL 0
#define FIPS_NUM_LEVELS  (FIPS_LAST_LEVEL - FIPS_FIRST_LEVEL + 1)

static int __init run_initcalls(void)
{
	typedef int (*initcall_t)(void);

	extern initcall_t __fips140_initcall4_start[], __fips140_initcall4_end[];
	extern initcall_t __fips140_initcall4s_start[], __fips140_initcall4s_end[];
	extern initcall_t __fips140_initcall5_start[], __fips140_initcall5_end[];
	extern initcall_t __fips140_initcall5s_start[], __fips140_initcall5s_end[];
	extern initcall_t __fips140_initcall_rootfs_start[], __fips140_initcall_rootfs_end[];
	extern initcall_t __fips140_initcall6_start[], __fips140_initcall6_end[];
	extern initcall_t __fips140_initcall6s_start[], __fips140_initcall6s_end[];
	extern initcall_t __fips140_initcall7_start[], __fips140_initcall7_end[];
	extern initcall_t __fips140_initcall7s_start[], __fips140_initcall7s_end[];

	struct {
		initcall_t *start, *end;
		initcall_t *sync_start, *sync_end;
	} levels[FIPS_NUM_LEVELS] = {
		[0] = { __fips140_initcall4_start, __fips140_initcall4_end,
			__fips140_initcall4s_start, __fips140_initcall4s_end },
		[1] = { __fips140_initcall5_start, __fips140_initcall5_end,
			__fips140_initcall5s_start, __fips140_initcall5s_end },
		[2] = { __fips140_initcall6_start, __fips140_initcall6_end,
			__fips140_initcall6s_start, __fips140_initcall6s_end },
		[3] = { __fips140_initcall7_start, __fips140_initcall7_end,
			__fips140_initcall7s_start, __fips140_initcall7s_end },
	};

	pr_info("FIPS 140: run_initcalls starting\n");

	for (int i = 0; i < FIPS_NUM_LEVELS; i++) {
		int level = FIPS_FIRST_LEVEL + i;
		initcall_t *fn;

		/* Run non-sync initcalls */
		for (fn = levels[i].start; fn < levels[i].end; fn++) {
			int ret = (*fn)();
			if (ret && ret != -ENODEV)
				pr_err("FIPS 140: initcall %pS failed: %d\n", *fn, ret);
		}

		fips140_mark_module_wait_kernel(level);

		/* Run _sync initcalls */
		for (fn = levels[i].sync_start; fn < levels[i].sync_end; fn++) {
			int ret = (*fn)();
			if (ret && ret != -ENODEV)
				pr_err("FIPS 140: initcall_sync %pS failed: %d\n", *fn, ret);
		}

		if (level < FIPS_LAST_LEVEL)
			fips140_mark_module_wait_kernel_sync(level);

		/* Run rootfs initcalls after level 5 sync (gated by rootfs barrier) */
		if (level == 5) {
			for (fn = __fips140_initcall_rootfs_start; fn < __fips140_initcall_rootfs_end; fn++) {
				int ret = (*fn)();
				if (ret && ret != -ENODEV)
					pr_err("FIPS 140: rootfs initcall %pS failed: %d\n", *fn, ret);
			}
			fips140_mark_module_wait_kernel(FIPS_ROOTFS_LEVEL);
			fips140_mark_module_wait_kernel_sync(FIPS_ROOTFS_LEVEL);
		}
	}

	pr_info("FIPS 140: run_initcalls finished\n");
	return 0;
}

/* Initialize the FIPS 140 module */
static int __init fips140_init(void)
{
	/* Signal that module is loaded — unblock kernel level 3 sync barrier */
	fips140_mark_module_wait_kernel_sync(FIPS_LOADER_LEVEL);

	pr_info("loading " FIPS140_MODULE_NAME "\n");

	run_initcalls();

	if (fips_enabled) {
		verify_integrity(); /* Panics if integrity check fails */
	}

	/* Final sync after verify_integrity */
	fips140_mark_module_wait_kernel_sync(FIPS_LAST_LEVEL);
	return 0;
}

static void __exit fips140_exit(void)
{
    pr_info("Unloading " FIPS140_MODULE_NAME "\n");
}

module_init(fips140_init);
module_exit(fips140_exit);

MODULE_IMPORT_NS(CRYPTO_INTERNAL);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION(FIPS140_MODULE_NAME);
MODULE_VERSION(FIPS140_MODULE_VERSION);
