// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140 Kernel Cryptographic Module
 *
 * This file is the core of fips140.ko, which contains various crypto algorithms
 * that are also built into vmlinux.  At load time, this module overrides the
 * built-in implementations of these algorithms with its implementations.  It
 * also runs self-tests on these algorithms and verifies the integrity of its
 * code and data.  If either of these steps fails, the kernel will panic.
 */

#include "fips140-module.h"

#define FIPS140_MODULE_NAME "FIPS 140 Kernel Cryptographic Module"
#define FIPS140_MODULE_VERSION "1.0.0"

#define CRYPTO_INTERNAL "CRYPTO_INTERNAL"

static int __init run_initcalls(void)
{
	typedef int (*initcall_t)(void);
	
	extern initcall_t __fips140_initcall0_start[], __fips140_initcall0_end[];
	extern initcall_t __fips140_initcall1_start[], __fips140_initcall1_end[];
	extern initcall_t __fips140_initcall2_start[], __fips140_initcall2_end[];

	initcall_t *starts[] = {
		__fips140_initcall0_start,
		__fips140_initcall1_start,
		__fips140_initcall2_start,
	};
	
	initcall_t *ends[] = {
		__fips140_initcall0_end,
		__fips140_initcall1_end,
		__fips140_initcall2_end,
	};

	pr_info("FIPS 140: run_initcalls starting\n");

	for (int level = 0; level < ARRAY_SIZE(starts); level++) {
		
		/* Run FIPS initcalls for this level */
		for (initcall_t *initcall = starts[level]; initcall < ends[level]; ++initcall) {
			int ret;
			initcall_t fn = *initcall;
			
			pr_info("FIPS 140: run initcall %pS\n", fn);
			ret = fn();
			if (!ret || ret == -ENODEV)
				continue;

			pr_err("FIPS 140: initcall %pS failed: %d\n", fn, ret);
		}
	
		if (level < 2)
			fips140_mark_module_level_complete(level);
		/* Wait for kernel to complete this level */
		wait_event(fips140_kernel_wq, fips140_is_kernel_level_complete(level));
	}

	pr_info("FIPS 140: run_initcalls finished\n");
	return 0;
}

/* Initialize the FIPS 140 module */
static int __init fips140_init(void)
{
    pr_info("loading " FIPS140_MODULE_NAME "\n");

	run_initcalls();
	fips140_mark_module_level_complete(2);
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
