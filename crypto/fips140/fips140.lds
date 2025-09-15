/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * FIPS 140 module initcall section layout.
 *
 * The overridden subsys_initcall/module_init/late_initcall macros
 * (include/linux/module.h) place function pointers into these
 * sections when compiled with FIPS_MODULE defined.
 *
 * Section mapping:
 *   .fips_initcall0  <-  subsys_initcall()
 *                        Syncs with kernel subsys_initcall (initcall level 4)
 *   .fips_initcall1  <-  module_init()
 *                        Syncs with kernel device_initcall (initcall level 6)
 *   .fips_initcall2  <-  late_initcall()
 *                        Syncs with kernel late_initcall (initcall level 7)
 *
 * The fips140 loader thread (fips140-loader.c) starts at
 * arch_initcall_sync (level 3) and run_initcalls() in
 * fips140-module.c executes each level in order, synchronizing
 * with the kernel's initcall progression via wait queues.
 */

SECTIONS {
	.init.data : {
		__fips140_initcalls_start = .;
		__fips140_initcall0_start = .;
		*(.fips_initcall0)
		__fips140_initcall0_end = .;
		__fips140_initcall1_start = .;
		*(.fips_initcall1)
		__fips140_initcall1_end = .;
		__fips140_initcall2_start = .;
		*(.fips_initcall2)
		__fips140_initcall2_end = .;
		__fips140_initcalls_end = .;
	}
}