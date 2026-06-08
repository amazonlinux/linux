/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * FIPS 140 module initcall section layout.
 *
 * Sections use kernel initcall level numbers directly (4-7):
 *   .fips_initcall4   <- subsys_initcall()     (kernel level 4)
 *   .fips_initcall4s  <- subsys_initcall_sync() 
 *   .fips_initcall5   <- fs_initcall()         (kernel level 5)
 *   .fips_initcall5s  <- fs_initcall_sync() / rootfs_initcall()
 *   .fips_initcall6   <- module_init() / device_initcall() (kernel level 6)
 *   .fips_initcall6s  <- device_initcall_sync()
 *   .fips_initcall7   <- late_initcall()       (kernel level 7)
 *   .fips_initcall7s  <- late_initcall_sync()
 */

SECTIONS {
	.init.data : {
		__fips140_initcalls_start = .;
		__fips140_initcall4_start = .;
		*(.fips_initcall4)
		__fips140_initcall4_end = .;
		__fips140_initcall4s_start = .;
		*(.fips_initcall4s)
		__fips140_initcall4s_end = .;
		__fips140_initcall5_start = .;
		*(.fips_initcall5)
		__fips140_initcall5_end = .;
		__fips140_initcall5s_start = .;
		*(.fips_initcall5s)
		__fips140_initcall5s_end = .;
		__fips140_initcall_rootfs_start = .;
		*(.fips_initcall_rootfs)
		__fips140_initcall_rootfs_end = .;
		__fips140_initcall6_start = .;
		*(.fips_initcall6)
		__fips140_initcall6_end = .;
		__fips140_initcall6s_start = .;
		*(.fips_initcall6s)
		__fips140_initcall6s_end = .;
		__fips140_initcall7_start = .;
		*(.fips_initcall7)
		__fips140_initcall7_end = .;
		__fips140_initcall7s_start = .;
		*(.fips_initcall7s)
		__fips140_initcall7s_end = .;
		__fips140_initcalls_end = .;
	}
}
