/* SPDX-License-Identifier: GPL-2.0-only */

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