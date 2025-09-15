/* SPDX-License-Identifier: GPL-2.0-only */

SECTIONS {
	.init.data : {
		__fips140_initcalls_start = .;
		*(.fips_initcall0)
		*(.fips_initcall1)
		*(.fips_initcall2)
		*(.fips_initcall3)
		*(.fips_initcall4)
		*(.fips_initcall5)
		*(.fips_initcall6)
		*(.fips_initcall7)
		__fips140_initcalls_end = .;
	}
}