/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linker script for FIPS140 module to collect initcalls
 * Uses standard kernel module linker script patterns
 */

SECTIONS {
	/*
	 * The FIPS140 module incorporates copies of builtin code, which gets
	 * integrity checked at module load time, and registered in a way that
	 * ensures that the integrity checked versions supersede the builtin
	 * ones.  These objects are compiled as builtin code, and so their init
	 * hooks will be exported from the binary in the same way as builtin
	 * initcalls are, i.e., annotated with a level that defines the order
	 * in which the hooks are expected to be invoked.
	 */
	.initcalls : {
		*(.initcalls._start)
		KEEP(*(.initcall0.init*))
		KEEP(*(.initcall0s.init*))
		KEEP(*(.initcall1.init*))
		KEEP(*(.initcall1s.init*))
		KEEP(*(.initcall2.init*))
		KEEP(*(.initcall2s.init*))
		KEEP(*(.initcall3.init*))
		KEEP(*(.initcall3s.init*))
		KEEP(*(.initcall4.init*))
		KEEP(*(.initcall4s.init*))
		KEEP(*(.initcall5.init*))
		KEEP(*(.initcall5s.init*))
		KEEP(*(.initcallrootfs.init*))
		KEEP(*(.initcallrootfss.init*))
		KEEP(*(.initcall6.init*))
		KEEP(*(.initcall6s.init*))
		KEEP(*(.initcall7.init*))
		KEEP(*(.initcall7s.init*))
		*(.initcalls._end)
	}
}
