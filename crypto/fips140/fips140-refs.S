/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * FIPS 140 Kernel Cryptographic Module
 * References to relocation information
 */

	.section	".rodata", "a"
	.align		8

	.globl		fips140_rela_text
fips140_rela_text:
	.long		__rela_text - .
	.long		__rela_text_size / 24

	.globl		fips140_rela_rodata
fips140_rela_rodata:
	.long		__rela_rodata - .
	.long		__rela_rodata_size / 24

	.section	".data..ro_after_init", "aw"
	.align		8

__rela_text:
	.skip		0
__rela_text_end:
	.set		__rela_text_size, __rela_text_end - __rela_text

__rela_rodata:
	.skip		0
__rela_rodata_end:
	.set		__rela_rodata_size, __rela_rodata_end - __rela_rodata
