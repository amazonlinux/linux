/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023, Oracle and/or its affiliates.
 *
 * This file contains definitions for the SFrame stack tracing format, which is
 * documented at https://sourceware.org/binutils/docs
 */
#ifndef _SFRAME_H
#define _SFRAME_H

#include <linux/types.h>

#define SFRAME_VERSION_1	1
#define SFRAME_VERSION_2	2
#define SFRAME_MAGIC		0xdee2

/* Function Descriptor Entries are sorted on PC. */
#define SFRAME_F_FDE_SORTED	0x1
/* Frame-pointer based stack tracing. Defined, but not set. */
#define SFRAME_F_FRAME_POINTER	0x2

#define SFRAME_CFA_FIXED_FP_INVALID 0
#define SFRAME_CFA_FIXED_RA_INVALID 0

/* Supported ABIs/Arch. */
#define SFRAME_ABI_AARCH64_ENDIAN_BIG	    1 /* AARCH64 big endian. */
#define SFRAME_ABI_AARCH64_ENDIAN_LITTLE    2 /* AARCH64 little endian. */
#define SFRAME_ABI_AMD64_ENDIAN_LITTLE	    3 /* AMD64 little endian. */

/* SFrame FRE types. */
#define SFRAME_FRE_TYPE_ADDR1	0
#define SFRAME_FRE_TYPE_ADDR2	1
#define SFRAME_FRE_TYPE_ADDR4	2

/*
 * SFrame Function Descriptor Entry types.
 *
 * The SFrame format has two possible representations for functions. The
 * choice of which type to use is made according to the instruction patterns
 * in the relevant program stub.
 */

/* Unwinders perform a (PC >= FRE_START_ADDR) to look up a matching FRE. */
#define SFRAME_FDE_TYPE_PCINC	0
/*
 * Unwinders perform a (PC & FRE_START_ADDR_AS_MASK >= FRE_START_ADDR_AS_MASK)
 * to look up a matching FRE. Typical usecases are pltN entries, trampolines
 * etc.
 */
#define SFRAME_FDE_TYPE_PCMASK	1

/**
 * struct sframe_preamble - SFrame Preamble.
 * @magic: Magic number (SFRAME_MAGIC).
 * @version: Format version number (SFRAME_VERSION).
 * @flags: Various flags.
 */
struct sframe_preamble {
	u16 magic;
	u8  version;
	u8  flags;
} __packed;

/**
 * struct sframe_header - SFrame Header.
 * @preamble: SFrame preamble.
 * @abi_arch: Identify the arch (including endianness) and ABI.
 * @cfa_fixed_fp_offset: Offset for the Frame Pointer (FP) from CFA may be
 *	  fixed for some ABIs ((e.g, in AMD64 when -fno-omit-frame-pointer is
 *	  used). When fixed, this field specifies the fixed stack frame offset
 *	  and the individual FREs do not need to track it. When not fixed, it
 *	  is set to SFRAME_CFA_FIXED_FP_INVALID, and the individual FREs may
 *	  provide the applicable stack frame offset, if any.
 * @cfa_fixed_ra_offset: Offset for the Return Address from CFA is fixed for
 *	  some ABIs. When fixed, this field specifies the fixed stack frame
 *	  offset and the individual FREs do not need to track it. When not
 *	  fixed, it is set to SFRAME_CFA_FIXED_FP_INVALID.
 * @auxhdr_len: Number of bytes making up the auxiliary header, if any.
 *	  Some ABI/arch, in the future, may use this space for extending the
 *	  information in SFrame header. Auxiliary header is contained in bytes
 *	  sequentially following the sframe_header.
 * @num_fdes: Number of SFrame FDEs in this SFrame section.
 * @num_fres: Number of SFrame Frame Row Entries.
 * @fre_len:  Number of bytes in the SFrame Frame Row Entry section.
 * @fdes_off: Offset of SFrame Function Descriptor Entry section.
 * @fres_off: Offset of SFrame Frame Row Entry section.
 */
struct sframe_header {
	struct sframe_preamble preamble;
	u8  abi_arch;
	s8  cfa_fixed_fp_offset;
	s8  cfa_fixed_ra_offset;
	u8  auxhdr_len;
	u32 num_fdes;
	u32 num_fres;
	u32 fre_len;
	u32 fdes_off;
	u32 fres_off;
} __packed;

#define SFRAME_HDR_SIZE(sframe_hdr)	\
	((sizeof(struct sframe_header) + (sframe_hdr).auxhdr_len))

/* Two possible keys for executable (instruction) pointers signing. */
#define SFRAME_AARCH64_PAUTH_KEY_A    0 /* Key A. */
#define SFRAME_AARCH64_PAUTH_KEY_B    1 /* Key B. */

/**
 * struct sframe_fde - SFrame Function Descriptor Entry.
 * @start_addr: Function start address. Encoded as a signed offset,
 *	  relative to the current FDE.
 * @size: Size of the function in bytes.
 * @fres_off: Offset of the first SFrame Frame Row Entry of the function,
 *	  relative to the beginning of the SFrame Frame Row Entry sub-section.
 * @fres_num: Number of frame row entries for the function.
 * @info: Additional information for deciphering the stack trace
 *	  information for the function. Contains information about SFrame FRE
 *	  type, SFrame FDE type, PAC authorization A/B key, etc.
 * @rep_size: Block size for SFRAME_FDE_TYPE_PCMASK
 * @padding: Unused
 */
struct sframe_fde {
	s32 start_addr;
	u32 size;
	u32 fres_off;
	u32 fres_num;
	u8  info;
	u8  rep_size;
	u16 padding;
} __packed;

/*
 * 'func_info' in SFrame FDE contains additional information for deciphering
 * the stack trace information for the function. In V1, the information is
 * organized as follows:
 *   - 4-bits: Identify the FRE type used for the function.
 *   - 1-bit: Identify the FDE type of the function - mask or inc.
 *   - 1-bit: PAC authorization A/B key (aarch64).
 *   - 2-bits: Unused.
 * ---------------------------------------------------------------------
 * |  Unused  |  PAC auth A/B key (aarch64) |  FDE type |   FRE type   |
 * |          |        Unused (amd64)       |           |              |
 * ---------------------------------------------------------------------
 * 8          6                             5           4              0
 */

/* Note: Set PAC auth key to SFRAME_AARCH64_PAUTH_KEY_A by default.  */
#define SFRAME_FUNC_INFO(fde_type, fre_enc_type) \
	(((SFRAME_AARCH64_PAUTH_KEY_A & 0x1) << 5) | \
	 (((fde_type) & 0x1) << 4) | ((fre_enc_type) & 0xf))

#define SFRAME_FUNC_FRE_TYPE(data)	  ((data) & 0xf)
#define SFRAME_FUNC_FDE_TYPE(data)	  (((data) >> 4) & 0x1)
#define SFRAME_FUNC_PAUTH_KEY(data)	  (((data) >> 5) & 0x1)

/*
 * Size of stack frame offsets in an SFrame Frame Row Entry. A single
 * SFrame FRE has all offsets of the same size. Offset size may vary
 * across frame row entries.
 */
#define SFRAME_FRE_OFFSET_1B	  0
#define SFRAME_FRE_OFFSET_2B	  1
#define SFRAME_FRE_OFFSET_4B	  2

/* An SFrame Frame Row Entry can be SP or FP based.  */
#define SFRAME_BASE_REG_FP	0
#define SFRAME_BASE_REG_SP	1

/*
 * The index at which a specific offset is presented in the variable length
 * bytes of an FRE.
 */
#define SFRAME_FRE_CFA_OFFSET_IDX   0
/*
 * The RA stack offset, if present, will always be at index 1 in the variable
 * length bytes of the FRE.
 */
#define SFRAME_FRE_RA_OFFSET_IDX    1
/*
 * The FP stack offset may appear at offset 1 or 2, depending on the ABI as RA
 * may or may not be tracked.
 */
#define SFRAME_FRE_FP_OFFSET_IDX    2

/*
 * 'fre_info' in SFrame FRE contains information about:
 *   - 1 bit: base reg for CFA
 *   - 4 bits: Number of offsets (N). A value of up to 3 is allowed to track
 *   all three of CFA, FP and RA (fixed implicit order).
 *   - 2 bits: information about size of the offsets (S) in bytes.
 *     Valid values are SFRAME_FRE_OFFSET_1B, SFRAME_FRE_OFFSET_2B,
 *     SFRAME_FRE_OFFSET_4B
 *   - 1 bit: Mangled RA state bit (aarch64 only).
 * ---------------------------------------------------------------
 * | Mangled-RA (aarch64) |  Size of   |   Number of  | base_reg |
 * |  Unused (amd64)      |  offsets   |    offsets   |          |
 * ---------------------------------------------------------------
 * 8                      7             5             1          0
 */

/* Note: Set mangled_ra_p to zero by default. */
#define SFRAME_FRE_INFO(base_reg_id, offset_num, offset_size) \
	(((0 & 0x1) << 7) | (((offset_size) & 0x3) << 5) | \
	 (((offset_num) & 0xf) << 1) | ((base_reg_id) & 0x1))

/* Set the mangled_ra_p bit as indicated. */
#define SFRAME_FRE_INFO_UPDATE_MANGLED_RA_P(mangled_ra_p, fre_info) \
	((((mangled_ra_p) & 0x1) << 7) | ((fre_info) & 0x7f))

#define SFRAME_FRE_CFA_BASE_REG_ID(data)	  ((data) & 0x1)
#define SFRAME_FRE_OFFSET_COUNT(data)		  (((data) >> 1) & 0xf)
#define SFRAME_FRE_OFFSET_SIZE(data)		  (((data) >> 5) & 0x3)
#define SFRAME_FRE_MANGLED_RA_P(data)		  (((data) >> 7) & 0x1)

#endif /* _SFRAME_H */
