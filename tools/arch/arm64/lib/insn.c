// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 */
#include <linux/bitops.h>
#include <linux/sizes.h>
#include <linux/types.h>

#include <asm/errno.h>
#include <asm/insn.h>

#define AARCH64_DECODE_FAULT 0xFFFFFFFF

#define AARCH64_INSN_SF_BIT	BIT(31)
#define AARCH64_INSN_N_BIT	BIT(22)
#define AARCH64_INSN_LSL_12	BIT(22)

static const int aarch64_insn_encoding_class[] = {
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_SVE,
	AARCH64_INSN_CLS_UNKNOWN,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_REG,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_FPSIMD,
	AARCH64_INSN_CLS_DP_IMM,
	AARCH64_INSN_CLS_DP_IMM,
	AARCH64_INSN_CLS_BR_SYS,
	AARCH64_INSN_CLS_BR_SYS,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_REG,
	AARCH64_INSN_CLS_LDST,
	AARCH64_INSN_CLS_DP_FPSIMD,
};

enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn)
{
	return aarch64_insn_encoding_class[(insn >> 25) & 0xf];
}

bool aarch64_insn_is_steppable_hint(u32 insn)
{
	if (!aarch64_insn_is_hint(insn))
		return false;

	switch (insn & 0xFE0) {
	case AARCH64_INSN_HINT_XPACLRI:
	case AARCH64_INSN_HINT_PACIA_1716:
	case AARCH64_INSN_HINT_PACIB_1716:
	case AARCH64_INSN_HINT_PACIAZ:
	case AARCH64_INSN_HINT_PACIASP:
	case AARCH64_INSN_HINT_PACIBZ:
	case AARCH64_INSN_HINT_PACIBSP:
	case AARCH64_INSN_HINT_BTI:
	case AARCH64_INSN_HINT_BTIC:
	case AARCH64_INSN_HINT_BTIJ:
	case AARCH64_INSN_HINT_BTIJC:
	case AARCH64_INSN_HINT_NOP:
		return true;
	default:
		return false;
	}
}

bool aarch64_insn_is_branch_imm(u32 insn)
{
	return (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn) ||
		aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn) ||
		aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
		aarch64_insn_is_bcond(insn));
}

bool aarch64_insn_uses_literal(u32 insn)
{
	/* ldr/ldrsw (literal), prfm */

	return aarch64_insn_is_ldr_lit(insn) ||
		aarch64_insn_is_ldrsw_lit(insn) ||
		aarch64_insn_is_adr_adrp(insn) ||
		aarch64_insn_is_prfm_lit(insn);
}

bool aarch64_insn_is_branch(u32 insn)
{
	/* b, bl, cb*, tb*, ret*, b.cond, br*, blr* */

	return aarch64_insn_is_b(insn) ||
		aarch64_insn_is_bl(insn) ||
		aarch64_insn_is_cbz(insn) ||
		aarch64_insn_is_cbnz(insn) ||
		aarch64_insn_is_tbz(insn) ||
		aarch64_insn_is_tbnz(insn) ||
		aarch64_insn_is_ret(insn) ||
		aarch64_insn_is_ret_auth(insn) ||
		aarch64_insn_is_br(insn) ||
		aarch64_insn_is_br_auth(insn) ||
		aarch64_insn_is_blr(insn) ||
		aarch64_insn_is_blr_auth(insn) ||
		aarch64_insn_is_bcond(insn);
}

static int aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
						u32 *maskp, int *shiftp)
{
	u32 mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	case AARCH64_INSN_IMM_N:
		mask = 1;
		shift = 22;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		SZ_2M
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5

u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
{
	u32 immlo, immhi, mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
		immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
		insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
		mask = ADR_IMM_SIZE - 1;
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			WARN("aarch64_insn_decode_immediate: unknown immediate encoding %d\n",
					type);
			return AARCH64_DECODE_FAULT;
		}
	}

	return (insn >> shift) & mask;
}

u32 aarch64_insn_decode_register(enum aarch64_insn_register_type type,
					u32 insn)
{
	int shift;

	switch (type) {
	case AARCH64_INSN_REGTYPE_RT:
	case AARCH64_INSN_REGTYPE_RD:
		shift = 0;
		break;
	case AARCH64_INSN_REGTYPE_RN:
		shift = 5;
		break;
	case AARCH64_INSN_REGTYPE_RT2:
	case AARCH64_INSN_REGTYPE_RA:
		shift = 10;
		break;
	case AARCH64_INSN_REGTYPE_RM:
		shift = 16;
		break;
	default:
		WARN("%s: unknown register type encoding %d\n", __func__,
				type);
		return AARCH64_DECODE_FAULT;
	}

	return (insn >> shift) & GENMASK(4, 0);
}

u32 aarch64_insn_gen_hint(enum aarch64_insn_hint_cr_op op)
{
	return aarch64_insn_get_hint_value() | op;
}

u32 aarch64_insn_gen_nop(void)
{
	return aarch64_insn_gen_hint(AARCH64_INSN_HINT_NOP);
}

static u32 aarch64_insn_encode_register(enum aarch64_insn_register_type type,
					u32 insn,
					enum aarch64_insn_register reg)
{
	int shift;

	if (insn == AARCH64_DECODE_FAULT)
		return AARCH64_DECODE_FAULT;

	if (reg < AARCH64_INSN_REG_0 || reg > AARCH64_INSN_REG_SP) {
		WARN("%s: unknown register encoding %d\n", __func__, reg);
		return AARCH64_DECODE_FAULT;
	}

	switch (type) {
	case AARCH64_INSN_REGTYPE_RT:
	case AARCH64_INSN_REGTYPE_RD:
		shift = 0;
		break;
	case AARCH64_INSN_REGTYPE_RN:
		shift = 5;
		break;
	case AARCH64_INSN_REGTYPE_RT2:
	case AARCH64_INSN_REGTYPE_RA:
		shift = 10;
		break;
	case AARCH64_INSN_REGTYPE_RM:
	case AARCH64_INSN_REGTYPE_RS:
		shift = 16;
		break;
	default:
		WARN("%s: unknown register type encoding %d\n", __func__,
		       type);
		return AARCH64_DECODE_FAULT;
	}

	insn &= ~(GENMASK(4, 0) << shift);
	insn |= reg << shift;

	return insn;
}

u32 aarch64_insn_gen_branch_reg(enum aarch64_insn_register reg,
				enum aarch64_insn_branch_type type)
{
	u32 insn;

	switch (type) {
	case AARCH64_INSN_BRANCH_NOLINK:
		insn = aarch64_insn_get_br_value();
		break;
	case AARCH64_INSN_BRANCH_LINK:
		insn = aarch64_insn_get_blr_value();
		break;
	case AARCH64_INSN_BRANCH_RETURN:
		insn = aarch64_insn_get_ret_value();
		break;
	default:
		WARN("%s: unknown branch encoding %d\n", __func__, type);
		return AARCH64_DECODE_FAULT;
	}

	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg);
}

/*
 * Decode the imm field of a branch, and return the byte offset as a
 * signed value (so it can be used when computing a new branch
 * target).
 */
s32 aarch64_get_branch_offset(u32 insn)
{
	s32 imm;

	if (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn)) {
		imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_26, insn);
		return (imm << 6) >> 4;
	}

	if (aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
	    aarch64_insn_is_bcond(insn)) {
		imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_19, insn);
		return (imm << 13) >> 11;
	}

	if (aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn)) {
		imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_14, insn);
		return (imm << 18) >> 16;
	}

	WARN("Unhandled instruction %x", insn);
	return AARCH64_DECODE_FAULT;
}

s32 aarch64_insn_adrp_get_offset(u32 insn)
{
	if (!aarch64_insn_is_adrp(insn)) {
		WARN("Unhandled instruction %x", insn);
		return AARCH64_DECODE_FAULT;
	}
	return aarch64_insn_decode_immediate(AARCH64_INSN_IMM_ADR, insn) << 12;
}
