// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <asm/insn.h>

#include <objtool/check.h>
#include <objtool/arch.h>
#include <objtool/elf.h>
#include <objtool/warn.h>

#include <arch/cfi_regs.h>

/* Hack needed to avoid depending on debug-monitors.h */
#define AARCH64_BREAK_FAULT	0xBAD

/* Hack needed to avoid depending on kprobes.h */
#ifndef __kprobes
#define __kprobes
#endif

#include "../../../arch/arm64/lib/insn.c"

static unsigned long sign_extend(unsigned long x, int nbits)
{
	unsigned long sign_bit = (x >> (nbits - 1)) & 1;

	return ((~0UL + (sign_bit ^ 1)) << nbits) | x;
}

bool arch_callee_saved_reg(unsigned char reg)
{
	switch (reg) {
	case AARCH64_INSN_REG_19:
	case AARCH64_INSN_REG_20:
	case AARCH64_INSN_REG_21:
	case AARCH64_INSN_REG_22:
	case AARCH64_INSN_REG_23:
	case AARCH64_INSN_REG_24:
	case AARCH64_INSN_REG_25:
	case AARCH64_INSN_REG_26:
	case AARCH64_INSN_REG_27:
	case AARCH64_INSN_REG_28:
	case AARCH64_INSN_REG_FP:
	case AARCH64_INSN_REG_LR:
		return true;
	default:
		return false;
	}
}

void arch_initial_func_cfi_state(struct cfi_init_state *state)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		state->regs[i].base = CFI_UNDEFINED;
		state->regs[i].offset = 0;
	}

	/* initial CFA (call frame address) */
	state->cfa.base = CFI_SP;
	state->cfa.offset = 0;
}

unsigned long arch_dest_reloc_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

const char *arch_nop_insn(int len)
{
	static u32 nop = 0;

	if (len != AARCH64_INSN_SIZE)
		WARN("invalid NOP size: %d\n", len);

	if (!nop)
		nop = aarch64_insn_gen_nop();

	return (const char*)&nop;
}

const char *arch_ret_insn(int len)
{
	return arch_nop_insn(len);
}

static int is_arm64(const struct elf *elf)
{
	switch (elf->ehdr.e_machine) {
	case EM_AARCH64: //0xB7
		return 1;
	default:
		WARN("unexpected ELF machine type %x",
		     elf->ehdr.e_machine);
		return 0;
	}
}

int arch_decode_hint_reg(u8 sp_reg, int *base)
{
	if (sp_reg == UNWIND_HINT_REG_UNDEFINED)
		*base = CFI_UNDEFINED;
	else
		*base = sp_reg;

	return 0;
}
}

static struct stack_op *arm_make_store_op(enum aarch64_insn_register base,
					  enum aarch64_insn_register reg,
					  int offset)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	if (!op) {
		WARN("calloc failed");
		return NULL;
	}
	op->dest.type = OP_DEST_REG_INDIRECT;
	op->dest.reg = base;
	op->dest.offset = offset;
	op->src.type = OP_SRC_REG;
	op->src.reg = reg;
	op->src.offset = 0;

	return op;
}

static struct stack_op *arm_make_load_op(enum aarch64_insn_register base,
					 enum aarch64_insn_register reg,
					 int offset)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	if (!op) {
		WARN("calloc failed");
		return NULL;
	}
	op->dest.type = OP_DEST_REG;
	op->dest.reg = reg;
	op->dest.offset = 0;
	op->src.type = OP_SRC_REG_INDIRECT;
	op->src.reg = base;
	op->src.offset = offset;

	return op;
}

static struct stack_op *arm_make_add_op(enum aarch64_insn_register dest,
					enum aarch64_insn_register src,
					int val)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	if (!op) {
		WARN("calloc failed");
		return NULL;
	}
	op->dest.type = OP_DEST_REG;
	op->dest.reg = dest;
	op->src.reg = src;
	op->src.type = val != 0 ? OP_SRC_ADD : OP_SRC_REG;
	op->src.offset = val;

	return op;
}

static int arm_decode_load_store(u32 insn, enum insn_type *type,
				 unsigned long *immediate,
				 struct list_head *ops_list)
{
	enum aarch64_insn_register base;
	enum aarch64_insn_register rt;
	struct stack_op *op;
	int size;
	int offset;

	*type = INSN_OTHER;

	if (aarch64_insn_is_store_single(insn) ||
	    aarch64_insn_is_load_single(insn))
		size = 1 << ((insn & GENMASK(31, 30)) >> 30);
	else
		size = 4 << ((insn >> 31) & 1);

	if (aarch64_insn_is_store_imm(insn) || aarch64_insn_is_load_imm(insn))
		*immediate = size * aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12,
								  insn);
	else if (aarch64_insn_is_store_pre(insn) ||
		 aarch64_insn_is_load_pre(insn) ||
		 aarch64_insn_is_store_post(insn) ||
		 aarch64_insn_is_load_post(insn))
		*immediate = sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_9,
								       insn),
					 9);
	else if (aarch64_insn_is_stp(insn) || aarch64_insn_is_ldp(insn) ||
		 aarch64_insn_is_stp_pre(insn) ||
		 aarch64_insn_is_ldp_pre(insn) ||
		 aarch64_insn_is_stp_post(insn) ||
		 aarch64_insn_is_ldp_post(insn))
		*immediate = size * sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_7,
									      insn),
						7);
	else
		return 1;

	base = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn);
	if (base != AARCH64_INSN_REG_FP && base != AARCH64_INSN_REG_SP)
		return 0;

	offset = *immediate;

	if (aarch64_insn_is_store_pre(insn) || aarch64_insn_is_stp_pre(insn) ||
	    aarch64_insn_is_store_post(insn) || aarch64_insn_is_stp_post(insn)) {
		op = arm_make_add_op(base, base, *immediate);
		list_add_tail(&op->list, ops_list);

		if (aarch64_insn_is_store_post(insn) || aarch64_insn_is_stp_post(insn))
			offset = -*immediate;
		else
			offset = 0;
	} else if (aarch64_insn_is_load_post(insn) || aarch64_insn_is_ldp_post(insn)) {
		offset = 0;
	}

	/* First register */
	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
	if (aarch64_insn_is_store_single(insn) ||
	    aarch64_insn_is_store_pair(insn))
		op = arm_make_store_op(base, rt, offset);
	else
		op = arm_make_load_op(base, rt, offset);

	if (!op)
		return -1;
	list_add_tail(&op->list, ops_list);

	/* Second register (if present) */
	if (aarch64_insn_is_store_pair(insn) ||
	    aarch64_insn_is_load_pair(insn)) {
		rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT2,
						  insn);
		if (aarch64_insn_is_store_pair(insn))
			op = arm_make_store_op(base, rt, offset + size);
		else
			op = arm_make_load_op(base, rt, offset + size);
		if (!op)
			return -1;
		list_add_tail(&op->list, ops_list);
	}

	if (aarch64_insn_is_load_pre(insn) || aarch64_insn_is_ldp_pre(insn) ||
	    aarch64_insn_is_load_post(insn) || aarch64_insn_is_ldp_post(insn)) {
		op = arm_make_add_op(base, base, *immediate);
		if (!op)
			return -1;
		list_add_tail(&op->list, ops_list);
	}

	return 0;
}

static int arm_decode_add_sub_imm(u32 instr, bool set_flags,
				  enum insn_type *type,
				  unsigned long *immediate,
				  struct list_head *ops_list)
{
	u32 rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, instr);
	u32 rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, instr);

	*type = INSN_OTHER;
	*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, instr);

	if (instr & AARCH64_INSN_LSL_12)
		*immediate <<= 12;

	if ((!set_flags && rd == AARCH64_INSN_REG_SP) ||
	    rd == AARCH64_INSN_REG_FP ||
	    rn == AARCH64_INSN_REG_FP ||
	    rn == AARCH64_INSN_REG_SP) {
		struct stack_op *op;
		int value;

		if (aarch64_insn_is_subs_imm(instr) || aarch64_insn_is_sub_imm(instr))
			value = -*immediate;
		else
			value = *immediate;

		op = arm_make_add_op(rd, rn, value);
		if (!op)
			return -1;
		list_add_tail(&op->list, ops_list);
	}

	return 0;
}

int arch_decode_instruction(const struct elf *elf, const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	u32 insn;

	if (!is_arm64(elf))
		return -1;

	if (maxlen < AARCH64_INSN_SIZE)
		return 0;

	*len = AARCH64_INSN_SIZE;
	*immediate = 0;

	insn = *(u32 *)(sec->data->d_buf + offset);

	switch (aarch64_get_insn_class(insn)) {
	case AARCH64_INSN_CLS_UNKNOWN:
		WARN("can't decode instruction at %s:0x%lx", sec->name, offset);
		return -1;
	case AARCH64_INSN_CLS_DP_IMM:
		/* Mov register to and from SP are aliases of add_imm */
		if (aarch64_insn_is_add_imm(insn) ||
		    aarch64_insn_is_sub_imm(insn))
			return arm_decode_add_sub_imm(insn, false, type, immediate,
						      ops_list);
		else if (aarch64_insn_is_adds_imm(insn) ||
			 aarch64_insn_is_subs_imm(insn))
			return arm_decode_add_sub_imm(insn, true, type, immediate,
						      ops_list);
		else
			*type = INSN_OTHER;
		break;
	case AARCH64_INSN_CLS_DP_REG:
		if (aarch64_insn_is_mov_reg(insn)) {
			enum aarch64_insn_register rd;
			enum aarch64_insn_register rm;

			rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, insn);
			rm = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RM, insn);
			if (rd == AARCH64_INSN_REG_FP || rm == AARCH64_INSN_REG_FP) {
				struct stack_op *op;

				op = arm_make_add_op(rd, rm, 0);
				if (!op)
					return -1;
				list_add_tail(&op->list, ops_list);
				break;
			}
		}
		*type = INSN_OTHER;
		break;
	case AARCH64_INSN_CLS_BR_SYS:
		if (aarch64_insn_is_ret(insn) &&
		    aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn) == AARCH64_INSN_REG_LR) {
			*type = INSN_RETURN;
		} else if (aarch64_insn_is_bl(insn)) {
			*type = INSN_CALL;
			*immediate = aarch64_get_branch_offset(insn);
		} else if (aarch64_insn_is_blr(insn)) {
			*type = INSN_CALL_DYNAMIC;
		} else if (aarch64_insn_is_b(insn)) {
			*type = INSN_JUMP_UNCONDITIONAL;
			*immediate = aarch64_get_branch_offset(insn);
		} else if (aarch64_insn_is_br(insn)) {
			*type = INSN_JUMP_DYNAMIC;
		} else if (aarch64_insn_is_branch_imm(insn)) {
			/* Remaining branch opcodes are conditional */
			*type = INSN_JUMP_CONDITIONAL;
			*immediate = aarch64_get_branch_offset(insn);
		} else if (aarch64_insn_is_eret(insn)) {
			*type = INSN_CONTEXT_SWITCH;
		} else if (aarch64_insn_is_steppable_hint(insn)) {
			*type = INSN_NOP;
		} else if (aarch64_insn_is_brk(insn)) {
			*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_16, insn);
			*type = INSN_BUG;
		} else {
			*type = INSN_OTHER;
		}
		break;
	case AARCH64_INSN_CLS_LDST:
	{
		int ret;

		ret = arm_decode_load_store(insn, type, immediate, ops_list);
		if (ret <= 0)
			return ret;

		*type = INSN_OTHER;
		break;
	}
	default:
		*type = INSN_OTHER;
		break;
	}

	return 0;
}
