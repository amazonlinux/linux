// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <asm/insn.h>

#include <objtool/check.h>
#include <objtool/arch.h>
#include <objtool/elf.h>
#include <objtool/warn.h>
#include <objtool/builtin.h>
#include <arch/cfi_regs.h>

#include "../../../arch/arm64/lib/insn.c"

#define is_SP(reg)		(reg == AARCH64_INSN_REG_SP)
#define is_FP(reg)		(reg == AARCH64_INSN_REG_FP)
#define is_SPFP(reg)	(reg == AARCH64_INSN_REG_SP || reg == AARCH64_INSN_REG_FP)

#define ADD_OP(op) \
	if (!(op = calloc(1, sizeof(*op)))) \
		return -1; \
	else for (list_add_tail(&op->list, ops_list); op; op = NULL)

static unsigned long sign_extend(unsigned long x, int nbits)
{
	unsigned long sign_bit = (x >> (nbits - 1)) & 1;

	return ((~0UL + (sign_bit ^ 1)) << nbits) | x;
}

struct insn_loc {
	const struct section *sec;
	unsigned long offset;
	struct hlist_node hnode;
};

DEFINE_HASHTABLE(invalid_insns, 16);

static int record_invalid_insn(const struct section *sec,
			       unsigned long offset)
{
	struct insn_loc *loc;
	struct hlist_head *l;

	l = &invalid_insns[hash_min(offset, HASH_BITS(invalid_insns))];
	if (!hlist_empty(l)) {
		loc = hlist_entry(l->first, struct insn_loc, hnode);
		return 0;
	}

	loc = malloc(sizeof(*loc));
	if (!loc) {
		WARN("malloc failed");
		return -1;
	}

	loc->sec = sec;
	loc->offset = offset;

	hash_add(invalid_insns, &loc->hnode, loc->offset);

	return 0;
}

int arch_post_process_instructions(struct objtool_file *file)
{
	struct hlist_node *tmp;
	struct insn_loc *loc;
	unsigned int bkt;
	int res = 0;

	hash_for_each_safe(invalid_insns, bkt, tmp, loc, hnode) {
		struct instruction *insn;

		insn = find_insn(file, (struct section *) loc->sec, loc->offset);
		if (insn) {
			list_del(&insn->list);
			hash_del(&insn->hash);
			free(insn);
		}

		hash_del(&loc->hnode);
		free(loc);
	}

	return res;
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
	static u32 nop;

	if (len != AARCH64_INSN_SIZE)
		WARN("invalid NOP size: %d\n", len);

	if (!nop)
		nop = aarch64_insn_gen_nop();

	return (const char *)&nop;
}

const char *arch_ret_insn(int len)
{
	static u32 ret;

	if (len != AARCH64_INSN_SIZE)
		WARN("invalid RET size: %d\n", len);

	if (!ret) {
		ret = aarch64_insn_gen_branch_reg(AARCH64_INSN_REG_LR,
				AARCH64_INSN_BRANCH_RETURN);
	}

	return (const char *)&ret;
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
	return -1;
}

static inline void make_add_op(enum aarch64_insn_register dest,
					enum aarch64_insn_register src,
					int val, struct stack_op *op)
{
	op->dest.type = OP_DEST_REG;
	op->dest.reg = dest;
	op->src.reg = src;
	op->src.type = val != 0 ? OP_SRC_ADD : OP_SRC_REG;
	op->src.offset = val;
}

static inline void make_store_op(enum aarch64_insn_register base,
					  enum aarch64_insn_register reg,
					  int offset, struct stack_op *op)
{
	op->dest.type = OP_DEST_REG_INDIRECT;
	op->dest.reg = base;
	op->dest.offset = offset;
	op->src.type = OP_SRC_REG;
	op->src.reg = reg;
	op->src.offset = 0;
}

static inline void make_load_op(enum aarch64_insn_register base,
					 enum aarch64_insn_register reg,
					 int offset, struct stack_op *op)
{
	op->dest.type = OP_DEST_REG;
	op->dest.reg = reg;
	op->dest.offset = 0;
	op->src.type = OP_SRC_REG_INDIRECT;
	op->src.reg = base;
	op->src.offset = offset;
}

static inline bool aarch64_insn_is_ldst_pre(u32 insn)
{
	return aarch64_insn_is_store_pre(insn) ||
		   aarch64_insn_is_load_pre(insn) ||
		   aarch64_insn_is_stp_pre(insn) ||
		   aarch64_insn_is_ldp_pre(insn);
}

static inline bool aarch64_insn_is_ldst_post(u32 insn)
{
	return aarch64_insn_is_store_post(insn) ||
		   aarch64_insn_is_load_post(insn) ||
		   aarch64_insn_is_stp_post(insn) ||
		   aarch64_insn_is_ldp_post(insn);
}

static int decode_load_store(u32 insn, unsigned long *immediate,
				 struct list_head *ops_list)
{
	enum aarch64_insn_register base;
	enum aarch64_insn_register rt;
	struct stack_op *op;
	int size;
	int offset;

	if (aarch64_insn_is_store_single(insn) ||
			aarch64_insn_is_load_single(insn))
		size = 1 << ((insn & GENMASK(31, 30)) >> 30);
	else
		size = 4 << ((insn >> 31) & 1);

	if (aarch64_insn_is_store_pair(insn) ||
			aarch64_insn_is_load_pair(insn))
		*immediate = size * sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_7,
									      insn), 7);
	else if (aarch64_insn_is_store_imm(insn) ||
			aarch64_insn_is_load_imm(insn))
		*immediate = size * aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, insn);
	else /* load/store_pre/post */
		*immediate = sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_9,
								       insn), 9);

	base = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn);
	if (!is_SPFP(base))
		return 0;

	if (aarch64_insn_is_ldst_post(insn))
		offset = 0;
	else
		offset = *immediate;

	/* First register */
	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
	ADD_OP(op) {
		if (aarch64_insn_is_store_single(insn) ||
			aarch64_insn_is_store_pair(insn))
			make_store_op(base, rt, offset, op);
		else
			make_load_op(base, rt, offset, op);
	}

	/* Second register (if present) */
	if (aarch64_insn_is_store_pair(insn) ||
			aarch64_insn_is_load_pair(insn)) {
		rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT2,
						  insn);
		ADD_OP(op) {
			if (aarch64_insn_is_store_pair(insn))
				make_store_op(base, rt, offset + size, op);
			else
				make_load_op(base, rt, offset + size, op);
		}
	}

	if (aarch64_insn_is_ldst_pre(insn) ||
			aarch64_insn_is_ldst_post(insn)) {
		ADD_OP(op) {
			make_add_op(base, base, *immediate, op);
		}
	}

	return 0;
}

static void decode_add_sub_imm(u32 instr, bool set_flags,
				  unsigned long *immediate,
				  struct stack_op *op)
{
	u32 rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, instr);
	u32 rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, instr);

	*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, instr);

	if (instr & AARCH64_INSN_LSL_12)
		*immediate <<= 12;

	if ((!set_flags && is_SP(rd)) || is_FP(rd)
			|| is_SPFP(rn)) {
		int value;

		if (aarch64_insn_is_subs_imm(instr) || aarch64_insn_is_sub_imm(instr))
			value = -*immediate;
		else
			value = *immediate;

		make_add_op(rd, rn, value, op);
	}
}

int arch_decode_instruction(struct objtool_file *file, const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	const struct elf *elf = file->elf;
	struct stack_op *op = NULL;
	u32 insn;

	if (!is_arm64(elf))
		return -1;

	if (maxlen < AARCH64_INSN_SIZE)
		return 0;

	*len = AARCH64_INSN_SIZE;
	*immediate = 0;
	*type = INSN_OTHER;

	insn = *(u32 *)(sec->data->d_buf + offset);

	switch (aarch64_get_insn_class(insn)) {
	case AARCH64_INSN_CLS_UNKNOWN:
		if (insn == 0x0) {
			*type = INSN_NOP;
		} else {
			WARN("undecoded insn at %s:0x%lx", sec->name, offset);
			return record_invalid_insn(sec, offset);
		}

		break;
	case AARCH64_INSN_CLS_DP_IMM:
		/* Mov register to and from SP are aliases of add_imm */
		if (aarch64_insn_is_add_imm(insn) ||
		    aarch64_insn_is_sub_imm(insn)) {
			ADD_OP(op) {
				decode_add_sub_imm(insn, false, immediate, op);
			}
		}
		else if (aarch64_insn_is_adds_imm(insn) ||
			     aarch64_insn_is_subs_imm(insn)) {
			ADD_OP(op) {
				decode_add_sub_imm(insn, true, immediate, op);
			}
		}
		break;
	case AARCH64_INSN_CLS_DP_REG:
		if (aarch64_insn_is_mov_reg(insn)) {
			enum aarch64_insn_register rd;
			enum aarch64_insn_register rm;

			rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, insn);
			rm = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RM, insn);
			if (is_FP(rd) || is_FP(rm)) {
				ADD_OP(op) {
					make_add_op(rd, rm, 0, op);
				}
			}
		}
		break;
	case AARCH64_INSN_CLS_BR_SYS:
		if (aarch64_insn_is_ret(insn) &&
		    aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn)
			== AARCH64_INSN_REG_LR) {
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
		} else if (aarch64_insn_is_hint(insn) ||
				   aarch64_insn_is_barrier(insn)) {
			*type = INSN_NOP;
		} else if (aarch64_insn_is_brk(insn)) {
			*type = INSN_BUG;
			*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_16, insn);
		}
		break;
	case AARCH64_INSN_CLS_LDST:
	{
		int ret;

		ret = decode_load_store(insn, immediate, ops_list);
		if (ret <= 0)
			return ret;

		/*
		 * For LDR ops, assembler can generate the data to be
		 * loaded in the code section
		 * Record and remove these data because they
		 * are never excuted
		 */
		if (aarch64_insn_is_ldr_lit(insn)) {
			long pc_offset;

			pc_offset = insn & GENMASK(23, 5);
			/* Sign extend and multiply by 4 */
			pc_offset = (pc_offset << (64 - 23));
			pc_offset = ((pc_offset >> (64 - 23)) >> 5) << 2;

			ret = record_invalid_insn(sec, offset + pc_offset);

			/* 64-bit literal */
			if (insn & BIT(30))
				ret = record_invalid_insn(sec, offset + pc_offset + 4);

			return ret;
		}
		break;
	}
	default:
		break;
	}

	return 0;
}
