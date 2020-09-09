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
	default:
		*type = INSN_OTHER;
		break;
	}

	return 0;
}
