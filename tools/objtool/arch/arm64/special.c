// SPDX-License-Identifier: GPL-2.0-or-later

#include <objtool/special.h>

void arch_handle_alternative(unsigned short feature, struct special_alt *alt)
{
}

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct reloc *reloc)
{
	u32 opcode = *(u32 *)(insn->sec->data->d_buf + insn->offset);

	return aarch64_insn_is_branch_imm(opcode) ||
	       aarch64_insn_is_adrp(opcode) ||
	       !aarch64_insn_uses_literal(opcode);
}


struct reloc *arch_find_switch_table(struct objtool_file *file,
				     struct instruction *insn)
{
	return NULL;
}
