// SPDX-License-Identifier: GPL-2.0-or-later

#include <objtool/special.h>

void arch_handle_alternative(unsigned short feature, struct special_alt *alt)
{
	if (alt->orig_len && !alt->new_len) {
		/*
		 * ARM64_CB_PATCH has no alternative instruction.
		 * a callback is called at alternative replacement time
		 * to dynamically change the original instructions.
		 *
		 * ARM64_CB_PATCH is the last ARM64 feature, it's value changes
		 * every time a new feature is added. So the orig/alt region
		 * length are used to detect those alternatives
		 */
		alt->skip_alt = true;
	}
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
