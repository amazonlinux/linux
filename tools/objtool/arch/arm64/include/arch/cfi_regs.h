/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _OBJTOOL_CFI_REGS_H
#define _OBJTOOL_CFI_REGS_H

#include <asm/insn.h>

#define CFI_BP			AARCH64_INSN_REG_FP
#define CFI_RA			AARCH64_INSN_REG_LR
#define CFI_SP			AARCH64_INSN_REG_SP

#define CFI_NUM_REGS		32

#endif /* _OBJTOOL_CFI_REGS_H */
