/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SFRAME_LOOKUP_H
#define _LINUX_SFRAME_LOOKUP_H

/**
 * struct sframe_ip_entry - sframe unwind info for given ip
 * @cfa_offset: Offset for the Canonical Frame Address(CFA) from Frame
 *              Pointer(FP) or Stack Pointer(SP)
 * @ra_offset: Offset for the Return Address from CFA.
 * @fp_offset: Offset for the Frame Pointer (FP) from CFA.
 * @use_fp: Use FP to get next CFA or not
 */
struct sframe_ip_entry {
	int32_t cfa_offset;
	int32_t ra_offset;
	int32_t fp_offset;
	bool use_fp;
};

/**
 * struct sframe_table - sframe struct of a table
 * @sfhdr_p: Pointer to sframe header
 * @fde_p: Pointer to the first of sframe frame description entry(FDE).
 * @fre_p: Pointer to the first of sframe frame row entry(FRE).
 */
struct sframe_table {
	struct sframe_header *sfhdr_p;
	struct sframe_fde *fde_p;
	char *fre_p;
};

#ifdef CONFIG_SFRAME_UNWINDER
void init_sframe_table(void);
int sframe_find_pc(unsigned long pc, struct sframe_ip_entry *entry);
#else
static inline void init_sframe_table(void) {}
static inline int sframe_find_pc(unsigned long pc, struct sframe_ip_entry *entry)
{
	return -EINVAL;
}
#endif

#endif /* _LINUX_SFRAME_LOOKUP_H */
