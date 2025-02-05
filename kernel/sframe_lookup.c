// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"sframe: " fmt

#include <linux/module.h>
#include <linux/sort.h>
#include <linux/sframe_lookup.h>
#include <linux/kallsyms.h>
#include "sframe.h"

extern char __start_sframe_header[];
extern char __stop_sframe_header[];

static bool sframe_init __ro_after_init;
static struct sframe_table sftbl;

#define SFRAME_READ_TYPE(in, out, type)					\
({									\
	type __tmp;							\
	memcpy(&__tmp, in, sizeof(__tmp));				\
	in += sizeof(__tmp);						\
	out = __tmp;							\
})

#define SFRAME_READ_ROW_ADDR(in_addr, out_addr, type)			\
({									\
	switch (type) {							\
	case SFRAME_FRE_TYPE_ADDR1:					\
		SFRAME_READ_TYPE(in_addr, out_addr, u8);		\
		break;							\
	case SFRAME_FRE_TYPE_ADDR2:					\
		SFRAME_READ_TYPE(in_addr, out_addr, u16);		\
		break;							\
	case SFRAME_FRE_TYPE_ADDR4:					\
		SFRAME_READ_TYPE(in_addr, out_addr, u32);		\
		break;							\
	default:							\
		break;							\
	}								\
})

#define SFRAME_READ_ROW_OFFSETS(in_addr, out_addr, size)		\
({									\
	switch (size) {							\
	case 1:								\
		SFRAME_READ_TYPE(in_addr, out_addr, s8);		\
		break;							\
	case 2:								\
		SFRAME_READ_TYPE(in_addr, out_addr, s16);		\
		break;							\
	case 4:								\
		SFRAME_READ_TYPE(in_addr, out_addr, s32);		\
		break;							\
	default:							\
		break;							\
	}								\
})

static struct sframe_fde *find_fde(const struct sframe_table *tbl, unsigned long pc)
{
	int l, r, m, f;
	int32_t ip;
	struct sframe_fde *fdep;

	if (!tbl || !tbl->sfhdr_p || !tbl->fde_p)
		return NULL;

	ip = (pc - (unsigned long)tbl->sfhdr_p);

	/* Do a binary range search to find the rightmost FDE start_addr < ip */
	l = m = f = 0;
	r = tbl->sfhdr_p->num_fdes;
	while (l < r) {
		m = l + ((r - l) / 2);
		fdep = tbl->fde_p + m;
		if (fdep->start_addr > ip)
			r = m;
		else
			l = m + 1;
	}
	/* use l - 1 because l will be the first item fdep->start_addr > ip */
	f = l - 1;
	if (f >= tbl->sfhdr_p->num_fdes || f < 0)
		return NULL;
	fdep = tbl->fde_p + f;
	if (ip < fdep->start_addr || ip > fdep->start_addr + fdep->size)
		return NULL;

	return fdep;
}

static int find_fre(const struct sframe_table *tbl, unsigned long pc,
		const struct sframe_fde *fdep, struct sframe_ip_entry *entry)
{
	int i, offset_size, offset_count;
	char *fres, *offsets_loc;
	int32_t ip_off;
	uint32_t next_row_ip_off;
	uint8_t fre_info, fde_type = SFRAME_FUNC_FDE_TYPE(fdep->info),
			fre_type = SFRAME_FUNC_FRE_TYPE(fdep->info);

	fres = tbl->fre_p + fdep->fres_off;

	/*  Whether PCs in the FREs should be treated as masks or not */
	if (fde_type == SFRAME_FDE_TYPE_PCMASK)
		ip_off = pc % fdep->rep_size;
	else
		ip_off = (int32_t)(pc - (unsigned long)tbl->sfhdr_p) - fdep->start_addr;

	if (ip_off < 0 || ip_off > fdep->size)
		return -EINVAL;

	/*
	 * FRE structure starts by address of the entry with variants length. Use
	 * two pointers to track current head(fres) and the address of last
	 * offset(offsets_loc)
	 */
	for (i = 0; i < fdep->fres_num; i++) {
		SFRAME_READ_ROW_ADDR(fres, next_row_ip_off, fre_type);
		if (ip_off < next_row_ip_off)
			break;
		SFRAME_READ_TYPE(fres, fre_info, u8);
		offsets_loc = fres;
		/*
		 * jump to the start of next fre
		 * fres += fre_offets_cnt*offset_size
		 */
		fres += SFRAME_FRE_OFFSET_COUNT(fre_info) << SFRAME_FRE_OFFSET_SIZE(fre_info);
	}

	offset_size = 1 << SFRAME_FRE_OFFSET_SIZE(fre_info);
	offset_count = SFRAME_FRE_OFFSET_COUNT(fre_info);

	if (offset_count > 0) {
		SFRAME_READ_ROW_OFFSETS(offsets_loc, entry->cfa_offset, offset_size);
		offset_count--;
	}
	if (offset_count > 0 && !entry->ra_offset) {
		SFRAME_READ_ROW_OFFSETS(offsets_loc, entry->ra_offset, offset_size);
		offset_count--;
	}
	if (offset_count > 0 && !entry->fp_offset) {
		SFRAME_READ_ROW_OFFSETS(offsets_loc, entry->fp_offset, offset_size);
		offset_count--;
	}
	if (offset_count)
		return -EINVAL;

	entry->use_fp = SFRAME_FRE_CFA_BASE_REG_ID(fre_info) == SFRAME_BASE_REG_FP;

	return 0;
}

int sframe_find_pc(unsigned long pc, struct sframe_ip_entry *entry)
{
	struct sframe_fde *fdep;
	struct sframe_table *sftbl_p = &sftbl;
	int err;

	if (!sframe_init)
		return -EINVAL;

	memset(entry, 0, sizeof(*entry));
	entry->ra_offset = sftbl_p->sfhdr_p->cfa_fixed_ra_offset;
	entry->fp_offset = sftbl_p->sfhdr_p->cfa_fixed_fp_offset;

	fdep = find_fde(sftbl_p, pc);
	if (!fdep)
		return -EINVAL;
	err = find_fre(sftbl_p, pc, fdep, entry);
	if (err)
		return err;

	return 0;
}

void __init init_sframe_table(void)
{
	size_t sframe_size = (void *)__stop_sframe_header - (void *)__start_sframe_header;
	void *sframe_buf = __start_sframe_header;

	if (sframe_size <= 0)
		return;
	sftbl.sfhdr_p = sframe_buf;
	if (!sftbl.sfhdr_p || sftbl.sfhdr_p->preamble.magic != SFRAME_MAGIC ||
	    sftbl.sfhdr_p->preamble.version != SFRAME_VERSION_2 ||
	    !(sftbl.sfhdr_p->preamble.flags & SFRAME_F_FDE_SORTED)) {
		pr_warn("WARNING: Unable to read sframe header.  Disabling unwinder.\n");
		return;
	}

	sftbl.fde_p = (struct sframe_fde *)(__start_sframe_header + SFRAME_HDR_SIZE(*sftbl.sfhdr_p)
						+ sftbl.sfhdr_p->fdes_off);
	sftbl.fre_p = __start_sframe_header + SFRAME_HDR_SIZE(*sftbl.sfhdr_p)
		+ sftbl.sfhdr_p->fres_off;
	sframe_init = true;
}
