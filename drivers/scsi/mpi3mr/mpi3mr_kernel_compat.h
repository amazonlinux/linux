/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Driver for Broadcom MPI3 Storage Controllers
 *
 * Copyright (C) 2017-2022 Broadcom Inc.
 *  (mailto: mpi3mr-linuxdrv.pdl@broadcom.com)
 *
 */
#include <linux/kmsg_dump.h>

struct mpi3mr_kmsg_dumper {
#if ((KERNEL_VERSION(5,13,0) <= LINUX_VERSION_CODE) || \
    (defined(RHEL_MAJOR) && (RHEL_MAJOR == 8) && (RHEL_MINOR >= 6)))
	struct kmsg_dump_iter kdumper;
#else
	struct kmsg_dumper kdumper;
#endif
};

static inline void mpi3mr_set_dumper_active(struct mpi3mr_kmsg_dumper *dumper)
{
#if ((KERNEL_VERSION(5,13,0) <= LINUX_VERSION_CODE) || \
    (defined(RHEL_MAJOR) && (RHEL_MAJOR == 8) && (RHEL_MINOR >= 6)))
	return;
#else
	dumper->kdumper.active = true;
	return;
#endif
}

#if (KERNEL_VERSION(5,15,0) <= LINUX_VERSION_CODE)
#define SCMD_GET_REQUEST(scmd)		scsi_cmd_to_rq(scmd)
#else
#define SCMD_GET_REQUEST(scmd)		scmd->request
#endif

#if (KERNEL_VERSION(5,16,0) <= LINUX_VERSION_CODE)
#define SCMD_DONE(scmd)			scsi_done(scmd)
#else
#define SCMD_DONE(scmd)			scmd->scsi_done(scmd)
#endif

static inline u32 mpi3mr_kc_prot_ref_tag(struct scsi_cmnd *scmd)
{
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) || \
     (defined(RHEL_MAJOR) && (RHEL_MAJOR == 8)) || \
     (defined(CONFIG_SUSE_KERNEL) && ((CONFIG_SUSE_VERSION == 15) && \
     (CONFIG_SUSE_PATCHLEVEL >= 1))))
	return t10_pi_ref_tag(SCMD_GET_REQUEST(scmd));
#else
	return scsi_prot_ref_tag(scmd);
#endif
}

static inline bool mpi3mr_use_blk_mq(struct Scsi_Host *shost)
{
#if ((defined(RHEL_MAJOR) && (RHEL_MAJOR == 8)) || \
     (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)))
	return true;
#else
	return shost_use_blk_mq(shost);
#endif
}

/*Revisit enabling Shared HostTag for RHEL8x kernels*/
#if ((defined(RHEL_MAJOR) && (RHEL_MAJOR == 8) && (RHEL_MINOR >= 6)) || \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)))
#define HOST_TAGSET_SUPPORT
#endif

#if (defined(SCMD_STATE_INFLIGHT) && !defined(HOST_TAGSET_SUPPORT))
#define IO_COUNTER_SUPPORT
#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
#define dma_zalloc_coherent dma_alloc_coherent
#endif

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)) || \
	(defined(RHEL_MAJOR) && (RHEL_MAJOR == 8)))
#define BLK_ITER_CALLBACK_RET_TYPE	bool
#define BLK_ITER_CALLBACK_RET_VAL(x)	return x
#else
#define BLK_ITER_CALLBACK_RET_TYPE	void
#define BLK_ITER_CALLBACK_RET_VAL(x)	return
#endif

/**
 * mpi3mr_scsi_build_sense - build sense data
 * @scmd:       scsi command object
 * @desc:       Sense format (non zero == descriptor format,
 *              0 == fixed format)
 * @key:        Sense key
 * @asc:        Additional sense code
 * @ascq:       Additional sense code qualifier
 **/
static inline void mpi3mr_scsi_build_sense(struct scsi_cmnd *scmd,
        int desc, u8 key, u8 asc, u8 ascq)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0))
	scsi_build_sense_buffer(desc, scmd->sense_buffer, key, asc, ascq);
	scmd->result = (DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;
	set_host_byte(scmd, DID_OK);
#else
	scsi_build_sense(scmd, desc, key, asc, ascq);
#endif
}

#ifndef fallthrough
#define fallthrough
#endif
