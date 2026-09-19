/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019 Arm Ltd. */

#ifndef __ASM_PVCLOCK_ABI_H
#define __ASM_PVCLOCK_ABI_H

/* The below structure is defined in ARM DEN0057A */

/*
 * Layout per ARM DEN0057A.  The trailing 48 bytes of "padding" are
 * vendor-extensible; we steal 8 bytes for cpu_guest_time, mirroring the
 * x86 struct kvm_steal_time::cpu_guest_time field.  Total size is
 * preserved at 64 bytes.
 */

struct pvclock_vcpu_stolen_time {
	__le32 revision;
	__le32 attributes;
	__le64 stolen_time;
	__le64 cpu_guest_time;
	/* Structure must be 64 byte aligned, pad to that size */
	u8 padding[40];
} __packed;

/*
 * Bits for pvclock_vcpu_stolen_time::attributes.  The spec reserves
 * the field and says zero means no attributes; we extend it with a
 * guest-time reclassification hint under AWS KVM.
 *
 * PVCLOCK_STOLEN_TIME_GUEST tells the guest that this vCPU is operating
 * under KVM_CAP_NO_STEAL_TIME.  When this bit is set:
 *   - .stolen_time is pinned (suppressed): its delta MUST NOT be
 *     accounted as CPUTIME_STEAL.
 *   - .cpu_guest_time carries the host-side preemption-time accumulator
 *     that would otherwise have flowed into .stolen_time.  Consumers
 *     that understand the new field SHOULD account its delta against
 *     CPUTIME_GUEST.
 * A guest that does not honor this bit sees .stolen_time pinned (no
 * growth), which is acceptable: the missing wall-clock time falls into
 * idle/user via the standard tick path with no regression vs the cap-off
 * case.
 */
#define PVCLOCK_STOLEN_TIME_GUEST   (1U << 0)

/*
 * Attribute bits this kernel knows how to interpret.  A region carrying
 * any bit outside this mask is rejected, because an unknown attribute may
 * change the meaning of .stolen_time and accounting its delta as
 * CPUTIME_STEAL would then be a guess.
 */
#define PVCLOCK_STOLEN_TIME_ATTRS_SUPPORTED	PVCLOCK_STOLEN_TIME_GUEST

#endif
