/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef _UAPI_LINUX_NITRO_ENCLAVES_H_
#define _UAPI_LINUX_NITRO_ENCLAVES_H_

#include <linux/types.h>

/**
 * DOC: Nitro Enclaves (NE) Kernel Driver Interface
 */

/**
 * struct ne_create_vm_args - NE_CREATE_VM2 ioctl payload.
 * @flags:	Launch-time flag word.  Passed through to the device's
 *		slot-allocation flags word verbatim.  Carries every
 *		launch-flag bit the device defines EXCEPT DEBUG (DEBUG
 *		remains per-launch and is carried by NE_START_ENCLAVE).
 *		Matched bits (PCIE / PCIE_VSOCK / PCIE_VIRTIO /
 *		PCIE_HOTPLUG) or DIRECT select PCIE enclave backing; zero
 *		selects a legacy slot.
 * @padding:	Reserved for future extension of @flags.  MUST be zero;
 *		the driver rejects non-zero values with -EINVAL so a
 *		future kernel that assigns meaning here can do so without
 *		silently reading stale userspace memory.
 * @slot_uid:	Unique slot id returned by the hypervisor on success.
 */
struct ne_create_vm_args {
	__u32	flags;
	__u32	padding;
	__u64	slot_uid;
};

/**
 * NE_CREATE_VM - The command is used to create a slot that is associated with
 *		  an enclave VM.
 *		  The generated unique slot id is an output parameter.
 *		  The ioctl can be invoked on the /dev/nitro_enclaves fd, before
 *		  setting any resources, such as memory and vCPUs, for an
 *		  enclave. Memory and vCPUs are set for the slot mapped to an enclave.
 *		  A NE CPU pool has to be set before calling this function. The
 *		  pool can be set after the NE driver load, using
 *		  /sys/module/nitro_enclaves/parameters/ne_cpus.
 *		  Its format is the detailed in the cpu-lists section:
 *		  https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
 *		  CPU 0 and its siblings have to remain available for the
 *		  primary / parent VM, so they cannot be set for enclaves. Full
 *		  CPU core(s), from the same NUMA node, need(s) to be included
 *		  in the CPU pool.
 *
 *		  This form is the legacy, flags-less variant.  Callers that
 *		  need to pass launch flags at allocation time (required for
 *		  PCIE enclave slot routing; optional otherwise) must use
 *		  NE_CREATE_VM2 instead.  Calling this ioctl is
 *		  equivalent to NE_CREATE_VM2 with flags = 0.
 *
 * Context: Process context.
 * Return:
 * * Enclave file descriptor		- Enclave file descriptor used with
 *					  ioctl calls to set vCPUs and memory
 *					  regions, then start the enclave.
 * *  -1				- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT				- copy_to_user() failure.
 * * ENOMEM				- Memory allocation failure for internal
 *					  bookkeeping variables.
 * * NE_ERR_NO_CPUS_AVAIL_IN_POOL	- No NE CPU pool set / no CPUs available
 *					  in the pool.
 * * Error codes from get_unused_fd_flags() and anon_inode_getfile().
 * * Error codes from the NE PCI device request.
 */
#define NE_CREATE_VM			_IOR(0xAE, 0x20, __u64)

/**
 * NE_CREATE_VM2 - Same as NE_CREATE_VM but carries a launch-flag
 *			    word as an input parameter.  The argument is a
 *			    struct ne_create_vm_args: flags are an input
 *			    that the caller fills in before the ioctl;
 *			    slot_uid is the output the kernel writes on
 *			    success.
 *
 *			    Old userspace that only knows about NE_CREATE_VM
 *			    continues to work unchanged; this ioctl is
 *			    additive.  New userspace should call this one
 *			    whenever it wants to request a specific slot
 *			    backing kind (legacy vs PCIE enclave), a direct
 *			    (non-confidential) slot, or any of the matched
 *			    enclave capability bits.
 *
 * Context: Process context.
 * Return:
 * * Enclave file descriptor		- As for NE_CREATE_VM.
 * *  -1				- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT				- copy_to_user() / copy_from_user() failure.
 * * EINVAL				- Unknown flag bits, or DEBUG set (DEBUG
 *					  belongs on NE_START_ENCLAVE).
 * * ENOMEM				- Memory allocation failure for internal
 *					  bookkeeping variables.
 * * NE_ERR_NO_CPUS_AVAIL_IN_POOL	- No NE CPU pool set / no CPUs available
 *					  in the pool.
 * * Error codes from get_unused_fd_flags() and anon_inode_getfile().
 * * Error codes from the NE PCI device request.
 */
#define NE_CREATE_VM2		_IOWR(0xAE, 0x30, struct ne_create_vm_args)

/**
 * NE_ADD_VCPU - The command is used to set a vCPU for an enclave. The vCPU can
 *		 be auto-chosen from the NE CPU pool or it can be set by the
 *		 caller, with the note that it needs to be available in the NE
 *		 CPU pool. Full CPU core(s), from the same NUMA node, need(s) to
 *		 be associated with an enclave.
 *		 The vCPU id is an input / output parameter. If its value is 0,
 *		 then a CPU is chosen from the enclave CPU pool and returned via
 *		 this parameter.
 *		 The ioctl can be invoked on the enclave fd, before an enclave
 *		 is started.
 *
 * Context: Process context.
 * Return:
 * * 0					- Logic successfully completed.
 * *  -1				- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT				- copy_from_user() / copy_to_user() failure.
 * * ENOMEM				- Memory allocation failure for internal
 *					  bookkeeping variables.
 * * EIO				- Current task mm is not the same as the one
 *					  that created the enclave.
 * * NE_ERR_NO_CPUS_AVAIL_IN_POOL	- No CPUs available in the NE CPU pool.
 * * NE_ERR_VCPU_ALREADY_USED		- The provided vCPU is already used.
 * * NE_ERR_VCPU_NOT_IN_CPU_POOL	- The provided vCPU is not available in the
 *					  NE CPU pool.
 * * NE_ERR_VCPU_INVALID_CPU_CORE	- The core id of the provided vCPU is invalid
 *					  or out of range.
 * * NE_ERR_NOT_IN_INIT_STATE		- The enclave is not in init state
 *					  (init = before being started).
 * * NE_ERR_INVALID_VCPU		- The provided vCPU is not in the available
 *					  CPUs range.
 * * Error codes from the NE PCI device request.
 */
#define NE_ADD_VCPU			_IOWR(0xAE, 0x21, __u32)

/**
 * struct ne_add_any_vcpu_args - NE_ADD_ANY_VCPU ioctl payload.
 * @numa_hint:	Host NUMA node to take the vCPU from. The kernel picks an
 *		unused core on that node and fails rather than crossing to
 *		another node, so an enclave's vCPUs and memory stay on the
 *		nodes it asked for. A node that is not a possible node is
 *		rejected with EINVAL. Use NE_NUMA_ANY (== -1) to take a core
 *		from any node.
 *
 *		One exception, on dedicated cores only: when the enclave
 *		already owns a core with a free sibling thread, that thread is
 *		handed out first to keep full cores together, whatever
 *		@numa_hint says. Pass the same node for every vCPU of an
 *		enclave to stay on one node.
 *
 * The struct wraps the single field so the ABI can grow additional input
 * flags later without renumbering the ioctl.
 */
struct ne_add_any_vcpu_args {
	__s32	numa_hint;
};

/**
 * NE_NUMA_ANY - Sentinel for ne_add_any_vcpu_args::numa_hint. Picks from any
 *		 NUMA node, with no node preference.
 */
#define NE_NUMA_ANY			((__s32)-1)

/**
 * NE_ADD_ANY_VCPU - Atomically pick and add a vCPU to the enclave, optionally
 *		     biased toward a preferred host NUMA node.
 *
 *		     The pick-and-commit happens under ne_cpu_pool.mutex, so
 *		     concurrent callers from independent enclave fds cannot
 *		     race for the same CPU.
 *
 *		     Designed for VMM userspaces (QEMU's nitro accelerator)
 *		     that resolve guest vCPU NUMA from -numa and want their
 *		     enclave vCPU pinned on the matching host node, without
 *		     any TOCTOU window between picking the CPU in userspace
 *		     and adding it via NE_ADD_VCPU.
 *
 *		     Legacy callers that need to pass an explicit cpu_id
 *		     (raw nitro-cli, custom userspaces) continue to use
 *		     NE_ADD_VCPU; that path is unchanged.  The kernel still
 *		     tracks which physical CPU was picked via the per-enclave
 *		     threads_per_core bitmap; no userspace round-trip is
 *		     needed and none is provided here.
 *
 * Context: Process context.
 * Return:
 * * 0					- Logic successfully completed.
 * *  -1				- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT				- copy_from_user() failure.
 * * EINVAL				- @numa_hint is not a possible node.
 * * NE_ERR_INVALID_VCPU		- No free vCPU id on @numa_hint
 *					  (overcommit enclaves).
 * * NE_ERR_NO_CPUS_AVAIL_IN_POOL	- No CPUs available in the NE CPU pool.
 * * NE_ERR_NOT_IN_INIT_STATE		- The enclave is not in init state.
 * * Error codes from the NE PCI device request.
 */
#define NE_ADD_ANY_VCPU			_IOW(0xAE, 0x2D, struct ne_add_any_vcpu_args)

/**
 * NE_GET_IMAGE_LOAD_INFO - The command is used to get information needed for
 *			    in-memory enclave image loading e.g. offset in
 *			    enclave memory to start placing the enclave image.
 *			    The image load info is an input / output parameter.
 *			    It includes info provided by the caller - flags -
 *			    and returns the offset in enclave memory where to
 *			    start placing the enclave image.
 *			    The ioctl can be invoked on the enclave fd, before
 *			    an enclave is started.
 *
 * Context: Process context.
 * Return:
 * * 0				- Logic successfully completed.
 * *  -1			- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT			- copy_from_user() / copy_to_user() failure.
 * * NE_ERR_NOT_IN_INIT_STATE	- The enclave is not in init state (init =
 *				  before being started).
 * * NE_ERR_INVALID_FLAG_VALUE	- The value of the provided flag is invalid.
 */
#define NE_GET_IMAGE_LOAD_INFO		_IOWR(0xAE, 0x22, struct ne_image_load_info)

/**
 * NE_SET_USER_MEMORY_REGION - The command is used to set a memory region for an
 *			       enclave, given the allocated memory from the
 *			       userspace. Enclave memory needs to be from the
 *			       same NUMA node as the enclave CPUs.
 *			       The user memory region is an input parameter. It
 *			       includes info provided by the caller - flags,
 *			       memory size and userspace address.
 *			       The ioctl can be invoked on the enclave fd,
 *			       before an enclave is started.
 *
 * Context: Process context.
 * Return:
 * * 0					- Logic successfully completed.
 * *  -1				- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT				- copy_from_user() failure.
 * * EINVAL				- Invalid physical memory region(s) e.g.
 *					  unaligned address.
 * * EIO				- Current task mm is not the same as
 *					  the one that created the enclave.
 * * ENOMEM				- Memory allocation failure for internal
 *					  bookkeeping variables.
 * * NE_ERR_NOT_IN_INIT_STATE		- The enclave is not in init state
 *					  (init = before being started).
 * * NE_ERR_INVALID_MEM_REGION_SIZE	- The memory size of the region is not
 *					  multiple of 2 MiB.
 * * NE_ERR_INVALID_MEM_REGION_ADDR	- Invalid user space address given.
 * * NE_ERR_UNALIGNED_MEM_REGION_ADDR	- Unaligned user space address given.
 * * NE_ERR_MEM_REGION_ALREADY_USED	- The memory region is already used.
 * * NE_ERR_MEM_NOT_HUGE_PAGE		- The memory region is not backed by
 *					  huge pages.
 * * NE_ERR_MEM_DIFFERENT_NUMA_NODE	- The memory region is not from the same
 *					  NUMA node as the CPUs.
 * * NE_ERR_MEM_MAX_REGIONS		- The number of memory regions set for
 *					  the enclave reached maximum.
 * * NE_ERR_INVALID_PAGE_SIZE		- The memory region is not backed by
 *					  pages multiple of 2 MiB.
 * * NE_ERR_INVALID_FLAG_VALUE		- The value of the provided flag is invalid.
 * * Error codes from get_user_pages().
 * * Error codes from the NE PCI device request.
 */
#define NE_SET_USER_MEMORY_REGION	_IOW(0xAE, 0x23, struct ne_user_memory_region)

/**
 * NE_SET_INFO_PAGE - Register an info page for PCI topology mode. The info
 *		      page is a 2 MiB huge-page-backed memory region provided
 *		      by userspace. The kernel pins the page and passes its
 *		      physical address to the hypervisor via SLOT_ADD_INFO_PAGE
 *		      from this ioctl, before returning to userspace.
 *		      The ioctl can be invoked on the enclave fd, before an
 *		      enclave is started.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * -1 on failure (errno set).
 */
#define NE_SET_INFO_PAGE		_IOW(0xAE, 0x25, struct ne_info_page)

/**
 * NE_START_ENCLAVE - The command is used to trigger enclave start after the
 *		      enclave resources, such as memory and CPU, have been set.
 *		      The enclave start info is an input / output parameter. It
 *		      includes info provided by the caller - enclave cid and
 *		      flags - and returns the cid (if input cid is 0).
 *		      The ioctl can be invoked on the enclave fd, after an
 *		      enclave slot is created and resources, such as memory and
 *		      vCPUs are set for an enclave.
 *
 * Context: Process context.
 * Return:
 * * 0					- Logic successfully completed.
 * *  -1				- There was a failure in the ioctl logic.
 * On failure, errno is set to:
 * * EFAULT				- copy_from_user() / copy_to_user() failure.
 * * NE_ERR_NOT_IN_INIT_STATE		- The enclave is not in init state
 *					  (init = before being started).
 * * NE_ERR_NO_MEM_REGIONS_ADDED	- No memory regions are set.
 * * NE_ERR_NO_VCPUS_ADDED		- No vCPUs are set.
 * *  NE_ERR_FULL_CORES_NOT_USED	- Full core(s) not set for the enclave.
 * * NE_ERR_ENCLAVE_MEM_MIN_SIZE	- Enclave memory is less than minimum
 *					  memory size (64 MiB).
 * * NE_ERR_INVALID_FLAG_VALUE		- The value of the provided flag is invalid.
 * *  NE_ERR_INVALID_ENCLAVE_CID	- The provided enclave CID is invalid.
 * * Error codes from the NE PCI device request.
 */
#define NE_START_ENCLAVE		_IOWR(0xAE, 0x24, struct ne_enclave_start_info)

/**
 * struct ne_account_vcpu_params - NE_ACCOUNT_VCPU ioctl payload.
 * @vcpu_idx:	Zero-based enclave vCPU index to bind the caller task to.
 *		The driver records the (task, vcpu_idx) tuple in the
 *		enclave's accounted-vCPU list and its 100 Hz hrtimer
 *		attributes KVM_RUN time read from the info page to the
 *		bound task via account_guest_time().
 * @reserved:	MUST be zero. Reserved for future per-binding flags.
 */
struct ne_account_vcpu_params {
	__u32	vcpu_idx;
	__u32	reserved;
};

/**
 * NE_ACCOUNT_VCPU - Bind the caller task to an enclave vCPU for host-side
 *		     per-vCPU time accounting (Parent-PID visibility).
 *
 *		     Only valid on an enclave that was started with
 *		     NE_ENCLAVE_CPU_ACCOUNTING_MODE and has already been
 *		     through NE_START_ENCLAVE. The driver pins the current
 *		     task via get_task_struct(), records it in the
 *		     enclave's accounted-vCPU list, and arms the per-enclave
 *		     100 Hz hrtimer if not already running. The ioctl
 *		     returns immediately; the caller is expected to stay
 *		     resident (e.g. block in pause()) so the pinned
 *		     task_struct remains a valid attribution target.
 *
 *		     The 100 Hz hrtimer walks all bound tasks, reads the
 *		     cumulative per-vCPU ns counter from the info page
 *		     (location discovered via SLOT_VCPU_TIME at enclave
 *		     start), and calls account_guest_time() so the delta
 *		     lands in the task's utime/gtime and in
 *		     kernel_cpustat[CPUTIME_GUEST].
 *
 * Context: Process context.
 * Return:
 * * 0			- Binding recorded.
 * * -EFAULT		- copy_from_user() failure.
 * * -EINVAL		- vcpu_idx out of range, reserved != 0, or the
 *			  enclave was not started with CPU_ACCOUNTING.
 * * -NE_ERR_NOT_IN_RUNNING_STATE - Enclave has not yet been started.
 */
#define NE_ACCOUNT_VCPU			_IOW(0xAE, 0x2A, struct ne_account_vcpu_params)

/**
 * NE_UPDATE_DEVICE_CONFIG - Push updated device-specific config to a running
 *			     enclave.  The config blob replaces the device's
 *			     config space from offset 0 and triggers a config
 *			     change interrupt to the enclave guest.
 *
 * Context: Process context.  Enclave must be in RUNNING state.
 * Return:
 * * 0			- Config update delivered successfully.
 * * -EFAULT		- copy_from_user() failure.
 * * -EINVAL		- config_size is 0 or exceeds NE_UPDATE_CONFIG_MAX_SIZE.
 * * -NE_ERR_NOT_IN_RUNNING_STATE - Enclave is not in RUNNING state.
 * * -NE_ERR_INVALID_DEVICE - device_uid does not belong to this enclave.
 */
#define NE_UPDATE_CONFIG_MAX_SIZE	64

#define NE_UPDATE_DEVICE_CONFIG		_IOW(0xAE, 0x2C, struct ne_update_device_config)

/**
 * DOC: NE specific error codes
 */

/**
 * NE_ERR_VCPU_ALREADY_USED - The provided vCPU is already used.
 */
#define NE_ERR_VCPU_ALREADY_USED		(256)
/**
 * NE_ERR_VCPU_NOT_IN_CPU_POOL - The provided vCPU is not available in the
 *				 NE CPU pool.
 */
#define NE_ERR_VCPU_NOT_IN_CPU_POOL		(257)
/**
 * NE_ERR_VCPU_INVALID_CPU_CORE - The core id of the provided vCPU is invalid
 *				  or out of range of the NE CPU pool.
 */
#define NE_ERR_VCPU_INVALID_CPU_CORE		(258)
/**
 * NE_ERR_INVALID_MEM_REGION_SIZE - The user space memory region size is not
 *				    multiple of 2 MiB.
 */
#define NE_ERR_INVALID_MEM_REGION_SIZE		(259)
/**
 * NE_ERR_INVALID_MEM_REGION_ADDR - The user space memory region address range
 *				    is invalid.
 */
#define NE_ERR_INVALID_MEM_REGION_ADDR		(260)
/**
 * NE_ERR_UNALIGNED_MEM_REGION_ADDR - The user space memory region address is
 *				      not aligned.
 */
#define NE_ERR_UNALIGNED_MEM_REGION_ADDR	(261)
/**
 * NE_ERR_MEM_REGION_ALREADY_USED - The user space memory region is already used.
 */
#define NE_ERR_MEM_REGION_ALREADY_USED		(262)
/**
 * NE_ERR_MEM_NOT_HUGE_PAGE - The user space memory region is not backed by
 *			      contiguous physical huge page(s).
 */
#define NE_ERR_MEM_NOT_HUGE_PAGE		(263)
/**
 * NE_ERR_MEM_DIFFERENT_NUMA_NODE - The user space memory region is backed by
 *				    pages from different NUMA nodes than the CPUs.
 */
#define NE_ERR_MEM_DIFFERENT_NUMA_NODE		(264)
/**
 * NE_ERR_MEM_MAX_REGIONS - The supported max memory regions per enclaves has
 *			    been reached.
 */
#define NE_ERR_MEM_MAX_REGIONS			(265)
/**
 * NE_ERR_NO_MEM_REGIONS_ADDED - The command to start an enclave is triggered
 *				 and no memory regions are added.
 */
#define NE_ERR_NO_MEM_REGIONS_ADDED		(266)
/**
 * NE_ERR_NO_VCPUS_ADDED - The command to start an enclave is triggered and no
 *			   vCPUs are added.
 */
#define NE_ERR_NO_VCPUS_ADDED			(267)
/**
 * NE_ERR_ENCLAVE_MEM_MIN_SIZE - The enclave memory size is lower than the
 *				 minimum supported.
 */
#define NE_ERR_ENCLAVE_MEM_MIN_SIZE		(268)
/**
 * NE_ERR_FULL_CORES_NOT_USED - The command to start an enclave is triggered and
 *				full CPU cores are not set.
 */
#define NE_ERR_FULL_CORES_NOT_USED		(269)
/**
 * NE_ERR_NOT_IN_INIT_STATE - The enclave is not in init state when setting
 *			      resources or triggering start.
 */
#define NE_ERR_NOT_IN_INIT_STATE		(270)
/**
 * NE_ERR_INVALID_VCPU - The provided vCPU is out of range of the available CPUs.
 */
#define NE_ERR_INVALID_VCPU			(271)
/**
 * NE_ERR_NO_CPUS_AVAIL_IN_POOL - The command to create an enclave is triggered
 *				  and no CPUs are available in the pool.
 */
#define NE_ERR_NO_CPUS_AVAIL_IN_POOL		(272)
/**
 * NE_ERR_INVALID_PAGE_SIZE - The user space memory region is not backed by pages
 *			      multiple of 2 MiB.
 */
#define NE_ERR_INVALID_PAGE_SIZE		(273)
/**
 * NE_ERR_INVALID_FLAG_VALUE - The provided flag value is invalid.
 */
#define NE_ERR_INVALID_FLAG_VALUE		(274)
/**
 * NE_ERR_INVALID_ENCLAVE_CID - The provided enclave CID is invalid, either
 *				being a well-known value or the CID of the
 *				parent / primary VM.
 */
#define NE_ERR_INVALID_ENCLAVE_CID		(275)
/**
 * NE_ERR_NOT_IN_RUNNING_STATE - The enclave is not in running state when
 *				 issuing a command that requires a running enclave.
 */
#define NE_ERR_NOT_IN_RUNNING_STATE		(276)

/**
 * DOC: NE enclave-device error codes
 *
 * Returned by the enclave device (not the NE driver), shifted up by
 * %NE_ERR_DEVICE_SHIFT so they occupy 532..554, disjoint from the driver's own
 * codes (256..276).  Subtract %NE_ERR_DEVICE_SHIFT to recover the native value.
 */

/**
 * NE_ERR_DEVICE_SHIFT - Offset added to an enclave-device error code before it
 *			 reaches userspace, keeping device and driver ranges apart.
 */
#define NE_ERR_DEVICE_SHIFT			(256)
/**
 * NE_ERR_INVALID_FLAGS - The command's reserved flags field was nonzero.
 */
#define NE_ERR_INVALID_FLAGS			(532)
/**
 * NE_ERR_INVALID_ALIGNMENT - Info page address or size is misaligned or too
 *			      small.
 */
#define NE_ERR_INVALID_ALIGNMENT		(533)
/**
 * NE_ERR_INVALID_SIZE - A size or count field is zero, too large, or too short.
 */
#define NE_ERR_INVALID_SIZE			(534)
/**
 * NE_ERR_INVALID_SLOT - The referenced enclave slot does not exist.
 */
#define NE_ERR_INVALID_SLOT			(535)
/**
 * NE_ERR_INVALID_DEVICE - The request names an invalid device, address, or
 *			   memory range.
 */
#define NE_ERR_INVALID_DEVICE			(536)
/**
 * NE_ERR_TOO_MANY_DEVICES - The per-enclave device limit has been reached.
 */
#define NE_ERR_TOO_MANY_DEVICES			(537)
/**
 * NE_ERR_TOO_MANY_VQS - The per-device virtqueue limit has been reached.
 */
#define NE_ERR_TOO_MANY_VQS			(538)
/**
 * NE_ERR_NO_RESOURCES - The device could not allocate an internal resource.
 */
#define NE_ERR_NO_RESOURCES			(539)
/**
 * NE_ERR_ALREADY_EXISTS - An info page is already registered for this slot.
 */
#define NE_ERR_ALREADY_EXISTS			(540)
/**
 * NE_ERR_MISSING_INFO_PAGE - Required info page is missing or too small.
 */
#define NE_ERR_MISSING_INFO_PAGE		(541)
/**
 * NE_ERR_INVALID_FLAG - An unknown or not-permitted flag bit was set.
 */
#define NE_ERR_INVALID_FLAG			(542)
/**
 * NE_ERR_RESERVED_FLAG - A reserved flag bit was set.
 */
#define NE_ERR_RESERVED_FLAG			(543)
/**
 * NE_ERR_MISSING_PCIE - A PCIe-dependent flag was set without the PCIe flag.
 */
#define NE_ERR_MISSING_PCIE			(544)
/**
 * NE_ERR_INCOMPATIBLE_FLAGS - The requested flag combination is not allowed.
 */
#define NE_ERR_INCOMPATIBLE_FLAGS		(545)
/**
 * NE_ERR_EIF_FLAG_MISMATCH - The image's matched flags differ from those
 *			      requested at enclave start.
 */
#define NE_ERR_EIF_FLAG_MISMATCH		(546)
/**
 * NE_ERR_DEVICE_DISALLOWED - The requested device type is not permitted.
 */
#define NE_ERR_DEVICE_DISALLOWED		(547)
/**
 * NE_ERR_HOTPLUG_DISABLED - Device hotplug is disabled for this enclave.
 */
#define NE_ERR_HOTPLUG_DISABLED			(548)
/**
 * NE_ERR_BAD_EIF - The enclave image is missing or failed validation at start.
 */
#define NE_ERR_BAD_EIF				(549)
/**
 * NE_ERR_MISSING_PCIE_VIRTIO - A dependent flag was set without the virtio-PCIe
 *			       flag.
 */
#define NE_ERR_MISSING_PCIE_VIRTIO		(550)
/**
 * NE_ERR_BAD_PAYLOAD_VERSION - Request payload version is unsupported or
 *			       malformed.
 */
#define NE_ERR_BAD_PAYLOAD_VERSION		(551)
/**
 * NE_ERR_INFO_VECTORS_EXHAUSTED - No free notification vectors remain.
 */
#define NE_ERR_INFO_VECTORS_EXHAUSTED		(552)
/**
 * NE_ERR_ENCLAVE_LIMIT - The per-instance PCIE enclave quota has been reached.
 *			  The hypervisor enforces a per-instance limit derived
 *			  from the parent instance's vCPU count, and holds
 *			  flexible-mode enclaves to a lower ceiling derived
 *			  from the same count.  This is a terminal rejection:
 *			  do not retry or donate pages.
 */
#define NE_ERR_ENCLAVE_LIMIT			(553)
/**
 * NE_ERR_NO_MEM_SLOTS_ON_NODE - Per-NUMA-node memory budget exhausted; distinct
 *				 from -ENOSPC (aggregate budget).
 */
#define NE_ERR_NO_MEM_SLOTS_ON_NODE		(554)

/**
 * DOC: Image load info flags
 */

/**
 * NE_EIF_IMAGE - Enclave Image Format (EIF)
 */
#define NE_EIF_IMAGE			(0x01)

#define NE_IMAGE_LOAD_MAX_FLAG_VAL	(0x02)

/**
 * struct ne_image_load_info - Info necessary for in-memory enclave image
 *			       loading (in / out).
 * @flags:		Flags to determine the enclave image type
 *			(e.g. Enclave Image Format - EIF) (in).
 * @memory_offset:	Offset in enclave memory where to start placing the
 *			enclave image (out).
 */
struct ne_image_load_info {
	__u64	flags;
	__u64	memory_offset;
};

/**
 * DOC: User memory region flags
 */

/**
 * NE_DEFAULT_MEMORY_REGION - Memory region for enclave general usage.
 */
#define NE_DEFAULT_MEMORY_REGION	(0x00)

#define NE_MEMORY_REGION_MAX_FLAG_VAL	(0x01)

/**
 * struct ne_user_memory_region - Memory region to be set for an enclave (in).
 * @flags:		Flags to determine the usage for the memory region (in).
 * @memory_size:	The size, in bytes, of the memory region to be set for
 *			an enclave (in).
 * @userspace_addr:	The start address of the userspace allocated memory of
 *			the memory region to set for an enclave (in).
 */
struct ne_user_memory_region {
	__u64	flags;
	__u64	memory_size;
	__u64	userspace_addr;
};

/**
 * DOC: Enclave start info flags
 */

/**
 * NE_ENCLAVE_PRODUCTION_MODE - Start enclave in production mode.
 */
#define NE_ENCLAVE_PRODUCTION_MODE	(0x00)
/**
 * NE_ENCLAVE_DEBUG_MODE - Start enclave in debug mode (unmatched, bit 0).
 */
#define NE_ENCLAVE_DEBUG_MODE		(1u << 0)
/**
 * NE_ENCLAVE_DIRECT_MODE - Start enclave in direct (non-confidential) mode:
 *			    no NSM attestation, parent has full memory
 *			    visibility (unmatched, bit 1). Requires
 *			    NE_ENCLAVE_PCIE_MODE.
 */
#define NE_ENCLAVE_DIRECT_MODE		(1u << 1)
/**
 * NE_ENCLAVE_PCIE_MODE - Start enclave with the PCIE device model (matched,
 *			  bit 6). Prerequisite for every other PCIE_* flag
 *			  and for DIRECT.
 */
#define NE_ENCLAVE_PCIE_MODE		(1u << 6)
/**
 * NE_ENCLAVE_PCIE_VSOCK_MODE - Rigid Enclaves-1.5 shape: exactly one
 *				virtio-vsock, cold-add only. Mutually
 *				exclusive with PCIE_VIRTIO and PCIE_HOTPLUG.
 */
#define NE_ENCLAVE_PCIE_VSOCK_MODE	(1u << 7)
/**
 * NE_ENCLAVE_PCIE_HOTPLUG_MODE - Allow NE_ADD_DEVICE after NE_START_ENCLAVE.
 *				  Requires PCIE_VIRTIO; mutually exclusive
 *				  with PCIE_VSOCK.
 */
#define NE_ENCLAVE_PCIE_HOTPLUG_MODE	(1u << 8)
/**
 * NE_ENCLAVE_PCIE_VIRTIO_MODE - Permissive shape: any virtio subtype may
 *				 be attached. Mutually exclusive with
 *				 PCIE_VSOCK.
 */
#define NE_ENCLAVE_PCIE_VIRTIO_MODE	(1u << 9)
/**
 * NE_ENCLAVE_PCIE_ASSIGN_MODE - Enclave may receive PCIe device-assignment
 *				 (PCIE_ASSIGN) donations from the parent VMM:
 *				 the hypervisor mirrors the parent VM's device
 *				 configuration into the enclave VMM, reserves
 *				 the persistent IOMMU bookkeeping segment,
 *				 installs parent-IOVA scratch IOMMU mappings,
 *				 and routes DIRECT-class SLOT_ADD_DEVICE
 *				 through the donated-pool path. Requires
 *				 NE_ENCLAVE_PCIE_MODE (matched, bit 10).
 */
#define NE_ENCLAVE_PCIE_ASSIGN_MODE	(1u << 10)
/**
 * NE_ENCLAVE_CPU_OVERCOMMIT_MODE - Start enclave with host-scheduled (floating)
 *				    vCPUs that share the parent's overcommit
 *				    pool via CFS, rather than pinned to
 *				    dedicated cores. Requires
 *				    NE_ENCLAVE_PCIE_MODE and
 *				    NE_ENCLAVE_PCIE_VIRTIO_MODE; the parent
 *				    instance must itself be an overcommit
 *				    instance (matched, bit 11).
 */
#define NE_ENCLAVE_CPU_OVERCOMMIT_MODE	(1u << 11)
/**
 * NE_ENCLAVE_CPU_ACCOUNTING_MODE - Opt into host-side per-vCPU time
 *				    accounting (Parent-PID visibility).
 *				    When set, the driver queries the per-vCPU
 *				    time-counter array location from the
 *				    hypervisor via SLOT_VCPU_TIME after slot
 *				    allocation and exposes a NE_ACCOUNT_VCPU
 *				    ioctl for QEMU to bind its per-vCPU
 *				    pthreads for CPUTIME_GUEST attribution.
 *
 *				    Requires NE_ENCLAVE_PCIE_MODE: the
 *				    counter array piggybacks on the shared
 *				    info page registered via
 *				    SLOT_ADD_INFO_PAGE.
 *
 *				    Independent of NE_ENCLAVE_CPU_OVERCOMMIT_MODE:
 *				    may be combined with it (the typical
 *				    overcommit-enclave use case) or used
 *				    alone. Matched, bit 12; the EIF's
 *				    matched bits must declare the same value.
 */
#define NE_ENCLAVE_CPU_ACCOUNTING_MODE	(1u << 12)
/**
 * NE_ENCLAVE_PCIE_NUMA_MODE - Request an explicit multi-NUMA enclave (matched,
 *			       bit 13). The flag word is forwarded verbatim to
 *			       the device's slot-allocation flags word, where
 *			       this bit is the PCIE_NUMA launch flag; the
 *			       hypervisor uses it to gate building a >1-node
 *			       guest SRAT/SLIT: without it, a slot whose vCPUs
 *			       and memory land on different nodes is rejected at
 *			       start and the launch fails with -EIO.  Requires
 *			       NE_ENCLAVE_PCIE_MODE.
 */
#define NE_ENCLAVE_PCIE_NUMA_MODE	(1u << 13)

/* Mask of unmatched flags: caller picks independently of what the EIF declares. */
#define NE_ENCLAVE_FLAG_UNMATCHED_MASK	(0x003fu)
/* Mask of matched flags: must equal the EIF's matched bits at START. */
#define NE_ENCLAVE_FLAG_MATCHED_MASK	(0xffc0u)
/* Union of all defined flag bits. */
#define NE_ENCLAVE_FLAG_VALID_MASK	(NE_ENCLAVE_DEBUG_MODE | \
					 NE_ENCLAVE_DIRECT_MODE | \
					 NE_ENCLAVE_PCIE_MODE | \
					 NE_ENCLAVE_PCIE_VSOCK_MODE | \
					 NE_ENCLAVE_PCIE_HOTPLUG_MODE | \
					 NE_ENCLAVE_PCIE_VIRTIO_MODE | \
					 NE_ENCLAVE_PCIE_ASSIGN_MODE | \
					 NE_ENCLAVE_CPU_OVERCOMMIT_MODE | \
					 NE_ENCLAVE_CPU_ACCOUNTING_MODE | \
					 NE_ENCLAVE_PCIE_NUMA_MODE)

/**
 * struct ne_enclave_start_info - Setup info necessary for enclave start (in / out).
 * @flags:		Flags for the enclave to start with (e.g. debug mode) (in).
 * @enclave_cid:	Context ID (CID) for the enclave vsock device. If 0 as
 *			input, the CID is autogenerated by the hypervisor and
 *			returned back as output by the driver (in / out).
 */
struct ne_enclave_start_info {
	__u64	flags;
	__u64	enclave_cid;
};

/**
 * struct ne_info_page - Info page registration (in).
 * @userspace_addr:	Userspace address of the info page (2 MiB aligned,
 *			must be backed by a 2 MiB huge page).
 * @size:		Size of the info page region (must be 2 MiB).
 */
struct ne_info_page {
	__u64	userspace_addr;
	__u64	size;
};

/**
 * NE_ADD_DEVICE - Add a device to the enclave. Must be called after
 * NE_START_ENCLAVE with NE_ENCLAVE_PCIE_MODE.
 *
 * Two device classes are supported, distinguished by the class bits
 * (bits 31..16) of ne_add_device.device_type:
 *
 *   NE_DEVICE_CLASS_VIRTIO (0x0000)
 *	virtio device. The device backing memory (DMB) is provided by
 *	userspace and shared with the enclave via num_shm_regions /
 *	shm_regions_ptr.
 *
 *   NE_DEVICE_CLASS_DIRECT (0x0001)
 *	Passthrough PCIe device grant (PCIE_ASSIGN). device_config carries
 *	a struct ne_pcie_assign_device_config (8 bytes). config_size must
 *	be 8, num_vqs must be 0, num_shm_regions must be 0, and
 *	device_features must be all-zero. vq_info is not populated on
 *	reply; only device_uid is.
 */
#define NE_ADD_DEVICE			_IOWR(0xAE, 0x26, struct ne_add_device)

#define NE_DEVICE_CLASS_VIRTIO		(0x0000)
#define NE_DEVICE_CLASS_DIRECT		(0x0001)
#define NE_MAX_VQS			(64)
#define NE_DEVICE_CONFIG_MAX_SIZE	(256)

/**
 * struct ne_pcie_assign_device_config - device_config payload for
 * NE_DEVICE_CLASS_DIRECT.
 * @parent_guest_sbdf:	Parent-guest SBDF of the passthrough VF to grant to
 *			the enclave slot (bus<<8 | device<<3 | function).
 *			The enclave sees the device at the same SBDF; this
 *			invariant is enforced at enclave launch by matching
 *			parent and enclave PCIe topologies.
 * @reserved:		Must be zero.
 * @flags:		Bit 0 = NE_PCIE_ASSIGN_RETAIN_IN_FREE_POOL. Other
 *			bits must be zero.
 *
 * Serialized into ne_add_device.device_config[0..7]. The kernel passes
 * this payload verbatim to the hypervisor as the SLOT_ADD_DEVICE(DIRECT)
 * device_config. Userspace must set ne_add_device.config_size = 8.
 */
struct ne_pcie_assign_device_config {
	__u16	parent_guest_sbdf;
	__u16	reserved;
	__u32	flags;
};

/*
 * Flag bits for struct ne_pcie_assign_device_config.flags. They mirror the
 * hypervisor's retain-in-free-pool behavior for direct assignment.
 */
#define NE_PCIE_ASSIGN_RETAIN_IN_FREE_POOL	(1u << 0)

/**
 * struct ne_shm_region - Shared memory region descriptor (userspace → kernel).
 * @shm_id:		SHM region identifier (0 = DMB, 1+ = virtio SHM regions).
 * @reserved:		Must be zero.
 * @userspace_addr:	Userspace virtual address of the mmap'd region.
 * @size:		Size in bytes.
 */
struct ne_shm_region {
	__u8	shm_id;
	__u8	reserved[7];
	__u64	userspace_addr;
	/*
	 * Size of the shared memory region in bytes.
	 * The kernel packs the shm_id into the hypervisor
	 * backing-range descriptor internally; userspace must
	 * supply a plain byte count here.
	 */
	__u64	size;
};

struct ne_vq_info {
	__u16	msix_vector;
	__u16	notify_index;
	__u16	msix_entry;		/* opaque MSI-X table index (hypervisor) */
	__u16	bar4_doorbell_offset;	/* opaque BAR4 byte offset (hypervisor) */
};

/**
 * struct ne_add_device - Device add request (in / out).
 * @device_type:	Device type (class << 16 | subtype) (in).
 * @num_vqs:		Number of virtqueues (in).
 * @config_size:	Size of device-specific config (in).
 * @device_features:	Virtio device feature bitmap, 512 bits (in).
 * @device_config:	Device-specific configuration data (in).
 * @num_shm_regions:	Number of shared memory regions (in).
 * @shm_regions_ptr:	Userspace pointer to array of struct ne_shm_region (in).
 * @device_uid:		Assigned device UID (out).
 * @vq_info:		Per-VQ MSI-X vector and notify index (out).
 */
struct ne_add_device {
	__u32	device_type;
	__u32	num_vqs;
	__u32	config_size;
	/*
	 * Per-device info-event MSI-X vector assigned by the hypervisor.
	 * Populated by the driver on successful NE_ADD_DEVICE for
	 * VIRTIO-class devices; zero for DIRECT-class devices (which
	 * don't use the info page).  Userspace passes this value back
	 * into NE_SET_INFO_EVENT_FD to register an eventfd for the
	 * per-device info-page change signal.
	 *
	 * Repurposes what was `__u32 reserved` at offset 12.  Userspace
	 * that pre-dates this field wrote zero to reserved; the driver
	 * ignores the input value and overwrites it with the hypervisor-
	 * returned vector on output.
	 */
	__u16	info_event_vector;
	__u16	reserved;
	__u8	device_features[64];
	__u8	device_config[NE_DEVICE_CONFIG_MAX_SIZE];
	__u32	num_shm_regions;
	__u32	reserved2;
	__u64	shm_regions_ptr;
	__u64	device_uid;
	struct ne_vq_info vq_info[NE_MAX_VQS];
};

/**
 * NE_SET_VRING_CALL - Wire an eventfd to a BAR4 notify offset.
 * When the eventfd is signaled (by vhost), the driver writes to BAR4 at
 * the specified offset, notifying the enclave that a vring has new data.
 * Named from vhost's perspective: this is the "call" fd that vhost uses
 * to notify the guest.
 */
struct ne_vring_call {
	__u64	device_uid;
	__s32	fd;		/* eventfd to monitor */
	__u16	bar4_doorbell_offset;	/* opaque BAR4 byte offset (hypervisor) */
	__u16	reserved;
};
#define NE_SET_VRING_CALL		_IOW(0xAE, 0x27, struct ne_vring_call)

/**
 * NE_SET_VRING_KICK - Wire an enclave-device MSI-X vector to an eventfd.
 * When the enclave kicks a vring (MSI-X fires on the parent), the driver
 * signals the eventfd so vhost wakes up and processes the vring.
 * Named from vhost's perspective: this is the "kick" fd that vhost polls.
 */
struct ne_vring_kick {
	__u64	device_uid;
	__s32	fd;		/* eventfd to signal */
	__u16	msix_vector;	/* enclave-device MSI-X vector index */
	__u16	reserved;
};
#define NE_SET_VRING_KICK		_IOW(0xAE, 0x28, struct ne_vring_kick)

/**
 * NE_SET_INFO_EVENT_FD - Wire an eventfd to a per-device info-event
 * MSI-X vector.
 *
 * Userspace creates an eventfd (EFD_NONBLOCK | EFD_CLOEXEC) and passes
 * its fd along with the per-device info_event_vector returned by
 * NE_ADD_DEVICE.  The driver takes an eventfd_ctx reference and binds
 * it into the matching info-event vector slot.  Each subsequent IRQ on
 * that vector wakes the fd, so the frontend can epoll() for info-page
 * change signals.
 *
 * Rebinding (fd >= 0): the old eventfd reference is dropped after an
 * RCU grace period so the IRQ handler cannot observe a stale pointer.
 *
 * Unbinding (fd < 0): same cleanup, leaves the slot empty.  Frontends
 * should unbind before closing their eventfd and before issuing
 * NE_REMOVE_DEVICE (once that command exists).
 *
 * Errors:
 *   -EINVAL       vector is outside the pool advertised at probe.
 *   -EBADF        fd does not refer to an eventfd.
 */
struct ne_info_event_fd {
	__s32	fd;		/* eventfd to signal; -1 to unbind */
	__u16	vector;		/* enclave-device MSI-X vector index
				 * (from ne_add_device.info_event_vector) */
	__u16	reserved;
};
#define NE_SET_INFO_EVENT_FD		_IOW(0xAE, 0x2B, struct ne_info_event_fd)

/**
 * NE_GET_SUPPORTED_FLAGS - Read the matched-flag subset the hypervisor
 *			    implements.
 *
 * Returns the value of the enclave device's supported-flags register as a
 * bitmap of NE_ENCLAVE_*_MODE bits. Frontends use this to avoid requesting
 * flags the running hypervisor doesn't support.
 */
#define NE_GET_SUPPORTED_FLAGS		_IOR(0xAE, 0x29, __u32)

/**
 * struct ne_update_device_config - NE_UPDATE_DEVICE_CONFIG ioctl payload.
 * @device_uid:	Device UID returned by NE_ADD_DEVICE.
 * @config_size: Number of valid bytes in config_data (1..64).
 * @config_offset: Byte offset within the device config space to write at.
 * @config_data: New device-specific config bytes, written at config[config_offset..].
 */
struct ne_update_device_config {
	__u64	device_uid;
	__u32	config_size;
	__u32	config_offset;
	__u8	config_data[NE_UPDATE_CONFIG_MAX_SIZE];
};

#endif /* _UAPI_LINUX_NITRO_ENCLAVES_H_ */
