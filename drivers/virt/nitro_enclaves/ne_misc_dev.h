/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef _NE_MISC_DEV_H_
#define _NE_MISC_DEV_H_

#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "ne_pci_dev.h"

/**
 * struct ne_mem_region - Entry in the enclave user space memory regions list.
 * @mem_region_list_entry:	Entry in the list of enclave memory regions.
 * @memory_size:		Size of the user space memory region.
 * @nr_pages:			Number of pages that make up the memory region.
 * @pages:			Pages that make up the user space memory region.
 * @userspace_addr:		User space address of the memory region.
 */
struct ne_mem_region {
	struct list_head	mem_region_list_entry;
	u64			memory_size;
	unsigned long		nr_pages;
	struct page		**pages;
	u64			userspace_addr;
};

/**
 * struct ne_enclave - Per-enclave data used for enclave lifetime management.
 * @enclave_info_mutex :	Mutex for accessing this internal state.
 * @enclave_list_entry :	Entry in the list of created enclaves.
 * @eventq:			Wait queue used for out-of-band event notifications
 *				triggered from the PCI device event handler to
 *				the enclave process via the poll function.
 * @has_event:			Variable used to determine if the out-of-band event
 *				was triggered.
 * @max_mem_regions:		The maximum number of memory regions that can be
 *				handled by the hypervisor.
 * @mem_regions_list:		Enclave user space memory regions list.
 * @mem_size:			Enclave memory size.
 * @mm :			Enclave process abstraction mm data struct.
 * @nr_mem_regions:		Number of memory regions associated with the enclave.
 * @nr_parent_vm_cores :	The size of the threads per core array. The
 *				total number of CPU cores available on the
 *				parent / primary VM.
 * @nr_threads_per_core:	The number of threads that a full CPU core has.
 * @nr_vcpus:			Number of vcpus associated with the enclave.
 * @numa_node:			NUMA node of the enclave memory and CPUs.
 * @slot_uid:			Slot unique id mapped to the enclave.
 * @state:			Enclave state, updated during enclave lifetime.
 * @threads_per_core:		Enclave full CPU cores array, indexed by core id,
 *				consisting of cpumasks with all their threads.
 *				Full CPU cores are taken from the NE CPU pool
 *				and are available to the enclave.
 * @vcpu_ids:			Cpumask of the vCPUs that are set for the enclave.
 */

/**
 * struct ne_device_pins - Pinned pages for one NE_ADD_DEVICE backing range.
 * @list:	List node for ne_enclave.device_pins_list.
 * @pages:	Array of pinned struct page pointers.
 * @nr_pages:	Number of pinned pages.
 */
struct ne_device_pins {
	struct list_head	list;
	struct page		**pages;
	unsigned long		nr_pages;
};

/**
 * struct ne_kick_binding_entry - Per-enclave tracking entry for one kick_xa
 *				  binding installed by NE_SET_VRING_KICK.
 * @list:	Entry in ne_enclave::kick_bindings.
 * @vq_id:	xarray key (vq_id) the owning enclave installed in
 *		ne_pci_dev->kick_xa.
 *
 * The binding itself (struct ne_mux_binding) lives in kick_xa keyed on
 * @vq_id and is freed via call_rcu() so ne_mux_handler() readers can
 * safely dereference it.  This entry is purely a cleanup-tracking aid:
 * ne_enclave_release() walks the owning enclave's kick_bindings list to
 * xa_erase() each entry, mirroring the body of ne_mux_teardown() but
 * scoped to the releasing enclave so bindings owned by other concurrent
 * enclaves stay visible to the IRQ handler.
 */
struct ne_kick_binding_entry {
	struct list_head	list;
	u64			vq_id;
};

struct ne_mem_sharing_ops;

struct ne_enclave {
	struct mutex		enclave_info_mutex;
	struct list_head	enclave_list_entry;
	wait_queue_head_t	eventq;
	bool			has_event;
	u64			max_mem_regions;
	struct list_head	mem_regions_list;
	u64			mem_size;
	struct mm_struct	*mm;
	unsigned int		nr_mem_regions;
	unsigned int		nr_parent_vm_cores;
	unsigned int		nr_threads_per_core;
	unsigned int		nr_vcpus;
	int			numa_node;
	u64			slot_uid;
	u16			state;
	cpumask_var_t		*threads_per_core;
	cpumask_var_t		vcpu_ids;
	bool			pcie_mode;
	u64			info_page_paddr;
	struct page		**info_pages;
	unsigned long		info_nr_pages;
	struct list_head	device_pins_list;
	/*
	 * DMB bytes the rollback would retain, for the leak report: counted
	 * once SLOT_ADD_DEVICE is submitted, since an abandoned command may
	 * still have donated. Not derivable at teardown, because the notifier
	 * unlinks entries first. A priv_holds kref can outlive a region that
	 * counted nothing, so the report is a floor, not a total.
	 */
	u64			dmb_bytes;
	struct mmu_notifier	mmu_notifier;

	/*
	 * Set once, the first time ne_mmu_notifier_release() drains. The
	 * ->release callback can be invoked twice concurrently during
	 * multi-threaded exit: once by __mmu_notifier_release() from
	 * exit_mmap() and once by mmu_notifier_unregister() from
	 * ne_enclave_release(). The subscription stays hashed across
	 * __mmu_notifier_release()'s release loop (mm/mmu_notifier.c), so a
	 * racing mmu_notifier_unregister() still observes it registered and
	 * invokes ->release a second time. This gate (atomic_cmpxchg) lets
	 * only the first invocation walk the resource lists, so the two never
	 * drain them concurrently and cannot double-free.
	 */
	atomic_t		mmu_release_done;

	/*
	 * Holds on contig vma priv structs.
	 *
	 * NE_SET_USER_MEMORY_REGION on a userspace mapping backed by the
	 * driver's own CMA mapping (vma->vm_ops == &ne_contig_vm_ops)
	 * triggers a host-side ownership move that hands the underlying
	 * physical pages from the parent VMM to the enclave.  The
	 * hypervisor only moves the memory back to the parent in
	 * response to SLOT_FREE.
	 *
	 * Without this list, exit_mmap() runs the priv kref_put before
	 * exit_files() drives ne_enclave_release()/SLOT_FREE: cma_release
	 * returns the pages to the host CMA pool while the host hypervisor
	 * still considers them owned by the dying enclave. The next allocator
	 * that hands those PFNs back to the parent hits an EPT-walk EPERM on
	 * the first guest write and the parent VMM panics.
	 *
	 * Each entry takes an extra kref on the contig priv at
	 * NE_SET_USER_MEMORY_REGION time and is dropped by ne_enclave_release()
	 * AFTER SLOT_FREE has returned successfully, which is the parent-side
	 * half of the "the hypervisor advertises SLOT_FREE only after it has
	 * moved page ownership back / the parent kernel only reuses CMA after
	 * that" contract.
	 *
	 * Protected by @enclave_info_mutex on the add path and by
	 * release-path serialization (no concurrent users after
	 * mmu_notifier_unregister returns) on the drop path.
	 * Entries are struct ne_contig_priv_hold defined in ne_misc_dev.c.
	 */
	struct list_head	priv_holds;
	/*
	 * Enclave ioeventfds (NE_SET_VRING_CALL).  A list of heap-allocated
	 * struct ne_ioeventfd nodes rather than an inline array: each node
	 * embeds a wait_queue_entry_t / poll_table registered on an eventfd
	 * waitqueue and recovered via container_of(), so it only needs a
	 * stable address, not array adjacency.  An inline
	 * ioeventfds[NE_MAX_IOEVENTFDS] array pushed struct ne_enclave into
	 * an order-3 (>4 KiB) allocation that could OOM on CMA-heavy hosts
	 * (see the kvzalloc change).  @num_ioeventfds stays as the counter
	 * enforcing the NE_MAX_IOEVENTFDS cap (BAR4 notify-window capacity).
	 * Both guarded by @enclave_info_mutex on add and drained on release.
	 */
	struct list_head	ioeventfds;
	u32			num_ioeventfds;

	/*
	 * Per-VQ kick_xa bindings owned by this enclave. Each successful
	 * NE_SET_VRING_KICK that installs a new binding (xa_store with
	 * old==NULL) appends an entry to this list under
	 * @enclave_info_mutex.  ne_enclave_release() walks the list and
	 * xa_erase()s each entry, the only path that scopes kick_xa
	 * cleanup to a single enclave.  Without this, kick_xa entries
	 * accumulated for the lifetime of the parent kernel because
	 * ne_mux_teardown() (the only other reaping site) only runs at
	 * driver unload / pci_shutdown.  An orphan binding keeps an
	 * eventfd_ctx reference alive on a long-dead QEMU's eventfd and
	 * (depending on the hypervisor's vq_id allocation policy) can
	 * route a future enclave's kick to the wrong eventfd.
	 *
	 * Bounded by the per-enclave VQ count (~max_pcie_devices times
	 * VQs-per-device), not by a hard array cap, so a list_head is
	 * the right shape.  Entries are struct ne_kick_binding_entry.
	 */
	struct list_head	kick_bindings;

	/*
	 * Total PCIe virtio devices added via NE_ADD_DEVICE.
	 * Used for fail-fast cap enforcement against
	 * ne_pci_dev->max_pcie_devices in ne_handle_add_device() so
	 * userspace gets a clear -EINVAL before the SLOT_ADD_DEVICE
	 * roundtrip.
	 */
	u32			num_pcie_devices;

	/*
	 * Start-time enclave flags captured at NE_CREATE_VM2 time (or
	 * left at zero on legacy NE_CREATE_VM). Used by the driver for
	 * behavior that needs the flag word after slot allocation:
	 * notably the Parent-PID visibility consumer below, which
	 * skips the SLOT_VCPU_TIME query entirely unless
	 * NE_ENCLAVE_CPU_ACCOUNTING_MODE is set, and the NE_ADD_VCPU
	 * path, which skips the dedicated-core pool lookup for
	 * NE_ENCLAVE_CPU_OVERCOMMIT_MODE enclaves.
	 */
	u64			start_flags;

	/*
	 * Parent-PID visibility consumer state.
	 *
	 * When userspace binds a task to an enclave vCPU via
	 * NE_ACCOUNT_VCPU, the driver pins the task, records it in
	 * @accounted_vcpus, and wakes up the per-enclave hrtimer. The
	 * ioctl then returns 0; the caller (QEMU's per-vCPU pthread)
	 * blocks in userspace (pause()) to keep the pinned task alive
	 * until QEMU exits. On each 100 Hz tick the timer reads the
	 * cumulative per-vCPU ns counter from the info page and
	 * attributes the delta to the bound task via
	 * account_guest_time().
	 *
	 * The info page (struct page *@info_page, vaddr cached in
	 * @info_page_vaddr) is shared with the hypervisor. The
	 * hypervisor tells us where the per-vCPU u64 counter array
	 * lives inside it via the SLOT_VCPU_TIME reply, which we cache
	 * as a byte offset + element count in
	 * @vcpu_time_array_offset / @vcpu_time_array_count. The driver
	 * treats the rest of the info page as opaque.
	 *
	 * All of these fields are protected by @accounted_lock, which
	 * is taken by both the ioctl path (process context) and the
	 * hrtimer callback (softirq). @info_page_vaddr is set in the
	 * NE_SET_INFO_PAGE handler after the underlying pages have
	 * been pinned, and stays valid until enclave release.
	 */
	spinlock_t		accounted_lock;
	struct list_head	accounted_vcpus;
	unsigned int		nr_accounted_vcpus;
	void			*info_page_vaddr;
	u32			vcpu_time_array_offset;
	u32			vcpu_time_array_count;

	/*
	 * Entry in the driver-global @ne_accounting_enclaves list.
	 *
	 * Added when NE_ACCOUNT_VCPU binds the first vCPU on this
	 * enclave (accounted_vcpus was empty before); removed on
	 * ne_enclave_drain_accounted_vcpus() at release time. List
	 * walk is performed by the driver-global 100 Hz account_timer
	 * callback, which holds @ne_accounting_lock for the scan.
	 * Per-enclave @accounted_lock nests inside
	 * @ne_accounting_lock.
	 */
	struct list_head	active_link;

	/* NIE sharing ops, NULL on non-NIE platforms. */
	const struct ne_mem_sharing_ops *sharing_ops;
};

/**
 * struct ne_accounted_vcpu - One parent-guest task bound to an enclave vCPU.
 * @list:		Entry in ne_enclave::accounted_vcpus.
 * @task:		The bound task, pinned via get_task_struct().
 * @enclave:		Back-pointer to the owning enclave.
 * @vcpu_idx:		Enclave vCPU index into the info-page counter array.
 * @last_vcpu_time_ns:	Last-observed producer counter value. Updated
 *			from the hrtimer softirq only.
 */
struct ne_accounted_vcpu {
	struct list_head	list;
	struct task_struct	*task;
	struct ne_enclave	*enclave;
	u32			vcpu_idx;
	u64			last_vcpu_time_ns;
};

/**
 * enum ne_state - States available for an enclave.
 * @NE_STATE_INIT:	The enclave has not been started yet.
 * @NE_STATE_RUNNING:	The enclave was started and is running as expected.
 * @NE_STATE_STOPPED:	The enclave exited without userspace interaction.
 */
enum ne_state {
	NE_STATE_INIT		= 0,
	NE_STATE_RUNNING	= 2,
	NE_STATE_STOPPED	= U16_MAX,
};

/**
 * struct ne_devs - Data structure to keep refs to the NE misc and PCI devices.
 * @ne_misc_dev:	Nitro Enclaves misc device.
 * @ne_pci_dev :	Nitro Enclaves PCI device.
 */
struct ne_devs {
	struct miscdevice	*ne_misc_dev;
	struct ne_pci_dev	*ne_pci_dev;
};

/* Nitro Enclaves (NE) data structure for keeping refs to the NE misc and PCI devices. */
extern struct ne_devs ne_devs;

/**
 * ne_cpu_pool_get_stats() - Report dedicated (non-overcommitted) CPU pool
 *			     occupancy, globally or for a single NUMA node.
 * @nid:	NUMA node id, or NUMA_NO_NODE for the whole pool.
 * @total:	Threads dedicated to the pool.
 * @in_use:	Threads currently claimed by enclave(s).
 * @free_cpus:	Threads currently available for allocation.
 */
void ne_cpu_pool_get_stats(int nid, unsigned int *total, unsigned int *in_use,
			   unsigned int *free_cpus);

/**
 * ne_mem_pool_get_stats() - Report NE CMA memory pool occupancy in bytes,
 *			     globally or for a single NUMA node.
 * @nid:	NUMA node id, or NUMA_NO_NODE for the whole pool. A per-node
 *		query sums the regions on that node, including regions
 *		reserved without an explicit node, which are attributed to
 *		the node of their base address.
 * @total:	Bytes reserved in the NE CMA pool.
 * @in_use:	Bytes currently allocated.
 * @free_bytes:	Bytes currently available for allocation.
 */
void ne_mem_pool_get_stats(int nid, u64 *total, u64 *in_use, u64 *free_bytes);

struct cma;

/**
 * ne_alloc_contig() - Allocate a physically contiguous range of pages.
 * @nr_pages:	Number of pages to allocate.
 * @out_cma:	Out-param that receives the originating CMA region.
 * @nid:	NUMA node the pages must come from, or NUMA_NO_NODE for any.
 *		A concrete node is a constraint: the call fails rather than
 *		returning pages from another node.
 *
 * Allocations are served exclusively from the reserved CMA pools (the
 * NE mempool regions, then the generic cma= area); there is no
 * fallback to the general page allocator.
 *
 * Return: First page of the allocation, or NULL on failure.
 */
struct page *ne_alloc_contig(unsigned long nr_pages, struct cma **out_cma,
			     int nid);

/**
 * ne_pcie_slot_donate_one() - Donate one granularity-sized page to the
 * PCIE slot pool.
 * @pdev: NE PCI device.
 *
 * Return: 0 on success, negative errno on failure.
 */
int ne_pcie_slot_donate_one(struct pci_dev *pdev);

/**
 * ne_pcie_base_donate() - Donate the base scratch page (the carve sink)
 * before any slot donation. Idempotent. Returns 0 on success or if
 * already donated, negative errno on failure.
 */
int ne_pcie_base_donate(struct pci_dev *pdev);

#endif /* _NE_MISC_DEV_H_ */
