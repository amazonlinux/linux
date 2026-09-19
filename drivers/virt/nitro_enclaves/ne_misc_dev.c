// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

/**
 * DOC: Enclave lifetime management driver for Nitro Enclaves (NE).
 * Nitro is a hypervisor that has been developed by Amazon.
 */

#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/cma.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/dma-map-ops.h>
#include <linux/efi.h>
#include <linux/file.h>
#include <linux/hugetlb.h>
#include <linux/kref.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mmu_notifier.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/nodemask.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nitro_enclaves.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/range.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/sched/isolation.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/eventfd.h>
#include <uapi/linux/vm_sockets.h>

#include "ne_mem_sharing.h"
#include "ne_misc_dev.h"
#include "ne_pci_dev.h"

/*
 * Early boot CMA reservation for enclave memory pool.
 * Parsed via early_param, reserved from arch setup_arch() via
 * ne_cma_reserve().
 *
 * Syntax: mempool=<entry>[,<entry>]...
 *   where <entry> is one of:
 *     <size>         absolute, no node preference: reserved wherever memblock
 *                    finds room, so it lands on one node rather than being
 *                    split.  ne_alloc_contig() will only serve that node,
 *                    so prefer a percentage form on a multi-node parent.
 *     <size>@<nid>   absolute, placed on specified node
 *     <N>%           N% of each NUMA node's available memory
 *     <N>%@<nid>    N% of a single node's available memory
 *     <N>%-<size>   N% of each node minus <size> (kernel reserve)
 *     <N>%-<size>@<nid>  same, on a single node
 *     <N>%+<size>   N% of each node plus <size> (extra CMA floor)
 *     <N>%+<size>@<nid>  same, on a single node
 *
 *   The minus form reserves a fixed amount for the kernel plus a
 *   percentage-based headroom that scales with RAM, e.g. 95%-1G means
 *   "CMA gets 95% of each node's memory minus 1 GiB".  This handles
 *   small and large instances with a single cmdline.
 *
 *   The plus form adds a fixed floor on top of the percentage, e.g.
 *   50%+2G means "CMA gets 50% of each node's memory plus 2 GiB".
 *   The minus and plus forms are mutually exclusive per entry.
 *
 *   Entries may be mixed: mempool=95%-1G@0,4G@1
 *   Percentage entries are resolved to absolute sizes at ne_cma_reserve() time.
 */
/*
 * Cap the number of CMA regions NE will try to allocate.  Derived from
 * CONFIG_CMA_AREAS to avoid exhausting the global CMA slot table:
 * other users (DMA default, hugetlb) need slots too.
 */
#define NE_CMA_RESERVED_SLOTS  4
#if (CONFIG_CMA_AREAS - NE_CMA_RESERVED_SLOTS) < 16
#define NE_MEMPOOL_MAX_REGIONS (CONFIG_CMA_AREAS - NE_CMA_RESERVED_SLOTS)
#else
#define NE_MEMPOOL_MAX_REGIONS 16
#endif

struct ne_mempool_entry {
	unsigned long size_mb;
	unsigned long subtract_mb;
	unsigned long add_mb;
	int nid;
	int pct;
};

static struct ne_mempool_entry ne_mempool_layout[NE_MEMPOOL_MAX_REGIONS] __initdata;
static int ne_mempool_nr_entries __initdata;

static int __init early_ne_mempool(char *p)
{
	if (!p || !*p)
		return 0;

	while (p && *p && ne_mempool_nr_entries < NE_MEMPOOL_MAX_REGIONS) {
		struct ne_mempool_entry *e =
			&ne_mempool_layout[ne_mempool_nr_entries];
		char *end;
		unsigned long val;

		val = simple_strtoul(p, &end, 10);

		if (*end == '%') {
			e->pct = val;
			e->size_mb = 0;
			e->subtract_mb = 0;
			e->add_mb = 0;
			end++;
			p = end;
			/* Parse optional -<size> or +<size> adjustment.
			 * The two are mutually exclusive per entry.
			 */
			if (*p == '-') {
				p++;
				e->subtract_mb = memparse(p, &p) >> 20;
			} else if (*p == '+') {
				p++;
				e->add_mb = memparse(p, &p) >> 20;
			}
		} else {
			e->size_mb = memparse(p, &p) >> 20;
			if (!e->size_mb)
				break;
			e->pct = 0;
			e->subtract_mb = 0;
			e->add_mb = 0;
		}

		if (*p == '@') {
			p++;
			e->nid = simple_strtol(p, &p, 10);
		} else {
			e->nid = NUMA_NO_NODE;
		}
		ne_mempool_nr_entries++;

		if (*p == ',')
			p++;
	}
	return 0;
}
early_param("nitro_enclaves.mempool", early_ne_mempool);

static phys_addr_t __init ne_node_available_mem(int nid)
{
	phys_addr_t size = 0;
	u64 idx;
	phys_addr_t start, end;

	__for_each_mem_range(idx, &memblock.memory, &memblock.reserved,
			     nid, MEMBLOCK_NONE, &start, &end, NULL)
		size += end - start;
	return size;
}

/*
 * Format a percentage entry back into its cmdline form for log messages,
 * e.g. "95%", "95%-1G", "50%+2G".  Writes into caller-provided buffer;
 * a 32-byte buffer is sufficient for any plausible value.
 */
static void __init ne_fmt_pct(char *buf, size_t size,
			      const struct ne_mempool_entry *e)
{
	if (e->subtract_mb)
		snprintf(buf, size, "%d%%-%luM", e->pct, e->subtract_mb);
	else if (e->add_mb)
		snprintf(buf, size, "%d%%+%luM", e->pct, e->add_mb);
	else
		snprintf(buf, size, "%d%%", e->pct);
}

/**
 * ne_resolve_pct - Resolve a percentage mempool entry to absolute sizes.
 * @e:          Percentage entry to resolve (e->pct > 0).
 * @resolved:   Output array to append resolved absolute entries to.
 * @nr_resolved: Current number of entries in @resolved.
 *
 * If @e targets a single node, appends one entry.  If @e targets all
 * nodes (nid == NUMA_NO_NODE), appends one entry per online node with
 * available memory.  Entries are 2 MiB aligned; zero-size results are
 * skipped.
 *
 * Return: Updated entry count for @resolved.
 */
static int __init ne_resolve_pct(struct ne_mempool_entry *e,
				 struct ne_mempool_entry *resolved,
				 int nr_resolved)
{
	if (e->nid != NUMA_NO_NODE) {
		phys_addr_t node_size = ne_node_available_mem(e->nid);
		phys_addr_t pool_size;
		phys_addr_t subtract = (phys_addr_t)e->subtract_mb << 20;
		phys_addr_t add = (phys_addr_t)e->add_mb << 20;
		char fmt[32];

		ne_fmt_pct(fmt, sizeof(fmt), e);

		pool_size = (node_size / 100) * e->pct;
		if (pool_size > subtract)
			pool_size -= subtract;
		else
			pool_size = 0;
		pool_size += add;
		pool_size &= ~((phys_addr_t)SZ_2M - 1);
		if (!pool_size) {
			pr_info("nitro_enclaves: mempool=%s@%d resolved to 0, skipping\n",
				fmt, e->nid);
			return nr_resolved;
		}

		if (nr_resolved < NE_MEMPOOL_MAX_REGIONS) {
			resolved[nr_resolved].size_mb = pool_size >> 20;
			resolved[nr_resolved].nid = e->nid;
			resolved[nr_resolved].pct = 0;
			resolved[nr_resolved].subtract_mb = 0;
			resolved[nr_resolved].add_mb = 0;
			nr_resolved++;
			pr_info("nitro_enclaves: mempool=%s@%d resolved to %llu MiB (node avail: %llu MiB)\n",
				fmt, e->nid,
				(unsigned long long)(pool_size >> 20),
				(unsigned long long)(node_size >> 20));
		} else {
			pr_warn("nitro_enclaves: mempool=%s@%d resolved to %llu MiB but dropped (max regions reached)\n",
				fmt, e->nid,
				(unsigned long long)(pool_size >> 20));
		}
	} else {
		int nid;
		char fmt[32];

		ne_fmt_pct(fmt, sizeof(fmt), e);

		for_each_online_node(nid) {
			phys_addr_t node_size = ne_node_available_mem(nid);
			phys_addr_t pool_size;
			phys_addr_t subtract = (phys_addr_t)e->subtract_mb << 20;
			phys_addr_t add = (phys_addr_t)e->add_mb << 20;

			if (nr_resolved >= NE_MEMPOOL_MAX_REGIONS)
				break;
			if (!node_size)
				continue;

			pool_size = (node_size / 100) * e->pct;
			if (pool_size > subtract)
				pool_size -= subtract;
			else
				pool_size = 0;
			pool_size += add;
			pool_size &= ~((phys_addr_t)SZ_2M - 1);
			if (!pool_size)
				continue;

			resolved[nr_resolved].size_mb = pool_size >> 20;
			resolved[nr_resolved].nid = nid;
			resolved[nr_resolved].pct = 0;
			resolved[nr_resolved].subtract_mb = 0;
			resolved[nr_resolved].add_mb = 0;
			nr_resolved++;

			pr_info("nitro_enclaves: mempool=%s node %d: %llu MiB (node avail: %llu MiB)\n",
				fmt, nid,
				(unsigned long long)(pool_size >> 20),
				(unsigned long long)(node_size >> 20));
		}
	}

	return nr_resolved;
}

/* Forward declarations for CMA region tracking (defined later) */
extern struct cma *ne_cma_regions[NE_MEMPOOL_MAX_REGIONS];
extern int ne_cma_region_nid[NE_MEMPOOL_MAX_REGIONS];
extern int ne_cma_nr_regions;

/**
 * ne_cma_reserve() - Reserve CMA regions for enclave memory pool.
 *
 * Called from arch setup_arch() after initmem_init(), before memblock
 * is freed. Splits the requested size across multiple CMA regions
 * using cma_declare_contiguous_multi() so that large pools can be
 * satisfied even when a single contiguous region isn't available.
 *
 * Only emitted when the driver is built-in. For CONFIG_NITRO_ENCLAVES=m
 * the header in <linux/nitro_enclaves.h> provides a static inline stub,
 * and an out-of-tree module build that also defines the real function
 * would conflict with that stub in the same TU.
 */
#ifndef MODULE
void __init ne_cma_reserve(void)
{
	int i, rc;
	int slots_per_entry, slots_remainder;
	unsigned long long reserved_mb = 0, requested_mb = 0;

	/*
	 * Skip CMA reservation when this parent VM was not launched
	 * enclave-capable.  The hypervisor UEFI installs the AWSNitroEnclaves
	 * configuration table only when the Nitro Enclaves PCI device is
	 * attached, which the substrate VMM does only for enclave-capable
	 * launches.  Non-enclave parents pay no CMA cost.
	 */
	if (efi.aws_nitro_enclaves == EFI_INVALID_TABLE_ADDR) {
		pr_info("nitro_enclaves: AWSNitroEnclaves EFI table absent, skipping CMA reservation\n");
		return;
	}

	/* Resolve percentage entries to absolute sizes in ne_mempool_layout[]. */
	{
		struct ne_mempool_entry resolved[NE_MEMPOOL_MAX_REGIONS];
		int nr_resolved = 0;

		for (i = 0; i < ne_mempool_nr_entries; i++) {
			struct ne_mempool_entry *e = &ne_mempool_layout[i];

			if (!e->pct) {
				if (nr_resolved < NE_MEMPOOL_MAX_REGIONS)
					resolved[nr_resolved++] = *e;
			} else {
				nr_resolved = ne_resolve_pct(e, resolved,
							    nr_resolved);
			}
		}

		memcpy(ne_mempool_layout, resolved, sizeof(resolved));
		ne_mempool_nr_entries = nr_resolved;
	}

	if (!ne_mempool_nr_entries)
		return;

	/*
	 * Split the available CMA slots evenly across the layout entries so a
	 * multi-entry mempool=A@0,B@1 places regions on every requested NUMA
	 * node.  Earlier entries get one extra slot when the count doesn't
	 * divide evenly.
	 */
	slots_per_entry = NE_MEMPOOL_MAX_REGIONS / ne_mempool_nr_entries;
	slots_remainder = NE_MEMPOOL_MAX_REGIONS % ne_mempool_nr_entries;
	if (!slots_per_entry)
		slots_per_entry = 1;

	for (i = 0; i < ne_mempool_nr_entries; i++) {
		phys_addr_t total = (phys_addr_t)ne_mempool_layout[i].size_mb << 20;
		int nid = ne_mempool_layout[i].nid;
		phys_addr_t per_region, remaining;
		int nr_regions = slots_per_entry + (i < slots_remainder ? 1 : 0);
		int slots_used = 0;

		requested_mb += ne_mempool_layout[i].size_mb;

		if (ne_cma_nr_regions >= NE_MEMPOOL_MAX_REGIONS)
			break;
		total = ALIGN_DOWN(total, CMA_MIN_ALIGNMENT_BYTES);
		if (!total)
			continue;
		per_region = ALIGN_DOWN(total / nr_regions,
					CMA_MIN_ALIGNMENT_BYTES);
		if (per_region < CMA_MIN_ALIGNMENT_BYTES)
			per_region = CMA_MIN_ALIGNMENT_BYTES;

		remaining = total;
		while (remaining > 0 && slots_used < nr_regions &&
		       ne_cma_nr_regions < NE_MEMPOOL_MAX_REGIONS) {
			phys_addr_t size = min(per_region, remaining);

			/* Last slot takes the whole aligned remainder. */
			if (slots_used == nr_regions - 1)
				size = remaining;
			char name[CMA_MAX_NAME];
			int idx = ne_cma_nr_regions;

			snprintf(name, sizeof(name), "ne_pool%d", idx);
			/*
			 * One bitmap bit per 2 MiB, matching the pool's
			 * allocation granularity: every allocation from the
			 * pool is a NE_MIN_MEM_REGION_SIZE multiple at SZ_2M
			 * alignment. The per-range allocation bitmap is a
			 * kmalloc bounded by KMALLOC_MAX_SIZE; at one bit
			 * per page that bound caps an activatable range at
			 * 128 GiB, and a larger range fails activation and
			 * releases the whole area.
			 */
			rc = cma_declare_contiguous_multi(size, SZ_2M,
							  ilog2(SZ_2M >> PAGE_SHIFT),
							  name,
							  &ne_cma_regions[idx],
							  nid);
			if (rc) {
				/*
				 * Truncation, not failure: the pool is built
				 * best-effort and what is already reserved
				 * stays usable. Expected whenever mempool=
				 * asks for more than the instance can give
				 * up, since CMA cannot take all of RAM.
				 * Logged at info with rc because the loop
				 * breaks on the first failure, so this is one
				 * line per layout entry, and rc is the only
				 * place a cause other than -ENOMEM would show
				 * up.
				 */
				pr_info("nitro_enclaves: CMA region %d (%llu MiB, nid %d) not reserved: %d; truncating the pool here\n",
					idx, (unsigned long long)size >> 20,
					nid, rc);
				break;
			}
			ne_cma_region_nid[idx] = nid;
			ne_cma_nr_regions++;
			slots_used++;
			remaining -= size;
			reserved_mb += (unsigned long long)size >> 20;
		}
	}

	/*
	 * Report the outcome unconditionally. The per-region line above only
	 * appears when a region is dropped, so without this summary a pool
	 * that is merely smaller than requested is indistinguishable from one
	 * that was never built.
	 */
	pr_info("nitro_enclaves: CMA pool: %llu MiB reserved in %d region(s), %llu MiB requested\n",
		reserved_mb, ne_cma_nr_regions, requested_mb);
}
#endif /* !MODULE */

/**
 * NE_CPUS_SIZE - Size for max 128 CPUs, for now, in a cpu-list string, comma
 *		  separated. The NE CPU pool includes CPUs from a single NUMA
 *		  node.
 */
#define NE_CPUS_SIZE		(512)

/**
 * NE_EIF_LOAD_OFFSET - The offset where to copy the Enclave Image Format (EIF)
 *			image in enclave memory.
 */
#define NE_EIF_LOAD_OFFSET	(8 * 1024UL * 1024UL)

/**
 * NE_MIN_ENCLAVE_MEM_SIZE - The minimum memory size an enclave can be launched
 *			     with.
 */
#define NE_MIN_ENCLAVE_MEM_SIZE	(64 * 1024UL * 1024UL)

/**
 * NE_MIN_MEM_REGION_SIZE - The minimum size of an enclave memory region.
 */
#define NE_MIN_MEM_REGION_SIZE	(2 * 1024UL * 1024UL)

/**
 * NE_PARENT_VM_CID - The CID for the vsock device of the primary / parent VM.
 */
#define NE_PARENT_VM_CID	(3)

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int ne_mmap(struct file *file, struct vm_area_struct *vma);

/*
 * Return a 2 MiB aligned virtual address for mmap.  The NE driver requires
 * all donated memory regions to be 2 MiB aligned, so the mmap VA must match.
 * Uses vm_unmapped_area() with align_mask, the kernel's native mechanism for
 * aligned VMA allocation (same as used by arch_get_unmapped_area internally).
 */
static unsigned long ne_get_unmapped_area(struct file *file, unsigned long addr,
					  unsigned long len, unsigned long pgoff,
					  unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_unmapped_area_info info = {};
	const unsigned long mmap_end = arch_get_mmap_end(addr, len, flags);

	if (len & (NE_MIN_MEM_REGION_SIZE - 1))
		return -EINVAL;

	if (flags & MAP_FIXED)
		return addr;

	info.length = len;
	info.align_mask = NE_MIN_MEM_REGION_SIZE - 1;

	if (mm_flags_test(MMF_TOPDOWN, mm)) {
		info.flags = VM_UNMAPPED_AREA_TOPDOWN;
		info.low_limit = PAGE_SIZE;
		info.high_limit = arch_get_mmap_base(addr, mm->mmap_base);

		addr = vm_unmapped_area(&info);
		if (!(addr & ~PAGE_MASK))
			return addr;

		/* Topdown failed, fall back to bottom-up */
		info.flags = 0;
	}

	info.low_limit = mm->mmap_base;
	info.high_limit = mmap_end;
	return vm_unmapped_area(&info);
}

static const struct file_operations ne_fops = {
	.owner			= THIS_MODULE,
	.llseek			= noop_llseek,
	.unlocked_ioctl		= ne_ioctl,
	.mmap			= ne_mmap,
	.get_unmapped_area	= ne_get_unmapped_area,
};

static struct miscdevice ne_misc_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "nitro_enclaves",
	.fops	= &ne_fops,
	.mode	= 0660,
};

struct ne_devs ne_devs = {
	.ne_misc_dev	= &ne_misc_dev,
};

/*
 * TODO: Update logic to create new sysfs entries instead of using
 * a kernel parameter e.g. if multiple sysfs files needed.
 */
static int ne_set_kernel_param(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops ne_cpu_pool_ops = {
	.get	= param_get_string,
	.set	= ne_set_kernel_param,
};

static char ne_cpus[NE_CPUS_SIZE] = "dynamic";
static struct kparam_string ne_cpus_arg = {
	.maxlen	= sizeof(ne_cpus),
	.string	= ne_cpus,
};

module_param_cb(ne_cpus, &ne_cpu_pool_ops, &ne_cpus_arg, 0644);
/* https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html#cpu-lists */
MODULE_PARM_DESC(ne_cpus,
	"<cpu-list> | 'dynamic' (default) - CPU pool used for Nitro Enclaves. "
	"Defaults to 'dynamic' which auto-discovers CPUs without offlining them.");

/*
 * Bytes of donated enclave memory intentionally leaked because SLOT_FREE
 * failed and the hypervisor never confirmed that it had moved ownership of the
 * pages back to the parent. See ne_enclave_release(). Read-only, exposed at
 * /sys/module/nitro_enclaves/parameters/leaked_donated_bytes so operators can
 * size the leak without a kernel log scrape.
 */
static atomic64_t ne_leaked_donated_bytes = ATOMIC64_INIT(0);

static int ne_leaked_get(char *buffer, const struct kernel_param *kp)
{
	return sysfs_emit(buffer, "%lld\n",
			  (long long)atomic64_read(&ne_leaked_donated_bytes));
}

static const struct kernel_param_ops ne_leaked_ops = {
	.get	= ne_leaked_get,
};

module_param_cb(leaked_donated_bytes, &ne_leaked_ops, NULL, 0444);
MODULE_PARM_DESC(leaked_donated_bytes,
	"Bytes of donated enclave memory leaked after a SLOT_FREE failure");

static bool ne_pool_is_dynamic(void)
{
	return sysfs_streq(ne_cpus, "dynamic");
}

/*
 * Contiguous memory pool support.
 *
 * When mempool= is specified, we declare CMA regions at early boot so that
 * movable allocations can still use the memory until an enclave needs it.
 * At mmap time, we allocate from these CMA regions. Every consumer is
 * confined to the reserved pools; there is no fallback to the general
 * page allocator (see ne_alloc_contig()).
 */

static DEFINE_MUTEX(ne_contig_mutex);

struct cma *ne_cma_regions[NE_MEMPOOL_MAX_REGIONS];
int ne_cma_region_nid[NE_MEMPOOL_MAX_REGIONS];
int ne_cma_nr_regions;

/* Track contiguous allocations for cleanup */
struct ne_contig_alloc {
	struct list_head list;
	struct page *page;
	unsigned long nr_pages;
	struct cma *cma; /* originating CMA region */
};

/**
 * struct ne_cpu_pool - CPU pool used for Nitro Enclaves.
 * @avail_threads_per_core:	Available full CPU cores to be dedicated to
 *				enclave(s). The cpumasks from the array, indexed
 *				by core id, contain all the threads from the
 *				available cores, that are not set for created
 *				enclave(s). The full CPU cores are part of the
 *				NE CPU pool.
 * @mutex:			Mutex for the access to the NE CPU pool.
 * @nr_parent_vm_cores :	The size of the available threads per core array.
 *				The total number of CPU cores available on the
 *				primary / parent VM.
 * @nr_threads_per_core:	The number of threads that a full CPU core has.
 * @numa_node:			NUMA node of the CPUs in the pool.
 * @nr_pool_cpus_per_node:	Total number of threads dedicated to the pool on
 *				each host NUMA node, captured at setup time and
 *				constant until teardown. Used to report the pool
 *				denominator per node even when every core on a
 *				node is currently claimed (avail mask empty).
 */
struct ne_cpu_pool {
	cpumask_var_t	*avail_threads_per_core;
	struct mutex	mutex;
	unsigned int	nr_parent_vm_cores;
	unsigned int	nr_threads_per_core;
	int		numa_node;
	unsigned int	nr_pool_cpus_per_node[MAX_NUMNODES];
};

static struct ne_cpu_pool ne_cpu_pool = {
	.mutex = __MUTEX_INITIALIZER(ne_cpu_pool.mutex),
};

/**
 * ne_cpu_pool_recount_nodes() - Recompute the per-NUMA-node pool totals from
 *				 the freshly-built avail_threads_per_core masks.
 *
 * Must be called with ne_cpu_pool.mutex held and before any core has been
 * claimed by an enclave (i.e. at setup time), when the avail masks still
 * reflect the full pool. The totals are the denominator reported by the
 * cpu_pool sysfs; they stay constant until the next teardown/setup.
 *
 * Context: Process context. ne_cpu_pool.mutex must be held.
 */
static void ne_cpu_pool_recount_nodes(void)
{
	unsigned int i, cpu;

	memset(ne_cpu_pool.nr_pool_cpus_per_node, 0,
	       sizeof(ne_cpu_pool.nr_pool_cpus_per_node));

	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
		for_each_cpu(cpu, ne_cpu_pool.avail_threads_per_core[i])
			ne_cpu_pool.nr_pool_cpus_per_node[cpu_to_node(cpu)]++;
}

/**
 * struct ne_phys_contig_mem_regions - Contiguous physical memory regions.
 * @num:	The number of regions that currently has.
 * @regions:	The array of physical memory regions.
 */
struct ne_phys_contig_mem_regions {
	unsigned long num;
	struct range  *regions;
};

/**
 * ne_check_enclaves_created() - Verify if at least one enclave has been created.
 * @void:	No parameters provided.
 *
 * Context: Process context.
 * Return:
 * * True if at least one enclave is created.
 * * False otherwise.
 */
static bool ne_check_enclaves_created(void)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	bool ret = false;

	if (!ne_pci_dev)
		return ret;

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);

	if (!list_empty(&ne_pci_dev->enclaves_list))
		ret = true;

	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	return ret;
}

/**
 * ne_setup_cpu_pool() - Set the NE CPU pool after handling sanity checks such
 *			 as not sharing CPU cores with the primary / parent VM
 *			 or not using CPU 0, which should remain available for
 *			 the primary / parent VM. Offline the CPUs from the
 *			 pool after the checks passed (static mode only).
 * @ne_cpu_list:	The CPU list used for setting NE CPU pool.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_setup_cpu_pool(const char *ne_cpu_list)
{
	unsigned int cpu = 0;
	cpumask_var_t cpu_pool;
	unsigned int cpu_sibling = 0;
	unsigned int i = 0;
	int numa_node = -1;
	int rc = -EINVAL;
	bool dynamic = ne_pool_is_dynamic();

	if (!zalloc_cpumask_var(&cpu_pool, GFP_KERNEL))
		return -ENOMEM;

	mutex_lock(&ne_cpu_pool.mutex);

	rc = cpulist_parse(ne_cpu_list, cpu_pool);
	if (rc < 0) {
		pr_err("%s: Error in cpulist parse [rc=%d]\n", ne_misc_dev.name, rc);

		goto free_pool_cpumask;
	}

	cpu = cpumask_any(cpu_pool);
	if (cpu >= nr_cpu_ids) {
		pr_err("%s: No CPUs available in CPU pool\n", ne_misc_dev.name);

		rc = -EINVAL;

		goto free_pool_cpumask;
	}

	/*
	 * Check if the CPUs are online, to further get info about them
	 * e.g. numa node, core id, siblings.
	 */
	for_each_cpu(cpu, cpu_pool)
		if (cpu_is_offline(cpu)) {
			pr_err("%s: CPU %d is offline, has to be online to get its metadata\n",
			       ne_misc_dev.name, cpu);

			rc = -EINVAL;

			goto free_pool_cpumask;
		}

	/*
	 * Determine the NUMA node of the CPUs in the pool. If CPUs span
	 * multiple NUMA nodes, set numa_node to NUMA_NO_NODE.
	 */
	for_each_cpu(cpu, cpu_pool)
		if (numa_node < 0) {
			numa_node = cpu_to_node(cpu);
			if (numa_node < 0) {
				pr_err("%s: Invalid NUMA node %d\n",
				       ne_misc_dev.name, numa_node);

				rc = -EINVAL;

				goto free_pool_cpumask;
			}
		} else {
			if (numa_node != cpu_to_node(cpu))
				numa_node = NUMA_NO_NODE;
		}

	/*
	 * Check if CPU 0 and its siblings are included in the provided CPU pool
	 * They should remain available for the primary / parent VM.
	 */
	if (cpumask_test_cpu(0, cpu_pool)) {
		pr_err("%s: CPU 0 has to remain available\n", ne_misc_dev.name);

		rc = -EINVAL;

		goto free_pool_cpumask;
	}

	for_each_cpu(cpu_sibling, topology_sibling_cpumask(0)) {
		if (cpumask_test_cpu(cpu_sibling, cpu_pool)) {
			pr_err("%s: CPU sibling %d for CPU 0 is in CPU pool\n",
			       ne_misc_dev.name, cpu_sibling);

			rc = -EINVAL;

			goto free_pool_cpumask;
		}
	}

	/*
	 * Check if CPU siblings are included in the provided CPU pool. The
	 * expectation is that full CPU cores are made available in the CPU pool
	 * for enclaves.
	 */
	for_each_cpu(cpu, cpu_pool) {
		for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
			if (!cpumask_test_cpu(cpu_sibling, cpu_pool)) {
				pr_err("%s: CPU %d is not in CPU pool\n",
				       ne_misc_dev.name, cpu_sibling);

				rc = -EINVAL;

				goto free_pool_cpumask;
			}
		}
	}

	/* Calculate the number of threads from a full CPU core. */
	cpu = cpumask_any(cpu_pool);
	for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu))
		ne_cpu_pool.nr_threads_per_core++;

	ne_cpu_pool.nr_parent_vm_cores = nr_cpu_ids / ne_cpu_pool.nr_threads_per_core;

	ne_cpu_pool.avail_threads_per_core = kcalloc(ne_cpu_pool.nr_parent_vm_cores,
						     sizeof(*ne_cpu_pool.avail_threads_per_core),
						     GFP_KERNEL);
	if (!ne_cpu_pool.avail_threads_per_core) {
		rc = -ENOMEM;

		goto free_pool_cpumask;
	}

	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
		if (!zalloc_cpumask_var(&ne_cpu_pool.avail_threads_per_core[i], GFP_KERNEL)) {
			rc = -ENOMEM;

			goto free_cores_cpumask;
		}

	/*
	 * Split the NE CPU pool in threads per core to keep the CPU topology
	 * after offlining the CPUs.  topology_core_id() is package-local on
	 * x86, so on multi-socket hosts two CPUs from different packages may
	 * share the same core_id; use the per-CPU sibling cpumask to assign
	 * globally-unique core slots.
	 */
	{
		cpumask_var_t processed;
		unsigned int next_core_idx = 0;
		unsigned int cpu_s;

		if (!zalloc_cpumask_var(&processed, GFP_KERNEL)) {
			rc = -ENOMEM;
			goto clear_cpumask;
		}

		for_each_cpu(cpu, cpu_pool) {
			const struct cpumask *sibs;

			if (cpumask_test_cpu(cpu, processed))
				continue;

			sibs = topology_sibling_cpumask(cpu);

			if (next_core_idx >= ne_cpu_pool.nr_parent_vm_cores) {
				free_cpumask_var(processed);
				pr_err("%s: CPU pool has more cores than nr_parent_vm_cores=%d\n",
				       ne_misc_dev.name,
				       ne_cpu_pool.nr_parent_vm_cores);
				rc = -EINVAL;
				goto clear_cpumask;
			}

			for_each_cpu(cpu_s, sibs) {
				if (!cpumask_test_cpu(cpu_s, cpu_pool))
					continue;
				cpumask_set_cpu(cpu_s,
					ne_cpu_pool.avail_threads_per_core[next_core_idx]);
				cpumask_set_cpu(cpu_s, processed);
			}
			next_core_idx++;
		}

		free_cpumask_var(processed);
	}

	if (dynamic) {
		/*
		 * Dynamic mode: CPUs stay online and schedulable. They are
		 * only isolated when actually allocated to an enclave.
		 */
		pr_debug("%s: Dynamic CPU pool configured with %d CPUs\n",
			ne_misc_dev.name, cpumask_weight(cpu_pool));
	} else {
		/*
		 * Static mode: offline CPUs so they are fully dedicated.
		 */
		for_each_cpu(cpu, cpu_pool) {
			rc = remove_cpu(cpu);
			if (rc != 0) {
				pr_err("%s: CPU %d is not offlined [rc=%d]\n",
				       ne_misc_dev.name, cpu, rc);

				goto online_cpus;
			}
		}
	}

	free_cpumask_var(cpu_pool);

	ne_cpu_pool.numa_node = numa_node;
	ne_cpu_pool_recount_nodes();

	mutex_unlock(&ne_cpu_pool.mutex);

	return 0;

online_cpus:
	if (!dynamic) {
		for_each_cpu(cpu, cpu_pool)
			add_cpu(cpu);
	}
clear_cpumask:
	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
		cpumask_clear(ne_cpu_pool.avail_threads_per_core[i]);
free_cores_cpumask:
	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
		free_cpumask_var(ne_cpu_pool.avail_threads_per_core[i]);
	kfree(ne_cpu_pool.avail_threads_per_core);
free_pool_cpumask:
	free_cpumask_var(cpu_pool);
	ne_cpu_pool.nr_parent_vm_cores = 0;
	ne_cpu_pool.nr_threads_per_core = 0;
	ne_cpu_pool.numa_node = -1;
	mutex_unlock(&ne_cpu_pool.mutex);

	return rc;
}

/**
 * ne_teardown_cpu_pool() - Online the CPUs from the NE CPU pool (static mode)
 *			    or just cleanup the data structures (dynamic mode).
 * @void:	No parameters provided.
 *
 * Context: Process context.
 */
static void ne_teardown_cpu_pool(void)
{
	unsigned int cpu = 0;
	unsigned int i = 0;
	int rc = -EINVAL;
	bool dynamic = ne_pool_is_dynamic();

	mutex_lock(&ne_cpu_pool.mutex);

	if (!ne_cpu_pool.nr_parent_vm_cores) {
		mutex_unlock(&ne_cpu_pool.mutex);

		return;
	}

	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++) {
		if (!dynamic) {
			for_each_cpu(cpu, ne_cpu_pool.avail_threads_per_core[i]) {
				rc = add_cpu(cpu);
				if (rc != 0)
					pr_err("%s: CPU %d is not onlined [rc=%d]\n",
					       ne_misc_dev.name, cpu, rc);
			}
		}

		cpumask_clear(ne_cpu_pool.avail_threads_per_core[i]);

		free_cpumask_var(ne_cpu_pool.avail_threads_per_core[i]);
	}

	kfree(ne_cpu_pool.avail_threads_per_core);
	ne_cpu_pool.nr_parent_vm_cores = 0;
	ne_cpu_pool.nr_threads_per_core = 0;
	ne_cpu_pool.numa_node = -1;
	memset(ne_cpu_pool.nr_pool_cpus_per_node, 0,
	       sizeof(ne_cpu_pool.nr_pool_cpus_per_node));

	mutex_unlock(&ne_cpu_pool.mutex);
}

/**
 * ne_cpu_pool_get_stats() - Report dedicated (non-overcommitted) CPU pool
 *			     occupancy, globally or for a single NUMA node.
 * @nid:	NUMA node id to report, or NUMA_NO_NODE for the whole pool.
 * @total:	Threads dedicated to the pool (the denominator).
 * @in_use:	Threads currently claimed by enclave(s).
 * @free_cpus:	Threads currently available for allocation.
 *
 * Overcommitted enclaves do not draw dedicated cores from this pool, so they
 * are not reflected here. Values are captured atomically under the pool mutex.
 *
 * Context: Process context.
 */
void ne_cpu_pool_get_stats(int nid, unsigned int *total, unsigned int *in_use,
			   unsigned int *free_cpus)
{
	unsigned int i, cpu, t = 0, f = 0;

	mutex_lock(&ne_cpu_pool.mutex);

	if (nid == NUMA_NO_NODE) {
		for (i = 0; i < MAX_NUMNODES; i++)
			t += ne_cpu_pool.nr_pool_cpus_per_node[i];

		for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
			f += cpumask_weight(ne_cpu_pool.avail_threads_per_core[i]);
	} else if (nid >= 0 && nid < MAX_NUMNODES) {
		t = ne_cpu_pool.nr_pool_cpus_per_node[nid];

		for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
			for_each_cpu(cpu, ne_cpu_pool.avail_threads_per_core[i])
				if (cpu_to_node(cpu) == nid)
					f++;
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	*total = t;
	*free_cpus = f;
	*in_use = t - f;
}

/**
 * ne_cma_node() - The NUMA node an NE CMA region's memory sits on.
 * @i:	Index into ne_cma_regions[].
 *
 * A region reserved without an explicit @nid is recorded as NUMA_NO_NODE, but
 * its pages still live on one node. ne_cma_reserve() pre-splits each mempool
 * entry into small per-region chunks, so cma_declare_contiguous_multi()
 * reserves each as a single physical range (nranges == 1) on one node; take
 * the node of its base PFN. (If a region ever fell back to multiple ranges,
 * cma_get_base() warns and returns range[0] only, so the region is still
 * attributed to exactly one node.)
 *
 * Return: NUMA node id.
 */
static int ne_cma_node(int i)
{
	if (ne_cma_region_nid[i] != NUMA_NO_NODE)
		return ne_cma_region_nid[i];

	return pfn_to_nid(PFN_DOWN(cma_get_base(ne_cma_regions[i])));
}

/**
 * ne_mem_pool_get_stats() - see ne_misc_dev.h.
 *
 * The NE CMA region set is built once at boot (ne_cma_reserve) and never
 * changes at runtime, so the region array needs no locking. Each region's
 * total (cma->count) is immutable after reservation and free
 * (cma->available_count) is a single word, so cma_get_size() and
 * cma_get_available() are read as an unlocked monitoring snapshot and
 * in_use = total - free cannot go negative. (cma_debug's "used" file locks
 * only because it reads count and available_count together as a consistent
 * pair; a single-counter read does not need that.)
 *
 * Context: Process context.
 */
void ne_mem_pool_get_stats(int nid, u64 *total, u64 *in_use, u64 *free_bytes)
{
	u64 t = 0, f = 0;
	int i;

	for (i = 0; i < ne_cma_nr_regions; i++) {
		if (nid != NUMA_NO_NODE && ne_cma_node(i) != nid)
			continue;
		t += cma_get_size(ne_cma_regions[i]);
		f += cma_get_available(ne_cma_regions[i]);
	}
	*total = t;
	*free_bytes = f;
	*in_use = t - f;
}

/**
 * ne_setup_dynamic_cpu_pool() - Auto-discover all available CPU cores (excluding
 *				 CPU 0's core) and set up the pool in dynamic mode.
 * @void:	No parameters provided.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_setup_dynamic_cpu_pool(void)
{
	unsigned int cpu;
	unsigned int cpu_sibling;
	unsigned int i;
	unsigned int nr_threads = 0;
	cpumask_var_t cpu0_siblings;

	if (!zalloc_cpumask_var(&cpu0_siblings, GFP_KERNEL))
		return -ENOMEM;

	/* Collect CPU 0's siblings to exclude them */
	for_each_cpu(cpu_sibling, topology_sibling_cpumask(0))
		cpumask_set_cpu(cpu_sibling, cpu0_siblings);

	/* Determine threads per core from CPU 0 */
	for_each_cpu(cpu_sibling, topology_sibling_cpumask(0))
		nr_threads++;

	if (!nr_threads) {
		free_cpumask_var(cpu0_siblings);
		return -EINVAL;
	}

	mutex_lock(&ne_cpu_pool.mutex);

	ne_cpu_pool.nr_threads_per_core = nr_threads;
	ne_cpu_pool.nr_parent_vm_cores = nr_cpu_ids / nr_threads;

	ne_cpu_pool.avail_threads_per_core = kcalloc(ne_cpu_pool.nr_parent_vm_cores,
						     sizeof(*ne_cpu_pool.avail_threads_per_core),
						     GFP_KERNEL);
	if (!ne_cpu_pool.avail_threads_per_core) {
		ne_cpu_pool.nr_parent_vm_cores = 0;
		ne_cpu_pool.nr_threads_per_core = 0;
		mutex_unlock(&ne_cpu_pool.mutex);
		free_cpumask_var(cpu0_siblings);
		return -ENOMEM;
	}

	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++) {
		if (!zalloc_cpumask_var(&ne_cpu_pool.avail_threads_per_core[i], GFP_KERNEL)) {
			unsigned int j;

			for (j = 0; j < i; j++)
				free_cpumask_var(ne_cpu_pool.avail_threads_per_core[j]);
			kfree(ne_cpu_pool.avail_threads_per_core);
			ne_cpu_pool.nr_parent_vm_cores = 0;
			ne_cpu_pool.nr_threads_per_core = 0;
			mutex_unlock(&ne_cpu_pool.mutex);
			free_cpumask_var(cpu0_siblings);
			return -ENOMEM;
		}
	}

	/*
	 * Add all online CPUs except CPU 0's siblings into per-core bitmaps.
	 * topology_core_id() is package-local on x86, so it collides between
	 * packages on multi-socket hosts.  Use the per-CPU sibling cpumask to
	 * group threads into globally-unique core slots: walk each unprocessed
	 * CPU, claim its sibling set as the next core, and skip already-mapped
	 * CPUs on subsequent iterations.
	 */
	{
		cpumask_var_t processed;
		unsigned int next_core_idx = 0;
		unsigned int cpu_s;

		if (!zalloc_cpumask_var(&processed, GFP_KERNEL)) {
			mutex_unlock(&ne_cpu_pool.mutex);
			free_cpumask_var(cpu0_siblings);
			return -ENOMEM;
		}

		for_each_online_cpu(cpu) {
			const struct cpumask *sibs;

			if (cpumask_test_cpu(cpu, processed))
				continue;

			sibs = topology_sibling_cpumask(cpu);

			if (cpumask_intersects(sibs, cpu0_siblings)) {
				/* Mark these as processed so we don't revisit. */
				for_each_cpu(cpu_s, sibs)
					cpumask_set_cpu(cpu_s, processed);
				continue;
			}

			if (next_core_idx >= ne_cpu_pool.nr_parent_vm_cores) {
				/* More cores than slots, should not happen */
				break;
			}

			for_each_cpu(cpu_s, sibs) {
				cpumask_set_cpu(cpu_s,
					ne_cpu_pool.avail_threads_per_core[next_core_idx]);
				cpumask_set_cpu(cpu_s, processed);
			}
			next_core_idx++;
		}

		free_cpumask_var(processed);
	}

	ne_cpu_pool.numa_node = NUMA_NO_NODE;
	ne_cpu_pool_recount_nodes();

	pr_debug("%s: Dynamic CPU pool auto-configured spanning all NUMA nodes\n",
		ne_misc_dev.name);

	mutex_unlock(&ne_cpu_pool.mutex);
	free_cpumask_var(cpu0_siblings);

	return 0;
}

/**
 * ne_set_kernel_param() - Set the NE CPU pool value via the NE kernel parameter.
 * @val:	NE CPU pool string value.
 * @kp :	NE kernel parameter associated with the NE CPU pool.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_set_kernel_param(const char *val, const struct kernel_param *kp)
{
	char error_val[] = "";
	int rc = -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * At early boot, kcalloc is not yet available. Just store the
	 * value; ne_init() will do the actual pool setup.
	 */
	if (!slab_is_available())
		return param_set_copystring(val, kp);

	if (ne_check_enclaves_created()) {
		pr_err("%s: The CPU pool is used by enclave(s)\n", ne_misc_dev.name);

		return -EPERM;
	}

	ne_teardown_cpu_pool();

	/*
	 * Publish the value before setup: ne_setup_cpu_pool() reads the global
	 * ne_cpus (via ne_pool_is_dynamic()), so setting it only afterwards
	 * makes the first static write after "dynamic" skip offlining. On a
	 * setup failure below the parameter is cleared to the empty string,
	 * not restored to the value it had before this call.
	 */
	rc = param_set_copystring(val, kp);
	if (rc < 0) {
		pr_err("%s: Error in param set copystring [rc=%d]\n", ne_misc_dev.name, rc);

		return rc;
	}

	if (ne_pool_is_dynamic())
		rc = ne_setup_dynamic_cpu_pool();
	else
		rc = ne_setup_cpu_pool(val);

	if (rc < 0) {
		pr_err("%s: Error in setup CPU pool [rc=%d]\n", ne_misc_dev.name, rc);

		ne_teardown_cpu_pool();

		param_set_copystring(error_val, kp);

		return rc;
	}

	return 0;
}

/**
 * ne_donated_cpu() - Check if the provided CPU is already used by the enclave.
 * @ne_enclave :	Private data associated with the current enclave.
 * @cpu:		CPU to check if already used.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * True if the provided CPU is already used by the enclave.
 * * False otherwise.
 */
static bool ne_donated_cpu(struct ne_enclave *ne_enclave, unsigned int cpu)
{
	if (cpumask_test_cpu(cpu, ne_enclave->vcpu_ids))
		return true;

	return false;
}

/**
 * ne_get_unused_core_from_cpu_pool() - Get the id of a full core from the
 *					NE CPU pool, optionally biased toward a
 *					preferred host NUMA node.
 * @preferred_numa:	Host NUMA node the core must sit on.  Pass NUMA_NO_NODE
 *			for "any node" (returns the first non-empty core in
 *			pool order).  Any other value returns a core whose
 *			first thread is on that node, and fails closed (-1) if
 *			that node has no free core left: it never crosses to
 *			another node.
 *
 * Context: Process context. This function is called with the ne_enclave and
 *	    ne_cpu_pool mutexes held.
 * Return:
 * * Core id.
 * * -1 if no usable core is available (pool empty, or @preferred_numa is
 *   exhausted).
 *
 * Single-NUMA invariant.  With ne_cpus=dynamic the pool spans every online
 * host NUMA node (ne_cpu_pool.numa_node == NUMA_NO_NODE), so it can hold
 * cores on several nodes at once.  A node-specific request must be satisfied
 * on that node or not at all: an enclave whose donated core lands on a
 * different host node than its memory is physically multi-NUMA, which the
 * hypervisor rejects at launch unless the device's PCIE_NUMA launch flag is
 * set (the start request fails and the enclave launch dies with -EIO).
 * Crossing nodes here would only trade a clean "node exhausted" rejection
 * for that opaque downstream -EIO.
 *
 *   - NE_ADD_ANY_VCPU (QEMU-driven enclaves) forwards QEMU's numa_hint: a
 *     default single-NUMA enclave hints one node and is kept on it; a
 *     multi-NUMA (PCIE_NUMA) enclave hints each vCPU to its own node and is
 *     likewise kept there, so the guest topology matches the placement.  The
 *     atomic pick-and-commit under ne_cpu_pool.mutex inside
 *     ne_get_cpu_from_cpu_pool() also closes the TOCTOU window QEMU's old
 *     userspace sysfs-walking picker had against parallel enclave launches.
 *
 *   - Legacy NE_ADD_VCPU(cpu_id == 0) consumers pass @preferred_numa = 0 and
 *     get deterministic node-0 placement.  This is stricter than the upstream
 *     picker, which had no node filter and returned the first free core on any
 *     node: a pool with no free core on node 0 fails closed here.
 *
 *   - @preferred_numa = NUMA_NO_NODE means "no preference" and returns the
 *     first non-empty core on any node.
 */
static int ne_get_unused_core_from_cpu_pool(int preferred_numa)
{
	unsigned int i = 0;
	bool any_node = (preferred_numa == NUMA_NO_NODE);

	/*
	 * Single pass: return a core on @preferred_numa, or any core when
	 * @preferred_numa == NUMA_NO_NODE.  When a specific node is requested
	 * but has no free core left, fail closed (-1) instead of crossing to
	 * another node: a cross-node single-NUMA placement is rejected
	 * downstream by the VMM and the launch dies with -EIO (see the
	 * kernel-doc above).
	 */
	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++) {
		unsigned int first_cpu;

		if (cpumask_empty(ne_cpu_pool.avail_threads_per_core[i]))
			continue;

		first_cpu = cpumask_first(ne_cpu_pool.avail_threads_per_core[i]);
		if (any_node || cpu_to_node(first_cpu) == preferred_numa)
			return i;
	}

	return -1;
}

/**
 * ne_set_enclave_threads_per_core() - Set the threads of the provided core in
 *				       the enclave data structure.
 * @ne_enclave :	Private data associated with the current enclave.
 * @core_id:		Core id to get its threads from the NE CPU pool.
 * @vcpu_id:		vCPU id part of the provided core.
 *
 * Context: Process context. This function is called with the ne_enclave and
 *	    ne_cpu_pool mutexes held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_set_enclave_threads_per_core(struct ne_enclave *ne_enclave,
					   int core_id, u32 vcpu_id)
{
	unsigned int cpu = 0;

	if (core_id < 0 && vcpu_id == 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in NE CPU pool\n");

		return -NE_ERR_NO_CPUS_AVAIL_IN_POOL;
	}

	if (core_id < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "CPU %d is not in NE CPU pool\n", vcpu_id);

		return -NE_ERR_VCPU_NOT_IN_CPU_POOL;
	}

	if (core_id >= ne_enclave->nr_parent_vm_cores) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid core id %d - ne_enclave\n", core_id);

		return -NE_ERR_VCPU_INVALID_CPU_CORE;
	}

	for_each_cpu(cpu, ne_cpu_pool.avail_threads_per_core[core_id])
		cpumask_set_cpu(cpu, ne_enclave->threads_per_core[core_id]);

	/*
	 * In dynamic mode we keep unbound parent-side work off the CPUs we're
	 * about to dedicate to enclave vCPU threads.  Without this,
	 * parent-side workqueues and ENA NAPI run there and preempt the
	 * pinned qemu vCPU threads, starving virtio I/O and eventually
	 * tripping the ENA TX watchdog under heavy concurrent-enclave load.
	 *
	 * sched_cpu_set_isolated() removes the CPU from the unbound-workqueue
	 * target set and makes cpu_is_isolated() report it as isolated, so
	 * callers consulting that helper place their work elsewhere, without
	 * taking the CPU offline.  It also rebuilds the sched domains, but CFS
	 * domain membership is driven by cpuset partitions and HK_TYPE_DOMAIN
	 * housekeeping, so the load balancer still sees the CPU; and this
	 * kernel has no interface for dropping it from the timer-migration
	 * hierarchy. Per-CPU kthreads (timers, RCU, ksoftirqd) continue to run
	 * there (they check cpu_online(), not cpu_active()), and the qemu vCPU
	 * thread that will be pinned here with sched_setaffinity() also runs
	 * normally (pinned tasks bypass load-balancer placement).
	 *
	 * Do not reach for set_cpu_active(cpu, false) instead. That wedges the
	 * instance: set_cpu_active() is meant to be a transient hotplug
	 * sub-step, not a steady state, and holding a CPU inactive-but-online
	 * triggers permanent sched_balance_softirq churn as the scheduler tries
	 * (and fails) to drain a runqueue that can't be drained.
	 * sched_cpu_set_isolated() reuses the same state-machine that cpuset
	 * PRS_ISOLATED partitions use, which the scheduler explicitly supports
	 * as a stable long-lived state.
	 */
	if (ne_pool_is_dynamic()) {
		for_each_cpu(cpu, ne_enclave->threads_per_core[core_id]) {
			int rc = sched_cpu_set_isolated(cpu);

			if (rc)
				pr_warn_ratelimited(
					"%s: sched_cpu_set_isolated(%u) failed [rc=%d]; CFS contention may preempt vCPU threads\n",
					ne_misc_dev.name, cpu, rc);
		}
	}

	cpumask_clear(ne_cpu_pool.avail_threads_per_core[core_id]);

	return 0;
}

/**
 * ne_get_cpu_from_cpu_pool() - Get a CPU from the NE CPU pool, either from the
 *				remaining sibling(s) of a CPU core or the first
 *				sibling of a new CPU core.
 * @ne_enclave :	Private data associated with the current enclave.
 * @vcpu_id:		vCPU to get from the NE CPU pool.
 * @preferred_numa:	Required host NUMA node for new-core picks.  Pass 0
 *			to keep NE_ADD_VCPU(cpu_id == 0) consumers on node 0,
 *			which fails when node 0 has no free core; pass
 *			NUMA_NO_NODE
 *			or another node id (forwarded from NE_ADD_ANY_VCPU's
 *			numa_hint) to pick on a specific node.  Ignored on
 *			the sibling-completion fast path because the sibling
 *			already inherits its core's NUMA from the first thread.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_get_cpu_from_cpu_pool(struct ne_enclave *ne_enclave, u32 *vcpu_id,
				    int preferred_numa)
{
	int core_id = -1;
	unsigned int cpu = 0;
	unsigned int i = 0;
	int rc = -EINVAL;

	/*
	 * If previously allocated a thread of a core to this enclave, first
	 * check remaining sibling(s) for new CPU allocations, so that full
	 * CPU cores are used for the enclave.
	 */
	for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++)
		for_each_cpu(cpu, ne_enclave->threads_per_core[i])
			if (!ne_donated_cpu(ne_enclave, cpu)) {
				*vcpu_id = cpu;

				return 0;
			}

	mutex_lock(&ne_cpu_pool.mutex);

	/*
	 * If no remaining siblings, get a core from the NE CPU pool and keep
	 * track of all the threads in the enclave threads per core data structure.
	 */
	core_id = ne_get_unused_core_from_cpu_pool(preferred_numa);

	rc = ne_set_enclave_threads_per_core(ne_enclave, core_id, *vcpu_id);
	if (rc < 0)
		goto unlock_mutex;

	*vcpu_id = cpumask_any(ne_enclave->threads_per_core[core_id]);

	rc = 0;

unlock_mutex:
	mutex_unlock(&ne_cpu_pool.mutex);

	return rc;
}

/**
 * ne_get_vcpu_core_from_cpu_pool() - Get from the NE CPU pool the id of the
 *				      core associated with the provided vCPU.
 * @vcpu_id:	Provided vCPU id to get its associated core id.
 *
 * Context: Process context. This function is called with the ne_enclave and
 *	    ne_cpu_pool mutexes held.
 * Return:
 * * Core id.
 * * -1 if the provided vCPU is not in the pool.
 */
static int ne_get_vcpu_core_from_cpu_pool(u32 vcpu_id)
{
	int core_id = -1;
	unsigned int i = 0;

	for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
		if (cpumask_test_cpu(vcpu_id, ne_cpu_pool.avail_threads_per_core[i])) {
			core_id = i;

			break;
	}

	return core_id;
}

/**
 * ne_check_cpu_in_cpu_pool() - Check if the given vCPU is in the available CPUs
 *				from the pool.
 * @ne_enclave :	Private data associated with the current enclave.
 * @vcpu_id:		ID of the vCPU to check if available in the NE CPU pool.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_check_cpu_in_cpu_pool(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	int core_id = -1;
	unsigned int i = 0;
	int rc = -EINVAL;

	if (ne_donated_cpu(ne_enclave, vcpu_id)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "CPU %d already used\n", vcpu_id);

		return -NE_ERR_VCPU_ALREADY_USED;
	}

	/*
	 * If previously allocated a thread of a core to this enclave, but not
	 * the full core, first check remaining sibling(s).
	 */
	for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++)
		if (cpumask_test_cpu(vcpu_id, ne_enclave->threads_per_core[i]))
			return 0;

	mutex_lock(&ne_cpu_pool.mutex);

	/*
	 * If no remaining siblings, get from the NE CPU pool the core
	 * associated with the vCPU and keep track of all the threads in the
	 * enclave threads per core data structure.
	 */
	core_id = ne_get_vcpu_core_from_cpu_pool(vcpu_id);

	rc = ne_set_enclave_threads_per_core(ne_enclave, core_id, vcpu_id);
	if (rc < 0)
		goto unlock_mutex;

	rc = 0;

unlock_mutex:
	mutex_unlock(&ne_cpu_pool.mutex);

	return rc;
}

/**
 * ne_add_vcpu_ioctl() - Add a vCPU to the slot associated with the current
 *			 enclave.
 * @ne_enclave :	Private data associated with the current enclave.
 * @vcpu_id:		ID of the CPU to be associated with the given slot,
 *			apic id on x86.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_add_vcpu_ioctl(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct pci_dev *pdev = ne_devs.ne_pci_dev->pdev;
	int rc = -EINVAL;
	struct slot_add_vcpu_req slot_add_vcpu_req = {};

	if (ne_enclave->mm != current->mm)
		return -EIO;

	slot_add_vcpu_req.slot_uid = ne_enclave->slot_uid;
	slot_add_vcpu_req.vcpu_id = vcpu_id;

	rc = ne_do_request_retry(pdev, SLOT_ADD_VCPU,
			   &slot_add_vcpu_req, sizeof(slot_add_vcpu_req),
			   &cmd_reply, sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot add vCPU [rc=%d]\n", rc);

		return rc;
	}

	cpumask_set_cpu(vcpu_id, ne_enclave->vcpu_ids);

	ne_enclave->nr_vcpus++;

	return 0;
}

/**
 * ne_sanity_check_user_mem_region() - Sanity check the user space memory
 *				       region received during the set user
 *				       memory region ioctl call.
 * @ne_enclave :	Private data associated with the current enclave.
 * @mem_region :	User space memory region to be sanity checked.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_sanity_check_user_mem_region(struct ne_enclave *ne_enclave,
					   struct ne_user_memory_region mem_region)
{
	struct ne_mem_region *ne_mem_region = NULL;

	if (ne_enclave->mm != current->mm)
		return -EIO;

	if (!mem_region.memory_size ||
	    (mem_region.memory_size & (NE_MIN_MEM_REGION_SIZE - 1))) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "User space memory size is not multiple of 2 MiB\n");

		return -NE_ERR_INVALID_MEM_REGION_SIZE;
	}

	if (!IS_ALIGNED(mem_region.userspace_addr, NE_MIN_MEM_REGION_SIZE)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "User space address is not 2 MiB aligned\n");

		return -NE_ERR_UNALIGNED_MEM_REGION_ADDR;
	}

	if ((mem_region.userspace_addr & (NE_MIN_MEM_REGION_SIZE - 1)) ||
	    !access_ok((void __user *)(unsigned long)mem_region.userspace_addr,
		       mem_region.memory_size)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid user space address range\n");

		return -NE_ERR_INVALID_MEM_REGION_ADDR;
	}

	list_for_each_entry(ne_mem_region, &ne_enclave->mem_regions_list,
			    mem_region_list_entry) {
		u64 memory_size = ne_mem_region->memory_size;
		u64 userspace_addr = ne_mem_region->userspace_addr;

		if ((userspace_addr <= mem_region.userspace_addr &&
		     mem_region.userspace_addr < (userspace_addr + memory_size)) ||
		    (mem_region.userspace_addr <= userspace_addr &&
		    (mem_region.userspace_addr + mem_region.memory_size) > userspace_addr)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "User space memory region already used\n");

			return -NE_ERR_MEM_REGION_ALREADY_USED;
		}
	}

	return 0;
}

/**
 * ne_sanity_check_user_mem_region_page() - Sanity check a page from the user space
 *					    memory region received during the set
 *					    user memory region ioctl call.
 * @ne_enclave :	Private data associated with the current enclave.
 * @mem_region_page:	Page from the user space memory region to be sanity checked.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_sanity_check_user_mem_region_page(struct ne_enclave *ne_enclave,
						struct page *mem_region_page)
{
	if (!PageHuge(mem_region_page)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Not a hugetlbfs page\n");

		return -NE_ERR_MEM_NOT_HUGE_PAGE;
	}

	if (page_size(mem_region_page) & (NE_MIN_MEM_REGION_SIZE - 1)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Page size not multiple of 2 MiB\n");

		return -NE_ERR_INVALID_PAGE_SIZE;
	}

	return 0;
}

/**
 * ne_sanity_check_phys_mem_region() - Sanity check the start address and the size
 *                                     of a physical memory region.
 * @phys_mem_region_paddr : Physical start address of the region to be sanity checked.
 * @phys_mem_region_size  : Length of the region to be sanity checked.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_sanity_check_phys_mem_region(u64 phys_mem_region_paddr,
					   u64 phys_mem_region_size)
{
	if (phys_mem_region_size & (NE_MIN_MEM_REGION_SIZE - 1)) {
		pr_err("nitro_enclaves: phys region size 0x%llx not 2M multiple (addr=0x%llx)\n",
		       phys_mem_region_size, phys_mem_region_paddr);

		return -EINVAL;
	}

	if (!IS_ALIGNED(phys_mem_region_paddr, NE_MIN_MEM_REGION_SIZE)) {
		pr_err("nitro_enclaves: phys region addr 0x%llx not 2M aligned (size=0x%llx)\n",
		       phys_mem_region_paddr, phys_mem_region_size);

		return -EINVAL;
	}

	return 0;
}

/**
 * ne_merge_phys_contig_memory_regions() - Add a memory region and merge the adjacent
 *                                         regions if they are physically contiguous.
 * @phys_contig_regions : Private data associated with the contiguous physical memory regions.
 * @page_paddr :          Physical start address of the region to be added.
 * @page_size :           Length of the region to be added.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int
ne_merge_phys_contig_memory_regions(struct ne_phys_contig_mem_regions *phys_contig_regions,
				    u64 page_paddr, u64 page_size)
{
	unsigned long num = phys_contig_regions->num;
	int rc = 0;

	rc = ne_sanity_check_phys_mem_region(page_paddr, page_size);
	if (rc < 0)
		return rc;

	/* Physically contiguous, just merge */
	if (num && (phys_contig_regions->regions[num - 1].end + 1) == page_paddr) {
		phys_contig_regions->regions[num - 1].end += page_size;
	} else {
		phys_contig_regions->regions[num].start = page_paddr;
		phys_contig_regions->regions[num].end = page_paddr + page_size - 1;
		phys_contig_regions->num++;
	}

	return 0;
}

/*
 * The pages[] arrays handed to ne_share_pages()/ne_unshare_pages() come in
 * two layouts, and the byte length each entry covers differs between them:
 *
 * - per_page_stride == true: one entry per (huge)page, each covering
 *   page_size(entry) bytes.  This is the mem_regions_list layout: the
 *   hugetlb path of ne_set_user_memory_region_ioctl() stores one head
 *   page per 2 MiB / 1 GiB huge page, the NE-CMA contig path stores
 *   order-0 pages (page_size() == PAGE_SIZE).
 *
 * - per_page_stride == false: one entry per PAGE_SIZE slot.  This is the
 *   device_pins layout built by ne_add_shm_region(): entries may point into
 *   hugetlb folios, where page_size() reports the folio size rather than the
 *   4 KiB slice the entry stands for, so the stride must stay fixed at
 *   PAGE_SIZE.  THP cannot appear here: ne_pin_user_range_longterm() takes
 *   only NE-CMA or hugetlb ranges, since neither the priv_holds hold nor the
 *   deferred pin can hold anonymous backing past SLOT_FREE.
 */

/*
 * Longest range a single Guest.Share/Guest.Unshare may cover.  An SRT entry
 * holds at most MAX_SHARED_REGION_PAGES (512) 2 MiB pages, and a longer range
 * is refused with HvcError::InvalidSize.  Both loops below must use this same
 * bound so the unshare presents the pairs the share created.
 */
#define NE_MAX_SHARE_RUN_BYTES SZ_1G

/**
 * ne_unshare_pages() - Unshare pinned pages from NIE, iterating contiguous runs.
 * @ne_enclave:	Enclave context (provides sharing_ops).
 * @pages:	Array of pinned pages.
 * @nr_pages:	Number of pages.
 * @per_page_stride: Array layout, see the comment above.
 */
static void ne_unshare_pages(struct ne_enclave *ne_enclave,
			     struct page **pages, unsigned long nr_pages,
			     bool per_page_stride)
{
	unsigned long p = 0;

	while (p < nr_pages) {
		phys_addr_t start = page_to_phys(pages[p]);
		size_t len = per_page_stride ? page_size(pages[p]) : PAGE_SIZE;

		p++;
		while (p < nr_pages && page_to_phys(pages[p]) == start + len) {
			size_t step = per_page_stride ? page_size(pages[p]) : PAGE_SIZE;

			if (len + step > NE_MAX_SHARE_RUN_BYTES)
				break;
			len += step;
			p++;
		}

		ne_enclave->sharing_ops->unshare(ne_enclave, start, len);
	}
}

/**
 * ne_share_pages() - Share pinned pages with NIE, iterating contiguous runs.
 * @ne_enclave:	Enclave context (provides sharing_ops and slot_uid).
 * @pages:	Array of pinned pages (may be physically discontiguous).
 * @nr_pages:	Number of pages.
 * @per_page_stride: Array layout, see the comment above.
 * @flags:	NE_SHARE_HYP / NE_SHARE_VM / NE_SHARE_DONATE flags.
 * @perms:	Packed permission bits.
 *
 * Return: 0 on success, negative errno on first failure.
 */
static int ne_share_pages(struct ne_enclave *ne_enclave,
			  struct page **pages, unsigned long nr_pages,
			  bool per_page_stride, u64 flags, u64 perms)
{
	unsigned long p = 0;

	while (p < nr_pages) {
		unsigned long run_start = p;
		phys_addr_t start = page_to_phys(pages[p]);
		size_t len = per_page_stride ? page_size(pages[p]) : PAGE_SIZE;
		int rc;

		p++;
		while (p < nr_pages && page_to_phys(pages[p]) == start + len) {
			size_t step = per_page_stride ? page_size(pages[p]) : PAGE_SIZE;

			if (len + step > NE_MAX_SHARE_RUN_BYTES)
				break;
			len += step;
			p++;
		}

		rc = ne_enclave->sharing_ops->share(ne_enclave, start, len,
						    flags, perms,
						    ne_enclave->slot_uid);
		if (rc < 0) {
			ne_unshare_pages(ne_enclave, pages, run_start,
					 per_page_stride);
			return rc;
		}
	}
	return 0;
}

/*
 * Forward declaration: the ops table is defined with the contig vma
 * .close/.fault handlers.
 */
static const struct vm_operations_struct ne_contig_vm_ops;

/*
 * Forward declarations for the contig-priv hold helpers.  The bodies live
 * with the contig vma priv kref machinery, but
 * ne_set_user_memory_region_ioctl() and ne_enclave_release() need them
 * visible here.
 */
struct ne_contig_vma_priv;
static int ne_enclave_hold_contig_priv(struct ne_enclave *ne_enclave,
				       struct ne_contig_vma_priv *priv);
static void ne_enclave_drop_priv_holds(struct ne_enclave *ne_enclave);
/*
 * Trivial wrappers around kref_get/kref_put on a contig vma priv,
 * exposed here so callers in the middle of the file can manipulate
 * the kref without needing the (deliberately opaque) struct
 * definition.  The kref_put wrapper hides the kref_release callback
 * pointer.
 */
static void ne_contig_vma_priv_get(struct ne_contig_vma_priv *priv);
static void ne_contig_vma_priv_put(struct ne_contig_vma_priv *priv);

/**
 * ne_mem_region_vma_check() - Validate that a user memory region is covered
 *			       gaplessly by VMAs of one accepted mapping.
 * @mm :		The mm to look the region up in.
 * @userspace_addr :	Start of the user memory region.
 * @memory_size :	Size of the user memory region in bytes.
 * @out_vma :		Receives the first VMA of the region on success.
 *
 * A memory region handed to the enclave must be backed end to end by the
 * SAME mapping, of an accepted type: the NE driver's own CMA mapping
 * (vm_ops == &ne_contig_vm_ops) or hugetlb.  The mapping may span several
 * adjacent VMAs (userspace legitimately splits its own mapping with
 * madvise/mprotect on a sub-range) as long as every VMA in the walk
 * belongs to it: NE-CMA VMAs must share the first VMA's vm_private_data
 * (split pieces of one ne_mmap() keep the priv pointer, a second mmap gets
 * a fresh one) and hugetlb VMAs must share the first VMA's vm_file (split
 * pieces keep the file, an unrelated hugetlb mapping references another
 * file; hugetlb's vm_private_data holds the per-VMA lock, fresh on every
 * split piece, so it identifies nothing there).  File offsets and vm_flags
 * are deliberately not part of the identity: pinning resolves each virtual
 * address to its own pages, so donating pieces of one mapping in a single
 * call is equivalent to donating each piece separately, which the per-VMA
 * checks already allow.  This keeps get_user_pages() from walking into an
 * adjacent mapping of a different origin, which would let unrelated pages
 * be handed to the enclave.
 *
 * Context: Requires mm's mmap lock held for reading.  The result is only
 *	    stable for as long as the caller keeps holding the lock.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_mem_region_vma_check(struct mm_struct *mm, u64 userspace_addr,
				   u64 memory_size,
				   struct vm_area_struct **out_vma)
{
	struct vm_area_struct *first = NULL;
	struct vm_area_struct *vma;
	unsigned long expect = userspace_addr;
	unsigned long end = userspace_addr + memory_size;
	VMA_ITERATOR(vmi, mm, userspace_addr);

	mmap_assert_locked(mm);

	for_each_vma_range(vmi, vma, end) {
		if (vma->vm_start > expect)
			break;
		if (!first) {
			if (vma->vm_ops != &ne_contig_vm_ops &&
			    !is_vm_hugetlb_page(vma)) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "User memory region is neither hugetlb nor NE CMA\n");

				return -NE_ERR_MEM_NOT_HUGE_PAGE;
			}
			first = vma;
		} else if (vma->vm_ops != first->vm_ops ||
			   vma->vm_file != first->vm_file ||
			   (first->vm_ops == &ne_contig_vm_ops &&
			    vma->vm_private_data != first->vm_private_data)) {
			break;
		}
		expect = vma->vm_end;
		if (expect >= end) {
			*out_vma = first;

			return 0;
		}
	}

	dev_err_ratelimited(ne_misc_dev.this_device,
			    "User memory region not backed by a single mapping\n");

	return -EFAULT;
}

/**
 * ne_set_user_memory_region_ioctl() - Add user space memory region to the slot
 *				       associated with the current enclave.
 * @ne_enclave :	Private data associated with the current enclave.
 * @mem_region :	User space memory region to be associated with the given slot.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_set_user_memory_region_ioctl(struct ne_enclave *ne_enclave,
					   struct ne_user_memory_region mem_region)
{
	long gup_rc = 0;
	unsigned long i = 0;
	unsigned long max_nr_pages = 0;
	unsigned long max_nr_regions = 0;
	unsigned long memory_size = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	struct mm_struct *mm = current->mm;
	struct pci_dev *pdev = ne_devs.ne_pci_dev->pdev;
	struct ne_phys_contig_mem_regions phys_contig_mem_regions = {};
	int rc = -EINVAL;
	bool is_contig = false;
	unsigned long total_base_pages;
	/*
	 * Priv pointer captured under mmap_read_lock so it outlives
	 * mmap_read_unlock. Holds an extra kref of its own; either transferred
	 * to ne_enclave->priv_holds at success, or dropped at the cleanup
	 * labels.
	 */
	struct ne_contig_vma_priv *contig_priv = NULL;

	rc = ne_sanity_check_user_mem_region(ne_enclave, mem_region);
	if (rc < 0)
		return rc;

	ne_mem_region = kzalloc(sizeof(*ne_mem_region), GFP_KERNEL);
	if (!ne_mem_region)
		return -ENOMEM;

	/*
	 * Classify the region as hugetlb or backed by the NE driver's own
	 * CMA mapping (vma->vm_ops == &ne_contig_vm_ops). Only those two
	 * layouts are supported; a plain anon VMA of 4K pages would take
	 * the contig fast path and overflow the bounded regions array
	 * below when pages are scattered.
	 *
	 * The region must lie fully inside one VMA of an accepted type.
	 * The check is repeated under the same mmap_read_lock as the pin
	 * further down; this pass only classifies the region and captures
	 * the contig priv.
	 */
	{
		struct vm_area_struct *vma;

		mmap_read_lock(mm);
		rc = ne_mem_region_vma_check(mm, mem_region.userspace_addr,
					     mem_region.memory_size, &vma);
		if (rc < 0) {
			mmap_read_unlock(mm);
			goto free_mem_region;
		}
		if (vma->vm_ops == &ne_contig_vm_ops) {
			is_contig = true;
			/*
			 * Capture the contig vma priv and take a local kref
			 * while @mmap_read_lock is held so the priv pointer
			 * remains valid past mmap_read_unlock. The priv is
			 * transferred to @ne_enclave->priv_holds after
			 * list_add() below; on any error path before that the
			 * local kref is released at the cleanup labels.
			 */
			contig_priv = vma->vm_private_data;
			if (contig_priv)
				ne_contig_vma_priv_get(contig_priv);
		}
		mmap_read_unlock(mm);
	}

	if (is_contig) {
		/*
		 * Contiguous page path: pages are 4K base pages, pinned in
		 * bulk, so the page array needs one entry per base page. The
		 * regions array does not: the VMA is populated exclusively
		 * from the driver's own CMA chunks, each 2 MiB-aligned and
		 * physically contiguous, so merged regions can only break at
		 * 2 MiB boundaries. Sizing it per base page instead asks
		 * kvmalloc for 16 bytes per 4 KiB - over its INT_MAX cap
		 * from 512 GiB regions upward, failing the registration.
		 */
		total_base_pages = mem_region.memory_size >> PAGE_SHIFT;
		max_nr_pages = total_base_pages;
		max_nr_regions = mem_region.memory_size / NE_MIN_MEM_REGION_SIZE;
	} else {
		/* Hugetlb path: one entry per huge page */
		max_nr_pages = mem_region.memory_size / NE_MIN_MEM_REGION_SIZE;
		max_nr_regions = max_nr_pages;
	}

	ne_mem_region->pages = kvcalloc(max_nr_pages, sizeof(*ne_mem_region->pages),
					GFP_KERNEL);
	if (!ne_mem_region->pages) {
		rc = -ENOMEM;
		goto free_mem_region;
	}

	phys_contig_mem_regions.regions = kvcalloc(
		max_nr_regions,
		sizeof(*phys_contig_mem_regions.regions), GFP_KERNEL);
	if (!phys_contig_mem_regions.regions) {
		rc = -ENOMEM;
		goto free_mem_region;
	}

	if (is_contig) {
		struct vm_area_struct *vma;

		/*
		 * Contiguous fast path: pin all pages at once, then build
		 * contiguous regions from the physical addresses.
		 *
		 * Revalidate the region and pin under one mmap_read_lock
		 * hold: the classification above dropped the lock, so
		 * without the recheck a concurrent thread could remap part
		 * of the range between validation and pin and have
		 * get_user_pages() pick up pages from a different mapping.
		 * get_user_pages() requires the caller to hold the mmap
		 * lock and does not drop it, unlike the _unlocked variant.
		 */
		mmap_read_lock(mm);
		rc = ne_mem_region_vma_check(mm, mem_region.userspace_addr,
					     mem_region.memory_size, &vma);
		if (rc < 0) {
			mmap_read_unlock(mm);
			goto free_mem_region;
		}
		if (vma->vm_ops != &ne_contig_vm_ops ||
		    vma->vm_private_data != contig_priv) {
			mmap_read_unlock(mm);
			rc = -EFAULT;
			goto free_mem_region;
		}
		gup_rc = get_user_pages(mem_region.userspace_addr,
					total_base_pages,
					FOLL_GET,
					ne_mem_region->pages);
		mmap_read_unlock(mm);
		if (gup_rc < 0 || (unsigned long)gup_rc != total_base_pages) {
			if (gup_rc >= 0) {
				/* Partial pin - release what we got */
				for (i = 0; i < (unsigned long)gup_rc; i++)
					put_page(ne_mem_region->pages[i]);
				rc = -EFAULT;
			} else {
				rc = (int)gup_rc;
			}
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "contig get_user_pages failed [rc=%d]\n", rc);
			goto free_mem_region;
		}

		ne_mem_region->nr_pages = total_base_pages;

		/* Build contiguous physical regions from the page array */
		for (i = 0; i < total_base_pages; i++) {
			u64 paddr = page_to_phys(ne_mem_region->pages[i]);
			unsigned long num = phys_contig_mem_regions.num;

			/*
			 * Skip per-page sanity check for contig - individual
			 * pages are 4K which won't pass the 2M check. We
			 * validate the final merged regions below.
			 */
			if (num && (phys_contig_mem_regions.regions[num - 1].end + 1) == paddr) {
				phys_contig_mem_regions.regions[num - 1].end += PAGE_SIZE;
			} else {
				/*
				 * More breaks than 2 MiB chunks can produce
				 * means the backing is not the CMA chunks the
				 * vm_ops check guarantees; fail loudly rather
				 * than write past the bound.
				 */
				if (num == max_nr_regions) {
					dev_err_ratelimited(ne_misc_dev.this_device,
							    "Non-contiguous backing in contig region [num=%lu]\n",
							    num);
					rc = -EFAULT;
					goto put_pages;
				}
				phys_contig_mem_regions.regions[num].start = paddr;
				phys_contig_mem_regions.regions[num].end = paddr + PAGE_SIZE - 1;
				phys_contig_mem_regions.num++;
			}
		}
	} else {
		struct vm_area_struct *vma;

		/*
		 * Hugetlb path.  As on the contig path, revalidate the
		 * region and pin under one mmap_read_lock hold so a
		 * concurrent remap cannot slip a different mapping under
		 * any part of the range between validation and pin.
		 */
		mmap_read_lock(mm);
		rc = ne_mem_region_vma_check(mm, mem_region.userspace_addr,
					     mem_region.memory_size, &vma);
		if (rc < 0) {
			mmap_read_unlock(mm);
			goto free_mem_region;
		}
		if (!is_vm_hugetlb_page(vma)) {
			mmap_read_unlock(mm);
			rc = -EFAULT;
			goto free_mem_region;
		}

		do {
			i = ne_mem_region->nr_pages;

			if (i == max_nr_pages) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Reached max nr of pages\n");
				rc = -ENOMEM;
				goto unlock_put_pages;
			}

			gup_rc = get_user_pages(
				mem_region.userspace_addr + memory_size, 1,
				FOLL_GET, ne_mem_region->pages + i);

			if (gup_rc < 0) {
				rc = (int)gup_rc;
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Error in get user pages [rc=%d]\n",
						    rc);
				goto unlock_put_pages;
			}

			/*
			 * Count the pin now, before the checks below, so the
			 * put_pages cleanup releases this page if a check fails.
			 */
			ne_mem_region->nr_pages++;

			rc = ne_sanity_check_user_mem_region_page(
				ne_enclave, ne_mem_region->pages[i]);
			if (rc < 0)
				goto unlock_put_pages;

			rc = ne_merge_phys_contig_memory_regions(
				&phys_contig_mem_regions,
				page_to_phys(ne_mem_region->pages[i]),
				page_size(ne_mem_region->pages[i]));
			if (rc < 0)
				goto unlock_put_pages;

			memory_size += page_size(ne_mem_region->pages[i]);
		} while (memory_size < mem_region.memory_size);

		mmap_read_unlock(mm);
	}

	if ((ne_enclave->nr_mem_regions + phys_contig_mem_regions.num) >
	    ne_enclave->max_mem_regions) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Reached max memory regions %lld\n",
				    ne_enclave->max_mem_regions);

		rc = -NE_ERR_MEM_MAX_REGIONS;

		goto put_pages;
	}

	for (i = 0; i < phys_contig_mem_regions.num; i++) {
		u64 phys_region_addr = phys_contig_mem_regions.regions[i].start;
		u64 phys_region_size = range_len(&phys_contig_mem_regions.regions[i]);

		rc = ne_sanity_check_phys_mem_region(phys_region_addr, phys_region_size);
		if (rc < 0)
			goto put_pages;
	}

	ne_mem_region->memory_size = mem_region.memory_size;
	ne_mem_region->userspace_addr = mem_region.userspace_addr;

	list_add(&ne_mem_region->mem_region_list_entry, &ne_enclave->mem_regions_list);

	/*
	 * Now that the mem region is on the enclave's mem_regions_list (so any
	 * SLOT_ADD_MEM-induced ownership move is tracked), transfer the contig
	 * priv into ne_enclave->priv_holds BEFORE issuing SLOT_ADD_MEM.
	 * ne_enclave_hold_contig_priv() takes its own kref; the local kref
	 * captured under mmap_read_lock is dropped immediately afterwards. On
	 * hold failure (-ENOMEM only) undo list_add and use the put_pages /
	 * free_mem_region cleanup so we do not leave a tracked mem region
	 * without the priv hold that would protect its CMA pages.
	 */
	if (contig_priv) {
		rc = ne_enclave_hold_contig_priv(ne_enclave, contig_priv);
		ne_contig_vma_priv_put(contig_priv);
		contig_priv = NULL;
		if (rc) {
			list_del(&ne_mem_region->mem_region_list_entry);
			goto put_pages;
		}
	}

	for (i = 0; i < phys_contig_mem_regions.num; i++) {
		struct ne_pci_dev_cmd_reply cmd_reply = {};
		struct slot_add_mem_req slot_add_mem_req = {};

		slot_add_mem_req.slot_uid = ne_enclave->slot_uid;
		slot_add_mem_req.paddr = phys_contig_mem_regions.regions[i].start;
		slot_add_mem_req.size = range_len(&phys_contig_mem_regions.regions[i]);

		rc = ne_do_request_retry(pdev, SLOT_ADD_MEM,
				   &slot_add_mem_req, sizeof(slot_add_mem_req),
				   &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in slot add mem [rc=%d]\n", rc);

			kvfree(phys_contig_mem_regions.regions);

			/*
			 * Exit here without put pages as memory regions may
			 * already been added.
			 */
			return rc;
		}

		ne_enclave->mem_size += slot_add_mem_req.size;
		ne_enclave->nr_mem_regions++;
	}

	kvfree(phys_contig_mem_regions.regions);

	/*
	 * Direct mode: share the entire mem region with the enclave after all
	 * sub-ranges have been registered via SLOT_ADD_MEM. Uses the same
	 * pages[] array that ne_unshare_pages() will walk at teardown,
	 * guaranteeing symmetric address/size pairs.
	 *
	 * Shared with the HYPERVISOR as well as the child, read-write. The
	 * hypervisor has to write this memory before the enclave runs (the
	 * DTB, the ACPI tables and the UEFI image go in the bottom of it and
	 * the enclave image is relocated within it) and it cannot write a
	 * range it has no access to: the enclave VMM takes SIGBUS in its
	 * loader. It also has to withdraw a slice for its own persistent
	 * state, which it cannot do while that slice is invisible to it.
	 *
	 * This is a deliberate property of direct mode, not an oversight: in
	 * direct mode the enclave runs on our pages and its memory is
	 * readable and writable by the hypervisor for the enclave's lifetime.
	 * A confidential enclave is the option that grants nobody access; it
	 * shares nothing and only donates, in the arm below.
	 *
	 * DONATE alongside the two share intents is what authorizes the
	 * withdrawal named above. Sharing a range read-write does not imply
	 * consent to losing it, so NIE will not withdraw from an entry that
	 * does not carry the flag, and the persistent-state slice the enclave
	 * VMM carves out of this region would be refused.
	 *
	 * Note this costs the enclave nothing it had: NIE requires the sharer
	 * to keep access to what it shares, so we retain read-write on every
	 * one of these pages regardless.
	 */
	if (ne_enclave->sharing_ops &&
	    (ne_enclave->start_flags & NE_ENCLAVE_DIRECT_MODE)) {
		rc = ne_share_pages(ne_enclave,
				    ne_mem_region->pages, ne_mem_region->nr_pages,
				    /*per_page_stride=*/true,
				    NE_SHARE_HYP | NE_SHARE_VM | NE_SHARE_DONATE,
				    ne_share_perms_pack(NE_PERM_RW, NE_PERM_RW, NE_PERM_RW));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Guest.Share for mem region failed [rc=%d]\n", rc);
			return rc;
		}
	} else if (ne_enclave->sharing_ops && ne_enclave->pcie_mode) {
		/* Confidential PCIE enclave: this region is not shared with the
		 * enclave, it is taken away from us and given to it. Say so now,
		 * over the same runs SLOT_ADD_MEM just declared, so the secure
		 * monitor is authorized to withdraw them when it carves the enclave
		 * at ENCLAVE_START.
		 *
		 * Without this the withdrawal is only permitted while an
		 * enclave-device command is being serviced, which the carve is
		 * not: it cannot run until the guest has stopped declaring
		 * regions, because that is when the pmem target and the IOMMU
		 * page are chosen.
		 *
		 * PCIE only. A legacy enclave slot is carved inside the
		 * SLOT_ADD_MEM window itself (the monitor moves the page
		 * ownership straight out of its add_mem_region()), so its
		 * withdrawal is already authorized and it has no need to
		 * consent in advance. pcie_mode is decided at NE_CREATE_VM, so
		 * it is settled by here.
		 *
		 * The range stays fully ours here (a donation maps nothing and
		 * retags nothing), so the enclave image can still be written into
		 * it after this call, exactly as before.
		 *
		 * Revoked at teardown alongside the direct-mode hugetlb regions,
		 * in ne_enclave_release() once SLOT_FREE has moved every donated
		 * page back to the parent, the one moment the range is wholly
		 * ours again and Guest.Unshare will accept it.
		 */
		rc = ne_share_pages(ne_enclave,
				    ne_mem_region->pages, ne_mem_region->nr_pages,
				    /*per_page_stride=*/true, NE_SHARE_DONATE,
				    ne_share_perms_pack(NE_PERM_RW, NE_PERM_NOACCESS, NE_PERM_NOACCESS));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Guest.Share DONATE for mem region failed [rc=%d]\n", rc);
			return rc;
		}
	}

	return 0;

unlock_put_pages:
	mmap_read_unlock(mm);
put_pages:
	for (i = 0; i < ne_mem_region->nr_pages; i++)
		put_page(ne_mem_region->pages[i]);
free_mem_region:
	/*
	 * Drop the local kref taken on the contig vma priv while
	 * @mmap_read_lock was held. NULL when the priv was already transferred
	 * into @ne_enclave->priv_holds, when the region was hugetlb, or when
	 * the contig vma had no priv.
	 */
	if (contig_priv)
		ne_contig_vma_priv_put(contig_priv);
	kvfree(phys_contig_mem_regions.regions);
	kvfree(ne_mem_region->pages);
	kfree(ne_mem_region);

	return rc;
}

/*
 * Forward declaration: defined in the Parent-PID visibility block below. Called
 * from ne_start_enclave_ioctl() on CPU_ACCOUNTING enclaves after ENCLAVE_START
 * has populated the info page's TOC.
 */
static int ne_query_vcpu_time(struct pci_dev *pdev,
			      struct ne_enclave *ne_enclave);

/**
 * ne_start_enclave_ioctl() - Trigger enclave start after the enclave resources,
 *			      such as memory and CPU, have been set.
 * @ne_enclave :		Private data associated with the current enclave.
 * @enclave_start_info :	Enclave info that includes enclave cid and flags.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_start_enclave_ioctl(struct ne_enclave *ne_enclave,
				  struct ne_enclave_start_info *enclave_start_info)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	unsigned int cpu = 0;
	struct enclave_start_req enclave_start_req = {};
	unsigned int i = 0;
	struct pci_dev *pdev = ne_devs.ne_pci_dev->pdev;
	int rc = -EINVAL;

	if (!ne_enclave->nr_mem_regions) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Enclave has no mem regions\n");

		return -NE_ERR_NO_MEM_REGIONS_ADDED;
	}

	if (ne_enclave->mem_size < NE_MIN_ENCLAVE_MEM_SIZE) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Enclave memory is less than %ld\n",
				    NE_MIN_ENCLAVE_MEM_SIZE);

		return -NE_ERR_ENCLAVE_MEM_MIN_SIZE;
	}

	if (!ne_enclave->nr_vcpus) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Enclave has no vCPUs\n");

		return -NE_ERR_NO_VCPUS_ADDED;
	}

	for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++)
		for_each_cpu(cpu, ne_enclave->threads_per_core[i])
			if (!cpumask_test_cpu(cpu, ne_enclave->vcpu_ids)) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Full CPU cores not used\n");

				return -NE_ERR_FULL_CORES_NOT_USED;
			}

	/*
	 * PCIE mode requires an info page registered with the Nitro
	 * Enclaves device before ENCLAVE_START. The info page is
	 * registered by the NE_SET_INFO_PAGE ioctl, which sends the
	 * SLOT_ADD_INFO_PAGE PCI command itself; by the time we get
	 * here @info_pages is non-NULL iff that round-trip succeeded.
	 *
	 * The pcie_mode bit was decided at NE_CREATE_VM based on the flag
	 * word passed to SLOT_ALLOC; the flags field on enclave_start_info
	 * now only carries DEBUG.
	 */
	if (ne_enclave->pcie_mode && !ne_enclave->info_pages) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "PCIE mode requires NE_SET_INFO_PAGE before NE_START_ENCLAVE\n");
		return -EINVAL;
	}

	enclave_start_req.enclave_cid = enclave_start_info->enclave_cid;
	enclave_start_req.flags = enclave_start_info->flags;
	enclave_start_req.slot_uid = ne_enclave->slot_uid;

	rc = ne_do_request_retry(pdev, ENCLAVE_START,
			   &enclave_start_req, sizeof(enclave_start_req),
			   &cmd_reply, sizeof(cmd_reply));

	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in enclave start [rc=%d]\n", rc);

		return rc;
	}

	ne_enclave->state = NE_STATE_RUNNING;

	enclave_start_info->enclave_cid = cmd_reply.start.enclave_cid;

	/*
	 * Query the per-vCPU time-counter array location for
	 * CPU_ACCOUNTING enclaves. Non-CPU_ACCOUNTING enclaves skip
	 * the round-trip; see ne_query_vcpu_time().
	 *
	 * Issued here (after ENCLAVE_START succeeds) so the hypervisor
	 * has fully initialized the info page, including writing the
	 * vCPU-time TOC entry with offset/size populated.
	 * A failure here is non-fatal for the enclave itself: the
	 * feature stays unavailable (vcpu_time_array_count stays 0) and
	 * subsequent NE_ACCOUNT_VCPU calls cleanly reject.
	 */
	rc = ne_query_vcpu_time(pdev, ne_enclave);
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in vcpu_time query [rc=%d]\n", rc);
		/* Not a fatal failure: enclave is running. */
	}

	return 0;
}

/**
 * ne_enclave_ioctl() - Ioctl function provided by the enclave file.
 * @file:	File associated with this ioctl function.
 * @cmd:	The command that is set for the ioctl call.
 * @arg:	The argument that is provided for the ioctl call.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */

/*
 * Enclave ioeventfd: when an eventfd is signaled, write to BAR4 to relay
 * the notification to the enclave.  Multiple ioeventfds can watch different
 * eventfds for the same BAR4 offset: all of them fire independently. This
 * allows the proxy's permanent eventfd and a backend's transient eventfd to
 * coexist without re-wiring.
 */
static int ne_ioeventfd_wakeup(wait_queue_entry_t *wait, unsigned int mode,
			       int sync, void *key)
{
	struct ne_ioeventfd *iofd = container_of(wait, struct ne_ioeventfd,
						 wait);
	__poll_t flags = key_to_poll(key);

	if (flags & EPOLLIN) {
		struct ne_pci_dev *ne_pci_dev = iofd->ne_pci_dev;

		if (ne_pci_dev->notify_base && iofd->active) {
			eventfd_ctx_do_read(iofd->ctx, &(u64){0});
			iowrite16(iofd->notify_offset / 2,
				  ne_pci_dev->notify_base +
				  iofd->notify_offset);
		}
	}
	return 0;
}

static void ne_ioeventfd_ptable_queue_proc(struct file *file,
					   wait_queue_head_t *wqh,
					   poll_table *pt)
{
	struct ne_ioeventfd *iofd = container_of(pt, struct ne_ioeventfd,
						 pt_storage);
	/*
	 * Refuse a second poll_wait() callback. ne_set_vring_call() now
	 * single-fdgets and validates eventfd-ness on the resulting file, so
	 * eventfd_poll(), which calls poll_wait() once, is the only legitimate
	 * caller. This guard is belt-and-braces against any future regression
	 * where vfs_poll() ends up running a ->poll that calls poll_wait() more
	 * than once: the same iofd->wait would otherwise be list_add()ed onto
	 * two wait_queue_head_t's, splicing the heads.
	 */
	if (iofd->wqh)
		return;
	iofd->wqh = wqh;
	add_wait_queue(wqh, &iofd->wait);
}

static int ne_set_vring_call(struct ne_enclave *ne_enclave,
			     struct ne_pci_dev *ne_pci_dev,
			     struct ne_vring_call __user *argp)
{
	struct ne_vring_call req;
	struct ne_ioeventfd *iofd;
	struct eventfd_ctx *ctx;
	struct fd f;
	unsigned int slot;

	if (!ne_pci_dev->notify_base)
		return -ENODEV;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	/*
	 * Bound the user-supplied BAR4 doorbell offset against the cached
	 * BAR4 length. ne_ioeventfd_wakeup() later does iowrite16() at
	 * notify_base + notify_offset; without this check, an offset
	 * up to 0xFFFE would store 2 bytes past the ioremap window: a
	 * kernel oops on the vmalloc guard page or silent corruption of
	 * an adjacent ioremap mapping (e.g. the enclave device's MSI-X table
	 * mapped immediately after notify_base by ne_setup_msix()).
	 *
	 * Reachable by any /dev/nitro_enclaves user (group `ne`, mode
	 * 0660) without enclave start, NE_ADD_DEVICE, or any hypervisor round
	 * trip.
	 *
	 * Enforce 2-byte alignment too: iowrite16() on x86 is unaligned-
	 * tolerant but unaligned MMIO is undefined on arm64.
	 *
	 * No lock needed: the bound is a pure function of req contents
	 * and a per-PCI-device length cached at probe.
	 */
	if (ne_pci_dev->notify_len < sizeof(u16) ||
	    req.bar4_doorbell_offset > ne_pci_dev->notify_len - sizeof(u16))
		return -EINVAL;
	if (req.bar4_doorbell_offset & 1)
		return -EINVAL;

	/*
	 * Serialize the entire check-bound / allocate-slot / init-wait-entry
	 * / poll / increment sequence. Without the lock, two threads racing
	 * NE_SET_VRING_CALL on the same enclave fd could pick the same slot
	 * index, init_waitqueue_func_entry() on a live waitqueue_entry_t and
	 * then add_wait_queue() it onto a second eventfd's waitqueue,
	 * corrupting the list and turning the next write() to either eventfd
	 * into an indirect call through attacker-controllable bytes.
	 */
	mutex_lock(&ne_enclave->enclave_info_mutex);

	if (ne_enclave->num_ioeventfds >= NE_MAX_IOEVENTFDS) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -ENOSPC;
	}
	slot = ne_enclave->num_ioeventfds;

	/*
	 * Resolve req.fd ONCE and validate eventfd-ness on the resulting struct
	 * file. The previous double-lookup pattern (eventfd_ctx_fdget + a
	 * separate fdget) raced a concurrent dup2() on req.fd: the first lookup
	 * validated an eventfd, the second returned the replacement file, and
	 * vfs_poll() then ran the replacement's ->poll. With pipe_poll() that
	 * yields a doubly-linked iofd->wait corrupting two waitqueue heads;
	 * with a poll-less file (e.g. /dev/null) iofd->wqh stays NULL and a
	 * later ne_enclave_release() NULL-derefs in remove_wait_queue(). Both
	 * paths are reachable from any /dev/nitro_enclaves user (group `ne`)
	 * sharing an fdtable.
	 */
	f = fdget(req.fd);
	if (!fd_file(f)) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -EBADF;
	}

	ctx = eventfd_ctx_fileget(fd_file(f));
	if (IS_ERR(ctx)) {
		fdput(f);
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return PTR_ERR(ctx);
	}

	/*
	 * Heap-allocate the node. Its embedded wait/pt_storage are handed to
	 * a waitqueue below and recovered via container_of(), so the node
	 * must have a stable address for its lifetime: a list node does,
	 * and unlike an inline array it never forces a large contiguous
	 * struct ne_enclave allocation.
	 */
	iofd = kzalloc(sizeof(*iofd), GFP_KERNEL);
	if (!iofd) {
		eventfd_ctx_put(ctx);
		fdput(f);
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -ENOMEM;
	}
	iofd->ctx = ctx;
	iofd->ne_pci_dev = ne_pci_dev;
	iofd->notify_offset = req.bar4_doorbell_offset;
	iofd->wqh = NULL;
	iofd->active = true;

	init_waitqueue_func_entry(&iofd->wait, ne_ioeventfd_wakeup);
	init_poll_funcptr(&iofd->pt_storage, ne_ioeventfd_ptable_queue_proc);

	vfs_poll(fd_file(f), &iofd->pt_storage);
	fdput(f);

	list_add_tail(&iofd->list, &ne_enclave->ioeventfds);
	ne_enclave->num_ioeventfds = slot + 1;
	pr_debug("NE: ioeventfd[%u] wired: fd=%d -> BAR4 offset=%u\n",
		 slot, req.fd, iofd->notify_offset);

	mutex_unlock(&ne_enclave->enclave_info_mutex);
	return 0;
}

/*
 * Enclave irqfd: when an MSI-X vector fires on the enclave PCI device,
 * signal the associated eventfd.  The handler dereferences nf->ctx through
 * a pointer so that ctx-swaps (on re-registration) take effect immediately
 * without tearing down the IRQ.
 */

static int ne_set_vring_kick(struct ne_enclave *ne_enclave,
			     struct ne_pci_dev *ne_pci_dev,
			     struct ne_vring_kick __user *argp)
{
	struct ne_kick_binding_entry *entry, *cur;
	struct ne_vring_kick req;
	struct ne_mux_binding *b, *old;
	struct eventfd_ctx *ctx;
	bool same_enclave_replace = false;
	u32 v_rel, bit;
	u64 vq_id;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	/* All VQ kicks route through the pooled mux. msix_vector carries
	 * 0x8000 | vq_id for hypervisor-assigned VQs. Unflagged values
	 * (e.g. from QEMU's extra config-change queues) are silently
	 * ignored. */
	if (!ne_pci_dev->nmux || !(req.msix_vector & 0x8000))
		return 0;

	ctx = eventfd_ctx_fdget(req.fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	vq_id = req.msix_vector & 0x7FFF;
	v_rel = (u32)(vq_id % ne_pci_dev->nmux);
	bit = (u32)(vq_id / ne_pci_dev->nmux);
	if (bit >= PAGE_SIZE * 8) {
		eventfd_ctx_put(ctx);
		return -E2BIG;
	}

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b) {
		eventfd_ctx_put(ctx);
		return -ENOMEM;
	}
	b->ctx = ctx;
	atomic64_set(&b->kicks, 0);

	/*
	 * Pre-allocate the per-enclave tracking entry outside the mutex.
	 * Discarded if this turns out to be a same-enclave replacement
	 * (the existing entry already tracks @vq_id).
	 */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		eventfd_ctx_put(ctx);
		kfree(b);
		return -ENOMEM;
	}
	entry->vq_id = vq_id;

	/*
	 * Take @enclave_info_mutex around the kick_xa update + per-enclave
	 * list manipulation so they appear atomic to ne_enclave_release()
	 * and to a concurrent NE_SET_VRING_KICK on the same enclave fd.
	 * Mirrors the lock pattern NE_SET_VRING_CALL uses.
	 */
	mutex_lock(&ne_enclave->enclave_info_mutex);

	list_for_each_entry(cur, &ne_enclave->kick_bindings, list) {
		if (cur->vq_id == vq_id) {
			same_enclave_replace = true;
			break;
		}
	}

	if (same_enclave_replace) {
		/*
		 * This enclave already owns @vq_id: it is tracked in our
		 * kick_bindings list and, by the install invariant enforced
		 * on the fresh-install path below, is the sole occupant of
		 * kick_xa[@vq_id].  Swap our own binding for the new one.
		 * ne_enclave_release()'s reap and any other kick/info-event
		 * ioctl on THIS enclave are serialized by @enclave_info_mutex,
		 * and no OTHER enclave can store here (their install uses
		 * xa_cmpxchg() against NULL and so fails while we occupy the
		 * slot), so @old is guaranteed to be our previous binding.
		 */
		old = xa_store(&ne_pci_dev->kick_xa, vq_id, b, GFP_KERNEL);
		if (xa_is_err(old)) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			kfree(entry);
			eventfd_ctx_put(ctx);
			kfree(b);
			return xa_err(old);
		}
		/* The tracking entry already exists; discard the spare. */
		kfree(entry);
		/*
		 * @old was visible to ne_mux_handler(), which dereferences the
		 * binding (and signals old->ctx) after xa_load()'s internal
		 * rcu_read_lock() has been released.  Defer its free (and the
		 * eventfd_ctx_put()) to an RCU grace period.
		 */
		if (old)
			ne_mux_binding_free_rcu(old);
	} else {
		/*
		 * Fresh install. kick_xa is a per-DEVICE xarray shared by all
		 * enclaves, yet every mutation site serializes it only under
		 * the caller's PER-enclave mutex, so two enclaves racing on the
		 * same hypervisor-assigned vq_id are not mutually excluded.
		 * Installing with an unconditional xa_store() (then rolling
		 * back with a second xa_store() on a cross-enclave collision)
		 * clobbers a concurrent enclave's live binding and leaves @b
		 * briefly visible: a concurrent reap or install can then free
		 * the same ne_mux_binding, double-arming its rcu_head
		 * (parent-kernel panic) or leaving a dangling kick_xa entry
		 * (use-after-free via ne_mux_handler()). Install atomically
		 * against an EMPTY slot instead: on a collision the store never
		 * happens, @b never becomes visible, and there is nothing to
		 * roll back. This upholds the invariant that each occupied
		 * kick_xa key is owned by exactly one enclave and tracked in
		 * exactly that enclave's kick_bindings list.
		 */
		old = xa_cmpxchg(&ne_pci_dev->kick_xa, vq_id, NULL, b,
				 GFP_KERNEL);
		if (xa_is_err(old)) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			kfree(entry);
			eventfd_ctx_put(ctx);
			kfree(b);
			return xa_err(old);
		}
		if (old) {
			/*
			 * Cross-enclave collision: @vq_id is still bound by
			 * another live enclave.  The cmpxchg left that binding
			 * in place and never published @b, so free @b
			 * synchronously and surface -EEXIST instead of silently
			 * stealing the other enclave's eventfd ctx.
			 */
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			kfree(entry);
			eventfd_ctx_put(ctx);
			kfree(b);
			return -EEXIST;
		}
		list_add(&entry->list, &ne_enclave->kick_bindings);
	}

	/*
	 * Raise the per-vector high-water mark race-free.  max_bit is a
	 * PER-DEVICE field, but this bump runs under the PER-enclave
	 * enclave_info_mutex, so two enclaves binding vectors on the same
	 * mux vec can race and lose a bump (same shared-kick_xa class as the
	 * cross-enclave double-free).  A lost bump shrinks
	 * ne_mux_handler()'s nwords = max_bit/64 + 1 scan and drops a kick.
	 * Use a cmpxchg raise loop on the u32 field instead of a plain RMW;
	 * try_cmpxchg() reloads cur on failure so the loop re-tests the
	 * monotonic condition.  The read side (ne_mux_handler) uses
	 * READ_ONCE().
	 */
	{
		u32 cur = READ_ONCE(ne_pci_dev->mux[v_rel].max_bit);

		while (bit > cur) {
			if (try_cmpxchg(&ne_pci_dev->mux[v_rel].max_bit,
					&cur, bit))
				break;
		}
	}

	mutex_unlock(&ne_enclave->enclave_info_mutex);

	pr_debug("NE: muxed vring kick: fd=%d vq_id=%llu v_rel=%u bit=%u\n",
		 req.fd, vq_id, v_rel, bit);
	return 0;
}

/**
 * ne_pin_user_range_longterm() - Long-term pin a userspace range of pages.
 *
 * @ne_enclave:   Enclave (used for mm check).
 * @uaddr:        Userspace virtual address. Must be page aligned.
 * @size:         Size in bytes. Must be a multiple of PAGE_SIZE.
 * @require_vm_ops:
 *                If non-NULL, require the backing VMA to have vm_ops == this
 *                pointer (i.e. a specific known driver mapping). Otherwise,
 *                only hugetlb VMAs are accepted. This gates the long-term pin
 *                to mappings whose owner understands "pinned pages live longer
 *                than the VMA".
 * @require_contiguous:
 *                If true, verify all pinned pages are physically contiguous.
 * @write:        Pass false to pin read-only. A write pin demands a writable
 *                VMA (FOLL_WRITE) that is also MAP_SHARED (this driver's own
 *                rule, below), so a read-only pin lets userspace back the
 *                region PROT_READ or MAP_PRIVATE.
 * @out_pages:    On success, returns a kvmalloc'd array of pinned pages. The
 *                caller owns the array and must unpin+kvfree it on release.
 * @out_nr_pages: Number of pages in @out_pages.
 * @out_contig_priv:
 *                On success, the NE-CMA contig vma priv with a kref taken
 *                (NULL for hugetlb, which needs no hold). Caller either
 *                transfers it into priv_holds or drops it.
 *
 * Callers: NE_SET_INFO_PAGE and ne_add_shm_region().
 *
 * Return: 0 on success; negative errno on failure, with nothing pinned and
 * no priv kref held.
 */
static int ne_pin_user_range_longterm(struct ne_enclave *ne_enclave,
				      unsigned long uaddr, u64 size,
				      const struct vm_operations_struct *require_vm_ops,
				      bool require_contiguous, bool write,
				      struct page ***out_pages,
				      unsigned long *out_nr_pages,
				      struct ne_contig_vma_priv **out_contig_priv)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct page **pages;
	unsigned long nr_pages;
	unsigned long i;
	long gup_rc;
	bool is_ne_cma = false;
	int rc;

	if (out_contig_priv)
		*out_contig_priv = NULL;

	if (!PAGE_ALIGNED(uaddr) || !PAGE_ALIGNED(size) || !size)
		return -EINVAL;

	if (ne_enclave && ne_enclave->mm != mm)
		return -EINVAL;

	nr_pages = size >> PAGE_SHIFT;

	pages = kvmalloc_array(nr_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	/*
	 * Verify the backing VMA matches an accepted mapping type before we
	 * pin. We accept either a caller-specified vm_ops (our own CMA
	 * mapping) or hugetlb VMAs. A plain anon VMA of 4K pages is rejected
	 * because we can't safely long-term pin those: the parent guest
	 * would end up with order-0 pages that go back to the allocator on
	 * munmap while the host still DMAs to the 2 MiB region.
	 *
	 * The checks and the pin sit under one mmap_read_lock hold:
	 * pin_user_pages() requires the caller to hold the mmap lock and
	 * does not drop it, so a concurrent remap cannot swap a different
	 * mapping under the range between validation and pin.
	 */
	mmap_read_lock(mm);
	vma = find_vma(mm, uaddr);
	if (!vma || uaddr < vma->vm_start || uaddr + size > vma->vm_end) {
		rc = -EFAULT;
		goto err_unlock;
	}
	if (!((require_vm_ops && vma->vm_ops == require_vm_ops) ||
	      is_vm_hugetlb_page(vma))) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Range is neither NE CMA nor hugetlb\n");
		rc = -NE_ERR_MEM_NOT_HUGE_PAGE;
		goto err_unlock;
	}
	/*
	 * Require MAP_SHARED for a write pin. GUP itself asks only for
	 * VM_WRITE; this is the driver's rule, so do not drop it as redundant.
	 * An NE-CMA vma is inserted write-protected, so a private mapping COWs
	 * on the FOLL_WRITE fault below and leaves this pin on anon copies
	 * while the pages the hypervisor was handed go unreferenced. Private
	 * hugetlb does not COW here, but donating a mapping whose pages a later
	 * fork() can substitute has no purpose, so refuse both rather than
	 * carry a rule that holds for one backing and not the other. A
	 * read-only pin never COWs, so the info page keeps taking either.
	 */
	if (write && !(vma->vm_flags & VM_SHARED)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Range must be MAP_SHARED for a write pin\n");
		rc = -EINVAL;
		goto err_unlock;
	}
	is_ne_cma = (require_vm_ops && vma->vm_ops == require_vm_ops);
	/*
	 * For the NE driver's own CMA mapping, capture the contig vma priv
	 * and take a local kref while @mmap_read_lock is held so the priv
	 * pointer stays valid past mmap_read_unlock. The caller transfers it
	 * into ne_enclave->priv_holds so cma_release() of the backing pages
	 * is deferred until the async slot free (after SLOT_FREE), otherwise
	 * an munmap on teardown returns the pages to the parent guest's page
	 * allocator while the host EPT still maps them read-only, and the
	 * next allocation of one of those pages faults. Mirrors the
	 * NE_SET_USER_MEMORY_REGION contig-priv hold.
	 */
	if (out_contig_priv && is_ne_cma) {
		*out_contig_priv = vma->vm_private_data;
		if (*out_contig_priv)
			ne_contig_vma_priv_get(*out_contig_priv);
	}

	/*
	 * For the NE driver's own CMA mapping, skip FOLL_LONGTERM. These
	 * pages are owned by the driver and won't be migrated or freed
	 * while the enclave exists. FOLL_LONGTERM triggers CMA page
	 * isolation which can deadlock on the CMA mutex.
	 *
	 * FOLL_WRITE only when pinning for write, so a read-only pin
	 * accepts a PROT_READ VMA.
	 */
	gup_rc = pin_user_pages(uaddr, nr_pages,
				(write ? FOLL_WRITE : 0) |
				(is_ne_cma ? 0 : FOLL_LONGTERM),
				pages);
	mmap_read_unlock(mm);
	if (gup_rc < 0) {
		rc = (int)gup_rc;
		goto err_put_priv;
	}
	if ((unsigned long)gup_rc != nr_pages) {
		/* Partial pin: unpin what we got and return EFAULT. */
		unpin_user_pages(pages, (unsigned long)gup_rc);
		rc = -EFAULT;
		goto err_put_priv;
	}

	if (require_contiguous) {
		phys_addr_t base = page_to_phys(pages[0]);

		for (i = 1; i < nr_pages; i++) {
			if (page_to_phys(pages[i]) != base + (i << PAGE_SHIFT)) {
				rc = -EINVAL;
				goto err_unpin;
			}
		}
	}

	*out_pages = pages;
	*out_nr_pages = nr_pages;
	return 0;

err_unpin:
	unpin_user_pages(pages, nr_pages);
	goto err_put_priv;
err_unlock:
	mmap_read_unlock(mm);
err_put_priv:
	/* A leaked kref would keep the CMA backing reserved for good. */
	if (out_contig_priv && *out_contig_priv) {
		ne_contig_vma_priv_put(*out_contig_priv);
		*out_contig_priv = NULL;
	}
	kvfree(pages);
	return rc;
}

/**
 * ne_set_info_event_fd() - Bind (or unbind) an info-event eventfd into the
 * shared kick_xa, keyed by the pseudo-VQ id assigned by the hypervisor.
 *
 * Info-event notifications use the same RCU-replace ne_mux_binding path
 * as ne_set_vring_kick(): ne_mux_handler() computes the vq_id from the
 * MSI-X vector and signals the bound eventfd.
 *
 * fd < 0 unbinds (xa_erase + RCU-deferred free).
 *
 * The binding is owned by @ne_enclave: it is tracked in
 * ne_enclave->kick_bindings and reaped by ne_enclave_release(), exactly
 * like ne_set_vring_kick().  Without this, info-event bindings would leak
 * in kick_xa across enclave teardown (an eventfd_ctx + ne_mux_binding per
 * dead enclave), and hypervisor pseudo-VQ-id reuse would later surface as a
 * spurious -EEXIST from ne_set_vring_kick().
 *
 * Return: 0 on success, negative errno on failure.
 */
static int ne_set_info_event_fd(struct ne_enclave *ne_enclave,
				struct ne_pci_dev *ne_pci_dev,
				struct ne_info_event_fd __user *argp)
{
	struct ne_kick_binding_entry *entry, *cur;
	struct ne_info_event_fd req;
	struct ne_mux_binding *b, *old;
	struct eventfd_ctx *ctx;
	bool same_enclave_replace = false;
	u32 v_rel, bit;
	u64 vq_id;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.reserved != 0)
		return -EINVAL;

	if (!ne_pci_dev->nmux)
		return -ENODEV;

	vq_id = (u64)req.vector;

	/*
	 * Unbind path: drop the binding and the matching per-enclave
	 * tracking entry under @enclave_info_mutex so kick_bindings stays
	 * consistent with ne_enclave_release()'s reap.
	 */
	if (req.fd < 0) {
		struct ne_kick_binding_entry *kb, *kb_tmp;
		bool owned = false;

		mutex_lock(&ne_enclave->enclave_info_mutex);
		/*
		 * kick_xa is shared per-device.  Only erase (and RCU-free) the
		 * binding if THIS enclave installed @vq_id: membership in our
		 * kick_bindings list is the ownership record.  Without this
		 * gate a parent could unbind another live enclave's binding at
		 * a colliding pseudo-VQ id.  Unbind of a vq_id we do not own is
		 * a no-op success (idempotent).
		 */
		list_for_each_entry_safe(kb, kb_tmp,
					 &ne_enclave->kick_bindings, list) {
			if (kb->vq_id == vq_id) {
				list_del(&kb->list);
				kfree(kb);
				owned = true;
				break;
			}
		}
		if (owned) {
			old = xa_erase(&ne_pci_dev->kick_xa, vq_id);
			if (old)
				ne_mux_binding_free_rcu(old);
		}
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return 0;
	}

	ctx = eventfd_ctx_fdget(req.fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	v_rel = (u32)(vq_id % ne_pci_dev->nmux);
	bit = (u32)(vq_id / ne_pci_dev->nmux);
	if (bit >= PAGE_SIZE * 8) {
		eventfd_ctx_put(ctx);
		return -E2BIG;
	}

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b) {
		eventfd_ctx_put(ctx);
		return -ENOMEM;
	}
	b->ctx = ctx;
	atomic64_set(&b->kicks, 0);

	/*
	 * Pre-allocate the per-enclave tracking entry outside the mutex.
	 * Discarded if this turns out to be a same-enclave replacement
	 * (the existing entry already tracks @vq_id).
	 */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		eventfd_ctx_put(ctx);
		kfree(b);
		return -ENOMEM;
	}
	entry->vq_id = vq_id;

	/*
	 * Take @enclave_info_mutex around the kick_xa update + per-enclave
	 * list manipulation so they appear atomic to ne_enclave_release()
	 * and to a concurrent NE_SET_VRING_KICK / NE_SET_INFO_EVENT_FD on
	 * the same enclave fd.  Mirrors ne_set_vring_kick().
	 */
	mutex_lock(&ne_enclave->enclave_info_mutex);

	list_for_each_entry(cur, &ne_enclave->kick_bindings, list) {
		if (cur->vq_id == vq_id) {
			same_enclave_replace = true;
			break;
		}
	}

	if (same_enclave_replace) {
		/*
		 * We already own @vq_id (tracked in kick_bindings and, per the
		 * fresh-install invariant below, sole occupant of kick_xa).
		 * Swap our own binding; same-enclave ioctls and the release
		 * reap are serialized by @enclave_info_mutex and no other
		 * enclave can store here, so @old is our previous binding.
		 */
		old = xa_store(&ne_pci_dev->kick_xa, vq_id, b, GFP_KERNEL);
		if (xa_is_err(old)) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			kfree(entry);
			eventfd_ctx_put(ctx);
			kfree(b);
			return xa_err(old);
		}
		kfree(entry);
		if (old)
			ne_mux_binding_free_rcu(old);
	} else {
		/*
		 * Fresh install into the shared per-device kick_xa.  Install
		 * atomically against an EMPTY slot: on a cross-enclave
		 * collision the store never happens and @b never becomes
		 * visible, so there is no publish-then-rollback window in which
		 * a concurrent reap/install could double-free the binding
		 * (double call_rcu -> parent-kernel panic) or leave a dangling
		 * kick_xa entry (use-after-free via ne_mux_handler()).  Mirrors
		 * ne_set_vring_kick().
		 */
		old = xa_cmpxchg(&ne_pci_dev->kick_xa, vq_id, NULL, b,
				 GFP_KERNEL);
		if (xa_is_err(old)) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			kfree(entry);
			eventfd_ctx_put(ctx);
			kfree(b);
			return xa_err(old);
		}
		if (old) {
			/*
			 * Cross-enclave collision: the pseudo-VQ id is still
			 * bound by another live enclave.  @b was never
			 * published, so free it synchronously and surface
			 * -EEXIST instead of stealing the other enclave's ctx.
			 */
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			kfree(entry);
			eventfd_ctx_put(ctx);
			kfree(b);
			return -EEXIST;
		}
		list_add(&entry->list, &ne_enclave->kick_bindings);
	}

	/*
	 * Raise the per-vector high-water mark race-free.  max_bit is a
	 * PER-DEVICE field, but this bump runs under the PER-enclave
	 * enclave_info_mutex, so two enclaves binding vectors on the same
	 * mux vec can race and lose a bump (same shared-kick_xa class as the
	 * cross-enclave double-free).  A lost bump shrinks
	 * ne_mux_handler()'s nwords = max_bit/64 + 1 scan and drops a kick.
	 * Use a cmpxchg raise loop on the u32 field instead of a plain RMW;
	 * try_cmpxchg() reloads cur on failure so the loop re-tests the
	 * monotonic condition.  The read side (ne_mux_handler) uses
	 * READ_ONCE().
	 */
	{
		u32 cur = READ_ONCE(ne_pci_dev->mux[v_rel].max_bit);

		while (bit > cur) {
			if (try_cmpxchg(&ne_pci_dev->mux[v_rel].max_bit,
					&cur, bit))
				break;
		}
	}

	mutex_unlock(&ne_enclave->enclave_info_mutex);

	return 0;
}

/**
 * ne_build_backing_ranges() - Walk a page array and build contiguous physical
 * backing ranges, appending to an existing output array.
 *
 * @pages:      Array of struct page pointers (already pinned).
 * @nr_pages:   Number of pages in the array.
 * @ranges:     Output array of backing ranges (caller-provided).
 * @max_ranges: Maximum number of ranges the output array can hold.
 * @num_ranges: In/out: number of ranges already in the array; updated on exit.
 * @shm_id:    SHM region ID, packed into top 8 bits of each range's size.
 *             A value of 0 means DMB (default for pre-uplift producers).
 *
 * Walks the page array, coalescing physically contiguous pages into ranges.
 * Appends new ranges starting at ranges[*num_ranges].
 * Returns 0 on success, -EINVAL if the number of non-contiguous regions
 * exceeds @max_ranges.
 *
 * Context: Any. No locks required. Pure computation on the page array.
 */
static int ne_build_backing_ranges(struct page **pages, unsigned long nr_pages,
				   struct slot_backing_range *ranges,
				   u32 max_ranges, u32 *num_ranges, u8 shm_id)
{
	unsigned long p;

	for (p = 0; p < nr_pages; p++) {
		phys_addr_t pa = page_to_phys(pages[p]);
		u32 ri = *num_ranges;

		if (ri > 0 &&
		    pa == (ranges[ri - 1].phys_addr +
			   (ranges[ri - 1].size & NE_RANGE_SIZE_MASK)) &&
		    (ranges[ri - 1].size >> NE_RANGE_SHMID_SHIFT) == shm_id) {
			ranges[ri - 1].size += PAGE_SIZE;
		} else {
			if (ri >= max_ranges)
				return -EINVAL;
			ranges[ri].phys_addr = pa;
			ranges[ri].size = PAGE_SIZE |
					  ((u64)shm_id << NE_RANGE_SHMID_SHIFT);
			(*num_ranges)++;
		}
	}

	return 0;
}

/**
 * ne_release_device_pins() - Release page references and free a device pins entry.
 * @pins: The device pins entry to release. Removed from its list and freed.
 * @defer_hugetlb:	Skip hugetlb-backed DMBs, whose pin is their only hold.
 *			Same meaning as in
 *			ne_enclave_remove_all_mem_region_entries().
 *
 * Return: true if released, false if deferred.
 */
static bool ne_release_device_pins(struct ne_device_pins *pins,
				   bool defer_hugetlb)
{
	unsigned long j;

	/*
	 * A hugetlb DMB has no priv_holds entry, so this pin alone keeps its
	 * pages from the parent allocator while the hypervisor may still share
	 * them. ne_enclave_release() drains it after SLOT_FREE.
	 */
	if (defer_hugetlb && pins->nr_pages && pins->pages[0] &&
	    PageHuge(pins->pages[0]))
		return false;

	if (pins->nr_pages && pins->pages[0])
		pr_debug("NE: DMB pins released hpa=0x%llx nr_pages=%lu\n",
			 (u64)page_to_phys(pins->pages[0]), pins->nr_pages);

	/* unpin_user_page(), not put_page(): pinned via pin_user_pages(). */
	for (j = 0; j < pins->nr_pages; j++) {
		if (pins->pages[j])
			unpin_user_page(pins->pages[j]);
	}
	kvfree(pins->pages);
	list_del(&pins->list);
	kvfree(pins);

	return true;
}

static void ne_enclave_remove_all_mem_region_entries(struct ne_enclave *ne_enclave,
						     bool defer_hugetlb);

/**
 * ne_mmu_notifier_release() - Drop GUP pins before VMA teardown.
 * @mn:		MMU notifier registered on the enclave's mm.
 * @mm:		The mm_struct being torn down.
 *
 * Called from exit_mmap() before any VMAs are closed. This ensures GUP pins
 * are dropped before ne_contig_vma_close() calls cma_release(), preventing
 * the "pages are still in use" WARNING from free_contig_range().
 *
 * In do_exit(), exit_mm() runs before exit_files()/exit_task_work(), so for
 * a single-threaded process this callback fires (from exit_mmap()) before
 * ne_enclave_release() runs, which then unregisters and finds nothing to do.
 *
 * For a MULTI-THREADED process the two paths race: one thread runs
 * exit_mm() -> exit_mmap() -> __mmu_notifier_release() while another runs
 * exit_files() -> __fput() -> ne_enclave_release() -> mmu_notifier_unregister().
 * __mmu_notifier_release() keeps the subscription hashed across its ->release
 * loop and only unhashes afterwards (mm/mmu_notifier.c), so the concurrent
 * mmu_notifier_unregister() still observes !hlist_unhashed() and invokes this
 * ->release a SECOND time. The two invocations are therefore NOT mutually
 * exclusive: without a guard they walk device_pins_list / mem_regions_list
 * concurrently and double-free (the crash was a NULL page[0] read in
 * ne_release_device_pins() off a kvfree()d array).
 *
 * @mmu_release_done gates the drain so only the first invocation walks the
 * lists; the loser returns immediately. mmu_notifier_unregister()'s trailing
 * synchronize_srcu() then guarantees the winning ->release has completed
 * before ne_enclave_release() runs its own post-SLOT_FREE drains, so those
 * never race this callback either.
 */
static void ne_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct ne_enclave *ne_enclave =
		container_of(mn, struct ne_enclave, mmu_notifier);
	struct ne_device_pins *p, *tmp;

	/*
	 * Let only the first ->release invocation drain (see the function
	 * comment): a concurrent second invocation from the other exit path
	 * returns here without touching the resource lists, so the two never
	 * walk them at the same time.
	 */
	if (atomic_cmpxchg(&ne_enclave->mmu_release_done, 0, 1) != 0)
		return;

	/*
	 * Drop CMA-backed mem-region, info-page and DMB device pins here:
	 * priv_holds keeps their backing reserved past ne_contig_vma_close(),
	 * and dropping the pin before that close avoids the free_contig_range()
	 * "pages still in use" WARNING. Hugetlb-backed pins are deferred to
	 * ne_enclave_release() (after SLOT_FREE): their GUP reference
	 * (FOLL_GET for RAM regions, FOLL_LONGTERM for the info page) is
	 * their only hold, so dropping it here would free host-read-only
	 * pages back to the parent allocator. This also drains the info-page
	 * pins with the same hugetlb deferral.
	 *
	 * DMB pins follow the same rule: a priv_holds entry covers NE-CMA, so
	 * drop the pin here; hugetlb has no contig priv, so defer.
	 *
	 * All of the above is the non-NIE rule, where what may be dropped here
	 * is decided by the backing alone. Under NIE the backing split does not
	 * decide the ranges the CHILD maps: direct-mode enclave RAM and every
	 * DMB, both shared with NE_SHARE_HYP | NE_SHARE_VM (direct-mode RAM adds
	 * NE_SHARE_DONATE, which changes who may take it, not who maps it).
	 * Those are deferred WHOLESALE, hugetlb or not: neither the
	 * Guest.Unshare nor the pin drop happens here, both run in
	 * ne_enclave_release() after SLOT_FREE. The lowvisor refuses to
	 * unshare a Shareable Range Table entry that still has pages mapped
	 * into the child:
	 *
	 *   ne: Guest.Unshare failed: gpa=0x434a00000 size=0x1000000 rc=21
	 *
	 * (rc=21 == HvcError::PageMapped). SLOT_FREE is what destroys the child
	 * and drops its mappings, and it is only issued from
	 * ne_enclave_release(); this callback runs from exit_mmap() strictly
	 * earlier (kernel/exit.c: exit_mm() before exit_files(), and mm/mmap.c:
	 * exit_mmap() calls mmu_notifier_release() first). Unsharing here
	 * therefore always failed for a live child, and the refusal is not
	 * benign: the SRT entry leaks permanently, so when the CMA allocator
	 * later hands the same physical range to another enclave, that
	 * enclave's own Guest.Share is refused with the same error and
	 * NE_ADD_DEVICE fails with -EIO. That is the intermittent "cannot
	 * launch multiple enclaves" failure, intermittent only because it
	 * needs address reuse.
	 *
	 * The pin has to be deferred with the unshare: dropping it here while
	 * the range is still shared would hand the pages back to the parent
	 * allocator with the child still mapping them. Deferring it costs
	 * nothing, because the NE-CMA backing is held either way by the
	 * priv_holds kref, which ne_enclave_drop_priv_holds() releases later
	 * still than the drain.
	 *
	 * The info page is deferred wholesale too, hugetlb or not.  The child
	 * never maps it, so Guest.Unshare is accepted here, but acceptance is
	 * not the hazard: Guest.Share also maps the range into the hypervisor
	 * (SRT_ENTRY_FLAGS::HYP_MAPPED) and Guest.Unshare tears that mapping
	 * down, while its only refusal, HvcError::PageMapped, looks at the
	 * child alone. The hypervisor reaches the info page through that
	 * mapping and a CPU_ACCOUNTING slot's sampler writes to it until
	 * SLOT_FREE, so unsharing here pulled the page from under a live
	 * writer.
	 */

	/*
	 * Under NIE nothing is unshared here: the info page, direct-mode memory
	 * regions and device backing all go with the post-SLOT_FREE batch, per
	 * the deferral note above.
	 */

	ne_enclave_remove_all_mem_region_entries(ne_enclave, /*defer_hugetlb=*/true);

	/*
	 * Drop DMB pins, deferring hugetlb-backed ones (see above). Under NIE
	 * every DMB is deferred instead, pin and unshare together.
	 */
	if (!ne_enclave->sharing_ops) {
		list_for_each_entry_safe(p, tmp, &ne_enclave->device_pins_list, list)
			ne_release_device_pins(p, /*defer_hugetlb=*/true);
	}
}

static const struct mmu_notifier_ops ne_mmu_notifier_ops = {
	.release = ne_mmu_notifier_release,
};

/**
 * ne_add_shm_region() - Pin, share and record one SHM region for a device.
 * @ne_enclave:	Enclave context.
 * @region:	SHM region descriptor (from userspace, already copied in).
 * @dev_req:	Hypervisor request being built; backing_ranges[] is appended.
 * @dmb_bytes:	Running total of this ioctl's donated bytes, added to the
 *		enclave's total when SLOT_ADD_DEVICE is submitted.
 *
 * Validates the region, pins its pages, builds contiguous backing ranges,
 * and records the pins on the enclave's list. On failure, all resources
 * allocated within this call are cleaned up: the caller only needs to
 * roll back pins from prior successful calls.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int ne_add_shm_region(struct ne_enclave *ne_enclave,
			     struct ne_shm_region *region,
			     struct slot_add_device_req *dev_req,
			     u64 *dmb_bytes)
{
	unsigned long uaddr = region->userspace_addr;
	struct ne_contig_vma_priv *contig_priv = NULL;
	u64 size = region->size;
	unsigned long nr_pages;
	struct page **pages;
	struct ne_device_pins *pins;
	int i, rc;

	for (i = 0; i < 7; i++) {
		if (region->reserved[i])
			return -EINVAL;
	}

	if (!size || !IS_ALIGNED(size, PAGE_SIZE) || size > SZ_256M ||
	    !IS_ALIGNED(uaddr, PAGE_SIZE))
		return -EINVAL;

	/*
	 * Pin via the helper to capture the contig priv for the hold below. The
	 * GUP pin alone does not keep CMA backing reserved, so without the hold
	 * cma_release() runs at exit_mm(), before SLOT_FREE.
	 *
	 * require_contiguous=false: ne_build_backing_ranges() coalesces runs.
	 * write=true: the parent services the rings in the DMB.
	 */
	rc = ne_pin_user_range_longterm(ne_enclave, uaddr, size,
					&ne_contig_vm_ops,
					/*require_contiguous=*/false,
					/*write=*/true,
					&pages, &nr_pages, &contig_priv);
	if (rc < 0)
		return rc;

	rc = ne_build_backing_ranges(pages, nr_pages,
				     dev_req->backing_ranges,
				     SLOT_MAX_BACKING_RANGES,
				     &dev_req->num_backing_ranges,
				     region->shm_id);
	if (rc < 0)
		goto out_unpin;

	pins = kvzalloc(sizeof(*pins), GFP_KERNEL);
	if (!pins) {
		rc = -ENOMEM;
		goto out_unpin;
	}

	pins->pages = pages;
	pins->nr_pages = nr_pages;

	/*
	 * Take the hold before the hypervisor learns of the donation, so no
	 * window leaves it holding a ledger entry over unprotected backing.
	 * ne_enclave_release() drains the hold once SLOT_FREE succeeds. No-op
	 * for hugetlb, which has no contig priv.
	 */
	if (contig_priv) {
		rc = ne_enclave_hold_contig_priv(ne_enclave, contig_priv);
		ne_contig_vma_priv_put(contig_priv);
		contig_priv = NULL;
		if (rc) {
			kvfree(pins);
			goto out_unpin;
		}
	}

	/* On NIE, share device backing (DMB) with hypervisor + enclave. */
	if (ne_enclave->sharing_ops) {
		rc = ne_share_pages(ne_enclave, pages, nr_pages,
				    /*per_page_stride=*/false,
				    NE_SHARE_HYP | NE_SHARE_VM,
				    ne_share_perms_pack(NE_PERM_RW, NE_PERM_RW, NE_PERM_RW));
		if (rc < 0) {
			kvfree(pins);
			goto out_unpin;
		}
	}

	list_add_tail(&pins->list, &ne_enclave->device_pins_list);
	*dmb_bytes += (u64)nr_pages << PAGE_SHIFT;
	return 0;

out_unpin:
	/* ne_enclave_drop_priv_holds() balances a transferred hold. */
	if (contig_priv)
		ne_contig_vma_priv_put(contig_priv);
	unpin_user_pages(pages, nr_pages);
	kvfree(pages);
	return rc;
}

/**
 * ne_handle_add_device_direct() - Handle NE_ADD_DEVICE for the DIRECT class.
 * @ne_enclave:	Enclave private data (caller holds enclave_info_mutex).
 * @add_dev:	In-kernel copy of the user-supplied request. The DIRECT-class
 *		payload is in @add_dev->device_config[0..7].
 *
 * Builds a SLOT_ADD_DEVICE request carrying the DIRECT-class wire header
 * and the 8-byte struct ne_pcie_assign_device_config payload verbatim.
 * The Nitro Hypervisor resolves the parent-guest SBDF in the payload
 * to a host SBDF via the parent_spec topology and advances the
 * PCIE_ASSIGN state machine to its grant step.
 *
 * DIRECT has no virtio state: no virtqueues, no shared memory regions,
 * no device_features. We validate that userspace set those fields to
 * zero, then send a minimal request. On reply we only consume
 * reply.add_device.device_uid (written back as @add_dev->device_uid);
 * there is no vq_info to copy.
 *
 * Return: 0 on success, negative errno on failure.
 */
static long ne_handle_add_device_direct(struct ne_enclave *ne_enclave,
					struct ne_add_device *add_dev)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct ne_pcie_assign_device_config payload;
	struct slot_add_device_req *dev_req = NULL;
	struct ne_pci_dev_cmd_reply reply = {};
	static const u8 zero_features[sizeof(add_dev->device_features)] = {};
	int rc;

	if (add_dev->num_vqs != 0 ||
	    add_dev->num_shm_regions != 0 ||
	    add_dev->config_size != sizeof(payload) ||
	    add_dev->reserved != 0 ||
	    add_dev->reserved2 != 0 ||
	    add_dev->shm_regions_ptr != 0 ||
	    memcmp(add_dev->device_features, zero_features,
		   sizeof(zero_features)) != 0)
		return -EINVAL;

	memcpy(&payload, add_dev->device_config, sizeof(payload));
	if (payload.reserved != 0)
		return -EINVAL;
	if (payload.flags & ~NE_PCIE_ASSIGN_RETAIN_IN_FREE_POOL)
		return -EINVAL;

	dev_req = kzalloc(sizeof(*dev_req), GFP_KERNEL);
	if (!dev_req)
		return -ENOMEM;

	dev_req->slot_uid = ne_enclave->slot_uid;
	dev_req->device_type = add_dev->device_type;
	dev_req->num_vqs = 0;
	dev_req->config_size = sizeof(payload);
	dev_req->num_backing_ranges = 0;
	memcpy(dev_req->device_config, &payload, sizeof(payload));

	rc = ne_do_request_retry(ne_pci_dev->pdev, SLOT_ADD_DEVICE,
			   dev_req, sizeof(*dev_req),
			   &reply, sizeof(reply));
	if (rc < 0)
		goto out_free;
	if (reply.rc < 0) {
		rc = reply.rc;
		goto out_free;
	}

	add_dev->device_uid = reply.add_device.device_uid;
	rc = 0;

out_free:
	kfree(dev_req);
	return rc;
}

/**
 * ne_handle_add_device() - Handle the NE_ADD_DEVICE ioctl.
 * @ne_enclave:	Enclave private data.
 * @arg:	Userspace pointer to struct ne_add_device.
 *
 * Copies the device descriptor from userspace, resolves SHM region physical
 * pages, builds hardware backing ranges, and sends SLOT_ADD_DEVICE to the
 * hypervisor. Pins all SHM pages for the lifetime of the device.
 *
 * Return: 0 on success, negative errno on failure.
 */
static long ne_handle_add_device(struct ne_enclave *ne_enclave,
				 unsigned long arg)
{
	struct ne_add_device *add_dev = NULL;
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct slot_add_device_req *dev_req = NULL;
	struct ne_shm_region *shm_regions = NULL;
	struct list_head *saved_pins_tail;
	struct ne_device_pins *p, *tmp;
	struct ne_pci_dev_cmd_reply reply = {};
	const struct slot_vq_info *vq_src;
	bool donated = false;
	u64 dmb_bytes = 0;
	u64 vq_info_off;
	u64 vq_info_len;
	int rc, i;

	add_dev = kzalloc(sizeof(*add_dev), GFP_KERNEL);
	dev_req = kzalloc(sizeof(*dev_req), GFP_KERNEL);
	if (!add_dev || !dev_req) {
		rc = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(add_dev, (void __user *)arg, sizeof(*add_dev))) {
		rc = -EFAULT;
		goto out_free;
	}

	mutex_lock(&ne_enclave->enclave_info_mutex);

	if (ne_enclave->state != NE_STATE_INIT &&
	    ne_enclave->state != NE_STATE_RUNNING) {
		rc = -EINVAL;
		goto out_unlock;
	}

	/*
	 * The Nitro Enclaves device requires the info page to be
	 * registered before NE_ADD_DEVICE: the SLOT_ADD_DEVICE reply
	 * carries an offset into the info page at which the per-VQ
	 * wire metadata table lives. Reject the ioctl up front rather
	 * than letting the round-trip fail with a less specific error
	 * code.
	 */
	if (!ne_enclave->info_pages) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "NE_ADD_DEVICE requires NE_SET_INFO_PAGE first\n");
		rc = -EINVAL;
		goto out_unlock;
	}

	/*
	 * Per-enclave device cap.  Fail-fast against the hypervisor-advertised
	 * limit before issuing the add-device command.  This rejection
	 * originates in the driver, so it returns -EINVAL rather than one of the
	 * enclave-device error codes, with a kernel log line to signal the cap
	 * was hit.  The cap covers both VIRTIO and DIRECT device classes.
	 */
	if (ne_enclave->num_pcie_devices >= ne_pci_dev->max_pcie_devices) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "NE_ADD_DEVICE rejected: enclave has %u devices, max %u (set max_pcie_devices module param to query)\n",
				    ne_enclave->num_pcie_devices,
				    ne_pci_dev->max_pcie_devices);
		rc = -EINVAL;
		goto out_unlock;
	}

	switch (add_dev->device_type >> 16) {
	case NE_DEVICE_CLASS_VIRTIO:
		break;
	case NE_DEVICE_CLASS_DIRECT:
		rc = ne_handle_add_device_direct(ne_enclave, add_dev);
		if (rc)
			goto out_unlock;
		ne_enclave->num_pcie_devices++;
		if (copy_to_user((void __user *)arg, add_dev, sizeof(*add_dev)))
			rc = -EFAULT;
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		kfree(add_dev);
		kfree(dev_req);
		return rc;
	default:
		rc = -EINVAL;
		goto out_unlock;
	}

	if (add_dev->num_vqs > NE_MAX_VQS) {
		rc = -EINVAL;
		goto out_unlock;
	}

	if (add_dev->num_shm_regions > NE_MAX_SHM_REGIONS) {
		rc = -EINVAL;
		goto out_unlock;
	}

	dev_req->slot_uid = ne_enclave->slot_uid;
	dev_req->device_type = add_dev->device_type;
	dev_req->num_vqs = add_dev->num_vqs;
	dev_req->config_size = min_t(u32, add_dev->config_size,
				     sizeof(dev_req->device_config));
	memcpy(dev_req->device_features, add_dev->device_features,
	       sizeof(dev_req->device_features));
	memcpy(dev_req->device_config, add_dev->device_config,
	       dev_req->config_size);

	saved_pins_tail = ne_enclave->device_pins_list.prev;
	dev_req->num_backing_ranges = 0;

	/* Copy SHM regions from userspace via pointer */
	if (add_dev->num_shm_regions > 0) {
		shm_regions = kvmalloc_array(add_dev->num_shm_regions,
					     sizeof(*shm_regions), GFP_KERNEL);
		if (!shm_regions) {
			rc = -ENOMEM;
			goto out_unpin;
		}
		if (copy_from_user(shm_regions,
				   (void __user *)add_dev->shm_regions_ptr,
				   add_dev->num_shm_regions * sizeof(*shm_regions))) {
			rc = -EFAULT;
			goto out_unpin;
		}
	}

	for (i = 0; i < (int)add_dev->num_shm_regions; i++) {
		rc = ne_add_shm_region(ne_enclave, &shm_regions[i], dev_req,
				       &dmb_bytes);
		if (rc < 0)
			goto out_unpin;
	}

	kvfree(shm_regions);
	shm_regions = NULL;

	/*
	 * Assume the donation happened from here on, and count it: there is no
	 * cancel primitive, so a -ERESTARTSYS or -ETIMEDOUT abandons an
	 * in-flight command the hypervisor may still execute (see
	 * ne_wait_for_reply()). ne_do_request() folds a negative reply.rc into
	 * its own return, so rc < 0 cannot tell a rejection apart from an
	 * abandoned command, and the rollback has to keep both. SLOT_ADD_MEM
	 * treats the same ambiguity the same way, "without put pages as memory
	 * regions may already been added".
	 *
	 * Counting here rather than after the reply keeps the SLOT_FREE-failure
	 * leak report in step with what the rollback retains.
	 */
	donated = true;
	ne_enclave->dmb_bytes += dmb_bytes;

	rc = ne_do_request_retry(ne_pci_dev->pdev, SLOT_ADD_DEVICE,
			   dev_req, sizeof(*dev_req),
			   &reply, sizeof(reply));
	if (rc < 0)
		goto out_unpin;

	add_dev->device_uid = reply.add_device.device_uid;

	/*
	 * The Nitro Enclaves device publishes the per-VQ wire metadata
	 * table on the shared info page, and tells us where in the
	 * info page it lives via @vq_info_offset. Validate the slice
	 * is fully inside the info page (NE_MIN_MEM_REGION_SIZE
	 * bytes) and that the device's @num_vqs matches what we
	 * requested, then copy each entry into the userspace
	 * @add_dev->vq_info[] array.
	 */
	if (reply.add_device.num_vqs != add_dev->num_vqs) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "SLOT_ADD_DEVICE num_vqs mismatch req=%u reply=%u\n",
				    add_dev->num_vqs,
				    reply.add_device.num_vqs);
		rc = -EPROTO;
		goto out_unpin;
	}

	vq_info_off = reply.add_device.vq_info_offset;
	vq_info_len = (u64)add_dev->num_vqs * sizeof(struct slot_vq_info);
	if (add_dev->num_vqs &&
	    (vq_info_off >= NE_MIN_MEM_REGION_SIZE ||
	     vq_info_len > NE_MIN_MEM_REGION_SIZE - vq_info_off)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "SLOT_ADD_DEVICE bogus vq_info slice off=%llu len=%llu\n",
				    vq_info_off, vq_info_len);
		rc = -EPROTO;
		goto out_unpin;
	}

	vq_src = (const struct slot_vq_info *)
		 ((u8 *)ne_enclave->info_page_vaddr + vq_info_off);
	for (i = 0; i < (int)add_dev->num_vqs; i++) {
		add_dev->vq_info[i].msix_vector = vq_src[i].msix_vector;
		add_dev->vq_info[i].notify_index = vq_src[i].notify_index;
		add_dev->vq_info[i].msix_entry = vq_src[i].msix_entry;
		add_dev->vq_info[i].bar4_doorbell_offset = vq_src[i].bar4_doorbell_offset;
	}
	/* Propagate the info-event pseudo-VQ id from the hypervisor's
	 * SLOT_ADD_DEVICE reply to userspace for NE_SET_INFO_EVENT_FD. */
	add_dev->info_event_vector = reply.add_device.info_event_vector;

	/* Count the device for fail-fast cap enforcement on subsequent
	 * NE_ADD_DEVICE calls. */
	ne_enclave->num_pcie_devices++;

	if (copy_to_user((void __user *)arg, add_dev, sizeof(*add_dev)))
		rc = -EFAULT;
	else
		rc = 0;

	mutex_unlock(&ne_enclave->enclave_info_mutex);
	kfree(add_dev);
	kfree(dev_req);
	return rc;

out_unpin:
	kvfree(shm_regions);
	list_for_each_entry_safe_reverse(p, tmp,
					 &ne_enclave->device_pins_list,
					 list) {
		if (&p->list == saved_pins_tail)
			break;
		/*
		 * Defer unless the round-trip never happened: there is no
		 * cancel primitive, so a -ERESTARTSYS or -ETIMEDOUT abandons a
		 * command the hypervisor may still execute (see
		 * ne_wait_for_reply()), and the driver never sends
		 * SLOT_REMOVE_DEVICE, so anything it may have taken lives
		 * until SLOT_FREE. SLOT_ADD_MEM treats the same ambiguity the
		 * same way. Unshare only what this walk will release; a
		 * deferred entry takes its single unshare in the
		 * post-SLOT_FREE drain instead.
		 */
		if (ne_enclave->sharing_ops &&
		    p->nr_pages && p->pages && p->pages[0] &&
		    !(donated && PageHuge(p->pages[0])))
			ne_unshare_pages(ne_enclave, p->pages, p->nr_pages,
					 /*per_page_stride=*/false);
		ne_release_device_pins(p, /*defer_hugetlb=*/donated);
	}
out_unlock:
	mutex_unlock(&ne_enclave->enclave_info_mutex);
out_free:
	kfree(add_dev);
	kfree(dev_req);
	return rc;
}

/*
 * Parent-PID visibility (CPU_ACCOUNTING).
 *
 * PCIE enclave vCPUs run as host-scheduled pthreads of the enclave VMM, not
 * as dedicated donated cores. That makes their KVM_RUN time invisible
 * to the parent guest via the usual NUMA/cpu-pool accounting paths:
 * from the parent's perspective, the cycles burned by the enclave
 * show up as CPUTIME_STEAL on whatever host CPU ran them. The
 * Parent-PID visibility feature reflects that time back into the
 * QEMU process's per-thread utime/gtime (and into
 * kernel_cpustat[CPUTIME_GUEST] for /proc/stat) so operators can see
 * which customer workload is responsible.
 *
 * Producer (the enclave VMM on the host): each KVM_RUN iteration stores a
 * monotonic cumulative vcpu_time_ns value into an info-page slot owned by this
 * enclave. The info page is a 2 MiB hugetlb page registered with
 * NE_SET_INFO_PAGE and shared with the hypervisor via SLOT_ADD_INFO_PAGE. The
 * hypervisor tells the NE driver where the counter array's location inside that
 * page via a dedicated SLOT_VCPU_TIME PCI command (issued by
 * ne_query_vcpu_time() right after slot allocation). The reply carries a byte
 * offset plus element count which are cached on @ne_enclave as
 * @vcpu_time_array_offset / @vcpu_time_array_count. The driver
 * treats the rest of the info page as opaque.
 *
 * Userspace (QEMU) spawns one pthread per enclave vCPU and each pthread calls
 * NE_ACCOUNT_VCPU(vcpu_idx) on the enclave fd. The ioctl binds the task to the
 * slot and returns immediately; the caller keeps itself alive in userspace
 * (e.g. via pause()) so the pinned task_struct remains a valid attribution
 * target. A driver-global 100 Hz hrtimer walks all enclaves with bound vCPUs,
 * reads the corresponding u64 counter with a plain load, and reflects the delta
 * into the bound task's @utime, @gtime and thread-group cputimer in place,
 * making enclave vCPU work visible in top -H, ps, and
 * /proc/<pid>/task/<tid>/stat field 43 on the parent. Per-CPU /proc/stat
 * CPUTIME_GUEST attribution is not driven from this path; the task-struct
 * fields are the customer-facing observable that Parent-PID visibility
 * guarantees.
 *
 * Locking: @accounted_lock serializes the @accounted_vcpus list for each
 * enclave. It is a spinlock because the hrtimer callback runs in softirq
 * context. The ioctl path is in process context and takes the spinlock only
 * around list mutations. The outer
 * @ne_accounting_lock (declared below) protects the driver-global
 * scan list and the arm/disarm transitions of the shared hrtimer;
 * lock order is ne_accounting_lock (outer) -> accounted_lock
 * (inner).
 */

#define NE_ACCOUNT_TIMER_HZ		100
#define NE_ACCOUNT_TIMER_PERIOD_NS	(NSEC_PER_SEC / NE_ACCOUNT_TIMER_HZ)

/**
 * ne_query_vcpu_time() - Ask the hypervisor where the per-vCPU
 *                        time-counter array lives inside the info page.
 * @pdev:	NE PCI device to issue SLOT_VCPU_TIME against.
 * @ne_enclave:	Running enclave. Called from ne_start_enclave_ioctl()
 *		after ENCLAVE_START has succeeded, so the hypervisor
 *		has fully initialized the info page (including the
 *		vCPU-time TOC entry with offset/size populated).
 *
 * Issues a SLOT_VCPU_TIME request for the enclave's slot and caches
 * the returned (offset, count) on @ne_enclave as
 * @vcpu_time_array_offset / @vcpu_time_array_count. A zero count
 * leaves the enclave without Parent-PID visibility: subsequent NE_ACCOUNT_VCPU
 * calls will return -EINVAL.
 *
 * Only issued when the enclave was allocated with
 * NE_ENCLAVE_CPU_ACCOUNTING_MODE. Regular enclaves skip the query
 * entirely, saving one PCI round-trip.
 *
 * Return: 0 on success (including "feature unavailable" replies),
 * negative errno on PCI transport failure or on a bogus reply.
 */
static int ne_query_vcpu_time(struct pci_dev *pdev,
			      struct ne_enclave *ne_enclave)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct slot_vcpu_time_req req = {};
	u64 end;
	int rc;

	/*
	 * CPU_ACCOUNTING is the per-enclave opt-in for Parent-PID
	 * visibility; CPU_OVERCOMMIT also implies it.
	 */
	if (!(ne_enclave->start_flags &
	      (NE_ENCLAVE_CPU_ACCOUNTING_MODE |
	       NE_ENCLAVE_CPU_OVERCOMMIT_MODE)))
		return 0;

	req.slot_uid = ne_enclave->slot_uid;

	rc = ne_do_request_retry(pdev, SLOT_VCPU_TIME,
			   &req, sizeof(req),
			   &cmd_reply, sizeof(cmd_reply));
	if (rc < 0) {
		/*
		 * Older hypervisors that don't recognize SLOT_VCPU_TIME
		 * reply with -EINVAL. That's a supported deployment mode:
		 * log once and leave the counter-array count at zero so
		 * NE_ACCOUNT_VCPU cleanly rejects with -EINVAL.
		 */
		dev_info_ratelimited(ne_misc_dev.this_device,
				     "SLOT_VCPU_TIME unavailable [rc=%d]\n", rc);
		return 0;
	}

	if (!cmd_reply.vcpu_time.vcpu_time_count)
		return 0;

	end = cmd_reply.vcpu_time.vcpu_time_offset +
	      (u64)cmd_reply.vcpu_time.vcpu_time_count * sizeof(u64);

	if (cmd_reply.vcpu_time.vcpu_time_offset >= NE_MIN_MEM_REGION_SIZE ||
	    end > NE_MIN_MEM_REGION_SIZE ||
	    cmd_reply.vcpu_time.vcpu_time_offset > U32_MAX ||
	    cmd_reply.vcpu_time.vcpu_time_count > U32_MAX) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Bogus SLOT_VCPU_TIME reply offset=%llu count=%llu\n",
				    cmd_reply.vcpu_time.vcpu_time_offset,
				    cmd_reply.vcpu_time.vcpu_time_count);
		return -EINVAL;
	}

	ne_enclave->vcpu_time_array_offset = cmd_reply.vcpu_time.vcpu_time_offset;
	ne_enclave->vcpu_time_array_count = cmd_reply.vcpu_time.vcpu_time_count;

	return 0;
}

/**
 * ne_read_vcpu_time() - Read a producer-written vCPU time counter.
 * @ne_enclave:	Enclave whose info page holds the u64 array.
 * @vcpu_idx:	Zero-based vCPU index.
 * @vcpu_time_ns: Output, monotonic cumulative ns since the enclave VMM
 *		started (or last producer restart).
 *
 * The array location inside the info page was communicated by the
 * hypervisor via SLOT_VCPU_TIME (see ne_query_vcpu_time()) and cached
 * on @ne_enclave as @vcpu_time_array_offset / @vcpu_time_array_count.
 * This helper does one bounds check plus one READ_ONCE().
 *
 * Protocol: the producer (enclave VMM) publishes with a single
 * WRITE_ONCE of a naturally-aligned u64. Naturally-aligned 8-byte
 * loads and stores are atomic on every architecture this driver
 * runs on (x86_64, arm64), so a READ_ONCE here is guaranteed to
 * see either the pre-update or the post-update value, never a
 * half-stale mix.
 *
 * Return: 0 on success, -EINVAL if vcpu_idx is out of range.
 */
static int ne_read_vcpu_time(struct ne_enclave *ne_enclave, u32 vcpu_idx,
			     u64 *vcpu_time_ns)
{
	const u64 *entry;

	if (vcpu_idx >= ne_enclave->vcpu_time_array_count)
		return -EINVAL;

	entry = (const u64 *)((u8 *)ne_enclave->info_page_vaddr +
			      ne_enclave->vcpu_time_array_offset +
			      (u64)vcpu_idx * sizeof(u64));

	*vcpu_time_ns = READ_ONCE(*entry);
	return 0;
}

/*
 * Driver-global CPU_ACCOUNTING timer state.
 *
 * @ne_accounting_enclaves
 *	List of enclaves that currently have at least one accounted vCPU
 *	bound via NE_ACCOUNT_VCPU. The per-tick scan in ne_account_tick()
 *	walks this list and, for each enclave, reads accumulated vCPU
 *	time from the enclave's info page and attributes deltas to the
 *	bound parent tasks.
 *
 *	An enclave is added on the NE_ACCOUNT_VCPU transition from
 *	zero accounted_vcpus to one, and removed by
 *	ne_enclave_drain_accounted_vcpus() at enclave release.
 *
 * @ne_accounting_lock
 *	Protects @ne_accounting_enclaves, @ne_account_timer_armed, and
 *	the hrtimer arm/disarm transitions on @ne_account_timer.
 *
 *	Lock order: ne_accounting_lock (outer) -> ne_enclave::accounted_lock
 *	(inner). All updaters take the outer lock first; the tick
 *	callback does the same when it needs to descend into a
 *	per-enclave accounted_vcpus list.
 *
 * @ne_account_timer
 *	Single hrtimer that fires at 100 Hz driver-globally. Replaces
 *	the per-enclave hrtimers that were used before: at scale
 *	(1000+ concurrent CPU_ACCOUNTING enclaves) the per-enclave
 *	design generated one hrtimer invocation per enclave per tick,
 *	i.e. 100000+ tick callbacks/sec. The consolidated timer does
 *	the same aggregate work in a single 100 Hz invocation, at the
 *	cost of one extra list walk.
 *
 * @ne_account_timer_armed
 *	Tracks whether @ne_account_timer is currently armed. Set to
 *	true when the first enclave is added to
 *	@ne_accounting_enclaves; reset to false by the tick callback
 *	when it sees the list empty and returns HRTIMER_NORESTART. Any
 *	subsequent NE_ACCOUNT_VCPU that re-enters the list re-arms the
 *	timer.
 */
static LIST_HEAD(ne_accounting_enclaves);
static DEFINE_SPINLOCK(ne_accounting_lock);
static struct hrtimer ne_account_timer;
static bool ne_account_timer_armed;

/**
 * ne_account_tick() - hrtimer callback: attribute enclave vCPU deltas to
 *		       bound parent tasks, across all enclaves.
 * @timer:	The driver-global hrtimer.
 *
 * Runs in softirq context. Walks @ne_accounting_enclaves under
 * @ne_accounting_lock; for each enclave, descends into
 * @accounted_vcpus under the enclave's @accounted_lock, reads each
 * bound vCPU's cumulative vcpu_time_ns, computes the delta since
 * the last tick, and reflects the delta into the bound task's
 * @utime, @gtime and thread-group cputimer directly (task-only
 * accounting).
 *
 * Per-CPU @kernel_cpustat is deliberately NOT touched here.
 * account_guest_time() would credit kcpustat_this_cpu, which in this hrtimer
 * context is the timer's affined CPU rather than the CPU on which the bound
 * task actually ran, skewing the per-CPU /proc/stat CPUTIME_GUEST column.
 * Per-CPU observability for enclave-consumed cycles is delivered out-of-band:
 * the host hypervisor suppresses paravirt steal for enclave-capable parents
 * (KVM_CAP_NO_STEAL_TIME), and per-parent-CPU enclave time is provided by a
 * dedicated counter maintained by the hypervisor. This driver tick remains
 * responsible only for per-task gtime.
 *
 * A decrease or jump back to zero indicates a producer restart
 * (e.g. live update without persisted vcpu_time). We reset the
 * last-seen anchor and skip emitting a delta for that tick.
 *
 * If the list is empty at the end of the tick (no enclave has any
 * accounted vCPUs bound anymore), clear @ne_account_timer_armed
 * under the lock and return HRTIMER_NORESTART. The next
 * NE_ACCOUNT_VCPU call will re-arm.
 */
static enum hrtimer_restart ne_account_tick(struct hrtimer *timer)
{
	struct ne_enclave *ne_enclave;
	unsigned long flags;

	spin_lock_irqsave(&ne_accounting_lock, flags);

	list_for_each_entry(ne_enclave, &ne_accounting_enclaves,
			    active_link) {
		struct ne_accounted_vcpu *av;
		u64 vcpu_time_ns;
		int rc;

		spin_lock(&ne_enclave->accounted_lock);

		list_for_each_entry(av, &ne_enclave->accounted_vcpus, list) {
			rc = ne_read_vcpu_time(ne_enclave, av->vcpu_idx,
					       &vcpu_time_ns);
			if (rc)
				continue;

			if (vcpu_time_ns > av->last_vcpu_time_ns) {
				u64 delta = vcpu_time_ns -
					    av->last_vcpu_time_ns;

				/*
				 * Task-only guest-time attribution: plain field
				 * writes plus the static-inline
				 * account_group_user_time() from
				 * <linux/sched/cputime.h>. No kcpustat_this_cpu
				 * write, by design. See the function-level
				 * comment above.
				 */
				av->task->utime += delta;
				account_group_user_time(av->task, delta);
				av->task->gtime += delta;
			}

			/*
			 * Always re-anchor, including on a regression
			 * (producer restart across live update without
			 * persisted counters) and on a no-change tick.
			 */
			av->last_vcpu_time_ns = vcpu_time_ns;
		}

		spin_unlock(&ne_enclave->accounted_lock);
	}

	if (list_empty(&ne_accounting_enclaves)) {
		ne_account_timer_armed = false;
		spin_unlock_irqrestore(&ne_accounting_lock, flags);
		return HRTIMER_NORESTART;
	}

	hrtimer_forward_now(timer, ns_to_ktime(NE_ACCOUNT_TIMER_PERIOD_NS));
	spin_unlock_irqrestore(&ne_accounting_lock, flags);
	return HRTIMER_RESTART;
}

/**
 * ne_account_enclave_activate() - Register an enclave into the
 *				   driver-global accounting tick.
 * @ne_enclave:	Enclave whose accounted_vcpus just transitioned
 *		from empty to non-empty.
 *
 * Called from NE_ACCOUNT_VCPU after adding the first accounted_vcpu
 * entry. Takes @ne_accounting_lock, adds the enclave to the
 * scan-list, and arms the driver-global hrtimer if it wasn't
 * already armed.
 *
 * Safe to call concurrently: the list_add + arm happens under the lock so a
 * second CPU adding another enclave at the same time either finds the timer
 * already armed (nothing to do) or arms it itself.
 */
static void ne_account_enclave_activate(struct ne_enclave *ne_enclave)
{
	unsigned long flags;

	spin_lock_irqsave(&ne_accounting_lock, flags);

	list_add_tail(&ne_enclave->active_link, &ne_accounting_enclaves);

	if (!ne_account_timer_armed) {
		ne_account_timer_armed = true;
		hrtimer_start(&ne_account_timer,
			      ns_to_ktime(NE_ACCOUNT_TIMER_PERIOD_NS),
			      HRTIMER_MODE_REL);
	}

	spin_unlock_irqrestore(&ne_accounting_lock, flags);
}

/**
 * ne_enclave_drain_accounted_vcpus() - Release task pins, free list
 *					entries, and remove the enclave
 *					from the driver-global scan list.
 *
 * Called on enclave release. Takes @ne_accounting_lock and the
 * per-enclave @accounted_lock together (outer-then-inner), splices
 * the accounted_vcpus list to a local list, clears it under the
 * per-enclave lock, removes the enclave from
 * @ne_accounting_enclaves if it was on it, and then drops both
 * locks before releasing the task pins.
 *
 * The timer is NOT canceled here. If this was the last enclave on the global
 * scan list, the next tick sees it empty and stops itself (HRTIMER_NORESTART).
 * This avoids racing with a concurrent NE_ACCOUNT_VCPU on another enclave that
 * re-arms the timer between our "list is empty" observation and the cancel
 * call.
 *
 * The bound pthread on the userspace side is asleep in pause() inside QEMU; it
 * wakes when QEMU exits (SIGTERM/SIGKILL at process teardown). The driver does
 * not need to wake it, because the task_struct stays valid until the pthread
 * actually exits: the get_task_struct() pin we are releasing here is what kept
 * it pinned against our own references, not against its own lifecycle.
 */
static void ne_enclave_drain_accounted_vcpus(struct ne_enclave *ne_enclave)
{
	struct ne_accounted_vcpu *av, *tmp;
	unsigned long flags;
	bool was_active;
	LIST_HEAD(to_free);

	spin_lock_irqsave(&ne_accounting_lock, flags);
	spin_lock(&ne_enclave->accounted_lock);

	was_active = !list_empty(&ne_enclave->accounted_vcpus);
	list_splice_init(&ne_enclave->accounted_vcpus, &to_free);
	ne_enclave->nr_accounted_vcpus = 0;

	spin_unlock(&ne_enclave->accounted_lock);

	if (was_active)
		list_del_init(&ne_enclave->active_link);

	spin_unlock_irqrestore(&ne_accounting_lock, flags);

	list_for_each_entry_safe(av, tmp, &to_free, list) {
		list_del(&av->list);
		put_task_struct(av->task);
		kfree(av);
	}
}

/**
 * ne_ioctl_account_vcpu() - NE_ACCOUNT_VCPU ioctl handler.
 *
 * Binds @current to the given enclave vCPU slot and arms the timer
 * if this is the first bound vCPU on the enclave. Returns immediately
 * once the binding is registered.
 *
 * The caller (QEMU's per-vCPU pthread) is expected to keep @current
 * alive in userspace (typically via pause()) so the driver retains
 * a valid task_struct to attribute guest time to. On enclave release,
 * ne_enclave_drain_accounted_vcpus() drops the pin and frees the
 * entry. The pthread dies with QEMU at process teardown.
 */
static long ne_ioctl_account_vcpu(struct ne_enclave *ne_enclave,
				  unsigned long arg)
{
	struct ne_account_vcpu_params params;
	struct ne_accounted_vcpu *av, *existing;
	unsigned long flags;

	if (copy_from_user(&params, (void __user *)arg, sizeof(params)))
		return -EFAULT;

	if (params.reserved)
		return -EINVAL;

	mutex_lock(&ne_enclave->enclave_info_mutex);

	if (ne_enclave->state != NE_STATE_RUNNING) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -NE_ERR_NOT_IN_INIT_STATE;
	}

	if (!ne_enclave->info_pages) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -EINVAL;
	}

	/*
	 * @info_page_vaddr is the linear-map base of the 2 MiB info
	 * page region. It was set in the NE_SET_INFO_PAGE handler
	 * after the pin succeeded; all 512 pages are pinned for the
	 * enclave lifetime, so addresses beyond the first 4 KiB are
	 * valid. The counter-array offset / count were populated at
	 * NE_CREATE_VM2 time from the SLOT_VCPU_TIME reply returned by
	 * the Nitro Enclaves device.
	 */
	if (!ne_enclave->vcpu_time_array_count) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -EINVAL;
	}

	if (params.vcpu_idx >= ne_enclave->vcpu_time_array_count) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -NE_ERR_INVALID_VCPU;
	}

	mutex_unlock(&ne_enclave->enclave_info_mutex);

	av = kzalloc(sizeof(*av), GFP_KERNEL);
	if (!av)
		return -ENOMEM;

	av->enclave = ne_enclave;
	av->vcpu_idx = params.vcpu_idx;
	av->task = current;
	/* Anchor at current producer value so the first tick emits a small delta. */
	if (ne_read_vcpu_time(ne_enclave, params.vcpu_idx, &av->last_vcpu_time_ns))
		av->last_vcpu_time_ns = 0;

	get_task_struct(current);

	spin_lock_irqsave(&ne_enclave->accounted_lock, flags);
	list_for_each_entry(existing, &ne_enclave->accounted_vcpus, list) {
		if (existing->vcpu_idx == params.vcpu_idx) {
			spin_unlock_irqrestore(&ne_enclave->accounted_lock, flags);
			put_task_struct(current);
			kfree(av);
			return -EEXIST;
		}
	}
	{
		bool was_empty = list_empty(&ne_enclave->accounted_vcpus);

		list_add_tail(&av->list, &ne_enclave->accounted_vcpus);
		ne_enclave->nr_accounted_vcpus++;
		spin_unlock_irqrestore(&ne_enclave->accounted_lock, flags);

		/*
		 * On the transition from zero accounted_vcpus to one,
		 * add this enclave to the driver-global scan list and
		 * arm the shared 100 Hz timer. Done outside
		 * @accounted_lock to respect the outer-then-inner lock
		 * order with @ne_accounting_lock.
		 */
		if (was_empty)
			ne_account_enclave_activate(ne_enclave);
	}

	return 0;
}

static long ne_handle_update_device_config(struct ne_enclave *ne_enclave,
					   unsigned long arg)
{
	struct ne_update_device_config user_cfg;
	struct slot_update_device_config_req req = {};
	struct ne_pci_dev_cmd_reply reply = {};
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	int rc;

	if (copy_from_user(&user_cfg, (void __user *)arg, sizeof(user_cfg)))
		return -EFAULT;

	if (user_cfg.config_size == 0 ||
	    user_cfg.config_size > NE_UPDATE_CONFIG_MAX_SIZE)
		return -EINVAL;

	if ((u64)user_cfg.config_offset + user_cfg.config_size > NE_UPDATE_CONFIG_MAX_SIZE)
		return -EINVAL;

	mutex_lock(&ne_enclave->enclave_info_mutex);

	if (ne_enclave->state != NE_STATE_RUNNING) {
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		return -NE_ERR_NOT_IN_RUNNING_STATE;
	}

	req.slot_uid = ne_enclave->slot_uid;
	req.device_uid = user_cfg.device_uid;
	req.config_size = user_cfg.config_size;
	req.config_offset = user_cfg.config_offset;
	memcpy(req.config_data, user_cfg.config_data, user_cfg.config_size);

	rc = ne_do_request_retry(ne_pci_dev->pdev, SLOT_UPDATE_DEVICE_CONFIG,
			   &req, sizeof(req), &reply, sizeof(reply));

	mutex_unlock(&ne_enclave->enclave_info_mutex);

	if (rc < 0)
		return rc;

	return reply.rc;
}

static long ne_enclave_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	switch (cmd) {
	case NE_ADD_VCPU: {
		int rc = -EINVAL;
		u32 vcpu_id = 0;

		if (copy_from_user(&vcpu_id, (void __user *)arg, sizeof(vcpu_id)))
			return -EFAULT;

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		if (vcpu_id >= (ne_enclave->nr_parent_vm_cores *
		    ne_enclave->nr_threads_per_core) &&
		    !(ne_enclave->start_flags & NE_ENCLAVE_CPU_OVERCOMMIT_MODE)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "vCPU id higher than max CPU id\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_INVALID_VCPU;
		}

		/*
		 * ne_cpus is only consulted by non-overcommitted (pinned-core)
		 * enclaves. OVERCOMMIT_MODE enclaves never touch ne_cpus: their
		 * vCPU threads are host-scheduled pthreads that float on the
		 * parent VMM's pcpu_pool per the VMM's NUMA-correct choice, and
		 * no parent core is taken away. Skip the pool check entirely
		 * whenever OVERCOMMIT_MODE is set, regardless of how ne_cpus is
		 * configured (empty, static cpu-list, or "dynamic"). Pinned and
		 * overcommit enclaves coexist on the same host: pinned ones
		 * claim from ne_cpus exclusively, overcommit ones float
		 * independently. The hypervisor still records the vcpu_id for
		 * bookkeeping; the floating scheduling decision is the parent
		 * VMM's to make.
		 */
		if (ne_enclave->start_flags & NE_ENCLAVE_CPU_OVERCOMMIT_MODE) {
			/*
			 * Pick the next unused parent vCPU id skipping parent
			 * core 0: the hypervisor reserves it for the parent VMM
			 * and rejects any vcpu_id whose APIC-derived core_id is
			 * 0 ("First core cannot be re-assigned"). The parent's
			 * apic_id layout is hyperthread-paired (cpus_per_core=2
			 * on current hosts), so vcpu_ids 0 and 1 share core 0
			 * and must both be skipped.
			 */
			if (vcpu_id == 0) {
				u32 candidate;
				bool found = false;

				for (candidate = 2; candidate < nr_cpu_ids;
				     candidate++) {
					if (cpumask_test_cpu(candidate,
							     ne_enclave->vcpu_ids))
						continue;
					vcpu_id = candidate;
					found = true;
					rc = 0;
					break;
				}
				if (!found) {
					dev_err_ratelimited(ne_misc_dev.this_device,
							    "No free vCPU id for overcommit enclave\n");
					mutex_unlock(&ne_enclave->enclave_info_mutex);
					return -NE_ERR_INVALID_VCPU;
				}
			}
		} else if (!vcpu_id) {
			/*
			 * Use the CPU pool for choosing a CPU for the enclave.
			 * Keep the node-0 bias that non-QEMU consumers (raw
			 * nitro-cli, custom userspace) rely on, which means the
			 * pick fails when node 0 has no free core; consumers
			 * that want a specific node, or any node, should use
			 * NE_ADD_ANY_VCPU instead.
			 */
			rc = ne_get_cpu_from_cpu_pool(ne_enclave, &vcpu_id, 0);
			if (rc < 0) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Error in get CPU from pool [rc=%d]\n",
						    rc);

				mutex_unlock(&ne_enclave->enclave_info_mutex);

				return rc;
			}
		} else {
			/* Check if the provided vCPU is available in the NE CPU pool. */
			rc = ne_check_cpu_in_cpu_pool(ne_enclave, vcpu_id);
			if (rc < 0) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Error in check CPU %d in pool [rc=%d]\n",
						    vcpu_id, rc);

				mutex_unlock(&ne_enclave->enclave_info_mutex);

				return rc;
			}
		}

		rc = ne_add_vcpu_ioctl(ne_enclave, vcpu_id);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void __user *)arg, &vcpu_id, sizeof(vcpu_id)))
			return -EFAULT;

		return 0;
	}

	case NE_ADD_ANY_VCPU: {
		struct ne_add_any_vcpu_args req = {};
		u32 vcpu_id = 0;
		int rc = -EINVAL;
		bool any_node;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		/*
		 * numa_hint names the node the vcpu must come from, for both
		 * branches below, so reject a node that does not exist here
		 * rather than letting either picker report it as an exhausted
		 * pool.  NE_NUMA_ANY is the one negative value that is valid.
		 */
		any_node = (req.numa_hint == NUMA_NO_NODE);

		if (!any_node &&
		    (req.numa_hint < 0 || req.numa_hint >= nr_node_ids ||
		     !node_state(req.numa_hint, N_POSSIBLE))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Invalid numa_hint %d\n",
					    req.numa_hint);

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		if (ne_enclave->start_flags & NE_ENCLAVE_CPU_OVERCOMMIT_MODE) {
			/*
			 * OVERCOMMIT_MODE enclaves never take dedicated CPUs
			 * from ne_cpu_pool: their vCPU threads are
			 * host-scheduled pthreads that float on the parent
			 * VMM's pcpu_pool via CFS.  Pick the next unused
			 * parent vcpu_id from the [0, nr_cpu_ids) range
			 * without touching ne_cpu_pool.avail_threads_per_core.
			 *
			 * Unlike non-OVERCOMMIT (and the legacy NE_ADD_VCPU
			 * auto-pick when vcpu_id==0), we DO NOT skip vcpu_ids 0
			 * and 1 (parent's BSP core). The hypervisor allows
			 * core_id == 0 for OVERCOMMIT slots specifically
			 * because VCPU_FLOATING semantics mean these vcpus
			 * never take exclusive ownership of any host core: the
			 * parent BSP is unaffected.
			 *
			 * numa_hint selects which NUMA node the vcpu_id should
			 * belong to. The hypervisor derives the enclave's NUMA
			 * topology from the host CPU behind each vCPU, so the
			 * vcpu_id must be on the same node as the enclave's
			 * memory to avoid a spurious multi-node rejection. A
			 * named node is therefore honored or the request fails,
			 * like ne_get_unused_core_from_cpu_pool() for dedicated
			 * cores; NE_NUMA_ANY takes a vcpu_id from any node.
			 */
			u32 candidate;
			bool found = false;
			int hint = req.numa_hint;

			for (candidate = 0; candidate < nr_cpu_ids;
			     candidate++) {
				if (!any_node &&
				    cpu_to_node(candidate) != hint)
					continue;
				if (cpumask_test_cpu(candidate,
						     ne_enclave->vcpu_ids))
					continue;
				vcpu_id = candidate;
				found = true;
				break;
			}

			if (!found) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "No free vCPU id for overcommit enclave [numa_hint=%d]\n",
						    hint);
				mutex_unlock(&ne_enclave->enclave_info_mutex);
				return -NE_ERR_INVALID_VCPU;
			}
		} else {
			/*
			 * The kernel atomically picks an unused CPU from the NE pool
			 * under ne_cpu_pool.mutex (inside ne_get_cpu_from_cpu_pool)
			 * and binds it to this enclave's threads_per_core bitmap.
			 * Concurrent callers from independent enclave fds cannot
			 * race for the same CPU.  Explicit-cpu_id callers continue
			 * to use NE_ADD_VCPU.  The picked vcpu_id is not surfaced
			 * to userspace; the kernel's per-enclave bookkeeping is
			 * the source of truth.
			 */
			rc = ne_get_cpu_from_cpu_pool(ne_enclave, &vcpu_id,
						      req.numa_hint);
			if (rc < 0) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Error in get CPU from pool [rc=%d numa_hint=%d]\n",
						    rc, req.numa_hint);

				mutex_unlock(&ne_enclave->enclave_info_mutex);

				return rc;
			}
		}

		rc = ne_add_vcpu_ioctl(ne_enclave, vcpu_id);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return 0;
	}

	case NE_GET_IMAGE_LOAD_INFO: {
		struct ne_image_load_info image_load_info = {};

		if (copy_from_user(&image_load_info, (void __user *)arg, sizeof(image_load_info)))
			return -EFAULT;

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (!image_load_info.flags ||
		    image_load_info.flags >= NE_IMAGE_LOAD_MAX_FLAG_VAL) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Incorrect flag in enclave image load info\n");

			return -NE_ERR_INVALID_FLAG_VALUE;
		}

		if (image_load_info.flags == NE_EIF_IMAGE)
			image_load_info.memory_offset = NE_EIF_LOAD_OFFSET;

		if (copy_to_user((void __user *)arg, &image_load_info, sizeof(image_load_info)))
			return -EFAULT;

		return 0;
	}

	case NE_SET_USER_MEMORY_REGION: {
		struct ne_user_memory_region mem_region = {};
		int rc = -EINVAL;

		if (copy_from_user(&mem_region, (void __user *)arg, sizeof(mem_region)))
			return -EFAULT;

		if (mem_region.flags >= NE_MEMORY_REGION_MAX_FLAG_VAL) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Incorrect flag for user memory region\n");

			return -NE_ERR_INVALID_FLAG_VALUE;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		rc = ne_set_user_memory_region_ioctl(ne_enclave, mem_region);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return 0;
	}

	case NE_SET_INFO_PAGE: {
		struct ne_info_page info_page = {};
		struct page **pages = NULL;
		unsigned long nr_pages = 0;
		struct slot_add_info_page_req info_req = {};
		struct ne_pci_dev_cmd_reply info_reply = {};
		struct pci_dev *pdev = ne_devs.ne_pci_dev->pdev;
		struct ne_contig_vma_priv *info_contig_priv = NULL;
		int rc = -EINVAL;

		if (copy_from_user(&info_page, (void __user *)arg,
				   sizeof(info_page)))
			return -EFAULT;

		if (info_page.size != NE_MIN_MEM_REGION_SIZE) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Info page size must be 2 MiB\n");
			return -EINVAL;
		}

		if (!IS_ALIGNED(info_page.userspace_addr, NE_MIN_MEM_REGION_SIZE)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Info page address not 2 MiB aligned\n");
			return -EINVAL;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		if (ne_enclave->info_pages) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			return -EEXIST;
		}

		/*
		 * Pin all pages of the 2 MiB info-page region with the shared
		 * long-term pin helper. The helper verifies the VMA is either
		 * hugetlb or the NE driver's own CMA mapping (so the host holds
		 * the pages for the lifetime of the enclave without the parent
		 * guest leaking them back to the page allocator), pins with
		 * FOLL_LONGTERM, and verifies physical contiguity.
		 *
		 * Pin read-only: the kernel only reads the info page (vCPU-time
		 * counters, the SLOT_ADD_DEVICE vq-info mirror) and the enclave
		 * producer writes it through its own share of the page, not
		 * this pin. This lets userspace back it with a PROT_READ
		 * mapping, which FOLL_WRITE would reject with -EFAULT.
		 */
		rc = ne_pin_user_range_longterm(ne_enclave,
						info_page.userspace_addr,
						info_page.size,
						&ne_contig_vm_ops,
						/*require_contiguous=*/true,
						/*write=*/false,
						&pages, &nr_pages,
						&info_contig_priv);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			return rc;
		}

		/* Additional constraint: the physical base must also be 2 MiB
		 * aligned so the host can map it as a single PMD entry. */
		if (!IS_ALIGNED(page_to_phys(pages[0]), NE_MIN_MEM_REGION_SIZE)) {
			if (info_contig_priv)
				ne_contig_vma_priv_put(info_contig_priv);
			unpin_user_pages(pages, nr_pages);
			kvfree(pages);
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Info page phys not 2 MiB aligned\n");
			return -EINVAL;
		}

		/*
		 * Transfer the contig vma priv (NE-CMA info page) into
		 * ne_enclave->priv_holds BEFORE registering the info page, so
		 * cma_release() of the info-page backing is deferred until
		 * ne_enclave_release() drains priv_holds AFTER SLOT_FREE. This
		 * keeps the pages out of the parent guest's allocator until the
		 * host has dropped its read-only mapping on teardown, closing
		 * the reallocate-while-still-read-only race that the NE-CMA
		 * (@no-hugetlbfs) info page hit under multi-enclave
		 * teardown. Hugetlb-backed info pages need no hold (their
		 * FOLL_LONGTERM pin already isolates them), so info_contig_priv
		 * stays NULL and this is a no-op.
		 */
		if (info_contig_priv) {
			int hrc = ne_enclave_hold_contig_priv(ne_enclave,
							      info_contig_priv);

			ne_contig_vma_priv_put(info_contig_priv);
			info_contig_priv = NULL;
			if (hrc) {
				unpin_user_pages(pages, nr_pages);
				kvfree(pages);
				mutex_unlock(&ne_enclave->enclave_info_mutex);
				return hrc;
			}
		}

		/*
		 * Register the info page with the Nitro Enclaves device.
		 * The device requires the info page to be registered before
		 * NE_ADD_DEVICE and NE_START_ENCLAVE on a PCIE-mode slot:
		 * the kernel-side preconditions on those paths assume the
		 * info page is set if the SLOT_ADD_INFO_PAGE round-trip
		 * succeeded here.
		 *
		 * On failure we unpin and leave @info_pages NULL so the
		 * userspace caller can retry NE_SET_INFO_PAGE without
		 * leaking pinned pages.
		 */
		info_req.slot_uid = ne_enclave->slot_uid;
		info_req.flags = 0;
		info_req.info_phys = page_to_phys(pages[0]);
		info_req.info_size = info_page.size;

		/* On NIE, share the info page with the hypervisor.
		 * smid=0: the info page is shared with the hypervisor only
		 * (not with a specific enclave), so no slot_uid needed. */
		if (ne_enclave->sharing_ops) {
			rc = ne_enclave->sharing_ops->share(ne_enclave,
							    info_req.info_phys,
							    info_req.info_size,
							    NE_SHARE_HYP,
							    ne_share_perms_pack(NE_PERM_RO, NE_PERM_RW, NE_PERM_NOACCESS),
							    0);
			if (rc < 0) {
				unpin_user_pages(pages, nr_pages);
				kvfree(pages);
				mutex_unlock(&ne_enclave->enclave_info_mutex);
				return rc;
			}
		}

		rc = ne_do_request_retry(pdev, SLOT_ADD_INFO_PAGE,
				   &info_req, sizeof(info_req),
				   &info_reply, sizeof(info_reply));
		if (rc < 0 || info_reply.rc < 0) {
			if (ne_enclave->sharing_ops)
				ne_enclave->sharing_ops->unshare(ne_enclave,
					info_req.info_phys,
					info_req.info_size);
			unpin_user_pages(pages, nr_pages);
			kvfree(pages);
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error registering info page [rc=%d reply_rc=%d]\n",
					    rc, info_reply.rc);
			return rc < 0 ? rc : info_reply.rc;
		}

		ne_enclave->info_pages = pages;
		ne_enclave->info_nr_pages = nr_pages;
		ne_enclave->info_page_paddr = info_req.info_phys;
		ne_enclave->info_page_vaddr = page_address(pages[0]);

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return 0;
	}

	case NE_START_ENCLAVE: {
		struct ne_enclave_start_info enclave_start_info = {};
		int rc = -EINVAL;

		if (copy_from_user(&enclave_start_info, (void __user *)arg,
				   sizeof(enclave_start_info)))
			return -EFAULT;

		/*
		 * Only DEBUG may be set at START_ENCLAVE time: every other
		 * flag is now a slot-level property, recorded at
		 * NE_CREATE_VM2.
		 *
		 * This is a semantic change for callers that used to set PCIE
		 * flags at START_ENCLAVE after calling the legacy flags-less
		 * NE_CREATE_VM. Such callers must migrate to NE_CREATE_VM2; the
		 * hypervisor cannot route slot backing retroactively from a
		 * START-time flag. Reject loudly so these callers get a clear
		 * signal instead of a silently misrouted enclave.
		 */
		if (enclave_start_info.flags & ~(u32)NE_ENCLAVE_DEBUG_MODE) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "NE_START_ENCLAVE: only DEBUG allowed here; pass PCIE/DIRECT flags at NE_CREATE_VM2\n");

			return -NE_ERR_INVALID_FLAG_VALUE;
		}

		/*
		 * Do not use well-known CIDs - 0, 1, 2 - for enclaves.
		 * VMADDR_CID_ANY = -1U
		 * VMADDR_CID_HYPERVISOR = 0
		 * VMADDR_CID_LOCAL = 1
		 * VMADDR_CID_HOST = 2
		 * Note: 0 is used as a placeholder to auto-generate an enclave CID.
		 * http://man7.org/linux/man-pages/man7/vsock.7.html
		 */
		if (enclave_start_info.enclave_cid > 0 &&
		    enclave_start_info.enclave_cid <= VMADDR_CID_HOST) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Well-known CID value, not to be used for enclaves\n");

			return -NE_ERR_INVALID_ENCLAVE_CID;
		}

		if (enclave_start_info.enclave_cid == U32_MAX) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Well-known CID value, not to be used for enclaves\n");

			return -NE_ERR_INVALID_ENCLAVE_CID;
		}

		/*
		 * Do not use the CID of the primary / parent VM for enclaves.
		 */
		if (enclave_start_info.enclave_cid == NE_PARENT_VM_CID) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "CID of the parent VM, not to be used for enclaves\n");

			return -NE_ERR_INVALID_ENCLAVE_CID;
		}

		/* 64-bit CIDs are not yet supported for the vsock device. */
		if (enclave_start_info.enclave_cid > U32_MAX) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "64-bit CIDs not yet supported for the vsock device\n");

			return -NE_ERR_INVALID_ENCLAVE_CID;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		rc = ne_start_enclave_ioctl(ne_enclave, &enclave_start_info);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void __user *)arg, &enclave_start_info,
				 sizeof(enclave_start_info)))
			return -EFAULT;

		return 0;
	}

	case NE_ADD_DEVICE:
		return ne_handle_add_device(ne_enclave, arg);
	case NE_SET_VRING_CALL:
		return ne_set_vring_call(ne_enclave, ne_devs.ne_pci_dev,
					(struct ne_vring_call __user *)arg);
	case NE_SET_VRING_KICK:
		return ne_set_vring_kick(ne_enclave, ne_devs.ne_pci_dev,
					(struct ne_vring_kick __user *)arg);
	case NE_SET_INFO_EVENT_FD:
		return ne_set_info_event_fd(ne_enclave, ne_devs.ne_pci_dev,
					(struct ne_info_event_fd __user *)arg);
	case NE_ACCOUNT_VCPU:
		return ne_ioctl_account_vcpu(ne_enclave, arg);
	case NE_UPDATE_DEVICE_CONFIG:
		return ne_handle_update_device_config(ne_enclave, arg);
	default:
		return -ENOTTY;
	}

	return 0;
}

/**
 * ne_enclave_remove_all_mem_region_entries() - Remove all memory region entries
 *						from the enclave data structure.
 * @ne_enclave :	Private data associated with the current enclave.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 */
static void ne_enclave_remove_all_mem_region_entries(struct ne_enclave *ne_enclave,
						     bool defer_hugetlb)
{
	unsigned long i = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	struct ne_mem_region *ne_mem_region_tmp = NULL;

	list_for_each_entry_safe(ne_mem_region, ne_mem_region_tmp,
				 &ne_enclave->mem_regions_list,
				 mem_region_list_entry) {
		/*
		 * Hugetlb-backed enclave RAM is held ONLY by its get_user_pages
		 * (FOLL_GET) reference, released via put_page() below: unlike
		 * the NE CMA mapping there is no priv_holds entry keeping the
		 * backing reserved. That elevated refcount is therefore the
		 * only thing keeping the (host-still-read-only) pages out of
		 * the parent's page allocator until the slot is proven freed.
		 * ne_mmu_notifier_release() runs from exit_mmap() BEFORE the
		 * SLOT_FREE round-trip, so dropping the pin there returns the
		 * pages to the parent allocator while the host still maps them
		 * read-only; the next allocation clear_page()s one and takes a
		 * #GP on the hypervisor's page-ownership check. Defer these to
		 * ne_enclave_release() (defer_hugetlb=false), which drains
		 * AFTER SLOT_FREE has cleared the host read-only mapping.
		 */
		if (defer_hugetlb && ne_mem_region->nr_pages &&
		    PageHuge(ne_mem_region->pages[0]))
			continue;

		/*
		 * Direct mode and confidential PCIE on NIE defer the WHOLE
		 * entry, hugetlb or not. The region is shared with NE_SHARE_HYP
		 * | NE_SHARE_VM, so the child has it mapped until SLOT_FREE
		 * destroys the child, and until then the lowvisor refuses
		 * Guest.Unshare on it ("Guest.Unshare failed: gpa=... rc=21",
		 * HvcError::PageMapped). The unshare therefore has to wait for
		 * the post-SLOT_FREE drain in ne_enclave_release(), and it
		 * needs this bookkeeping to find the pages, so freeing the
		 * entry here would strand the Shareable Range Table entry for
		 * good, which then breaks the next enclave handed the same
		 * physical range. Deferring the pin drop with it costs nothing:
		 * priv_holds keeps NE-CMA backing reserved until
		 * ne_enclave_drop_priv_holds(), later still than the drain.
		 */
		if (defer_hugetlb && ne_enclave->sharing_ops &&
		    ((ne_enclave->start_flags & NE_ENCLAVE_DIRECT_MODE) ||
		     ne_enclave->pcie_mode))
			continue;

		list_del(&ne_mem_region->mem_region_list_entry);

		for (i = 0; i < ne_mem_region->nr_pages; i++) {
			/*
			 * Defensive NULL check, mirroring ne_release_device_pins():
			 * a listed entry always has every slot populated, so this
			 * only ever fires on a torn/stale entry seen on a buggy
			 * release path.
			 */
			if (ne_mem_region->pages[i])
				put_page(ne_mem_region->pages[i]);
		}

		kvfree(ne_mem_region->pages);

		kfree(ne_mem_region);
	}

	if (ne_enclave->info_pages) {
		/*
		 * Defer the unpin whenever the unshare is deferred: the
		 * post-SLOT_FREE unshare reads these fields and this block
		 * clears them, so unpinning early would skip it and leak the
		 * SRT entry.  Under NIE that is every backing; without it the
		 * hugetlb-only rule still applies, priv_holds keeping a
		 * CMA-backed info page alive until ne_enclave_release().
		 */
		if (defer_hugetlb && ne_enclave->info_nr_pages &&
		    (ne_enclave->sharing_ops ||
		     PageHuge(ne_enclave->info_pages[0])))
			return;

		unpin_user_pages(ne_enclave->info_pages,
				 ne_enclave->info_nr_pages);
		kvfree(ne_enclave->info_pages);
		ne_enclave->info_pages = NULL;
		ne_enclave->info_nr_pages = 0;
	}
}

/**
 * ne_enclave_remove_all_vcpu_id_entries() - Remove all vCPU id entries from
 *					     the enclave data structure.
 * @ne_enclave :	Private data associated with the current enclave.
 *
 * Context: Process context. This function is called with the ne_enclave mutex held.
 */
static void ne_enclave_remove_all_vcpu_id_entries(struct ne_enclave *ne_enclave)
{
	unsigned int cpu = 0;
	unsigned int i = 0;

	mutex_lock(&ne_cpu_pool.mutex);

	for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++) {
		for_each_cpu(cpu, ne_enclave->threads_per_core[i]) {
			/*
			 * Return the CPU to the available pool and, in
			 * dynamic mode, drop the scheduler isolation the
			 * allocation path installed in
			 * ne_set_enclave_threads_per_core().  Mirror the
			 * allocation order exactly so reference counts stay
			 * balanced even if an enclave is torn down without
			 * having reached NE_START_ENCLAVE.
			 */
			cpumask_set_cpu(cpu, ne_cpu_pool.avail_threads_per_core[i]);
			if (ne_pool_is_dynamic()) {
				int rc = sched_cpu_set_unisolated(cpu);

				if (rc)
					pr_warn_ratelimited(
						"%s: sched_cpu_set_unisolated(%u) failed [rc=%d]\n",
						ne_misc_dev.name, cpu, rc);
			}
		}

		free_cpumask_var(ne_enclave->threads_per_core[i]);
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	kfree(ne_enclave->threads_per_core);
	ne_enclave->threads_per_core = NULL;
}

/**
 * ne_pci_dev_remove_enclave_entry() - Remove the enclave entry from the data
 *				       structure that is part of the NE PCI
 *				       device private data.
 * @ne_enclave :	Private data associated with the current enclave.
 * @ne_pci_dev :	Private data associated with the PCI device.
 *
 * Context: Process context. This function is called with the ne_pci_dev enclave
 *	    mutex held.
 */
static void ne_pci_dev_remove_enclave_entry(struct ne_enclave *ne_enclave,
					    struct ne_pci_dev *ne_pci_dev)
{
	struct ne_enclave *ne_enclave_entry = NULL;
	struct ne_enclave *ne_enclave_entry_tmp = NULL;

	list_for_each_entry_safe(ne_enclave_entry, ne_enclave_entry_tmp,
				 &ne_pci_dev->enclaves_list, enclave_list_entry) {
		if (ne_enclave_entry->slot_uid == ne_enclave->slot_uid) {
			list_del(&ne_enclave_entry->enclave_list_entry);

			break;
		}
	}
}

/**
 * ne_enclave_release() - Release function provided by the enclave file.
 * @inode:	Inode associated with this file release function.
 * @file:	File associated with this release function.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_enclave_release(struct inode *inode, struct file *file)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct enclave_stop_req enclave_stop_request = {};
	struct ne_enclave *ne_enclave = file->private_data;
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct pci_dev *pdev = ne_pci_dev->pdev;
	int rc = -EINVAL;
	unsigned int i;
	struct slot_free_req slot_free_req = {};
	/*
	 * Whether the hypervisor confirmed SLOT_FREE (and with it moving
	 * ownership of every donated page back to the parent). Starts true so
	 * the slot_uid==0 error path (where nothing was ever donated) still
	 * runs the (no-op) drains below.
	 */
	bool slot_free_ok = true;
	u64 leaked;

	if (!ne_enclave)
		return 0;

	/*
	 * Drain the Parent-PID visibility consumer before anything
	 * else: the hrtimer may be queued and its callback walks
	 * ne_enclave under @accounted_lock; no more async work on
	 * this enclave must be in flight before we start freeing
	 * state below. Safe to call even when CPU_ACCOUNTING was
	 * never requested (list is empty, timer never armed).
	 */
	ne_enclave_drain_accounted_vcpus(ne_enclave);

	/*
	 * If we got as far as allocating a hypervisor slot, tear it down.
	 * Otherwise (release() entered on an error path from ne_create_vm_ioctl
	 * before SLOT_ALLOC succeeded) skip straight to freeing the partial
	 * state: ne_enclave may have an empty enclave_list_entry, no
	 * mmu_notifier registered, and no mem/vcpu/device_pins lists used.
	 * mutex/list heads were all initialized before anon_inode_getfile()
	 * so we can still take the locks safely if we want to.
	 */
	if (ne_enclave->slot_uid) {
		/*
		 * Acquire the enclave list mutex before the enclave mutex
		 * in order to avoid deadlocks with @ref ne_event_work_handler.
		 */
		mutex_lock(&ne_pci_dev->enclaves_list_mutex);
		mutex_lock(&ne_enclave->enclave_info_mutex);

		/*
		 * Always send ENCLAVE_STOP when a slot_uid is assigned. The
		 * hypervisor may have spawned a VMM during ENCLAVE_START even
		 * if the kernel state never advanced past NE_STATE_INIT (e.g.
		 * the owning process crashed before the ioctl returned). It
		 * handles ENCLAVE_STOP idempotently for any slot state.
		 */
		enclave_stop_request.slot_uid = ne_enclave->slot_uid;

		rc = ne_do_request_retry(pdev, ENCLAVE_STOP,
					 &enclave_stop_request, sizeof(enclave_stop_request),
					 &cmd_reply, sizeof(cmd_reply));
		if (rc < 0)
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in enclave stop [rc=%d]\n", rc);

		/*
		 * Reap this enclave's kick_xa bindings BEFORE SLOT_FREE, not
		 * during the state-drain further below.
		 *
		 * kick_xa is a per-device xarray keyed on the
		 * hypervisor-assigned vq_id, and the hypervisor scopes vq_ids
		 * per slot: once SLOT_FREE returns, it may reallocate this
		 * slot (and its vq_id range) to another enclave. If our
		 * bindings are still present then, that enclave's
		 * fresh-install NE_SET_VRING_KICK runs xa_cmpxchg(vq_id, NULL,
		 * b), finds our stale binding, and fails with -EEXIST even
		 * though no live enclave owns the vq_id.  Reaping only after
		 * SLOT_FREE would fix the permanent leak yet leave this reuse
		 * window open. Erase here, between ENCLAVE_STOP (the VMM has
		 * been told to stop, so no legitimate kick is in flight) and
		 * SLOT_FREE, so kick_xa[vq_id] is empty before the hypervisor
		 * can hand the vq_id to anyone else. This
		 * upholds the invariant "kick_xa[vq_id] is empty before the
		 * hypervisor may reuse vq_id".
		 *
		 * The eventfd_ctx_put + kfree of each ne_mux_binding stay
		 * RCU-deferred (ne_mux_binding_free_rcu) so an in-flight
		 * ne_mux_handler() reader that already loaded the binding
		 * cannot touch a freed object; only the xa_erase visibility
		 * needs to move earlier.
		 */
		{
			struct ne_kick_binding_entry *kb, *kb_tmp;

			list_for_each_entry_safe(kb, kb_tmp,
						 &ne_enclave->kick_bindings,
						 list) {
				struct ne_mux_binding *b;

				b = xa_erase(&ne_pci_dev->kick_xa, kb->vq_id);
				if (b)
					ne_mux_binding_free_rcu(b);
				list_del(&kb->list);
				kfree(kb);
			}
		}

		memset(&cmd_reply, 0, sizeof(cmd_reply));

		slot_free_req.slot_uid = ne_enclave->slot_uid;

		rc = ne_do_request_retry(pdev, SLOT_FREE,
					 &slot_free_req, sizeof(slot_free_req),
					 &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in slot free [rc=%d]\n", rc);
			/*
			 * The hypervisor did not confirm the slot free, so
			 * it never moved ownership of the pages back: every
			 * donated page (hugetlb GUP-pinned RAM, the info
			 * page, and the CMA backing behind priv_holds) may
			 * still be absent from the parent's EPT. Returning
			 * them to the parent allocator now lets an
			 * unrelated fault hand one out; the first write
			 * (clear_page_erms()) to that GPA takes a #GP and
			 * panics the parent, which has happened in practice.
			 * Leak them instead.
			 */
			slot_free_ok = false;
			leaked = ne_enclave->mem_size +
				 ((u64)ne_enclave->info_nr_pages << PAGE_SHIFT);
			/*
			 * DMB backing leaks too, since we skip the drop below.
			 * Use the counter rather than walking the list: on the
			 * non-NIE path the notifier has already unlinked the
			 * CMA-backed entries, so the list undercounts. The
			 * counter is every DMB either way.
			 */
			leaked += ne_enclave->dmb_bytes;
			atomic64_add(leaked, &ne_leaked_donated_bytes);
			WARN_ONCE(1,
				  "nitro_enclaves: SLOT_FREE failed (rc=%d), leaking %llu MiB of donated memory to avoid #GP on still-moved pages\n",
				  rc, leaked >> 20);
		}

		ne_pci_dev_remove_enclave_entry(ne_enclave, ne_pci_dev);
		ne_enclave_remove_all_vcpu_id_entries(ne_enclave);

		/*
		 * Unregister the MMU notifier before draining mem_regions,
		 * device_pins, or info_pages.  mmu_notifier_unregister()
		 * serializes against a concurrent ne_mmu_notifier_release():
		 * if the callback already ran, the lists are already drained
		 * and the cleanup below is a no-op; if it hasn't run, the
		 * unregister prevents it from ever firing.
		 *
		 * Must be called outside enclave_info_mutex because
		 * mmu_notifier_unregister() takes mmap_lock internally.
		 */
		mutex_unlock(&ne_enclave->enclave_info_mutex);
		if (ne_enclave->mmu_notifier.ops)
			mmu_notifier_unregister(&ne_enclave->mmu_notifier,
						ne_enclave->mm);
		mutex_lock(&ne_enclave->enclave_info_mutex);

		/*
		 * Release memory-region and info-page pins. Runs AFTER the
		 * SLOT_FREE round-trip above, so the host has cleared its
		 * read-only mapping and moved ownership back: it is now
		 * safe to return hugetlb-backed pages to the parent
		 * allocator, so drain them here (defer_hugetlb=false) even
		 * though ne_mmu_notifier_release() left them pinned. No-op
		 * for entries the notifier already drained (CMA-backed).
		 *
		 * Skipped when SLOT_FREE failed: the hugetlb / info-page GUP
		 * pin is then the ONLY thing keeping those PFNs out of the
		 * parent allocator, and dropping it while the host still owns
		 * the pages is exactly the #GP path. The ne_mem_region /
		 * info_pages bookkeeping leaks with the pages: a few kmalloc
		 * structs are noise next to the donated memory itself.
		 */
		if (slot_free_ok) {
			/* On NIE, unshare everything the mmu notifier had to
			 * skip: the info page whatever its backing, plus every
			 * direct-mode memory region and every DMB regardless of
			 * backing, the child having mapped those until the
			 * SLOT_FREE above destroyed it. Each loop below simply
			 * takes whatever the notifier left on its list.
			 */
			if (ne_enclave->sharing_ops) {
				struct ne_device_pins *dp;
				struct ne_mem_region *mr;

				/*
				 * Unshare the info page, every backing and not
				 * just hugetlb: the SLOT_FREE above took the
				 * slot out of SLOT_RUNNING, so this is the
				 * first point at which the hypervisor has
				 * stopped writing to it.
				 */
				if (ne_enclave->info_pages)
					ne_enclave->sharing_ops->unshare(
						ne_enclave,
						ne_enclave->info_page_paddr,
						(size_t)ne_enclave->info_nr_pages << PAGE_SHIFT);

				/* Direct mode: unshare every memory region still
				 * listed. The child mapped them all (NE_SHARE_VM),
				 * so this is the first point at which any of them
				 * can be unshared, CMA and hugetlb alike, and both
				 * are still on mem_regions_list because
				 * ne_enclave_remove_all_mem_region_entries()
				 * deferred the whole entry.
				 *
				 * Confidential PCIE takes the same path, for the
				 * DONATE entries it recorded at registration. This
				 * is the only point at which revoking one is valid,
				 * and it is valid whether or not the slot ever
				 * started: SLOT_FREE has just moved ownership
				 * of every donated page back to the parent, so
				 * the range is the parent's again and
				 * every page is private guest data once more, which
				 * is what Guest.Unshare requires. Earlier (from the
				 * mmu notifier) a withdrawn range would be refused,
				 * and on the !slot_free_ok path we must not ask at
				 * all: the pages may still be moved, which is why
				 * that path leaks instead (see the SLOT_FREE failure
				 * handling above).
				 *
				 * Without this the SRT entry outlives the slot and is
				 * only dropped when the parent VM is destroyed, so a
				 * create/abandon loop exhausts the parent's SRT and
				 * re-registering the same hugepages is refused, the
				 * lowvisor rejecting a re-donation of a live range.
				 */
				if ((ne_enclave->start_flags & NE_ENCLAVE_DIRECT_MODE) ||
				    ne_enclave->pcie_mode) {
					list_for_each_entry(mr, &ne_enclave->mem_regions_list,
							    mem_region_list_entry) {
						if (mr->nr_pages && mr->pages && mr->pages[0])
							ne_unshare_pages(ne_enclave,
									 mr->pages, mr->nr_pages,
									 /*per_page_stride=*/true);
					}
				}

				/* Unshare device backing. Every DMB is deferred to
				 * here, not just hugetlb: a DMB is shared with
				 * NE_SHARE_VM, so the child mapped it until the
				 * SLOT_FREE above. A rollback in
				 * ne_handle_add_device() may already have unshared an
				 * entry, but it releases whatever it unshares, so
				 * nothing it touched is still on this list.
				 */
				list_for_each_entry(dp, &ne_enclave->device_pins_list,
						    list) {
					if (dp->nr_pages && dp->pages && dp->pages[0])
						ne_unshare_pages(ne_enclave,
								 dp->pages, dp->nr_pages,
								 /*per_page_stride=*/false);
				}
			}

			ne_enclave_remove_all_mem_region_entries(ne_enclave,
								 /*defer_hugetlb=*/false);

			/* Release device backing page references (unshared
			 * above, or by ne_mmu_notifier_release for CMA). */
			{
				struct ne_device_pins *p, *tmp;

				list_for_each_entry_safe(p, tmp,
							 &ne_enclave->device_pins_list, list)
					ne_release_device_pins(p, /*defer_hugetlb=*/false);
			}
		}

		/* Clean up enclave ioeventfds */
		{
			struct ne_ioeventfd *iofd, *iofd_tmp;

			list_for_each_entry_safe(iofd, iofd_tmp,
						 &ne_enclave->ioeventfds, list) {
				if (iofd->active) {
					iofd->active = false;
					/*
					 * iofd->wqh is left NULL when vfs_poll() ran a ->poll
					 * that never called poll_wait(): historically reachable
					 * via the dup2() TOCTOU on req.fd when
					 * the replacement file was poll-less
					 * (e.g. /dev/null). The
					 * fd-resolution fix prevents that, but if a future change
					 * re-introduces a path where poll_wait() is skipped, this
					 * guard prevents NULL-deref in remove_wait_queue().
					 */
					if (iofd->wqh)
						remove_wait_queue(iofd->wqh, &iofd->wait);
					eventfd_ctx_put(iofd->ctx);
					iofd->ctx = NULL;
				}
				list_del(&iofd->list);
				kfree(iofd);
			}
			ne_enclave->num_ioeventfds = 0;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);
		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);
	}

	/*
	 * Free resources allocated in ne_create_vm_ioctl before slot alloc.
	 * threads_per_core and vcpu_ids are populated unconditionally when
	 * ne_enclave is allocated, so they are always freed here.
	 */
	if (ne_enclave->threads_per_core) {
		for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++)
			free_cpumask_var(ne_enclave->threads_per_core[i]);
		kfree(ne_enclave->threads_per_core);
	}
	free_cpumask_var(ne_enclave->vcpu_ids);

	/*
	 * Drop the kref/list pairs we accumulated against the contig vma privs
	 * in NE_SET_USER_MEMORY_REGION. This must happen AFTER the SLOT_FREE
	 * round-trip above so the host hypervisor has already moved ownership
	 * of the underlying physical pages back from this enclave to the
	 * parent, and AFTER mmu_notifier_unregister() so no further
	 * mmu_notifier_release() can run concurrently. cma_release() inside the
	 * priv kref_put is therefore the first parent-side operation that lets
	 * those PFNs be reused by any other allocator, which is exactly the
	 * "parent kernel reuses CMA only after the slot is freed" half of
	 * the contract.
	 *
	 * Do NOT drop when SLOT_FREE failed above. The intuitive reasoning ("a
	 * hard SLOT_FREE failure means the host has abandoned the slot") does
	 * not hold in practice: SLOT_FREE has returned -ETIMEDOUT because the
	 * command channel was wedged, the enclave VMM was still very much alive
	 * with the pages owned by it, cma_release() handed a page to
	 * firecracker's next anon fault, and the parent took a #GP in
	 * clear_page_erms() 12 ms later. Leaking the priv_hold refs (and with
	 * them the CMA reservation) is strictly better than a guaranteed panic.
	 * The leak is accounted in ne_leaked_donated_bytes above.
	 *
	 * No-op when slot_uid was 0 (NE_CREATE_VM error path): there was
	 * no NE_SET_USER_MEMORY_REGION call so priv_holds is empty.
	 */
	if (slot_free_ok)
		ne_enclave_drop_priv_holds(ne_enclave);

	kfree(ne_enclave);

	return 0;
}

/**
 * ne_enclave_poll() - Poll functionality used for enclave out-of-band events.
 * @file:	File associated with this poll function.
 * @wait:	Poll table data structure.
 *
 * Context: Process context.
 * Return:
 * * Poll mask.
 */
static __poll_t ne_enclave_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;
	struct ne_enclave *ne_enclave = file->private_data;

	poll_wait(file, &ne_enclave->eventq, wait);

	if (ne_enclave->has_event)
		mask |= EPOLLHUP;

	return mask;
}

static const struct file_operations ne_enclave_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.poll		= ne_enclave_poll,
	.unlocked_ioctl	= ne_enclave_ioctl,
	.release	= ne_enclave_release,
};

/**
 * ne_create_vm_ioctl() - Alloc slot to be associated with an enclave. Create
 *			  enclave file descriptor to be further used for enclave
 *			  resources handling e.g. memory regions and CPUs.
 * @ne_pci_dev :	Private data associated with the PCI device.
 * @slot_uid:		User pointer to store the generated unique slot id
 *			associated with an enclave to.
 *
 * Context: Process context. This function is called with the ne_pci_dev enclave
 *	    mutex held.
 * Return:
 * * Enclave fd on success.
 * * Negative return value on failure.
 */
static int ne_create_vm_ioctl(struct ne_pci_dev *ne_pci_dev,
			      struct ne_create_vm_args *args)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int enclave_fd = -1;
	struct file *enclave_file = NULL;
	unsigned int i = 0;
	struct ne_enclave *ne_enclave = NULL;
	struct pci_dev *pdev = ne_pci_dev->pdev;
	int rc = -EINVAL;
	struct slot_alloc_req slot_alloc_req = {};

	/*
	 * The NE CPU pool sanity check below verifies that at least one
	 * parent VM core has an available thread before any per-enclave
	 * state is allocated.  It is meaningful only for non-OVERCOMMIT
	 * enclaves, which take dedicated CPUs from ne_cpu_pool via
	 * ne_get_cpu_from_cpu_pool() at NE_ADD_VCPU time and progressively
	 * drain avail_threads_per_core[] as enclaves consume cores.
	 *
	 * NE_ENCLAVE_CPU_OVERCOMMIT_MODE enclaves never touch
	 * ne_cpu_pool.avail_threads_per_core: their vCPU threads are
	 * host-scheduled pthreads that float on the parent VMM's pcpu_pool via
	 * CFS. Once the pool drains for non-overcommit enclaves (or is
	 * intentionally undersized relative to the
	 * concurrent-overcommit-enclave count), this gate would spuriously
	 * reject every subsequent overcommit NE_CREATE_VM2 call with
	 * -NE_ERR_NO_CPUS_AVAIL_IN_POOL.
	 *
	 * Skip the gate whenever args->flags carries OVERCOMMIT_MODE.
	 * Validation of the flag bitmask itself happens below.
	 */
	if (!(args->flags & NE_ENCLAVE_CPU_OVERCOMMIT_MODE)) {
		mutex_lock(&ne_cpu_pool.mutex);

		for (i = 0; i < ne_cpu_pool.nr_parent_vm_cores; i++)
			if (!cpumask_empty(ne_cpu_pool.avail_threads_per_core[i]))
				break;

		if (i == ne_cpu_pool.nr_parent_vm_cores) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "No CPUs available in CPU pool\n");

			mutex_unlock(&ne_cpu_pool.mutex);

			return -NE_ERR_NO_CPUS_AVAIL_IN_POOL;
		}

		mutex_unlock(&ne_cpu_pool.mutex);
	}

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (!ne_enclave)
		return -ENOMEM;

	/*
	 * Initialize the Parent-PID visibility consumer state up
	 * front so ne_enclave_drain_accounted_vcpus() can be called
	 * unconditionally from ne_enclave_release() even on error
	 * paths that bail out before ne_query_vcpu_time().
	 */
	spin_lock_init(&ne_enclave->accounted_lock);
	INIT_LIST_HEAD(&ne_enclave->accounted_vcpus);
	INIT_LIST_HEAD(&ne_enclave->active_link);

	mutex_lock(&ne_cpu_pool.mutex);

	ne_enclave->nr_parent_vm_cores = ne_cpu_pool.nr_parent_vm_cores;
	ne_enclave->nr_threads_per_core = ne_cpu_pool.nr_threads_per_core;
	ne_enclave->numa_node = ne_cpu_pool.numa_node;

	mutex_unlock(&ne_cpu_pool.mutex);

	ne_enclave->threads_per_core = kcalloc(ne_enclave->nr_parent_vm_cores,
					       sizeof(*ne_enclave->threads_per_core),
					       GFP_KERNEL);
	if (!ne_enclave->threads_per_core) {
		rc = -ENOMEM;

		goto free_ne_enclave;
	}

	for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++)
		if (!zalloc_cpumask_var(&ne_enclave->threads_per_core[i], GFP_KERNEL)) {
			rc = -ENOMEM;

			goto free_cpumask;
		}

	if (!zalloc_cpumask_var(&ne_enclave->vcpu_ids, GFP_KERNEL)) {
		rc = -ENOMEM;

		goto free_cpumask;
	}

	/*
	 * Initialize fields that ne_enclave_release() touches BEFORE handing
	 * ownership of ne_enclave to the enclave file. After
	 * anon_inode_getfile() succeeds, any further error path must transfer
	 * cleanup responsibility to ne_enclave_release() via fput(): it is
	 * not safe to kfree(ne_enclave) synchronously because fput() defers
	 * the actual release via task_work_add(TWA_RESUME), so release runs
	 * later on what would otherwise be freed memory.
	 */
	init_waitqueue_head(&ne_enclave->eventq);
	ne_enclave->has_event = false;
	mutex_init(&ne_enclave->enclave_info_mutex);
	INIT_LIST_HEAD(&ne_enclave->mem_regions_list);
	INIT_LIST_HEAD(&ne_enclave->device_pins_list);
	INIT_LIST_HEAD(&ne_enclave->enclave_list_entry);
	INIT_LIST_HEAD(&ne_enclave->kick_bindings);
	INIT_LIST_HEAD(&ne_enclave->priv_holds);
	INIT_LIST_HEAD(&ne_enclave->ioeventfds);

	enclave_fd = get_unused_fd_flags(O_CLOEXEC);
	if (enclave_fd < 0) {
		rc = enclave_fd;

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in getting unused fd [rc=%d]\n", rc);

		goto free_cpumask;
	}

	enclave_file = anon_inode_getfile("ne-vm", &ne_enclave_fops, ne_enclave, O_RDWR);
	if (IS_ERR(enclave_file)) {
		rc = PTR_ERR(enclave_file);

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in anon inode get file [rc=%d]\n", rc);

		goto put_fd;
	}
	/*
	 * From this point on, ne_enclave is owned by enclave_file.
	 * All error paths release the enclave via fput(enclave_file), which
	 * schedules ne_enclave_release() to run after current returns to
	 * user mode. Do NOT fall through to free_cpumask/free_ne_enclave.
	 */

	/*
	 * Stage every launch-time flag except DEBUG on the SLOT_ALLOC
	 * request. The hypervisor records them on the slot and its routing
	 * logic picks PCIE vs legacy backing from the matched/DIRECT
	 * bits.  DEBUG remains per-launch and will travel with START_ENCLAVE.
	 *
	 * The legacy NE_CREATE_VM ioctl passes args->flags == 0, which is
	 * the unchanged "legacy enclave, DEBUG-or-nothing" path.  The new
	 * NE_CREATE_VM2 ioctl lets userspace set any allowed bit.
	 *
	 * Validate here: reject any bit we don't know about, reject DEBUG
	 * (per-launch, not a slot-level property), and enforce mutual
	 * exclusion + dependencies via the same NE_ENCLAVE_FLAG_* masks the
	 * START_ENCLAVE path uses.
	 */
	if (args->padding != 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "NE_CREATE_VM2: padding must be zero (got 0x%x); reserved for future extensions\n",
				    args->padding);
		rc = -EINVAL;
		goto put_file;
	}
	if (args->flags & ~NE_ENCLAVE_FLAG_VALID_MASK) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "NE_CREATE_VM2: invalid flag bits 0x%x\n",
				    args->flags & ~NE_ENCLAVE_FLAG_VALID_MASK);
		rc = -EINVAL;
		goto put_file;
	}
	if (args->flags & NE_ENCLAVE_DEBUG_MODE) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "NE_CREATE_VM2: DEBUG must be passed at NE_START_ENCLAVE\n");
		rc = -EINVAL;
		goto put_file;
	}
	/*
	 * Wire-version the payload only when the caller actually requested a
	 * flag bit.  args->flags == 0 is indistinguishable from the stock
	 * upstream driver and the Windows driver writing `u8 unused = 0`, so
	 * we leave payload_version at 0 in that case and the hypervisor routes
	 * the request down the identical legacy path.
	 */
	if (args->flags) {
		slot_alloc_req.payload_version = 1;
		slot_alloc_req.flags = args->flags;
	}

	rc = ne_do_request_retry(pdev, SLOT_ALLOC,
			   &slot_alloc_req, sizeof(slot_alloc_req),
			   &cmd_reply, sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot alloc [rc=%d]\n", rc);

		goto put_file;
	}

	/* Other fields (waitqueue, mutex, list heads) were initialized before
	 * anon_inode_getfile() so release() can always run. */
	ne_enclave->max_mem_regions = cmd_reply.alloc.mem_regions;
	/*
	 * Record slot_uid now, before mmu_notifier_register() can fail:
	 * ne_enclave_release() only sends SLOT_FREE when slot_uid != 0, so if
	 * we set it later the put_file unwind would leak the hypervisor slot.
	 */
	ne_enclave->slot_uid = cmd_reply.alloc.slot_uid;
	ne_enclave->mm = current->mm;
	atomic_set(&ne_enclave->mmu_release_done, 0);
	ne_enclave->mmu_notifier.ops = &ne_mmu_notifier_ops;
	rc = mmu_notifier_register(&ne_enclave->mmu_notifier, ne_enclave->mm);
	if (rc) {
		ne_enclave->mmu_notifier.ops = NULL;
		goto put_file;
	}
	ne_enclave->state = NE_STATE_INIT;
	/*
	 * PCIE mode is a slot-level property now (the hypervisor routes based
	 * on it at SLOT_ALLOC). Reflect it on the ne_enclave immediately so
	 * that NE_ADD_DEVICE / NE_SET_INFO_PAGE and downstream code can key off
	 * ne_enclave->pcie_mode from CREATE time onward, instead of waiting
	 * for NE_START_ENCLAVE to set it.
	 */
	if (args->flags & NE_ENCLAVE_PCIE_MODE)
		ne_enclave->pcie_mode = true;

	/*
	 * Persist the full flag word so post-create code paths (the
	 * NE_ADD_VCPU skip-pool logic and the post-ENCLAVE_START
	 * SLOT_VCPU_TIME query) can key off it without copying from
	 * the args struct again.
	 */
	ne_enclave->start_flags = args->flags;

	/* Resolved once at probe; every enclave inherits the same backend. */
	ne_enclave->sharing_ops = ne_pci_dev->sharing_ops;

	list_add(&ne_enclave->enclave_list_entry, &ne_pci_dev->enclaves_list);

	args->slot_uid = ne_enclave->slot_uid;

	fd_install(enclave_fd, enclave_file);

	return enclave_fd;

put_file:
	/* enclave_file owns ne_enclave; fput() schedules ne_enclave_release()
	 * which will free ne_enclave (and the cpumask/threads_per_core
	 * allocations below) once it runs. */
	fput(enclave_file);
	put_unused_fd(enclave_fd);
	return rc;

put_fd:
	put_unused_fd(enclave_fd);
free_cpumask:
	free_cpumask_var(ne_enclave->vcpu_ids);
	for (i = 0; i < ne_enclave->nr_parent_vm_cores; i++)
		free_cpumask_var(ne_enclave->threads_per_core[i]);
	kfree(ne_enclave->threads_per_core);
free_ne_enclave:
	kfree(ne_enclave);

	return rc;
}

/**
 * ne_ioctl() - Ioctl function provided by the NE misc device.
 * @file:	File associated with this ioctl function.
 * @cmd:	The command that is set for the ioctl call.
 * @arg:	The argument that is provided for the ioctl call.
 *
 * Context: Process context.
 * Return:
 * * Ioctl result (e.g. enclave file descriptor) on success.
 * * Negative return value on failure.
 */
static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NE_CREATE_VM: {
		/*
		 * Legacy flags-less variant.  Preserved byte-for-byte from
		 * the pre-flag-at-create UAPI so old userspace keeps working.
		 * Internally we still route through ne_create_vm_ioctl()
		 * using a zeroed ne_create_vm_args; a zero flag word selects
		 * legacy backing.
		 */
		int enclave_fd = -1;
		struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
		u64 __user *slot_uid = (void __user *)arg;
		struct ne_create_vm_args args = {};

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);
		enclave_fd = ne_create_vm_ioctl(ne_pci_dev, &args);
		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		if (enclave_fd >= 0 &&
		    copy_to_user(slot_uid, &args.slot_uid,
				 sizeof(args.slot_uid))) {
			/*
			 * The fd has already been fd_install()'d.  Userspace
			 * will see an enclave_fd it can close but has no
			 * slot_uid for.  Surface the failure via -EFAULT and
			 * rely on userspace to close the enclave fd.
			 */
			return -EFAULT;
		}

		return enclave_fd;
	}

	case NE_CREATE_VM2: {
		int enclave_fd = -1;
		struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
		struct ne_create_vm_args args = {};

		if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
			return -EFAULT;

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);
		enclave_fd = ne_create_vm_ioctl(ne_pci_dev, &args);
		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		if (enclave_fd >= 0 &&
		    copy_to_user((void __user *)arg, &args, sizeof(args))) {
			/*
			 * The fd has already been fd_install()'d.  Userspace
			 * will see an enclave_fd it can close but has no
			 * slot_uid for.  Surface the failure via -EFAULT and
			 * rely on userspace to close the enclave fd.
			 */
			return -EFAULT;
		}

		return enclave_fd;
	}

	case NE_GET_SUPPORTED_FLAGS: {
		struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
		u32 supported;

		supported = ioread32(ne_pci_dev->iomem_base +
				     NE_SUPPORTED_FLAGS);
		if (copy_to_user((void __user *)arg, &supported,
				 sizeof(supported)))
			return -EFAULT;
		return 0;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

/*
 * Contiguous memory mmap support.
 *
 * User space can mmap /dev/nitro_enclaves to allocate physically contiguous
 * memory, served exclusively from the boot-time CMA reservations.
 *   - All allocations are at least 2 MiB aligned, via the CMA
 *     allocation order
 *
 * The mapping appears virtually contiguous to user space even when backed
 * by multiple contiguous allocations.
 */

struct ne_contig_vma_priv {
	struct list_head allocs;
	struct mutex lock;
	/*
	 * VMAs may be split by mprotect/munmap/mremap after mmap() returns.
	 * The mm core calls vm_ops->open on the new half and vm_ops->close
	 * on every VMA that references this priv, so we must keep priv
	 * alive until the LAST vm_ops->close.  Without this, a partial
	 * munmap triggers kfree(priv) in the first close and the exit-mmap
	 * close of the other half then dereferences freed memory (POISON_FREE
	 * = 0x6b).
	 */
	struct kref refcount;
};

/*
 * One-per-NE_SET_USER_MEMORY_REGION-on-contig hold on a contig vma's priv.
 * Linked into ne_enclave->priv_holds at memory region attach time, drained by
 * ne_enclave_release() AFTER the SLOT_FREE round-trip completes so that
 * cma_release(), and therefore reuse of the underlying CMA pages by anything
 * else in the parent, cannot happen until the host hypervisor has moved
 * ownership of the pages back to the parent.
 */
struct ne_contig_priv_hold {
	struct list_head list;
	struct ne_contig_vma_priv *priv;
};

static void ne_contig_vma_priv_release(struct kref *kref);

/**
 * ne_enclave_hold_contig_priv() - Take an extra kref on a contig priv
 *	on behalf of @ne_enclave so that cma_release() is deferred until
 *	ne_enclave_release() has completed SLOT_FREE.
 * @ne_enclave : Enclave that just consumed @priv via NE_SET_USER_MEMORY_REGION.
 *               Caller holds @enclave_info_mutex.
 * @priv       : The contig vma priv (vma->vm_private_data with vm_ops ==
 *               &ne_contig_vm_ops) being added to a memory region.
 *
 * Multiple calls with the same @priv accumulate independent kref/list pairs.
 * That is fine (each pair is balanced by exactly one drop in
 * ne_enclave_drop_priv_holds()) and avoids walking the (potentially long)
 * priv_holds list in the hot ioctl path.
 *
 * Return: 0 on success, -ENOMEM on allocation failure.  The caller must
 *         not assume the kref was taken if the call returns nonzero.
 */
static int ne_enclave_hold_contig_priv(struct ne_enclave *ne_enclave,
				       struct ne_contig_vma_priv *priv)
{
	struct ne_contig_priv_hold *hold;

	if (!priv)
		return -EINVAL;

	hold = kmalloc(sizeof(*hold), GFP_KERNEL);
	if (!hold)
		return -ENOMEM;

	kref_get(&priv->refcount);
	hold->priv = priv;
	list_add(&hold->list, &ne_enclave->priv_holds);

	return 0;
}

/**
 * ne_enclave_drop_priv_holds() - Drop every extra kref this enclave is
 *	holding on contig vma privs.  Must be called from the enclave
 *	release path AFTER SLOT_FREE has returned: at that point the host
 *	has finished moving ownership of the underlying pages back to the
 *	parent and cma_release() can safely run without any subsequent
 *	allocator handing the same PFNs to a writer that the host's EPT
 *	will then reject.
 * @ne_enclave : Enclave whose priv_holds list to drain.  No external
 *               serialization is required because the release path runs
 *               after mmu_notifier_unregister() and after the file's
 *               last reference has been dropped.
 */
static void ne_enclave_drop_priv_holds(struct ne_enclave *ne_enclave)
{
	struct ne_contig_priv_hold *hold, *tmp;

	list_for_each_entry_safe(hold, tmp, &ne_enclave->priv_holds, list) {
		list_del(&hold->list);
		kref_put(&hold->priv->refcount, ne_contig_vma_priv_release);
		kfree(hold);
	}
}

static void ne_contig_vma_priv_release(struct kref *kref)
{
	struct ne_contig_vma_priv *priv =
		container_of(kref, struct ne_contig_vma_priv, refcount);
	struct ne_contig_alloc *alloc, *tmp;
	bool released_cma = false;

	mutex_lock(&priv->lock);
	list_for_each_entry_safe(alloc, tmp, &priv->allocs, list) {
		if (alloc->cma) {
			/*
			 * The pages become reusable here. Trace the HPA to
			 * order this against the hypervisor's rejection naming
			 * the same HPA.
			 */
			pr_debug("NE: cma_release hpa=0x%llx nr_pages=%lu\n",
				 (u64)page_to_phys(alloc->page),
				 alloc->nr_pages);
			cma_release(alloc->cma, alloc->page, alloc->nr_pages);
			released_cma = true;
		} else {
			unsigned long i;

			for (i = 0; i < alloc->nr_pages; i++)
				put_page(alloc->page + i);
		}
		list_del(&alloc->list);
		kfree(alloc);
	}
	mutex_unlock(&priv->lock);
	mutex_destroy(&priv->lock);
	kfree(priv);

	/*
	 * cma_release() -> free_contig_range() frees order-0 pages via
	 * __free_page(), which parks them on the per-CPU page lists as
	 * MIGRATE_MOVABLE.  NR_FREE_CMA_PAGES is only re-derived from the
	 * pageblock migratetype when those pages drain to the buddy
	 * (free_pcppages_bulk()), so on an idle host CmaFree can under-count
	 * for tens of seconds after an enclave teardown.  Force a drain now so
	 * the accounting is immediately consistent; drain_all_pages() takes
	 * pcpu_drain_mutex, and every path into this kref release is already
	 * sleepable process context (it takes priv->lock above).
	 */
	if (released_cma)
		drain_all_pages(NULL);
}

/*
 * Trivial kref get/put wrappers to let callers earlier in the file
 * (ne_set_user_memory_region_ioctl) manipulate the kref without
 * needing the struct definition or the kref release callback in
 * scope.  See the forward declarations near the top of the file.
 */
static void ne_contig_vma_priv_get(struct ne_contig_vma_priv *priv)
{
	kref_get(&priv->refcount);
}

static void ne_contig_vma_priv_put(struct ne_contig_vma_priv *priv)
{
	kref_put(&priv->refcount, ne_contig_vma_priv_release);
}

static void ne_contig_vma_open(struct vm_area_struct *vma)
{
	struct ne_contig_vma_priv *priv = vma->vm_private_data;

	if (priv)
		kref_get(&priv->refcount);
}

static void ne_contig_vma_close(struct vm_area_struct *vma)
{
	struct ne_contig_vma_priv *priv = vma->vm_private_data;

	if (!priv)
		return;

	kref_put(&priv->refcount, ne_contig_vma_priv_release);
}

static vm_fault_t ne_contig_vma_fault(struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static const struct vm_operations_struct ne_contig_vm_ops = {
	.open	= ne_contig_vma_open,
	.close	= ne_contig_vma_close,
	.fault	= ne_contig_vma_fault,
};

/*
 * Try to allocate from NE CMA regions first (guaranteed to succeed if
 * mempool was reserved), then fall back to the kernel's generic
 * "cma=" reservation.
 *
 * The fallback chain is:
 *
 *   1. NE-driver-specific CMA regions (declared via
 *      nitro_enclaves.mempool=, NUMA-node-filtered).
 *   2. The generic kernel CMA pool (cma= cmdline). This lets enclave
 *      density runs that bring up an unmodified parent kernel with
 *      cma=<size> consume that reservation without having to plumb
 *      mempool=. The default pool is shared with other DMA-coherent
 *      users; pages are guaranteed to come from CMA-reserved memory
 *      rather than competing with the regular Normal zone, which is a
 *      much more deterministic source under high parallel allocation
 *      pressure.
 * There is deliberately no fallback past the reserved pools: the
 * reservation is the allocation budget for every consumer, userspace
 * mmaps of /dev/nitro_enclaves and the kernel-internal donations
 * alike. Spilling past it into the general page allocator would hand
 * any process with access to the device node a primitive to drain the
 * parent of every movable allocation, and would quietly serve memory
 * that nothing sized against the pool ever budgeted for. A request
 * the pools cannot serve fails instead, and a boot with no
 * reservation of either kind cannot allocate contiguous enclave
 * memory at all.
 *
 * @nid: NUMA node the pages must come from, or NUMA_NO_NODE for any node.
 *       The userspace-facing path (ne_mmap) always passes a concrete node
 *       id (0 when unspecified by the caller); NUMA_NO_NODE is also used by
 *       the kernel-internal callers in ne_pci_dev.c. A concrete @nid is a
 *       constraint: memory on another node than the enclave's vcpus makes
 *       the slot multi-NUMA, which the VMM rejects unless PCIE_NUMA is set.
 *       Callers preferring any node over failure retry with NUMA_NO_NODE
 *       (see ne_system_ram_donate_one()).
 *
 * Returns zeroed pages. CMA pool pages may contain residual data from
 * prior use by the general page allocator (MIGRATE_CMA), so we zero
 * unconditionally to prevent sensitive parent data from leaking into
 * enclave guests via donated memory.
 */
struct page *ne_alloc_contig(unsigned long nr_pages,
			     struct cma **out_cma, int nid)
{
	struct page *page = NULL;
	unsigned int align_order = ilog2(NE_MIN_MEM_REGION_SIZE >> PAGE_SHIFT);
	bool have_pool = ne_cma_nr_regions > 0 || dev_get_cma_area(NULL);

	*out_cma = NULL;

	/*
	 * Contiguous enclave memory comes only from the reserved pools.
	 * A boot without one (no nitro_enclaves.mempool=, no cma=, or the
	 * EFI gate skipping the reservation) cannot serve any request:
	 * say so once, loudly, so a misconfigured boot is distinguishable
	 * from pool exhaustion.
	 */
	if (!have_pool) {
		pr_warn_once("nitro_enclaves: no reserved CMA pool on this boot; contiguous enclave allocations will fail\n");
		return NULL;
	}

	/* Try NE-specific CMA regions first, filtering by NUMA node */
	{
		int i;

		for (i = 0; i < ne_cma_nr_regions; i++) {
			if (nid != NUMA_NO_NODE &&
			    ne_cma_node(i) != nid)
				continue;
			page = cma_alloc(ne_cma_regions[i], nr_pages,
					 align_order, true);
			if (page) {
				*out_cma = ne_cma_regions[i];
				break;
			}
		}
	}

	/*
	 * Fall back to the generic kernel CMA pool (cma= cmdline).
	 * dev_get_cma_area(NULL) returns dma_contiguous_default_area
	 * when CONFIG_DMA_CMA is enabled and a default area was reserved
	 * (i.e. cma= was supplied at boot), or NULL otherwise.
	 *
	 * This area carries no node id, but it is always a single
	 * reserved range (dma_contiguous_reserve_area() never takes the
	 * multi-range path) and a range cannot straddle nodes, so the node
	 * of its base PFN is the node of the whole area.
	 */
	if (!page) {
		struct cma *default_cma = dev_get_cma_area(NULL);

		if (default_cma &&
		    (nid == NUMA_NO_NODE ||
		     pfn_to_nid(PFN_DOWN(cma_get_base(default_cma))) == nid)) {
			page = cma_alloc(default_cma, nr_pages, align_order,
					 true);
			if (page)
				*out_cma = default_cma;
		}
	}

	if (page)
		memset(page_address(page), 0, nr_pages << PAGE_SHIFT);

	return page;
}

static int ne_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long remaining = size;
	unsigned long vaddr = vma->vm_start;
	struct ne_contig_vma_priv *priv;
	int nid = NUMA_NO_NODE;
	unsigned long offset;
	int rc = 0;

	if (size & (NE_MIN_MEM_REGION_SIZE - 1))
		return -EINVAL;

	/*
	 * The mapping base must sit on the same 2 MiB grid as the chunks
	 * that populate it: region registration requires a 2 MiB-aligned
	 * userspace address, and the merged-regions bound in
	 * ne_set_user_memory_region_ioctl() counts one region per 2 MiB
	 * chunk window. ne_get_unmapped_area() already returns aligned
	 * addresses; this rejects a misaligned MAP_FIXED request, which
	 * could never register anyway.
	 */
	if (vma->vm_start & (NE_MIN_MEM_REGION_SIZE - 1))
		return -EINVAL;

	/*
	 * Decode NUMA node from mmap offset.
	 * Bits [63:48] encode the host NUMA node id.
	 * Bits [47:0] are reserved and must be zero.
	 *
	 * offset=0 means NUMA node 0 (the default). There is no
	 * "any NUMA" semantic on the userspace-facing path.
	 */
#define NE_MMAP_NUMA_SHIFT	48
#define NE_MMAP_NUMA_MASK	(0xffffUL << NE_MMAP_NUMA_SHIFT)

	offset = (unsigned long)vma->vm_pgoff << PAGE_SHIFT;
	if (offset & ~NE_MMAP_NUMA_MASK)
		return -EINVAL;

	nid = (int)((offset & NE_MMAP_NUMA_MASK) >> NE_MMAP_NUMA_SHIFT);
	if (nid >= MAX_NUMNODES || !node_online(nid))
		return -EINVAL;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	INIT_LIST_HEAD(&priv->allocs);
	mutex_init(&priv->lock);
	kref_init(&priv->refcount);

	vma->vm_ops = &ne_contig_vm_ops;
	vma->vm_private_data = priv;
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP);

	mutex_lock(&ne_contig_mutex);

	while (remaining > 0) {
		struct page *page = NULL;
		struct cma *from_cma = NULL;
		unsigned long chunk;
		unsigned long p;
		struct ne_contig_alloc *alloc;

		for (chunk = remaining; chunk >= NE_MIN_MEM_REGION_SIZE;
		     chunk >>= 1) {
			chunk = round_down(chunk, NE_MIN_MEM_REGION_SIZE);
			if (!chunk)
				break;

			page = ne_alloc_contig(chunk >> PAGE_SHIFT, &from_cma,
					       nid);
			if (page)
				break;
		}

		if (!page) {
			rc = -ENOMEM;
			goto err_release;
		}

		alloc = kzalloc(sizeof(*alloc), GFP_KERNEL);
		if (!alloc) {
			/*
			 * This chunk is not yet on priv->allocs, so release its
			 * refs inline; err_release drains the earlier chunks.
			 */
			if (from_cma) {
				cma_release(from_cma, page,
					    chunk >> PAGE_SHIFT);
			} else {
				unsigned long j;

				for (j = 0; j < (chunk >> PAGE_SHIFT); j++)
					put_page(page + j);
			}
			rc = -ENOMEM;
			goto err_release;
		}

		alloc->page = page;
		alloc->nr_pages = chunk >> PAGE_SHIFT;
		alloc->cma = from_cma;

		mutex_lock(&priv->lock);
		list_add_tail(&alloc->list, &priv->allocs);
		mutex_unlock(&priv->lock);

		for (p = 0; p < (chunk >> PAGE_SHIFT); p++) {
			rc = vm_insert_page(vma, vaddr + (p << PAGE_SHIFT),
					    page + p);
			if (rc)
				goto err_release;
		}

		vaddr += chunk;
		remaining -= chunk;
	}

	mutex_unlock(&ne_contig_mutex);

	return 0;

err_release:
	mutex_unlock(&ne_contig_mutex);
	/*
	 * A failing ->mmap never gets vm_ops->close on this kernel (the VMA is
	 * freed without vma_close() and never entered into the maple tree), so
	 * release priv and its donated pages here or they leak.
	 *
	 * The mm core still runs unmap_region() after we return, dropping the
	 * vm_insert_page() PTE refs, so zap those PTEs first: otherwise
	 * cma_release()/put_page() frees the pages while still mapped (WARN +
	 * double free once unmap_region() runs). Use zap_page_range_single(),
	 * not zap_vma_ptes(): the latter no-ops on this VM_MIXEDMAP VMA (it
	 * only acts on VM_PFNMAP). Zapping the whole range covers PTEs left by
	 * a mid-chunk vm_insert_page() failure.
	 */
	zap_page_range_single(vma, vma->vm_start, size, NULL);
	vma->vm_private_data = NULL;
	ne_contig_vma_priv_put(priv);

	return rc;
}

#if defined(CONFIG_NITRO_ENCLAVES_MISC_DEV_TEST)
#include "ne_misc_dev_test.c"
#endif

static int __init ne_init(void)
{
	/*
	 * Set up the driver-global CPU_ACCOUNTING hrtimer. The timer is
	 * initialized unconditionally but not armed until the first enclave
	 * activates (ne_account_enclave_activate), so kernels without any
	 * CPU_ACCOUNTING enclaves pay zero runtime cost for this.
	 */
	hrtimer_setup(&ne_account_timer, ne_account_tick,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	/*
	 * Set up the CPU pool. This handles both:
	 * - Default "dynamic" value (param callback was never called)
	 * - Cmdline value deferred because slab wasn't available yet
	 */
	if (ne_cpus[0] != '\0' && !ne_cpu_pool.nr_parent_vm_cores) {
		int rc;

		if (ne_pool_is_dynamic())
			rc = ne_setup_dynamic_cpu_pool();
		else
			rc = ne_setup_cpu_pool(ne_cpus);

		if (rc < 0)
			pr_warn("%s: CPU pool setup failed [rc=%d]\n",
				ne_misc_dev.name, rc);
	}

	return pci_register_driver(&ne_pci_driver);
}

static void __exit ne_exit(void)
{
	pci_unregister_driver(&ne_pci_driver);

	/*
	 * Wait for any pending call_rcu(ne_mux_binding_rcu_free) callbacks to
	 * run before the module text is freed. ne_enclave_release() can queue
	 * one just before the last module_put(), and module unload does not
	 * barrier RCU itself. See Documentation/RCU/rcubarrier.rst.
	 */
	rcu_barrier();

	/*
	 * Quiesce the shared accounting timer after the PCI driver
	 * is gone, so any tick in flight finishes before we free
	 * module state. By the time we get here all enclaves should
	 * have drained via ne_enclave_drain_accounted_vcpus(), which
	 * already removes them from @ne_accounting_enclaves; the
	 * cancel is a defensive belt-and-braces to cover a race on
	 * the last enclave's self-disarm.
	 */
	hrtimer_cancel(&ne_account_timer);

	ne_teardown_cpu_pool();
}

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
