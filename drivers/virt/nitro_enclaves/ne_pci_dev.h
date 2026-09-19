/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef _NE_PCI_DEV_H_
#define _NE_PCI_DEV_H_

#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/eventfd.h>
#include <linux/xarray.h>

/**
 * DOC: Nitro Enclaves (NE) PCI device
 */

struct ne_mem_sharing_ops;

/**
 * PCI_DEVICE_ID_NE - Nitro Enclaves PCI device id.
 */
#define PCI_DEVICE_ID_NE	(0xe4c1)
/**
 * PCI_BAR_NE - Nitro Enclaves PCI device MMIO BAR.
 */
#define PCI_BAR_NE		(0x03)

/**
 * DOC: Device registers in the NE PCI device MMIO BAR
 */

/**
 * NE_ENABLE - (1 byte) Register to notify the device that the driver is using
 *	       it (Read/Write).
 */
#define NE_ENABLE		(0x0000)
#define NE_ENABLE_OFF		(0x00)
#define NE_ENABLE_ON		(0x01)

/**
 * NE_VERSION - (2 bytes) Register to select the device run-time version
 *		(Read/Write).
 */
#define NE_VERSION		(0x0002)
#define NE_VERSION_MAX		(0x0001)

/**
 * NE_COMMAND - (4 bytes) Register to notify the device what command was
 *		requested (Write-Only).
 */
#define NE_COMMAND		(0x0004)

/**
 * NE_EVTCNT - (4 bytes) Register to notify the driver that a reply or a device
 *	       event is available (Read-Only):
 *	       - Lower half  - command reply counter
 *	       - Higher half - out-of-band device event counter
 */
#define NE_EVTCNT		(0x000c)
#define NE_EVTCNT_REPLY_SHIFT	(0)
#define NE_EVTCNT_REPLY_MASK	(0x0000ffff)
#define NE_EVTCNT_REPLY(cnt)	(((cnt) & NE_EVTCNT_REPLY_MASK) >> \
				NE_EVTCNT_REPLY_SHIFT)
#define NE_EVTCNT_EVENT_SHIFT	(16)
#define NE_EVTCNT_EVENT_MASK	(0xffff0000)
#define NE_EVTCNT_EVENT(cnt)	(((cnt) & NE_EVTCNT_EVENT_MASK) >> \
				NE_EVTCNT_EVENT_SHIFT)

/**
 * NE_SEND_DATA - (240 bytes) Buffer for sending the command request payload
 *		  (Read/Write).
 */
#define NE_SEND_DATA		(0x0010)

/**
 * NE_RECV_DATA - (240 bytes) Buffer for receiving the command reply payload
 *		  (Read-Only).
 */
#define NE_RECV_DATA		(0x0100)

/**
 * DOC: Device MMIO buffer sizes
 */

/**
 * NE_SEND_DATA_SIZE - Size of the send buffer, in bytes.
 */
#define NE_SEND_DATA_SIZE	(240)

/**
 * NE_RECV_DATA_SIZE - Size of the receive buffer, in bytes.
 */
#define NE_RECV_DATA_SIZE	(240)

/**
 * DOC: MSI-X interrupt vectors
 */

/**
 * NE_VEC_REPLY - MSI-X vector used for command reply notification.
 */
#define NE_VEC_REPLY		(0)

/**
 * NE_VEC_EVENT - MSI-X vector used for out-of-band events e.g. enclave crash.
 */
#define NE_VEC_EVENT		(1)

/**
 * DOC: Per-enclave PCIe device cap register
 *
 *   NE_MAX_PCIE_DEVICES (0x020e, u16 RO) - per-enclave cap on the
 *       number of PCIe virtio devices the hypervisor accepts via
 *       NE_ADD_DEVICE.  Read once at probe and exposed to userspace
 *       as the read-only nitro_enclaves.max_pcie_devices module
 *       parameter so VMMs (FC/QEMU/EKS shim) can query the limit
 *       instead of hardcoding it.  Older hypervisors that do not
 *       advertise this register return 0; the driver falls back to
 *       the legacy hardcoded cap of 8.
 */
#define NE_MAX_PCIE_DEVICES		(0x020e)

/**
 * enum ne_pci_dev_cmd_type - Device command types.
 * @INVALID_CMD:		Invalid command.
 * @ENCLAVE_START:		Start an enclave, after setting its resources.
 * @ENCLAVE_GET_SLOT:		Get the slot uid of an enclave.
 * @ENCLAVE_STOP:		Terminate an enclave.
 * @SLOT_ALLOC :		Allocate a slot for an enclave.
 * @SLOT_FREE:			Free the slot allocated for an enclave
 * @SLOT_ADD_MEM:		Add a memory region to an enclave slot.
 * @SLOT_ADD_VCPU:		Add a vCPU to an enclave slot.
 * @SLOT_COUNT :		Get the number of allocated slots.
 * @NEXT_SLOT:			Get the next slot in the list of allocated slots.
 * @SLOT_INFO:			Get the info for a slot e.g. slot uid, vCPUs count.
 * @SLOT_ADD_BULK_VCPUS:	Add a number of vCPUs, not providing CPU ids.
 * @SLOT_VCPU_TIME:		Query the Parent-PID-visibility per-vCPU
 *				time-counter array location inside the shared
 *				info page for a running enclave slot. Reply
 *				carries vcpu_time.vcpu_time_offset (byte
 *				offset) and vcpu_time.vcpu_time_count (number
 *				of u64 entries) on struct ne_pci_dev_cmd_reply.
 *				A reply with vcpu_time_count == 0 means the
 *				feature is unavailable for this slot (e.g.
 *				slot was not allocated with CPU_ACCOUNTING).
 * @SM_CLAIM_FROM_PARENT:
 *				Parent guest userspace asks the hypervisor to
 *				remove a PCI device from the parent's PCI
 *				topology and move it to the hypervisor's free
 *				pool.
 *				Triggered by writing the device SBDF to
 *				/sys/class/misc/nitro_enclaves/device_pool/claim.
 *				Payload: struct sm_claim_from_parent_req.
 * @SM_RELEASE_TO_PARENT:
 *				Inverse of CLAIM. Moves a device from that
 *				free pool back into the parent's PCI
 *				topology. Triggered by writing the device
 *				SBDF to pool/release. Payload: struct
 *				sm_release_to_parent_req.
 * @MAX_CMD:			A gatekeeper for max possible command type.
 */
enum ne_pci_dev_cmd_type {
	INVALID_CMD		= 0,
	ENCLAVE_START		= 1,
	ENCLAVE_GET_SLOT	= 2,
	ENCLAVE_STOP		= 3,
	SLOT_ALLOC		= 4,
	SLOT_FREE		= 5,
	SLOT_ADD_MEM		= 6,
	SLOT_ADD_VCPU		= 7,
	SLOT_ADD_INFO_PAGE	= 13,
	SLOT_COUNT		= 8,
	NEXT_SLOT		= 9,
	SLOT_INFO		= 10,
	SLOT_ADD_BULK_VCPUS	= 11,
	SLOT_ADD_DEVICE		= 14,
	PCIE_SLOT_DONATE	= 16,
	PCIE_SLOT_SHUTDOWN	= 17,
	SLOT_VCPU_TIME		= 18,
	SM_CLAIM_FROM_PARENT	= 21,
	SM_RELEASE_TO_PARENT	= 22,
	SLOT_UPDATE_DEVICE_CONFIG = 24,
	PCIE_BASE_DONATE	= 25,
	SYSTEM_RAM_DONATE	= 26,
	GET_SLOT_LIMITS		= 27,
	MAX_CMD			= 28,
};

/**
 * struct pcie_slot_donate_req - PCIE_SLOT_DONATE request.
 * @parent_gpa:	Parent-GPA of a 2 MiB-aligned hugepage donated to the
 *		hypervisor for pcie_slot_entry storage.
 */
struct pcie_slot_donate_req {
	u64	parent_gpa;
};

/**
 * struct system_ram_donate_req - SYSTEM_RAM_DONATE request.
 * @parent_gpa:	Parent-GPA of a 128 MiB-aligned, 128 MiB span donated into
 *		the hypervisor's host-Linux pool to back enclave VMM RSS.
 * @size:	Donation span in bytes (SZ_128M).
 */
struct system_ram_donate_req {
	u64	parent_gpa;
	u64	size;
};

/**
 * struct pcie_slot_shutdown_req - PCIE_SLOT_SHUTDOWN request.
 * @unused:	Payload must be at least one byte.
 */
struct pcie_slot_shutdown_req {
	u8	unused;
};

/**
 * struct sm_claim_from_parent_req - SM_CLAIM_FROM_PARENT request.
 *
 * Mirrors the device-side claim request. Sent when parent guest userspace
 * writes a device SBDF to /sys/class/misc/nitro_enclaves/device_pool/claim.
 * The SBDF identifies the guest-facing PCI location of the device to remove
 * from the parent's PCI topology and move to the hypervisor's free pool.
 *
 * @parent_guest_sbdf:	16-bit packed SBDF: (bus << 8) | (dev << 3) | fn.
 * @reserved:		Must be zero on the wire.
 * @flags:		Reserved for forward compatibility; must be zero.
 */
struct sm_claim_from_parent_req {
	u16	parent_guest_sbdf;
	u16	reserved;
	u32	flags;
};

/**
 * struct sm_release_to_parent_req - SM_RELEASE_TO_PARENT request.
 *
 * Mirrors the device-side release request. Sent when parent guest userspace
 * writes a device SBDF to /sys/class/misc/nitro_enclaves/device_pool/release
 * to move a pooled device back into the parent's PCI topology.
 *
 * @parent_guest_sbdf:	16-bit packed SBDF matching a prior CLAIM.
 * @reserved:		Must be zero on the wire.
 * @flags:		Reserved for forward compatibility; must be zero.
 */
struct sm_release_to_parent_req {
	u16	parent_guest_sbdf;
	u16	reserved;
	u32	flags;
};

/**
 * DOC: Device commands - payload structure for requests and replies.
 */

/**
 * struct enclave_start_req - ENCLAVE_START request.
 * @slot_uid:		Slot unique id mapped to the enclave to start.
 * @enclave_cid:	Context ID (CID) for the enclave vsock device.
 *			If 0, CID is autogenerated.
 * @flags:		Flags for the enclave to start with (DEBUG only;
 *			other flags travel with SLOT_ALLOC).  u64 matches
 *			the upstream NE_START_ENCLAVE UAPI.
 */
struct enclave_start_req {
	u64	slot_uid;
	u64	enclave_cid;
	u64	flags;
};

/**
 * struct enclave_get_slot_req - ENCLAVE_GET_SLOT request.
 * @enclave_cid:	Context ID (CID) for the enclave vsock device.
 */
struct enclave_get_slot_req {
	u64	enclave_cid;
};

/**
 * struct enclave_stop_req - ENCLAVE_STOP request.
 * @slot_uid:	Slot unique id mapped to the enclave to stop.
 */
struct enclave_stop_req {
	u64	slot_uid;
};

/**
 * struct slot_alloc_req - SLOT_ALLOC request.
 * @payload_version:	Wire version discriminator at offset 0.
 *			0 = legacy (this byte only; caller is the stock
 *			    upstream NE driver or the Windows awsenclv
 *			    driver, both of which write a single u8 = 0).
 *			    @reserved and @flags are absent / stale on the
 *			    wire and MUST NOT be consulted.
 *			1 = v1: @reserved and @flags are valid.
 * @reserved:		Reserved bytes at offsets 1..3. MBZ when
 *			@payload_version >= 1.  Cover the gap between
 *			@payload_version and the naturally-aligned u32
 *			@flags; v1 producers must write 0 so future
 *			version bumps can assign meaning without
 *			colliding with stale data.
 * @flags:		Launch-time flag word recorded at allocation. Valid
 *			iff @payload_version >= 1.  u32 matches
 *			slot_common::flags (pmem) and the flags fields of the
 *			device-side start and reply structures: full flag
 *			plumbing is u32 end-to-end with no
 *			narrowing casts.  Today only the low 16 bits are used
 *			(the device's launch-flag bits), bits [31:16] are
 *			reserved for future growth (overcommit knobs,
 *			pass-through, etc.).  Carries every launch-flag bit
 *			the device defines EXCEPT DEBUG (which stays with
 *			START_ENCLAVE).  The device consults this word for
 *			PCIE-vs-legacy routing (matched bits or DIRECT route
 *			to the donated PCIE slot pool) and for the
 *			EIF-matching / validation checks at START_ENCLAVE.
 *
 * Wire layout compatibility: NE_SEND_DATA in BAR0 is a 240-byte window the
 * hypervisor does NOT clear between commands.  Producers write exactly the
 * bytes they own; trailing bytes retain whatever the previous command left
 * there.  Byte 0 of the window is guaranteed zero across every known
 * legacy producer (stock Linux wrote `u8 unused = 0`; Windows awsenclv
 * v1.0.1.2 writes exactly one zero byte), which is why @payload_version
 * lives at offset 0 and means "legacy" when 0.
 *
 * Total wire size is 8 bytes.  @flags is naturally aligned at offset 4 so
 * a single 32-bit load on the device side covers it.
 */
struct slot_alloc_req {
	u8	payload_version;
	u8	reserved[3];
	u32	flags;
};

/**
 * struct slot_free_req - SLOT_FREE request.
 * @slot_uid:	Slot unique id mapped to the slot to free.
 */
struct slot_free_req {
	u64	slot_uid;
};

/* TODO: Add flags field to the request to add memory region. */
/**
 * struct slot_add_mem_req - SLOT_ADD_MEM request.
 * @slot_uid:	Slot unique id mapped to the slot to add the memory region to.
 * @paddr:	Physical address of the memory region to add to the slot.
 * @size:	Memory size, in bytes, of the memory region to add to the slot.
 */
struct slot_add_mem_req {
	u64	slot_uid;
	u64	paddr;
	u64	size;
};

/**
 * struct slot_add_vcpu_req - SLOT_ADD_VCPU request.
 * @slot_uid:	Slot unique id mapped to the slot to add the vCPU to.
 * @vcpu_id:	vCPU ID of the CPU to add to the enclave.
 * @padding:	Padding for the overall data structure.
 */
struct slot_add_vcpu_req {
	u64	slot_uid;
	u32	vcpu_id;
	u8	padding[4];
};

/**
 * struct slot_count_req - SLOT_COUNT request.
 * @unused:	In order to avoid weird sizeof edge cases.
 */
struct slot_count_req {
	u8	unused;
};

/**
 * struct next_slot_req - NEXT_SLOT request.
 * @slot_uid:	Slot unique id of the next slot in the iteration.
 */
struct next_slot_req {
	u64	slot_uid;
};

/**
 * struct slot_info_req - SLOT_INFO request.
 * @slot_uid:	Slot unique id mapped to the slot to get information about.
 */
struct slot_info_req {
	u64	slot_uid;
};

/**
 * struct slot_add_bulk_vcpus_req - SLOT_ADD_BULK_VCPUS request.
 * @slot_uid:	Slot unique id mapped to the slot to add vCPUs to.
 * @nr_vcpus:	Number of vCPUs to add to the slot.
 */
struct slot_add_bulk_vcpus_req {
	u64	slot_uid;
	u64	nr_vcpus;
};

struct slot_add_info_page_req {
	u64	slot_uid;
	u64	flags;
	u64	info_phys;
	u64	info_size;
};

/**
 * struct slot_vcpu_time_req - SLOT_VCPU_TIME request.
 * @slot_uid:	Slot unique id mapped to a running enclave whose
 *		Parent-PID-visibility per-vCPU counter-array location is
 *		being queried.
 *
 * Reply carries the location in the shared struct ne_pci_dev_cmd_reply
 * via the vcpu_time arm:
 *   vcpu_time.vcpu_time_offset - byte offset of the u64 counter array
 *                                inside the info page registered with
 *                                SLOT_ADD_INFO_PAGE
 *   vcpu_time.vcpu_time_count  - number of u64 entries in that array
 *
 * A reply with vcpu_time_count == 0 means the feature is not available
 * for this slot (e.g. enclave was not started with
 * NE_ENCLAVE_CPU_ACCOUNTING_MODE, or the hypervisor doesn't support it).
 */
struct slot_vcpu_time_req {
	u64	slot_uid;
};

/*
 * Maximum number of VQs whose wiring fits in the 72-byte vq_info window
 * of the SLOT_ADD_DEVICE reply buffer (offsets 16..87 inclusive on the
 * hypervisor side).  Mirror of the device's own reply-window limit; must
 * stay in sync.
 *
 * Per-VQ wiring uses 4 u16 slots (msix_vector, notify_index, msix_entry,
 * bar4_doorbell_offset).  4 * u16 * 9 = 72 bytes of VQ wiring; the
 * hypervisor parks the per-device info_event_vector at offset 88,
 * immediately past the last in-use VQ slot.
 */
#define NE_MAX_VQS_IN_ADD_DEVICE_REPLY	9

struct slot_backing_range {
	u64	phys_addr;
	u64	size;
};

#define SLOT_MAX_BACKING_RANGES	4
#define NE_MAX_SHM_REGIONS	16

/* Packing constants for slot_backing_range.size: top 8 bits = SHM ID */
#define NE_RANGE_SIZE_MASK	GENMASK_ULL(55, 0)
#define NE_RANGE_SHMID_SHIFT	56

struct slot_vq_info {
	u16	msix_vector;
	u16	notify_index;
	u16	msix_entry;
	u16	bar4_doorbell_offset;
};
static_assert(sizeof(struct slot_vq_info) == 8,
	      "slot_vq_info wire size must stay 8 bytes");

/* Compact version that fits in PCI command buffer (240 bytes) */
struct slot_add_device_req {
	u64	slot_uid;
	u32	device_type;
	u32	num_vqs;
	u8	device_features[64];
	u32	config_size;
	u32	num_backing_ranges;
	u8	device_config[64];
	struct slot_backing_range backing_ranges[SLOT_MAX_BACKING_RANGES];
} __packed;

/* SLOT_UPDATE_DEVICE_CONFIG request: fits in PCI command buffer (240 bytes) */
struct slot_update_device_config_req {
	u64	slot_uid;
	u64	device_uid;
	u32	config_size;
	u32	config_offset;
	u8	config_data[64];
} __packed;

static_assert(sizeof(struct slot_update_device_config_req) <= NE_SEND_DATA_SIZE,
	      "slot_update_device_config_req must fit in PCI command buffer");

/**
 * struct ne_pci_dev_cmd_reply - Reply payload returned by the Nitro
 *	Enclaves device for every command issued through ne_do_request().
 *
 * Per-command tagged union. @rc is the return code of the command and
 * is valid for every command. The remaining 64 bytes are an anonymous
 * union of per-command arms: each command writes through the arm
 * matching its request type, and the caller reads through the same
 * arm.
 *
 * Legacy arms (commands that exist in the upstream NE driver) preserve
 * the upstream byte offsets for their fields so that an NE driver
 * without the PCIE-enclave arms, mapping the reply as a single flat
 * struct, still reads correct values.
 *
 * The PCIE-enclave arms (@add_device, @vcpu_time) are not bound by
 * upstream layout and place their fields starting from union offset 0
 * (struct offset 8).
 *
 * Variable-length data (per-VQ wire metadata for SLOT_ADD_DEVICE,
 * per-vCPU counter arrays for SLOT_VCPU_TIME) is published on the
 * shared info page by the Nitro Enclaves device. The reply only
 * carries (offset, count) into the info page.
 *
 * @rc:		Return code of the logic that processed the request.
 * @padding0:	Padding for the overall data structure.
 * @start.slot_uid:	ENCLAVE_START. Slot whose enclave was started.
 * @start.enclave_cid:	ENCLAVE_START. Context ID assigned to the enclave.
 * @alloc.slot_uid:	SLOT_ALLOC. Slot unique id of the new slot.
 * @alloc.mem_regions:	SLOT_ALLOC. Maximum number of memory regions
 *			allowed on this slot.
 * @count.slot_count:	SLOT_COUNT. Number of slots currently allocated.
 * @info.slot_uid:	SLOT_INFO. Slot unique id queried.
 * @info.enclave_cid:	SLOT_INFO. Context ID assigned to the enclave.
 * @info.mem_regions:	SLOT_INFO. Maximum number of memory regions
 *			allowed on this slot.
 * @info.mem_size:	SLOT_INFO. Total memory size added to the slot.
 * @info.nr_vcpus:	SLOT_INFO. Number of vCPUs added to the slot.
 * @info.flags:		SLOT_INFO. Slot flags recorded at SLOT_ALLOC.
 * @info.state:		SLOT_INFO. Slot state.
 * @info.padding1:	SLOT_INFO. Padding for natural alignment.
 * @ack.slot_uid:	Slot unique id echo for the slot_uid-only commands
 *			(SLOT_FREE, SLOT_ADD_MEM, SLOT_ADD_VCPU,
 *			SLOT_ADD_BULK_VCPUS, ENCLAVE_GET_SLOT,
 *			ENCLAVE_STOP, NEXT_SLOT, SLOT_ADD_INFO_PAGE,
 *			PCIE_SLOT_DONATE, PCIE_SLOT_SHUTDOWN).
 * @add_device.device_uid:	SLOT_ADD_DEVICE. Device unique id assigned
 *				by the Nitro Hypervisor.
 * @add_device.num_vqs:		SLOT_ADD_DEVICE. Number of per-VQ wire
 *				entries published on the info page; matches
 *				the num_vqs requested.
 * @add_device.reserved:	SLOT_ADD_DEVICE. Writer zero, reader
 *				ignore. Reserved for a future flag word.
 * @add_device.vq_info_offset:	SLOT_ADD_DEVICE. Byte offset into the
 *				info page at which @num_vqs entries of
 *				struct slot_vq_info wire shape start.
 * @vcpu_time.slot_uid:		SLOT_VCPU_TIME. Slot queried.
 * @vcpu_time.vcpu_time_offset:	SLOT_VCPU_TIME. Byte offset inside the
 *				shared info page at which the
 *				Parent-PID-visibility per-vCPU u64
 *				counter array starts.
 * @vcpu_time.vcpu_time_count:	SLOT_VCPU_TIME. Number of u64 entries in
 *				the counter array above. Zero count means
 *				the feature is not available for this
 *				slot.
 *
 * Total reply size: 72 bytes. Both @ne_pci_dev_cmd_reply (this
 * driver) and the corresponding reply struct on the Nitro Enclaves
 * device side share this byte-for-byte layout: the wire ABI MUST
 * stay in lockstep.
 */
struct ne_pci_dev_cmd_reply {
	s32	rc;
	u8	padding0[4];
	union {
		/* === Legacy arms: upstream byte offsets preserved === */
		struct {
			u64	slot_uid;	/* @ 8  */
			u64	enclave_cid;	/* @ 16 */
		} start;
		struct {
			u64	slot_uid;	/* @ 8  */
			u64	_reserved16;	/* @ 16 (upstream enclave_cid slot) */
			u64	_reserved24;	/* @ 24 (upstream slot_count slot)  */
			u64	mem_regions;	/* @ 32 */
		} alloc;
		struct {
			u64	_reserved8;	/* @ 8  (upstream slot_uid slot)    */
			u64	_reserved16;	/* @ 16 (upstream enclave_cid slot) */
			u64	slot_count;	/* @ 24 */
		} count;
		struct {
			u64	slot_uid;	/* @ 8  */
			u64	enclave_cid;	/* @ 16 */
			u64	_reserved24;	/* @ 24 (upstream slot_count slot) */
			u64	mem_regions;	/* @ 32 */
			u64	mem_size;	/* @ 40 */
			u64	nr_vcpus;	/* @ 48 */
			u64	flags;		/* @ 56 */
			u16	state;		/* @ 64 */
			u8	padding1[6];	/* @ 66 */
		} info;
		struct {
			u64	slot_uid;	/* @ 8 */
		} ack;

		/* === PCIE-enclave arms: fields from struct offset 8 === */
		struct {
			u64	device_uid;		/* @ 8  */
			u32	num_vqs;		/* @ 16 */
			u16	info_event_vector;	/* @ 20 */
			u16	reserved;		/* @ 22: writer 0, reader ignore */
			u64	vq_info_offset;		/* @ 24 */
		} add_device;
		struct {
			u64	slot_uid;		/* @ 8  */
			u64	vcpu_time_offset;	/* @ 16 */
			u64	vcpu_time_count;	/* @ 24 */
		} vcpu_time;
		struct {
			u16	pcie_current_limit;	/* @ 8  */
			u16	system_ram_current_slots; /* @ 10 */
			u16	slots_per_donation;	/* @ 12 */
			u16	reserved;		/* @ 14 */
		} slot_limits;

		/*
		 * SYSTEM_RAM_DONATE. The device reports the parent-GPA
		 * window it consumed out of the larger span we provided,
		 * so we free the unused remainder back to CMA and track
		 * only the donated block. consumed_size is 0 when the
		 * device reported no window (failed donation or an older
		 * hypervisor); we then hold the full span.
		 */
		struct {
			u64	consumed_gpa;	/* @ 8  */
			u64	consumed_size;	/* @ 16 */
		} system_ram_donate;
	};
};
static_assert(sizeof(struct ne_pci_dev_cmd_reply) == 72,
	      "ne_pci_dev_cmd_reply wire size must stay 72 bytes");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, rc)                       == 0,
	      "rc @ 0");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, start.slot_uid)           == 8,
	      "start.slot_uid @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, start.enclave_cid)        == 16,
	      "start.enclave_cid @ 16");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, alloc.slot_uid)           == 8,
	      "alloc.slot_uid @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, alloc.mem_regions)        == 32,
	      "alloc.mem_regions @ 32");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, count.slot_count)         == 24,
	      "count.slot_count @ 24");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.slot_uid)            == 8,
	      "info.slot_uid @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.enclave_cid)         == 16,
	      "info.enclave_cid @ 16");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.mem_regions)         == 32,
	      "info.mem_regions @ 32");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.mem_size)            == 40,
	      "info.mem_size @ 40");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.nr_vcpus)            == 48,
	      "info.nr_vcpus @ 48");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.flags)               == 56,
	      "info.flags @ 56");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, info.state)               == 64,
	      "info.state @ 64");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, ack.slot_uid)             == 8,
	      "ack.slot_uid @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, add_device.device_uid)    == 8,
	      "add_device.device_uid @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, add_device.info_event_vector) == 20,
	      "add_device.info_event_vector @ 20");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, add_device.num_vqs)       == 16,
	      "add_device.num_vqs @ 16");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, add_device.vq_info_offset) == 24,
	      "add_device.vq_info_offset @ 24");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, vcpu_time.slot_uid)         == 8,
	      "vcpu_time.slot_uid @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, vcpu_time.vcpu_time_offset) == 16,
	      "vcpu_time.vcpu_time_offset @ 16");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, vcpu_time.vcpu_time_count)  == 24,
	      "vcpu_time.vcpu_time_count @ 24");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, slot_limits.pcie_current_limit) == 8,
	      "slot_limits.pcie_current_limit @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, system_ram_donate.consumed_gpa) == 8,
	      "system_ram_donate.consumed_gpa @ 8");
static_assert(offsetof(struct ne_pci_dev_cmd_reply, system_ram_donate.consumed_size) == 16,
	      "system_ram_donate.consumed_size @ 16");

/**
 * struct ne_pci_dev - Nitro Enclaves (NE) PCI device.
 * @cmd_reply_avail:		Variable set if a reply has been sent by the
 *				PCI device.
 * @cmd_reply_wait_q:		Wait queue for handling command reply from the
 *				PCI device.
 * @enclaves_list:		List of the enclaves managed by the PCI device.
 * @enclaves_list_mutex:	Mutex for accessing the list of enclaves.
 * @event_wq:			Work queue for handling out-of-band events
 *				triggered by the Nitro Hypervisor which require
 *				enclave state scanning and propagation to the
 *				enclave process.
 * @iomem_base :		MMIO region of the PCI device.
 * @notify_work:		Work item for every received out-of-band event.
 * @pci_dev_mutex:		Mutex for accessing the PCI device MMIO space.
 * @pdev:			PCI device data structure.
 */
#define NE_NOTIFY_BAR		(0x04)
#define NE_MAX_IOEVENTFDS	256

/*
 * IRQ multiplexer registers (mirrors of the device-side register block
 * at the same offsets). The driver uses these to read the pooled-vector
 * geometry at probe and to donate bitmap pages.
 */
#define NE_VQ_VECTOR_BASE		(0x0008)	/* u16 RO */
#define NE_SUPPORTED_FLAGS		(0x01FC)	/* u32 RO */
#define NE_MUX_NUM_VECTORS		(0x01F0)	/* u16 RO */
#define NE_MUX_DONATE_ERR		(0x01F4)	/* u16 RO (r-to-clear) */
#define NE_MUX_SHUTDOWN			(0x01F8)	/* u32 WO */
#define NE_MUX_DONATE_BASE		(0x0800)	/* u64 RW[N] */

/* Hypervisor-enforced PCIE slot cap (read-only). */
#define NE_REG_MAX_PCIE_SLOTS		(0x01F2)	/* u16 RO */

/*
 * Explicit donation-math protocol. The hypervisor advertises the
 * required donation granularity and the current slot ceiling; the
 * driver loops allocating chunks of GROW_GRANULARITY_SIZE and
 * donating them until CURRENT_LIMIT reaches MAX_PCIE_SLOTS.
 */
#define NE_REG_PCIE_SLOT_CURRENT_LIMIT		(0x01F6)	/* u16 RO */
#define NE_REG_PCIE_SLOT_GROW_GRANULARITY_SIZE	(0x0200)	/* u32 RO */
#define NE_REG_PCIE_SLOT_GROW_GRANULARITY_ALIGN	(0x0204)	/* u32 RO */

/* Size of the base-donation scratch page the parent must donate (via
 * PCIE_BASE_DONATE) before any PCIE slot is usable. */
#define NE_REG_PCIE_BASE_DONATION_SIZE		(0x0208)	/* u32 RO */
#define NE_REG_NIE_ENABLED			(0x0210)	/* u32 RO */
#define NE_REG_NIE_PAGES_NEEDED			(0x0214)	/* u32 RO */

/* Max pool size bounded by BAR0 layout; actual Nmux read at probe. */
#define NE_MUX_MAX_VECTORS		256

/* Per pooled-vector mux state (one bitmap page per vector). */
struct ne_mux_vec {
	struct ne_pci_dev	*ne_pci_dev;
	u64			*bitmap;	/* PAGE-sized, WB memory; points
						 * into ne_pci_dev->mux_bitmap_base
						 * and is not separately freed */
	bool			irq_installed;	/* request_irq() succeeded, so
						 * teardown must free_irq(). Not
						 * inferable from @bitmap, which
						 * is non-NULL for every vector
						 * as soon as the shared block is
						 * allocated */
	u32			v_rel;		/* index 0..Nmux */
	u32			max_bit;	/* high-water for bounded scan */
	atomic64_t		ints;		/* MSI-X handler invocations */
	atomic64_t		dispatches;	/* bits dispatched (total) */
};

/* Per-VQ binding stored in kick_xa (keyed on vq_id). */
struct ne_mux_binding {
	struct eventfd_ctx	*ctx;
	atomic64_t		kicks;
	/* Freed via call_rcu() so ne_mux_handler() (which dereferences the
	 * binding pointer returned by xa_load() after its internal rcu
	 * read-side has already been released) cannot observe a stale or
	 * reused object.  Readers must bracket the binding use with
	 * rcu_read_lock()/rcu_read_unlock() for this to be effective. */
	struct rcu_head		rcu;
};

struct ne_ioeventfd {
	struct list_head	list;		/* entry in ne_enclave::ioeventfds */
	struct eventfd_ctx	*ctx;
	wait_queue_head_t	*wqh;
	wait_queue_entry_t	wait;
	poll_table		pt_storage;
	/* Points to the shared PCI device; outlives every enclave. */
	struct ne_pci_dev	*ne_pci_dev;
	u16			notify_offset;
	bool			active;
};

/*
 * Memory-pool donation policy (exposed via the pcie_slots sysfs).
 * Baseline NE_MEM_SLOTS_FREE_BASE slots need no memory donation;
 * each donated 128 MiB chunk adds NE_MEM_SLOTS_PER_CHUNK to the limit.
 */
#define NE_MEM_SLOTS_FREE_BASE		4u
#define NE_MEM_SLOTS_PER_CHUNK		10u
#define NE_MEM_DONATE_MAX_CHUNKS	128u

/**
 * struct ne_mem_donation - One 128 MiB memory-pool donation.
 * @alloc_page:		Base of the tracked contiguous region: the donated
 *			128 MiB block once the device reports the consumed
 *			window, or the full over-allocation on fallback.
 * @cma:		CMA region the allocation came from.
 * @alloc_nr_pages:	Size of the tracked region in pages (128 MiB once
 *			the unused remainder has been freed back to CMA).
 * @donated_gpa:	128 MiB-aligned parent-GPA window actually donated.
 *
 * CMA only guarantees 2 MiB base alignment, but the host add_memory path
 * needs 128 MiB alignment. We over-allocate a 256 MiB span; the device
 * consumes a 128 MiB-aligned 128 MiB window and reports it back, and we
 * free the unused head and tail to CMA, tracking only the donated block.
 */
struct ne_mem_donation {
	struct page	*alloc_page;
	struct cma	*cma;
	unsigned long	alloc_nr_pages;
	u64		donated_gpa;
};

struct ne_pci_dev {
	atomic_t		cmd_reply_avail;
	wait_queue_head_t	cmd_reply_wait_q;
	struct list_head	enclaves_list;
	struct mutex		enclaves_list_mutex;
	struct workqueue_struct	*event_wq;
	void __iomem		*iomem_base;
	void __iomem		*notify_base;	/* BAR4 notify window */
	resource_size_t		notify_len;	/* BAR4 length cached at probe */
	struct work_struct	notify_work;
	struct mutex		pci_dev_mutex;
	struct pci_dev		*pdev;
	struct dentry		*debugfs_root;
	/* IRQ multiplexer: one bitmap page per pooled vector, pooled
	 * vectors = [base_vector .. base_vector + nmux). kick_xa maps
	 * vq_id -> struct ne_mux_binding *, populated by
	 * NE_SET_VRING_KICK; probe only sets up the pool itself. */
	struct ne_mux_vec	*mux;
	u32			nmux;
	u32			base_vector;
	struct xarray		kick_xa;
	struct notifier_block	shutdown_nb;

	/* Backing store for every mux bitmap: one physically contiguous,
	 * 2 MiB-aligned block carved into @nmux per-vector pages. Allocated as
	 * one block, rather than a page at a time, so that under NIE the whole
	 * span, and nothing else, can be handed to the hypervisor with a
	 * single Guest.Share. The hypervisor has to be able to *write* these
	 * pages to post kick bits, and Guest.Share works in 2 MiB units, so
	 * page-at-a-time allocations would have forced us to share whatever
	 * unrelated kernel data shared their 2 MiB. @mux_bitmap_shared records
	 * whether that share is live, so teardown knows to revoke it. */
	void			*mux_bitmap_base;
	size_t			mux_bitmap_size;
	unsigned int		mux_bitmap_order;
	bool			mux_bitmap_shared;

	/* PCIE slot-metadata donation: CMA pages donated to the hypervisor
	 * lazily (on NE_CREATE_VM ENOSPC) for pcie_slot_entry storage, plus
	 * the NIE metadata pool donated eagerly at probe. Held until parent
	 * kexec. The two tracking arrays are sized dynamically at probe:
	 * a NIE parent needs nie_pages_needed (thousands of 2 MiB pages on
	 * real Graviton) for the metadata pool, far more than the old fixed
	 * [32] could hold. pcie_slot_pages_cap is the allocated entry count. */
	u16			max_pcie_slots;
	u32			pcie_slot_gran_size;
	struct page		**pcie_slot_pages;
	struct cma		**pcie_slot_cmas;
	u32			pcie_slot_pages_cap;
	u32			pcie_slot_nr_donated;

	/* Base-donation scratch page (the "base PCIe tax"): backs the
	 * hypervisor-private IOMMU sink that gates PCIE slot usage. Donated
	 * once before any slot page; held until parent kexec. */
	struct page		*pcie_base_page;
	struct cma		*pcie_base_cma;

	/* Memory-pool donation (sysfs pcie_slots): 128 MiB chunks donated
	 * into the device's memory pool. Each chunk raises the limit by
	 * NE_MEM_SLOTS_PER_CHUNK on top of the NE_MEM_SLOTS_FREE_BASE
	 * baseline. The unused remainder of each over-allocation is freed
	 * back to CMA immediately; the donated block is held until parent
	 * kexec. Serialized by enclaves_list_mutex. */
	struct ne_mem_donation	mem_donations[NE_MEM_DONATE_MAX_CHUNKS];
	u32			mem_donate_nr;

	/* Per-enclave PCIe virtio device cap, read from NE_MAX_PCIE_DEVICES
	 * at probe time. */
	u16			max_pcie_devices;

	/* NIE detected at probe. */
	bool			nie_enabled;

	/* NIE Guest.Share/Guest.Unshare backend, resolved once from
	 * @nie_enabled at probe, or NULL when there is nothing to share with.
	 * Every consumer (the mux bitmaps here, and each enclave, which takes
	 * its own copy) reads it from here rather than deciding again. */
	const struct ne_mem_sharing_ops *sharing_ops;

	/* Number of PCIE slot pages needed for NIE metadata. */
	u32			nie_pages_needed;
};

/**
 * ne_do_request() - Submit command request to the PCI device based on the command
 *		     type and retrieve the associated reply.
 * @pdev:		PCI device to send the command to and receive the reply from.
 * @cmd_type:		Command type of the request sent to the PCI device.
 * @cmd_request:	Command request payload.
 * @cmd_request_size:	Size of the command request payload.
 * @cmd_reply:		Command reply payload.
 * @cmd_reply_size:	Size of the command reply payload.
 *
 * Context: Process context. This function uses the ne_pci_dev mutex to handle
 *	    one command at a time.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
int ne_do_request(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
		  void *cmd_request, size_t cmd_request_size,
		  struct ne_pci_dev_cmd_reply *cmd_reply,
		  size_t cmd_reply_size);

/**
 * ne_do_request_retry() - Submit a command request to the PCI device and
 *			   transparently retry on -EAGAIN until the Slot
 *			   Manager reaches a stable state.
 * @pdev:		PCI device to send the command to and receive the reply from.
 * @cmd_type:		Command type of the request sent to the PCI device.
 * @cmd_request:	Command request payload.
 * @cmd_request_size:	Size of the command request payload.
 * @cmd_reply:		Command reply payload.
 * @cmd_reply_size:	Size of the command reply payload.
 *
 * The device returns -EAGAIN as a transient backpressure signal
 * for certain commands when the addressed slot is in a scrubbing/stopping
 * state, when an asynchronous donation/shutdown batch is in flight, or
 * when a request overlaps a deferred-reply command already holding the
 * device's single-flight command slot.  The contract is "retry me"; this
 * wrapper does so with a 1-2 ms sleep between attempts.  The retry is
 * bounded by wall clock (NE_RETRY_BUDGET_MSECS, sized to cover the longest
 * deferred-reply holder, the 30 s PCIE ENCLAVE_START) so a hypervisor
 * defect that never clears the transient cannot leave a caller contending
 * for pci_dev_mutex indefinitely.
 *
 * The overlap gate can return -EAGAIN to any guest-driven command, and the
 * serialization gate can return -EAGAIN to every command while a live
 * update or live migration is serializing state.  This wrapper is
 * therefore the default entry point for all command submission from
 * process context.  The bare ne_do_request() is used only where a bounded
 * retry is inappropriate (the reboot notifier's PCIE_SLOT_SHUTDOWN, whose
 * caller ignores rc and must not delay kexec).
 *
 * Context: Process context.  Calls usleep_range() so the caller MUST NOT
 *	    hold a spinlock or be in an atomic context.
 * Return:
 * * 0 on success.
 * * -ERESTARTSYS if a fatal signal is pending on the caller.
 * * -EAGAIN if the retry budget was exhausted (still transient at the device).
 * * Negative return value on other failure.
 */
int ne_do_request_retry(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
			void *cmd_request, size_t cmd_request_size,
			struct ne_pci_dev_cmd_reply *cmd_reply,
			size_t cmd_reply_size);

/**
 * ne_mux_binding_free_rcu() - Defer the free of an ne_mux_binding.
 * @b: binding that was just replaced in kick_xa.
 *
 * Must be used instead of kfree() for bindings that may still be
 * visible to ne_mux_handler() via xa_load().  The binding and its
 * eventfd reference are released after a full RCU grace period.
 */
void ne_mux_binding_free_rcu(struct ne_mux_binding *b);

/* Nitro Enclaves (NE) PCI device driver */
extern struct pci_driver ne_pci_driver;

#endif /* _NE_PCI_DEV_H_ */
