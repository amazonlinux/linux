// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

/**
 * DOC: Nitro Enclaves (NE) PCI device driver.
 */

#include <linux/cma.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nitro_enclaves.h>
#include <linux/nodemask.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/reboot.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/xarray.h>

#include "ne_mem_sharing.h"
#include "ne_misc_dev.h"
#include "ne_pci_dev.h"

/**
 * NE_DEFAULT_TIMEOUT_MSECS - Default timeout to wait for a reply from
 *			      the NE PCI device.
 */
#define NE_DEFAULT_TIMEOUT_MSECS	(120000) /* 120 sec */

/**
 * NE_RETRY_BUDGET_MSECS - Wall-clock upper bound on -EAGAIN retries in
 *			   ne_do_request_retry().  Must cover the longest
 *			   window the device may legitimately keep its
 *			   command slot busy: the deferred reply of a PCIE
 *			   ENCLAVE_START is bounded at 30 s.  40 s gives
 *			   ~10 s of margin.
 */
#define NE_RETRY_BUDGET_MSECS		(40000)

/*
 * max_pcie_devices - Per-enclave PCIe virtio device limit, exposed
 * read-only at /sys/module/nitro_enclaves/parameters/max_pcie_devices.
 *
 * Populated at probe time from the hypervisor's NE_MAX_PCIE_DEVICES
 * register; before probe, reads as the legacy default of 8.  The value
 * is the cap a single enclave may attach via NE_ADD_DEVICE.  Userspace
 * VMMs (FC/QEMU/EKS shim) consult this to decide how many devices an
 * enclave is allowed to declare instead of hardcoding the limit.
 *
 * Multi-device hypervisors are not currently supported by the NE
 * driver: a single ne_pci_dev publishes the value for the whole
 * driver instance.
 */
static unsigned int max_pcie_devices = 8;
module_param(max_pcie_devices, uint, 0444);
MODULE_PARM_DESC(max_pcie_devices,
		 "Per-enclave PCIe virtio device limit (read-only, set at probe from hypervisor).");

static const struct pci_device_id ne_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMAZON, PCI_DEVICE_ID_NE) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, ne_pci_ids);

static void ne_free_contig(struct cma *cma, struct page *page,
			   unsigned long nr_pages);

/**
 * ne_submit_request() - Submit command request to the PCI device based on the
 *			 command type.
 * @pdev:		PCI device to send the command to.
 * @cmd_type:		Command type of the request sent to the PCI device.
 * @cmd_request:	Command request payload.
 * @cmd_request_size:	Size of the command request payload.
 *
 * Context: Process context. This function is called with the ne_pci_dev mutex held.
 */
static void ne_submit_request(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
			      void *cmd_request, size_t cmd_request_size)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	memcpy_toio(ne_pci_dev->iomem_base + NE_SEND_DATA, cmd_request, cmd_request_size);

	iowrite32(cmd_type, ne_pci_dev->iomem_base + NE_COMMAND);
}

/**
 * ne_retrieve_reply() - Retrieve reply from the PCI device.
 * @pdev:		PCI device to receive the reply from.
 * @cmd_reply:		Command reply payload.
 * @cmd_reply_size:	Size of the command reply payload.
 *
 * Context: Process context. This function is called with the ne_pci_dev mutex held.
 */
static void ne_retrieve_reply(struct pci_dev *pdev, struct ne_pci_dev_cmd_reply *cmd_reply,
			      size_t cmd_reply_size)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	memcpy_fromio(cmd_reply, ne_pci_dev->iomem_base + NE_RECV_DATA, cmd_reply_size);
}

/**
 * ne_wait_for_reply() - Wait for a reply of a PCI device command.
 * @pdev:	PCI device for which a reply is waited.
 *
 * Context: Process context. This function is called with the ne_pci_dev mutex held.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_wait_for_reply(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	long rc;

	/*
	 * Uninterruptible on purpose.  The request is already written to the
	 * device and there is no way to cancel it, so returning early leaves a
	 * command in flight whose reply nothing is waiting for.  The reply
	 * carries no request id, so once the next command has been submitted
	 * that reply is indistinguishable from its own and is returned as its
	 * result: a healthy enclave failing with an errno belonging to
	 * someone else's command, and for SLOT_FREE a success that makes the
	 * caller drop pins the hypervisor may still hold.
	 *
	 * Waiting here keeps one command in flight at a time, which is what the
	 * single reply window and single cmd_reply_avail flag already assume.
	 * The cost is that a task killed while waiting stays in D state until
	 * the reply or the timeout, and tasks queued on pci_dev_mutex behind it
	 * likewise.  Bounded, and no CPU consumed.
	 *
	 * The timeout still abandons a command, and NE_DEFAULT_TIMEOUT_MSECS is
	 * not a bound the device respects: the device's own longest deferrals
	 * are a 600 s ML-accelerator CLAIM scrub and an ENCLAVE_STOP with no
	 * stated bound at all, so this can fire on a healthy host.  Do not lower
	 * it.  Recovering from that needs the device to stop holding a command
	 * slot indefinitely (it clears cmd_reg only on a reply, never on its
	 * own timeout), which is not something this side can fix.
	 */
	rc = wait_event_timeout(ne_pci_dev->cmd_reply_wait_q,
				atomic_read(&ne_pci_dev->cmd_reply_avail) != 0,
				msecs_to_jiffies(NE_DEFAULT_TIMEOUT_MSECS));
	if (!rc)
		return -ETIMEDOUT;

	return 0;
}

int ne_do_request(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
		  void *cmd_request, size_t cmd_request_size,
		  struct ne_pci_dev_cmd_reply *cmd_reply, size_t cmd_reply_size)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	int rc = -EINVAL;

	if (cmd_type <= INVALID_CMD || cmd_type >= MAX_CMD) {
		dev_err_ratelimited(&pdev->dev, "Invalid cmd type=%u\n", cmd_type);

		return -EINVAL;
	}

	if (!cmd_request) {
		dev_err_ratelimited(&pdev->dev, "Null cmd request for cmd type=%u\n",
				    cmd_type);

		return -EINVAL;
	}

	if (cmd_request_size > NE_SEND_DATA_SIZE) {
		dev_err_ratelimited(&pdev->dev, "Invalid req size=%zu for cmd type=%u\n",
				    cmd_request_size, cmd_type);

		return -EINVAL;
	}

	if (!cmd_reply) {
		dev_err_ratelimited(&pdev->dev, "Null cmd reply for cmd type=%u\n",
				    cmd_type);

		return -EINVAL;
	}

	if (cmd_reply_size > NE_RECV_DATA_SIZE) {
		dev_err_ratelimited(&pdev->dev, "Invalid reply size=%zu for cmd type=%u\n",
				    cmd_reply_size, cmd_type);

		return -EINVAL;
	}

	/*
	 * Use this mutex so that the PCI device handles one command request at
	 * a time.
	 */
	mutex_lock(&ne_pci_dev->pci_dev_mutex);

	atomic_set(&ne_pci_dev->cmd_reply_avail, 0);

	ne_submit_request(pdev, cmd_type, cmd_request, cmd_request_size);

	rc = ne_wait_for_reply(pdev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev, "Error in wait for reply for cmd type=%u [rc=%d]\n",
				    cmd_type, rc);

		goto unlock_mutex;
	}

	ne_retrieve_reply(pdev, cmd_reply, cmd_reply_size);

	atomic_set(&ne_pci_dev->cmd_reply_avail, 0);

	if (cmd_reply->rc < 0) {
		s32 dev_rc = -cmd_reply->rc;

		/*
		 * Shift device error codes into the UAPI range (see
		 * NE_ERR_DEVICE_SHIFT).  Range-limited so plain errnos the
		 * device also returns (-ENOSPC, -EINVAL, -EAGAIN) are untouched.
		 */
		if (dev_rc >= NE_ERR_INVALID_FLAGS - NE_ERR_DEVICE_SHIFT &&
		    dev_rc <= NE_ERR_NO_MEM_SLOTS_ON_NODE - NE_ERR_DEVICE_SHIFT)
			cmd_reply->rc -= NE_ERR_DEVICE_SHIFT;

		rc = cmd_reply->rc;

		if (rc == -ENOSPC) {
			dev_info_ratelimited(&pdev->dev, "not enough resources, this may be expected. cmd type=%u [rc=%d]\n",
					     cmd_type, rc);
		} else if (rc == -NE_ERR_ENCLAVE_LIMIT) {
			dev_info_ratelimited(&pdev->dev, "per-instance PCIE enclave limit reached. cmd type=%u [rc=%d]\n",
					     cmd_type, rc);
		} else {
			dev_err_ratelimited(&pdev->dev, "Error in cmd process logic, cmd type=%u [rc=%d]\n",
					    cmd_type, rc);
		}

		goto unlock_mutex;
	}

	rc = 0;

unlock_mutex:
	mutex_unlock(&ne_pci_dev->pci_dev_mutex);

	return rc;
}

int ne_do_request_retry(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
			void *cmd_request, size_t cmd_request_size,
			struct ne_pci_dev_cmd_reply *cmd_reply,
			size_t cmd_reply_size)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(NE_RETRY_BUDGET_MSECS);
	int rc;

	/*
	 * The device returns -EAGAIN for transient slot states such as
	 * SLOT_RUNNING, SLOT_SCRUBBING, and SLOT_STOPPING, and while an
	 * asynchronous donation/shutdown batch is in flight on the PCIE slot
	 * pool (PCIE_SLOT_DONATE).  It also returns -EAGAIN when a request
	 * overlaps a deferred-reply command, the longest of which is the
	 * synchronous PCIE ENCLAVE_START at up to 30 s.
	 *
	 * Without this retry, a -EAGAIN reply from SLOT_FREE leaves the
	 * enclave slot stuck in SLOT_ZOMBIE forever and the donated PCIE
	 * pool eventually exhausts.
	 *
	 * Bound the retry by wall clock so a hypervisor bug that never
	 * clears the transient state cannot leave this task contending for
	 * pci_dev_mutex once per millisecond indefinitely and delay every
	 * other enclave's ioctl.  Also break out on a fatal signal so a dying
	 * task does not sit here.
	 */
	do {
		rc = ne_do_request(pdev, cmd_type,
				   cmd_request, cmd_request_size,
				   cmd_reply, cmd_reply_size);
		if (rc != -EAGAIN)
			return rc;

		if (fatal_signal_pending(current))
			return -ERESTARTSYS;

		usleep_range(1000, 2000);
	} while (time_before(jiffies, deadline));

	dev_warn_ratelimited(&pdev->dev,
			     "cmd type=%u still -EAGAIN after %u ms, giving up\n",
			     cmd_type, NE_RETRY_BUDGET_MSECS);
	return -EAGAIN;
}

/**
 * ne_reply_handler() - Interrupt handler for retrieving a reply matching a
 *			request sent to the PCI device for enclave lifetime
 *			management.
 * @irq:	Received interrupt for a reply sent by the PCI device.
 * @args:	PCI device private data structure.
 *
 * Context: Interrupt context.
 * Return:
 * * IRQ_HANDLED on handled interrupt.
 */
static irqreturn_t ne_reply_handler(int irq, void *args)
{
	struct ne_pci_dev *ne_pci_dev = (struct ne_pci_dev *)args;

	atomic_set(&ne_pci_dev->cmd_reply_avail, 1);

	wake_up(&ne_pci_dev->cmd_reply_wait_q);

	return IRQ_HANDLED;
}

/**
 * ne_event_work_handler() - Work queue handler for notifying enclaves on a
 *			     state change received by the event interrupt
 *			     handler.
 * @work:	Item containing the NE PCI device for which an out-of-band event
 *		was issued.
 *
 * An out-of-band event is being issued by the Nitro Hypervisor when at least
 * one enclave is changing state without client interaction.
 *
 * Context: Work queue context.
 */
static void ne_event_work_handler(struct work_struct *work)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct ne_enclave *ne_enclave = NULL;
	struct ne_pci_dev *ne_pci_dev =
		container_of(work, struct ne_pci_dev, notify_work);
	struct pci_dev *pdev = ne_pci_dev->pdev;
	int rc = -EINVAL;
	struct slot_info_req slot_info_req = {};

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);

	/*
	 * Iterate over all enclaves registered for the Nitro Enclaves
	 * PCI device and determine for which enclave(s) the out-of-band event
	 * is corresponding to.
	 */
	list_for_each_entry(ne_enclave, &ne_pci_dev->enclaves_list, enclave_list_entry) {
		mutex_lock(&ne_enclave->enclave_info_mutex);

		/*
		 * Enclaves that were never started cannot receive out-of-band
		 * events.
		 */
		if (ne_enclave->state != NE_STATE_RUNNING)
			goto unlock;

		slot_info_req.slot_uid = ne_enclave->slot_uid;

		rc = ne_do_request_retry(pdev, SLOT_INFO,
				   &slot_info_req, sizeof(slot_info_req),
				   &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			dev_err(&pdev->dev, "Error in slot info [rc=%d]\n", rc);
			goto unlock;
		}

		/* Notify enclave process that the enclave state changed. */
		if (ne_enclave->state != cmd_reply.info.state) {
			ne_enclave->state = cmd_reply.info.state;

			ne_enclave->has_event = true;

			wake_up_interruptible(&ne_enclave->eventq);
		}

unlock:
		 mutex_unlock(&ne_enclave->enclave_info_mutex);
	}

	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);
}

/**
 * ne_event_handler() - Interrupt handler for PCI device out-of-band events.
 *			This interrupt does not supply any data in the MMIO
 *			region. It notifies a change in the state of any of
 *			the launched enclaves.
 * @irq:	Received interrupt for an out-of-band event.
 * @args:	PCI device private data structure.
 *
 * Context: Interrupt context.
 * Return:
 * * IRQ_HANDLED on handled interrupt.
 */
static irqreturn_t ne_event_handler(int irq, void *args)
{
	struct ne_pci_dev *ne_pci_dev = (struct ne_pci_dev *)args;

	queue_work(ne_pci_dev->event_wq, &ne_pci_dev->notify_work);

	return IRQ_HANDLED;
}

/**
 * ne_setup_msix() - Setup MSI-X vectors for the PCI device.
 * @pdev:	PCI device to setup the MSI-X for.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_setup_msix(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	int nr_vecs = 0;
	int rc = -EINVAL;

	nr_vecs = pci_msix_vec_count(pdev);
	if (nr_vecs < 0) {
		rc = nr_vecs;

		dev_err(&pdev->dev, "Error in getting vec count [rc=%d]\n", rc);

		return rc;
	}

	rc = pci_alloc_irq_vectors(pdev, nr_vecs, nr_vecs, PCI_IRQ_MSIX);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in alloc MSI-X vecs [rc=%d]\n", rc);

		return rc;
	}

	/*
	 * This IRQ gets triggered every time the PCI device responds to a
	 * command request. The reply is then retrieved, reading from the MMIO
	 * space of the PCI device.
	 */
	rc = request_irq(pci_irq_vector(pdev, NE_VEC_REPLY), ne_reply_handler,
			 IRQF_SHARED, "enclave_cmd", ne_pci_dev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in request irq reply [rc=%d]\n", rc);

		goto free_irq_vectors;
	}

	ne_pci_dev->event_wq = create_singlethread_workqueue("ne_pci_dev_wq");
	if (!ne_pci_dev->event_wq) {
		rc = -ENOMEM;

		dev_err(&pdev->dev, "Cannot get wq for dev events [rc=%d]\n", rc);

		goto free_reply_irq_vec;
	}

	INIT_WORK(&ne_pci_dev->notify_work, ne_event_work_handler);

	/*
	 * This IRQ gets triggered every time any enclave's state changes. Its
	 * handler then scans for the changes and propagates them to the user
	 * space.
	 */
	rc = request_irq(pci_irq_vector(pdev, NE_VEC_EVENT), ne_event_handler,
			 IRQF_SHARED, "enclave_evt", ne_pci_dev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in request irq event [rc=%d]\n", rc);

		goto destroy_wq;
	}

	return 0;

destroy_wq:
	destroy_workqueue(ne_pci_dev->event_wq);
free_reply_irq_vec:
	free_irq(pci_irq_vector(pdev, NE_VEC_REPLY), ne_pci_dev);
free_irq_vectors:
	pci_free_irq_vectors(pdev);

	return rc;
}

/**
 * ne_teardown_msix() - Teardown MSI-X vectors for the PCI device.
 * @pdev:	PCI device to teardown the MSI-X for.
 *
 * Context: Process context.
 */
static void ne_teardown_msix(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	free_irq(pci_irq_vector(pdev, NE_VEC_EVENT), ne_pci_dev);

	flush_work(&ne_pci_dev->notify_work);
	destroy_workqueue(ne_pci_dev->event_wq);

	free_irq(pci_irq_vector(pdev, NE_VEC_REPLY), ne_pci_dev);

	pci_free_irq_vectors(pdev);
}

/**
 * ne_mux_binding_rcu_free() - Deferred free for an ne_mux_binding.
 *
 * The binding is freed only after a full RCU grace period, so any
 * ne_mux_handler() invocation that loaded the pointer via xa_load()
 * before the grace period started is guaranteed to have finished
 * dereferencing it.  Drop the eventfd reference from here as well so
 * readers that call eventfd_signal(b->ctx) cannot race with the put.
 */
static void ne_mux_binding_rcu_free(struct rcu_head *head)
{
	struct ne_mux_binding *b =
		container_of(head, struct ne_mux_binding, rcu);

	eventfd_ctx_put(b->ctx);
	kfree(b);
}

/**
 * ne_mux_handler() - MSI-X handler for a pooled mux vector.
 *
 * Scans the vector's bitmap, clears each set bit, and signals the eventfd
 * bound to the matching vq_id. A vector with no bound vq_id sees an
 * all-zero bitmap and exits without signalling any kick_fd. The high-water
 * mark @max_bit bounds the scan so a fresh driver reads only one u64.
 */
static irqreturn_t ne_mux_handler(int irq, void *data)
{
	struct ne_mux_vec *v = data;
	struct ne_pci_dev *ne_pci_dev = v->ne_pci_dev;
	u32 nwords = READ_ONCE(v->max_bit) / 64 + 1;
	u32 i;
	bool dispatched = false;

	atomic64_inc(&v->ints);

	/*
	 * Protect ne_set_vring_kick()'s replacement path: it uses xa_store()
	 * which returns the old binding, then schedules it for RCU-deferred
	 * free via call_rcu().  xa_load()'s built-in rcu_read_lock() is
	 * released before xa_load() returns, so we must hold our own RCU
	 * read-side across the entire dereference of b to keep the object
	 * alive.  Hard IRQ context is not an implicit RCU reader under
	 * CONFIG_PREEMPT_RCU.
	 */
	rcu_read_lock();
	for (i = 0; i < nwords; i++) {
		u64 w = xchg(&v->bitmap[i], 0);

		while (w) {
			u32 bit_in_word = __ffs64(w);
			u32 bit = i * 64 + bit_in_word;
			u64 vq_id = (u64)bit * ne_pci_dev->nmux + v->v_rel;
			struct ne_mux_binding *b =
				xa_load(&ne_pci_dev->kick_xa, vq_id);

			w &= w - 1;
			if (b) {
				atomic64_inc(&b->kicks);
				atomic64_inc(&v->dispatches);
				eventfd_signal(b->ctx);
				dispatched = true;
			}
		}
	}
	rcu_read_unlock();
	if (!dispatched && atomic64_read(&v->ints) <= 5)
		pr_info("NE: mux_handler v_rel=%u irq=%d nwords=%u max_bit=%u bitmap=0 (no dispatch)\n",
			v->v_rel, irq, nwords, READ_ONCE(v->max_bit));
	return IRQ_HANDLED;
}

static void ne_mux_teardown(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	unsigned long vq_id;
	struct ne_mux_binding *b;
	u32 v;

	if (!ne_pci_dev->mux)
		return;

	/* Ask the hypervisor to drop everything before we free pages. */
	iowrite32(1, ne_pci_dev->iomem_base + NE_MUX_SHUTDOWN);

	for (v = 0; v < ne_pci_dev->nmux; v++) {
		int irq = pci_irq_vector(pdev, ne_pci_dev->base_vector + v);

		if (irq >= 0 && ne_pci_dev->mux[v].irq_installed)
			free_irq(irq, &ne_pci_dev->mux[v]);
		ne_pci_dev->mux[v].irq_installed = false;
		/* Freed as one block below, not per vector. */
		ne_pci_dev->mux[v].bitmap = NULL;
	}

	/*
	 * Revoke the share, then release the block. Both orderings matter.
	 *
	 * The MUX_SHUTDOWN write above told the hypervisor to drop the donation
	 * and the free_irq() loop quiesced the only reader, so by here nothing
	 * is writing kick bits and nothing is scanning for them.
	 *
	 * Guest.Unshare has to come before free_pages(): it is what takes the
	 * pages out of the hypervisor's stage-2 and restores their private page
	 * state, and it can only do that while they are still ours. Freeing
	 * first would hand pages the hypervisor can still write back to the
	 * page allocator, for arbitrary kernel data to land in.
	 */
	if (ne_pci_dev->mux_bitmap_shared) {
		ne_pci_dev->sharing_ops->unshare(NULL,
					virt_to_phys(ne_pci_dev->mux_bitmap_base),
					ne_pci_dev->mux_bitmap_size);
		ne_pci_dev->mux_bitmap_shared = false;
	}

	if (ne_pci_dev->mux_bitmap_base) {
		free_pages((unsigned long)ne_pci_dev->mux_bitmap_base,
			   ne_pci_dev->mux_bitmap_order);
		ne_pci_dev->mux_bitmap_base = NULL;
	}

	kfree(ne_pci_dev->mux);
	ne_pci_dev->mux = NULL;

	xa_for_each(&ne_pci_dev->kick_xa, vq_id, b) {
		xa_erase(&ne_pci_dev->kick_xa, vq_id);
		eventfd_ctx_put(b->ctx);
		kfree(b);
	}

	/*
	 * Replacement/unbind paths free bindings via call_rcu()
	 * (ne_mux_binding_free_rcu).  free_irq() above quiesced the only
	 * reader (ne_mux_handler), and the loop above freed the surviving
	 * bindings synchronously, so no new callback can be scheduled from
	 * here on.  Wait for any already-queued ne_mux_binding_rcu_free
	 * callback to complete before returning; otherwise on rmmod/shutdown
	 * it could run after the module text is freed and oops.
	 */
	rcu_barrier();
	xa_destroy(&ne_pci_dev->kick_xa);
}

/**
 * ne_mux_binding_free_rcu() - Defer freeing a replaced ne_mux_binding.
 * @b: binding previously stored in kick_xa and just replaced.
 *
 * Callable from ne_set_vring_kick() (process context) after a successful
 * xa_store() that returns a non-NULL old entry.  Freeing is deferred to a
 * grace period so ne_mux_handler()'s rcu_read_lock()-protected access to
 * the binding (and to b->ctx via eventfd_signal) completes first.
 */
void ne_mux_binding_free_rcu(struct ne_mux_binding *b)
{
	call_rcu(&b->rcu, ne_mux_binding_rcu_free);
}

static int ne_mux_shutdown_notify(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	struct ne_pci_dev *ne_pci_dev =
		container_of(nb, struct ne_pci_dev, shutdown_nb);
	struct pcie_slot_shutdown_req req = { .unused = 0 };
	struct ne_pci_dev_cmd_reply reply = { 0 };
	struct ne_enclave *ne_enclave;
	struct enclave_stop_req enclave_stop_request = {};
	struct slot_free_req slot_free_req = {};
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int rc;

	/*
	 * Stop every running enclave on this NE device BEFORE issuing
	 * PCIE_SLOT_SHUTDOWN.
	 *
	 * Shutdown makes the hypervisor unmap the donation region.  If any
	 * enclave slot still references that region, the hypervisor's 100 Hz
	 * vCPU-time accounting tick dereferences a freed pointer microseconds
	 * later and dies, taking the parent's passthrough devices down with it.
	 *
	 * To avoid that, drain every live enclave through ENCLAVE_STOP +
	 * SLOT_FREE here.  Those commands detach the slot and drop the
	 * hypervisor's count of slots in use.  Only after that count reaches
	 * zero is PCIE_SLOT_SHUTDOWN accepted (otherwise it returns -EBUSY and
	 * the donation pool stays intact, which is also safe but leaves the
	 * kexec / driver-unload path with stale donations).
	 *
	 * Lock order matches ne_event_work_handler() and ne_enclave_release():
	 *   ne_pci_dev->enclaves_list_mutex
	 *     -> ne_enclave->enclave_info_mutex
	 *
	 * We do NOT remove enclaves from the list or free per-enclave state
	 * here: ne_enclave_release() / driver-shutdown / module-remove will
	 * still run for the surviving fds, and ENCLAVE_STOP / SLOT_FREE are
	 * idempotent for any subsequent calls.
	 */
	mutex_lock(&ne_pci_dev->enclaves_list_mutex);
	list_for_each_entry(ne_enclave, &ne_pci_dev->enclaves_list,
			    enclave_list_entry) {
		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (!ne_enclave->slot_uid) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);
			continue;
		}

		enclave_stop_request.slot_uid = ne_enclave->slot_uid;
		rc = ne_do_request_retry(ne_pci_dev->pdev, ENCLAVE_STOP,
					 &enclave_stop_request,
					 sizeof(enclave_stop_request),
					 &cmd_reply, sizeof(cmd_reply));
		if (rc < 0)
			dev_err(&ne_pci_dev->pdev->dev,
				"shutdown_notify: ENCLAVE_STOP slot_uid=0x%llx rc=%d\n",
				(unsigned long long)ne_enclave->slot_uid, rc);

		memset(&cmd_reply, 0, sizeof(cmd_reply));
		slot_free_req.slot_uid = ne_enclave->slot_uid;
		rc = ne_do_request_retry(ne_pci_dev->pdev, SLOT_FREE,
					 &slot_free_req, sizeof(slot_free_req),
					 &cmd_reply, sizeof(cmd_reply));
		if (rc < 0)
			dev_err(&ne_pci_dev->pdev->dev,
				"shutdown_notify: SLOT_FREE slot_uid=0x%llx rc=%d\n",
				(unsigned long long)ne_enclave->slot_uid, rc);

		/*
		 * Mark stopped so any concurrent observer (ne_event_work_handler,
		 * userspace polling NE_GET_ENCLAVE_INFO) sees the new state
		 * before the kernel kexecs / shuts down.
		 */
		ne_enclave->state = NE_STATE_STOPPED;

		mutex_unlock(&ne_enclave->enclave_info_mutex);
	}
	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	/* Pre-kexec: tear the device down so the hypervisor stops writing into
	 * the donated pages before the new kernel takes them back. */
	if (ne_pci_dev->iomem_base)
		iowrite32(1, ne_pci_dev->iomem_base + NE_MUX_SHUTDOWN);

	/* Also drop PCIE slot-metadata donations and the base donation
	 * (PCIE_SLOT_SHUTDOWN releases both on the hypervisor side). */
	if (ne_pci_dev->pcie_slot_nr_donated || ne_pci_dev->pcie_base_page)
		ne_do_request(ne_pci_dev->pdev,
			      PCIE_SLOT_SHUTDOWN,
			      &req, sizeof(req),
			      &reply, sizeof(reply));
	return NOTIFY_DONE;
}

static int ne_mux_vectors_show(struct seq_file *s, void *unused)
{
	struct ne_pci_dev *ne_pci_dev = s->private;
	u32 v;

	seq_puts(s, "v_rel msix_vec ints         dispatches   max_bit\n");
	if (!ne_pci_dev->mux)
		return 0;
	for (v = 0; v < ne_pci_dev->nmux; v++) {
		struct ne_mux_vec *mv = &ne_pci_dev->mux[v];

		seq_printf(s, "%5u %8u %12lld %12lld %7u\n",
			   v, ne_pci_dev->base_vector + v,
			   (long long)atomic64_read(&mv->ints),
			   (long long)atomic64_read(&mv->dispatches),
			   READ_ONCE(mv->max_bit));
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ne_mux_vectors);

static int ne_kicks_show(struct seq_file *s, void *unused)
{
	struct ne_pci_dev *ne_pci_dev = s->private;
	unsigned long vq_id;
	struct ne_mux_binding *b;

	seq_puts(s, "vq_id    v_rel bit    kicks\n");
	/*
	 * The replace/unbind/reap paths free kick_xa entries via call_rcu()
	 * (ne_mux_binding_free_rcu -> ne_mux_binding_rcu_free), so one of those
	 * deferred frees can drop b mid-iteration.  Hold the RCU read-side
	 * across the whole walk, matching ne_mux_handler()'s discipline.
	 * seq_printf() formats into the seq_file buffer and does not sleep, so
	 * it is safe here.
	 *
	 * Teardown is a separate case, not covered by this rcu_read_lock():
	 * ne_mux_teardown() frees the surviving bindings synchronously (kfree,
	 * not call_rcu), so a grace period would not protect against it.
	 * Instead, ne_pci_dev_teardown() calls ne_mux_debugfs_exit() first,
	 * and debugfs_remove_recursive() drains any active reader before
	 * ne_mux_teardown() runs, so no walk can be in progress when it frees.
	 */
	rcu_read_lock();
	xa_for_each(&ne_pci_dev->kick_xa, vq_id, b) {
		u32 v_rel = (u32)(vq_id % ne_pci_dev->nmux);
		u32 bit   = (u32)(vq_id / ne_pci_dev->nmux);

		seq_printf(s, "%-8lu %-5u %-6u %lld\n",
			   vq_id, v_rel, bit,
			   (long long)atomic64_read(&b->kicks));
	}
	rcu_read_unlock();
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ne_kicks);



static void ne_mux_debugfs_init(struct ne_pci_dev *ne_pci_dev)
{
	ne_pci_dev->debugfs_root =
		debugfs_create_dir("nitro_enclaves", NULL);
	debugfs_create_file("mux_vectors", 0400,
			    ne_pci_dev->debugfs_root, ne_pci_dev,
			    &ne_mux_vectors_fops);
	debugfs_create_file("kicks", 0400,
			    ne_pci_dev->debugfs_root, ne_pci_dev,
			    &ne_kicks_fops);
}

static void ne_mux_debugfs_exit(struct ne_pci_dev *ne_pci_dev)
{
	debugfs_remove_recursive(ne_pci_dev->debugfs_root);
	ne_pci_dev->debugfs_root = NULL;
}

/**
 * ne_pcie_slot_probe_init() - Read PCIE slot pool geometry at probe.
 *
 * Reads the advertised slot cap and donation granularity from the device
 * but does NOT donate any pages. Donations happen lazily from
 * ne_pcie_slot_donate_one() on NE_CREATE_VM -ENOSPC.
 */
static void ne_pcie_slot_probe_init(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	u32 gran_size, gran_align;
	u16 cap;

	cap = ioread16(ne_pci_dev->iomem_base + NE_REG_MAX_PCIE_SLOTS);
	ne_pci_dev->max_pcie_slots = cap;
	if (!cap) {
		dev_info(&pdev->dev, "No PCIE slot pool advertised\n");
		return;
	}

	gran_size = ioread32(ne_pci_dev->iomem_base +
			     NE_REG_PCIE_SLOT_GROW_GRANULARITY_SIZE);
	gran_align = ioread32(ne_pci_dev->iomem_base +
			      NE_REG_PCIE_SLOT_GROW_GRANULARITY_ALIGN);
	if (gran_size != SZ_2M || gran_align != SZ_2M) {
		dev_warn(&pdev->dev,
			 "PCIE slot pool: unsupported granularity size=%u align=%u (expected %u/%u)\n",
			 gran_size, gran_align,
			 (unsigned int)SZ_2M, (unsigned int)SZ_2M);
		ne_pci_dev->max_pcie_slots = 0;
		return;
	}

	ne_pci_dev->pcie_slot_gran_size = gran_size;
	dev_info(&pdev->dev,
		 "PCIE slot pool: cap=%u granularity=%u (lazy donation on NE_CREATE_VM)\n",
		 cap, gran_size);
}

/**
 * ne_pcie_base_donate() - Donate the base scratch page (the "base PCIe
 * tax") to the hypervisor's PCIE slot pool.
 *
 * The hypervisor uses this single page as the private IOMMU sink that
 * backs the slot-stride carve; it must be donated before any slot
 * donation (the hypervisor rejects slot donations until it is present).
 * Idempotent: a no-op once the base page is donated. The page is held
 * until parent kexec. Returns 0 on success or if already donated,
 * negative errno on failure.
 *
 * Caller must hold the ne_pci_dev->enclaves_list_mutex to serialize
 * donations with concurrent NE_CREATE_VM attempts.
 */
int ne_pcie_base_donate(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	struct pcie_slot_donate_req req = { 0 };
	struct ne_pci_dev_cmd_reply reply = { 0 };
	struct page *page;
	struct cma *cma = NULL;
	u32 size, nr_pages;
	int rc;

	if (ne_pci_dev->pcie_base_page)
		return 0;

	if (!ne_pci_dev->max_pcie_slots)
		return -ENOTSUPP;

	size = ioread32(ne_pci_dev->iomem_base +
			NE_REG_PCIE_BASE_DONATION_SIZE);
	if (size != SZ_2M) {
		dev_warn(&pdev->dev,
			 "PCIE base donate: unsupported size=%u (expected %u)\n",
			 size, (unsigned int)SZ_2M);
		return -ENOTSUPP;
	}

	nr_pages = size >> PAGE_SHIFT;
	page = ne_alloc_contig(nr_pages, &cma, NUMA_NO_NODE);
	if (!page) {
		dev_warn(&pdev->dev, "PCIE base donate: alloc failed\n");
		return -ENOMEM;
	}

	req.parent_gpa = page_to_phys(page);
	rc = ne_do_request_retry(pdev, PCIE_BASE_DONATE,
				 &req, sizeof(req), &reply, sizeof(reply));
	if (rc < 0 || reply.rc < 0) {
		/*
		 * The hypervisor collapses every base-donate rejection to
		 * -EINVAL and logs the specific reason only on its own side, so
		 * report what this end chose: the GPA, whether it satisfies the
		 * 2 MiB alignment the hypervisor requires. Without this the
		 * guest sees a bare rc=-22.
		 */
		dev_warn(&pdev->dev,
			 "PCIE base donate: cmd rc=%d reply_rc=%d gpa=0x%llx aligned_2m=%s\n",
			 rc, reply.rc, (unsigned long long)req.parent_gpa,
			 IS_ALIGNED(req.parent_gpa, SZ_2M) ? "yes" : "NO");
		ne_free_contig(cma, page, nr_pages);
		return rc ? rc : reply.rc;
	}

	ne_pci_dev->pcie_base_page = page;
	ne_pci_dev->pcie_base_cma = cma;
	dev_info(&pdev->dev, "PCIE base donate: donated base sink page\n");
	return 0;
}

/**
 * ne_pcie_slot_donate_one() - Donate one granularity-sized page to the
 * hypervisor's PCIE slot pool.
 *
 * Called from the NE_CREATE_VM ioctl on SLOT_ALLOC -ENOSPC, to extend the
 * hypervisor's slot capacity by one granularity. Returns 0 on success,
 * negative errno on failure. The donation pool capacity (number of
 * donations stored in pcie_slot_pages[]) caps how many extensions are
 * possible per probe.
 *
 * Caller must hold the ne_pci_dev->enclaves_list_mutex to serialize
 * donations with concurrent NE_CREATE_VM attempts.
 */
int ne_pcie_slot_donate_one(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	struct pcie_slot_donate_req req = { 0 };
	struct ne_pci_dev_cmd_reply reply = { 0 };
	struct page *page;
	struct cma *cma = NULL;
	u16 current_limit;
	u32 slot, nr_pages;
	int rc;

	if (!ne_pci_dev->max_pcie_slots || !ne_pci_dev->pcie_slot_gran_size)
		return -ENOTSUPP;

	current_limit = ioread16(ne_pci_dev->iomem_base +
				 NE_REG_PCIE_SLOT_CURRENT_LIMIT);
	if (current_limit >= ne_pci_dev->max_pcie_slots) {
		dev_warn(&pdev->dev,
			 "PCIE slot donate: hypervisor cap reached (current_limit=%u cap=%u)\n",
			 current_limit, ne_pci_dev->max_pcie_slots);
		return -ENOSPC;
	}

	slot = ne_pci_dev->pcie_slot_nr_donated;
	if (!ne_pci_dev->pcie_slot_pages ||
	    slot >= ne_pci_dev->pcie_slot_pages_cap) {
		dev_warn(&pdev->dev,
			 "PCIE slot donate: driver page-tracking slots exhausted (nr=%u cap=%u)\n",
			 slot, ne_pci_dev->pcie_slot_pages_cap);
		return -ENOMEM;
	}

	nr_pages = ne_pci_dev->pcie_slot_gran_size >> PAGE_SHIFT;
	page = ne_alloc_contig(nr_pages, &cma, NUMA_NO_NODE);
	if (!page) {
		dev_warn(&pdev->dev,
			 "PCIE slot donate: alloc failed (current_limit=%u cap=%u)\n",
			 current_limit, ne_pci_dev->max_pcie_slots);
		return -ENOMEM;
	}

	req.parent_gpa = page_to_phys(page);
	rc = ne_do_request_retry(pdev, PCIE_SLOT_DONATE,
				 &req, sizeof(req), &reply, sizeof(reply));
	if (rc < 0 || reply.rc < 0) {
		dev_warn(&pdev->dev,
			 "PCIE slot donate: cmd rc=%d reply_rc=%d\n",
			 rc, reply.rc);
		ne_free_contig(cma, page, nr_pages);
		return rc ? rc : reply.rc;
	}

	ne_pci_dev->pcie_slot_pages[slot] = page;
	ne_pci_dev->pcie_slot_cmas[slot] = cma;
	ne_pci_dev->pcie_slot_nr_donated++;

	current_limit = ioread16(ne_pci_dev->iomem_base +
				 NE_REG_PCIE_SLOT_CURRENT_LIMIT);
	dev_info(&pdev->dev,
		 "PCIE slot donate: donated page %u, current_limit=%u\n",
		 slot, current_limit);
	return 0;
}

/**
 * ne_get_slot_limits() - Query current PCIE slot limits from the device.
 * @pdev:	PCI device.
 * @out:	Receives the slot_limits reply on success.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int ne_get_slot_limits(struct pci_dev *pdev,
			      struct ne_pci_dev_cmd_reply *out)
{
	u8 dummy = 0;

	return ne_do_request_retry(pdev, GET_SLOT_LIMITS,
				   &dummy, sizeof(dummy),
				   out, sizeof(*out));
}

/**
 * ne_free_contig() - Release a contiguous allocation (or sub-range) obtained
 * from ne_alloc_contig() back to its CMA region.
 * @cma:	CMA region the pages came from. The put_page() arm below the
 *		cma_release() survives only as a defensive path; every live
 *		allocation originates in a CMA region.
 * @page:	First page of the (sub-)range to free.
 * @nr_pages:	Number of pages to free.
 *
 * Safe on a sub-range of a larger allocation: cma_release() clears only the
 * given bitmap range and the put_page() loop drops one ref per page, matching
 * how ne_alloc_contig() hands them out.
 */
static void ne_free_contig(struct cma *cma, struct page *page,
			   unsigned long nr_pages)
{
	unsigned long k;

	if (cma) {
		cma_release(cma, page, nr_pages);
		return;
	}
	for (k = 0; k < nr_pages; k++)
		put_page(page + k);
}

/**
 * ne_system_ram_donate_one() - Donate one 128 MiB chunk of parent guest RAM
 * into the device's memory pool.
 *
 * CMA only guarantees 2 MiB base alignment but the host add_memory path needs
 * 128 MiB alignment, so we over-allocate 256 MiB and hand the device the full
 * span (which always contains a 128 MiB-aligned 128 MiB window). The device
 * consumes an aligned window and reports back the parent-GPA range it took;
 * we then free the unused head and tail to CMA and track only the donated
 * block. If the device reports no window (older hypervisor, or a window out
 * of range), we fall back to holding the full allocation. Returns 0 on
 * success, -ENOMEM on alloc/tracking exhaustion, or a negative errno from the
 * device.
 *
 * Caller must hold ne_pci_dev->enclaves_list_mutex.
 */
static int ne_system_ram_donate_one(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	struct system_ram_donate_req req = { 0 };
	struct ne_pci_dev_cmd_reply reply = { 0 };
	const unsigned long over_pages = (2 * SZ_128M) >> PAGE_SHIFT;
	const unsigned long donate_pages = SZ_128M >> PAGE_SHIFT;
	unsigned long head_pages, tail_pages;
	struct page *page, *donated_page;
	struct cma *cma = NULL;
	u64 base_phys, consumed_gpa, consumed_size;
	u32 slot;
	int nid, i, nr_mem_nodes;
	int rc;

	slot = ne_pci_dev->mem_donate_nr;
	if (slot >= NE_MEM_DONATE_MAX_CHUNKS) {
		dev_warn(&pdev->dev,
			 "system-ram donate: chunk-tracking slots exhausted (nr=%u)\n",
			 slot);
		return -ENOMEM;
	}

	/*
	 * Round-robin the donation across the parent's memory nodes so the
	 * hypervisor's ZONE_MOVABLE hot-add lands on every host NUMA node.
	 * ne_alloc_contig(NUMA_NO_NODE) drains ne_cma_regions[] in
	 * declaration order (all node-0 regions first on a
	 * mempool=X@0,X@1,... boot), which on a multi-socket parent leaves
	 * every non-zero host node with no ZONE_MOVABLE and pushes ~half the
	 * enclave VMMs' anon-rss into that node's ZONE_NORMAL until the host
	 * kernel global-OOMs the whole slot cgroup.  Instead pick the
	 * (slot % nr_mem_nodes)-th online memory node so successive
	 * donations interleave.  Falls back to any-node if the target node's
	 * CMA is exhausted, so single-node parents and asymmetric mempool=
	 * layouts still make forward progress.
	 *
	 * This is guest-side best-effort only; the hypervisor independently
	 * derives and enforces a per-host-node slot budget from the actual
	 * HPA of each donation.
	 */
	nr_mem_nodes = num_node_state(N_MEMORY);
	if (nr_mem_nodes < 1)
		nr_mem_nodes = 1;
	nid = first_node(node_states[N_MEMORY]);
	for (i = 0; i < (int)(slot % nr_mem_nodes); i++)
		nid = next_node_in(nid, node_states[N_MEMORY]);

	page = ne_alloc_contig(over_pages, &cma, nid);
	if (!page && nid != NUMA_NO_NODE)
		page = ne_alloc_contig(over_pages, &cma, NUMA_NO_NODE);
	if (!page) {
		dev_warn(&pdev->dev,
			 "system-ram donate: 256 MiB alloc failed (nr_chunks=%u)\n",
			 slot);
		return -ENOMEM;
	}

	base_phys = page_to_phys(page);
	/* Hand the device the full 256 MiB span. A 128 MiB-aligned GPA need
	 * not map to a 128 MiB-aligned host address, so the device aligns up
	 * and carves a 128 MiB-aligned 128 MiB window from within this span
	 * (a 256 MiB span always contains one), then reports back the window
	 * it consumed. */
	req.parent_gpa = base_phys;
	req.size = 2 * SZ_128M;
	rc = ne_do_request_retry(pdev, SYSTEM_RAM_DONATE,
				 &req, sizeof(req), &reply, sizeof(reply));
	if (rc < 0 || reply.rc < 0) {
		dev_warn(&pdev->dev,
			 "system-ram donate: cmd rc=%d reply_rc=%d\n",
			 rc, reply.rc);
		ne_free_contig(cma, page, over_pages);
		return rc ? rc : reply.rc;
	}

	consumed_gpa = reply.system_ram_donate.consumed_gpa;
	consumed_size = reply.system_ram_donate.consumed_size;

	/* Device reported a valid 128 MiB window inside our span: free the
	 * unused head and tail back to CMA and track only the donated block. */
	if (consumed_size == SZ_128M &&
	    consumed_gpa >= base_phys &&
	    consumed_gpa + SZ_128M <= base_phys + 2 * SZ_128M) {
		head_pages = (consumed_gpa - base_phys) >> PAGE_SHIFT;
		tail_pages = over_pages - head_pages - donate_pages;
		donated_page = page + head_pages;

		if (head_pages)
			ne_free_contig(cma, page, head_pages);
		if (tail_pages)
			ne_free_contig(cma, donated_page + donate_pages,
				       tail_pages);

		ne_pci_dev->mem_donations[slot].alloc_page = donated_page;
		ne_pci_dev->mem_donations[slot].cma = cma;
		ne_pci_dev->mem_donations[slot].alloc_nr_pages = donate_pages;
		ne_pci_dev->mem_donations[slot].donated_gpa = consumed_gpa;
		ne_pci_dev->mem_donate_nr++;

		dev_info(&pdev->dev,
			 "system-ram donate: chunk %u gpa=0x%llx nid=%d (128 MiB donated, 128 MiB freed back), donations=%u\n",
			 slot, consumed_gpa, page_to_nid(donated_page),
			 ne_pci_dev->mem_donate_nr);
		return 0;
	}

	/* Fallback: device did not report a usable window; hold the full
	 * over-allocation as before. */
	ne_pci_dev->mem_donations[slot].alloc_page = page;
	ne_pci_dev->mem_donations[slot].cma = cma;
	ne_pci_dev->mem_donations[slot].alloc_nr_pages = over_pages;
	ne_pci_dev->mem_donations[slot].donated_gpa =
		consumed_size ? consumed_gpa : base_phys;
	ne_pci_dev->mem_donate_nr++;

	dev_info(&pdev->dev,
		 "system-ram donate: chunk %u gpa=0x%llx (no window reported, holding 256 MiB), donations=%u\n",
		 slot, base_phys, ne_pci_dev->mem_donate_nr);
	return 0;
}

/**
 * ne_mux_setup() - Initialize the IRQ multiplexer at probe.
 *
 * Reads the pooled-vector geometry from the device, allocates the bitmap pages
 * for all the vectors as one 2 MiB-aligned block, donates the pages via the
 * donate-base registers, and installs a shared MSI-X handler per vector. No
 * vq_id is bound at probe, so the handlers see all-zero bitmaps until
 * userspace wires one with NE_SET_VRING_KICK.
 *
 * Under NIE the block still has to be shared with the hypervisor before any
 * kick can be delivered; that cannot happen here, see ne_mux_share_bitmaps().
 */
static int ne_mux_setup(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	struct page *bitmap_pages;
	size_t needed;
	u32 v;
	int rc;

	ne_pci_dev->base_vector =
		ioread16(ne_pci_dev->iomem_base + NE_VQ_VECTOR_BASE);
	ne_pci_dev->nmux =
		ioread16(ne_pci_dev->iomem_base + NE_MUX_NUM_VECTORS);

	if (!ne_pci_dev->nmux) {
		dev_info(&pdev->dev, "No mux vectors advertised\n");
		return 0;
	}
	if (ne_pci_dev->nmux > NE_MUX_MAX_VECTORS) {
		dev_err(&pdev->dev, "Nmux=%u exceeds driver max %u\n",
			ne_pci_dev->nmux, NE_MUX_MAX_VECTORS);
		return -EINVAL;
	}

	ne_pci_dev->mux = kcalloc(ne_pci_dev->nmux,
				  sizeof(*ne_pci_dev->mux), GFP_KERNEL);
	if (!ne_pci_dev->mux)
		return -ENOMEM;
	xa_init(&ne_pci_dev->kick_xa);

	/*
	 * One block for every bitmap, rather than a page at a time. Round the
	 * span up to a whole number of 2 MiB units and let the buddy allocator
	 * hand back a naturally aligned block of that order, which is at least
	 * 2 MiB aligned: Guest.Share below needs the base and the size aligned
	 * that way, and sharing a block we allocated wholly for this purpose is
	 * what keeps unrelated kernel data out of the hypervisor's reach. A
	 * page-at-a-time allocation would have scattered the bitmaps through
	 * whatever 2 MiB the page allocator happened to be handing out.
	 */
	needed = (size_t)ne_pci_dev->nmux << PAGE_SHIFT;
	ne_pci_dev->mux_bitmap_order = get_order(max_t(size_t, needed, SZ_2M));
	ne_pci_dev->mux_bitmap_size = (size_t)PAGE_SIZE <<
				      ne_pci_dev->mux_bitmap_order;

	bitmap_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO,
				   ne_pci_dev->mux_bitmap_order);
	if (!bitmap_pages) {
		dev_err(&pdev->dev,
			"Cannot allocate %zu bytes backing %u mux bitmaps\n",
			ne_pci_dev->mux_bitmap_size, ne_pci_dev->nmux);
		rc = -ENOMEM;
		goto err;
	}
	ne_pci_dev->mux_bitmap_base = page_address(bitmap_pages);

	for (v = 0; v < ne_pci_dev->nmux; v++) {
		struct ne_mux_vec *mv = &ne_pci_dev->mux[v];
		u64 gpa;
		u32 err;
		int irq;

		mv->ne_pci_dev = ne_pci_dev;
		mv->v_rel = v;
		mv->bitmap = (u64 *)((char *)ne_pci_dev->mux_bitmap_base +
				     ((size_t)v << PAGE_SHIFT));
		gpa = (u64)virt_to_phys(mv->bitmap);
		writeq(gpa, ne_pci_dev->iomem_base +
			    NE_MUX_DONATE_BASE + v * sizeof(u64));
		err = ioread16(ne_pci_dev->iomem_base +
			       NE_MUX_DONATE_ERR);
		if (err) {
			dev_err(&pdev->dev,
				"mux donate vec=%u err=%u\n", v, err);
			rc = -EIO;
			goto err;
		}

		irq = pci_irq_vector(pdev, ne_pci_dev->base_vector + v);
		if (irq < 0) {
			rc = irq;
			goto err;
		}
		rc = request_irq(irq, ne_mux_handler, IRQF_SHARED,
				 "ne_mux", mv);
		if (rc < 0) {
			dev_err(&pdev->dev,
				"mux request_irq vec=%u rc=%d\n", v, rc);
			/* Un-donate before the block goes back to the guest. */
			writeq(0, ne_pci_dev->iomem_base +
				  NE_MUX_DONATE_BASE +
				  v * sizeof(u64));
			goto err;
		}
		mv->irq_installed = true;
	}

	ne_pci_dev->shutdown_nb.notifier_call = ne_mux_shutdown_notify;
	register_reboot_notifier(&ne_pci_dev->shutdown_nb);

	ne_mux_debugfs_init(ne_pci_dev);

	dev_info(&pdev->dev, "mux: nmux=%u base_vector=%u\n",
		 ne_pci_dev->nmux, ne_pci_dev->base_vector);
	return 0;

err:
	ne_mux_teardown(pdev);
	return rc;
}

/**
 * ne_mux_share_bitmaps() - Share the mux bitmap block with the hypervisor.
 *
 * Under NIE the parent's memory is not the hypervisor's to touch, but the
 * hypervisor is what posts kick bits into these pages. Without the share it
 * refuses the donation when it replays it at ENCLAVE_START, reporting that
 * the donated bitmap page is not accessible to it, and every kick on every
 * vector is dropped, which strands the enclave's virtqueues.
 *
 * We keep read-write access (the MSI-X handler scans the bitmap and clears
 * the bits it dispatched) and the enclave gets none: it reaches the bitmap
 * only through the hypervisor, never directly.
 *
 * Must be called *after* the NIE metadata pool has been donated, not from
 * ne_mux_setup(). Guest.Share needs the parent to have a Shareable Range Table,
 * and the SRT is provisioned by the hypervisor as a side effect of the
 * PCIE_SLOT_DONATE that hands over the SRT page: sharing before that gets
 * NIE error 104, NoSrt. The donation itself does not care about the ordering
 * (the donate-base writes only record the GPAs; accessibility is not checked
 * until the replay), so the writes can stay in ne_mux_setup() where they are.
 *
 * Best-effort, like the pool donation it follows: a failure here costs
 * virtqueue kicks, so it is loud, but it must not take the whole driver down
 * and with it every enclave that needs no virtqueue kicks at all.
 */
static void ne_mux_share_bitmaps(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	int rc;

	if (!ne_pci_dev->sharing_ops || !ne_pci_dev->mux_bitmap_base)
		return;

	rc = ne_pci_dev->sharing_ops->share(NULL,
				virt_to_phys(ne_pci_dev->mux_bitmap_base),
				ne_pci_dev->mux_bitmap_size,
				NE_SHARE_HYP,
				ne_share_perms_pack(NE_PERM_RW, NE_PERM_RW,
						    NE_PERM_NOACCESS),
				0);
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Guest.Share for the mux bitmaps failed [rc=%d]; virtqueue kicks will be dropped\n",
			rc);
		return;
	}

	ne_pci_dev->mux_bitmap_shared = true;
	dev_info(&pdev->dev, "mux: shared %zu bytes of bitmaps with the hypervisor\n",
		 ne_pci_dev->mux_bitmap_size);
}

/**
 * ne_info_events_probe() - Read per-enclave PCIe device cap at probe.
 *
 * Reads NE_MAX_PCIE_DEVICES from the device register. Info-event
 * notifications route through the KVM mux as pseudo-VQ ids, so the
 * only probe-time work is reading the max_pcie_devices cap.
 */
static int ne_info_events_probe(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	ne_pci_dev->max_pcie_devices =
		ioread16(ne_pci_dev->iomem_base + NE_MAX_PCIE_DEVICES);
	if (!ne_pci_dev->max_pcie_devices)
		ne_pci_dev->max_pcie_devices = 8;
	max_pcie_devices = ne_pci_dev->max_pcie_devices;

	dev_info(&pdev->dev, "max_pcie_devices=%u\n",
		 ne_pci_dev->max_pcie_devices);
	return 0;
}









/**
 * ne_pci_dev_enable() - Select the PCI device version and enable it.
 * @pdev:	PCI device to select version for and then enable.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_pci_dev_enable(struct pci_dev *pdev)
{
	u8 dev_enable_reply = 0;
	u16 dev_version_reply = 0;
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	iowrite16(NE_VERSION_MAX, ne_pci_dev->iomem_base + NE_VERSION);

	dev_version_reply = ioread16(ne_pci_dev->iomem_base + NE_VERSION);
	if (dev_version_reply != NE_VERSION_MAX) {
		dev_err(&pdev->dev, "Error in pci dev version cmd\n");

		return -EIO;
	}

	iowrite8(NE_ENABLE_ON, ne_pci_dev->iomem_base + NE_ENABLE);

	dev_enable_reply = ioread8(ne_pci_dev->iomem_base + NE_ENABLE);
	if (dev_enable_reply != NE_ENABLE_ON) {
		dev_err(&pdev->dev, "Error in pci dev enable cmd\n");

		return -EIO;
	}

	return 0;
}

/**
 * ne_pci_dev_disable() - Disable the PCI device.
 * @pdev:	PCI device to disable.
 *
 * Context: Process context.
 */
static void ne_pci_dev_disable(struct pci_dev *pdev)
{
	u8 dev_disable_reply = 0;
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	const unsigned int sleep_time = 10; /* 10 ms */
	unsigned int sleep_time_count = 0;

	iowrite8(NE_ENABLE_OFF, ne_pci_dev->iomem_base + NE_ENABLE);

	/*
	 * Check for NE_ENABLE_OFF in a loop, to handle cases when the device
	 * state is not immediately set to disabled and going through a
	 * transitory state of disabling.
	 */
	while (sleep_time_count < NE_DEFAULT_TIMEOUT_MSECS) {
		dev_disable_reply = ioread8(ne_pci_dev->iomem_base + NE_ENABLE);
		if (dev_disable_reply == NE_ENABLE_OFF)
			return;

		msleep_interruptible(sleep_time);
		sleep_time_count += sleep_time;
	}

	dev_disable_reply = ioread8(ne_pci_dev->iomem_base + NE_ENABLE);
	if (dev_disable_reply != NE_ENABLE_OFF)
		dev_err(&pdev->dev, "Error in pci dev disable cmd\n");
}

/*
 * device_pool/ sysfs tree: parent-guest trigger for the CLAIM/RELEASE
 * handshake. Anchored at /sys/class/misc/nitro_enclaves/device_pool/.
 * The store handlers parse an SBDF, build the matching wire request, and
 * call ne_do_request() so the parent VMM forwards it to the hypervisor as
 * SM_CLAIM_FROM_PARENT / SM_RELEASE_TO_PARENT. The driver does NOT touch
 * the target device's pci_dev; the hot-unplug / hot-add is driven by the
 * VMM via the PCIe attention-button handshake and observed by the guest's
 * own pciehp driver.
 */

struct ne_device_pool_entry {
	u16			sbdf;
	struct list_head	node;
};

static LIST_HEAD(ne_device_pool_entries);
static DEFINE_MUTEX(ne_device_pool_mutex);
static struct kobject *ne_device_pool_kobj;

/**
 * ne_device_pool_parse_sbdf() - Parse "0000:BB:DD.F" or "BB:DD.F" into a
 *			  packed SBDF. Domain is ignored (virt PCIe is
 *			  single-domain, always 0).
 * @buf: Input string (may include trailing newline; scanf handles it).
 * @out_sbdf: Parsed (bus << 8) | (dev << 3) | fn.
 * Return: 0 on success, -EINVAL on malformed input or out-of-range
 *	   field values.
 */
static int ne_device_pool_parse_sbdf(const char *buf, u16 *out_sbdf)
{
	unsigned int domain = 0, bus, dev, fn;

	if (sscanf(buf, "%x:%x:%x.%x", &domain, &bus, &dev, &fn) != 4) {
		if (sscanf(buf, "%x:%x.%x", &bus, &dev, &fn) != 3)
			return -EINVAL;
	}

	if (bus > 0xff || dev > 0x1f || fn > 0x07)
		return -EINVAL;

	*out_sbdf = (u16)((bus << 8) | (dev << 3) | fn);
	return 0;
}

static ssize_t claim_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct sm_claim_from_parent_req req = {};
	struct ne_pci_dev_cmd_reply reply = {};
	struct ne_device_pool_entry *entry;
	u16 sbdf;
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!ne_pci_dev)
		return -ENODEV;

	rc = ne_device_pool_parse_sbdf(buf, &sbdf);
	if (rc)
		return rc;

	req.parent_guest_sbdf = sbdf;

	rc = ne_do_request_retry(ne_pci_dev->pdev, SM_CLAIM_FROM_PARENT,
			   &req, sizeof(req), &reply, sizeof(reply));
	if (rc)
		return rc;
	if (reply.rc < 0)
		return reply.rc;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->sbdf = sbdf;

	mutex_lock(&ne_device_pool_mutex);
	list_add_tail(&entry->node, &ne_device_pool_entries);
	mutex_unlock(&ne_device_pool_mutex);

	return count;
}

static ssize_t release_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct sm_release_to_parent_req req = {};
	struct ne_pci_dev_cmd_reply reply = {};
	struct ne_device_pool_entry *entry, *tmp;
	u16 sbdf;
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!ne_pci_dev)
		return -ENODEV;

	rc = ne_device_pool_parse_sbdf(buf, &sbdf);
	if (rc)
		return rc;

	req.parent_guest_sbdf = sbdf;

	rc = ne_do_request_retry(ne_pci_dev->pdev, SM_RELEASE_TO_PARENT,
			   &req, sizeof(req), &reply, sizeof(reply));
	if (rc)
		return rc;
	if (reply.rc < 0)
		return reply.rc;

	mutex_lock(&ne_device_pool_mutex);
	list_for_each_entry_safe(entry, tmp, &ne_device_pool_entries, node) {
		if (entry->sbdf == sbdf) {
			list_del(&entry->node);
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&ne_device_pool_mutex);

	return count;
}

static ssize_t list_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct ne_device_pool_entry *entry;
	ssize_t len = 0;

	mutex_lock(&ne_device_pool_mutex);
	list_for_each_entry(entry, &ne_device_pool_entries, node) {
		len += scnprintf(buf + len, PAGE_SIZE - len,
				 "0000:%02x:%02x.%x\n",
				 (entry->sbdf >> 8) & 0xff,
				 (entry->sbdf >> 3) & 0x1f,
				 entry->sbdf & 0x07);
		if (len >= PAGE_SIZE)
			break;
	}
	mutex_unlock(&ne_device_pool_mutex);
	return len;
}

static struct kobj_attribute device_pool_claim_attr =
	__ATTR(claim, 0200, NULL, claim_store);
static struct kobj_attribute device_pool_release_attr =
	__ATTR(release, 0200, NULL, release_store);
static struct kobj_attribute device_pool_list_attr =
	__ATTR(list, 0444, list_show, NULL);

static struct attribute *ne_device_pool_attrs[] = {
	&device_pool_claim_attr.attr,
	&device_pool_release_attr.attr,
	&device_pool_list_attr.attr,
	NULL,
};

static const struct attribute_group ne_device_pool_attr_group = {
	.attrs = ne_device_pool_attrs,
};

/**
 * ne_device_pool_init() - Create the /sys/class/misc/nitro_enclaves/device_pool/
 *		    sysfs subtree and register the claim/release/list
 *		    attributes. Must be called after misc_register().
 * Return: 0 on success, -errno on failure.
 */
static int ne_device_pool_init(void)
{
	struct miscdevice *miscdev = ne_devs.ne_misc_dev;
	int rc;

	ne_device_pool_kobj = kobject_create_and_add("device_pool",
					      &miscdev->this_device->kobj);
	if (!ne_device_pool_kobj)
		return -ENOMEM;

	rc = sysfs_create_group(ne_device_pool_kobj, &ne_device_pool_attr_group);
	if (rc) {
		kobject_put(ne_device_pool_kobj);
		ne_device_pool_kobj = NULL;
		return rc;
	}

	return 0;
}

/**
 * ne_device_pool_exit() - Tear down the pool sysfs subtree and drain the local
 *		    CLAIM-tracking list. Must be called before
 *		    misc_deregister(). Idempotent.
 */
static void ne_device_pool_exit(void)
{
	struct ne_device_pool_entry *entry, *tmp;

	if (ne_device_pool_kobj) {
		sysfs_remove_group(ne_device_pool_kobj, &ne_device_pool_attr_group);
		kobject_put(ne_device_pool_kobj);
		ne_device_pool_kobj = NULL;
	}

	mutex_lock(&ne_device_pool_mutex);
	list_for_each_entry_safe(entry, tmp, &ne_device_pool_entries, node) {
		list_del(&entry->node);
		kfree(entry);
	}
	mutex_unlock(&ne_device_pool_mutex);
}

/*
 * cpu_pool/ sysfs tree: visibility into the dedicated (non-overcommitted)
 * CPU pool that pinned-core enclaves draw from. Their launches fail once this
 * pool is exhausted, so schedulers and operators need to see how many
 * dedicated threads exist and how many remain. The pool spans all NUMA nodes
 * in dynamic mode and (typically) a single node in static mode, and
 * allocation is NUMA-aware, so both a global view and a per-node view are
 * exported:
 *
 *   /sys/class/misc/nitro_enclaves/cpu_pool/{total,in_use,free}
 *   /sys/class/misc/nitro_enclaves/cpu_pool/node<N>/{total,in_use,free}
 *
 * Counts are threads. Overcommitted enclaves are not counted: their vCPUs
 * float on the parent's CPUs rather than consuming dedicated cores. A
 * node<N>/ subdirectory is created for every online NUMA node; nodes with no
 * pool capacity simply report zero.
 */
static struct kobject *ne_cpu_pool_kobj;
static struct kobject *ne_cpu_pool_node_kobj[MAX_NUMNODES];

static ssize_t cpu_pool_total_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	unsigned int total, in_use, free_cpus;

	ne_cpu_pool_get_stats(NUMA_NO_NODE, &total, &in_use, &free_cpus);
	return sysfs_emit(buf, "%u\n", total);
}

static ssize_t cpu_pool_in_use_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	unsigned int total, in_use, free_cpus;

	ne_cpu_pool_get_stats(NUMA_NO_NODE, &total, &in_use, &free_cpus);
	return sysfs_emit(buf, "%u\n", in_use);
}

static ssize_t cpu_pool_free_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	unsigned int total, in_use, free_cpus;

	ne_cpu_pool_get_stats(NUMA_NO_NODE, &total, &in_use, &free_cpus);
	return sysfs_emit(buf, "%u\n", free_cpus);
}

static struct kobj_attribute cpu_pool_total_attr =
	__ATTR(total, 0444, cpu_pool_total_show, NULL);
static struct kobj_attribute cpu_pool_in_use_attr =
	__ATTR(in_use, 0444, cpu_pool_in_use_show, NULL);
static struct kobj_attribute cpu_pool_free_attr =
	__ATTR(free, 0444, cpu_pool_free_show, NULL);

static struct attribute *ne_cpu_pool_attrs[] = {
	&cpu_pool_total_attr.attr,
	&cpu_pool_in_use_attr.attr,
	&cpu_pool_free_attr.attr,
	NULL,
};

static const struct attribute_group ne_cpu_pool_attr_group = {
	.attrs = ne_cpu_pool_attrs,
};

/*
 * Per-node attributes. The node id is encoded in the parent kobject name
 * ("node<N>") and parsed back out in each show, so the same attributes are
 * shared by every node<N>/ subdirectory (of both cpu_pool/ and mem_pool/).
 */
static int ne_pool_kobj_nid(struct kobject *kobj)
{
	int nid;

	if (kstrtoint(kobject_name(kobj) + strlen("node"), 10, &nid))
		return NUMA_NO_NODE;
	return nid;
}

static ssize_t cpu_node_total_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	unsigned int total, in_use, free_cpus;

	ne_cpu_pool_get_stats(ne_pool_kobj_nid(kobj), &total, &in_use,
			      &free_cpus);
	return sysfs_emit(buf, "%u\n", total);
}

static ssize_t cpu_node_in_use_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	unsigned int total, in_use, free_cpus;

	ne_cpu_pool_get_stats(ne_pool_kobj_nid(kobj), &total, &in_use,
			      &free_cpus);
	return sysfs_emit(buf, "%u\n", in_use);
}

static ssize_t cpu_node_free_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	unsigned int total, in_use, free_cpus;

	ne_cpu_pool_get_stats(ne_pool_kobj_nid(kobj), &total, &in_use,
			      &free_cpus);
	return sysfs_emit(buf, "%u\n", free_cpus);
}

static struct kobj_attribute cpu_node_total_attr =
	__ATTR(total, 0444, cpu_node_total_show, NULL);
static struct kobj_attribute cpu_node_in_use_attr =
	__ATTR(in_use, 0444, cpu_node_in_use_show, NULL);
static struct kobj_attribute cpu_node_free_attr =
	__ATTR(free, 0444, cpu_node_free_show, NULL);

static struct attribute *ne_cpu_node_attrs[] = {
	&cpu_node_total_attr.attr,
	&cpu_node_in_use_attr.attr,
	&cpu_node_free_attr.attr,
	NULL,
};

static const struct attribute_group ne_cpu_node_attr_group = {
	.attrs = ne_cpu_node_attrs,
};

/**
 * ne_cpu_pool_sysfs_exit() - Tear down the cpu_pool/ sysfs subtree, including
 *			      every per-node subdirectory. Idempotent.
 */
static void ne_cpu_pool_sysfs_exit(void)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		if (ne_cpu_pool_node_kobj[nid]) {
			sysfs_remove_group(ne_cpu_pool_node_kobj[nid],
					   &ne_cpu_node_attr_group);
			kobject_put(ne_cpu_pool_node_kobj[nid]);
			ne_cpu_pool_node_kobj[nid] = NULL;
		}
	}

	if (ne_cpu_pool_kobj) {
		sysfs_remove_group(ne_cpu_pool_kobj, &ne_cpu_pool_attr_group);
		kobject_put(ne_cpu_pool_kobj);
		ne_cpu_pool_kobj = NULL;
	}
}

/**
 * ne_cpu_pool_sysfs_init() - Create /sys/class/misc/nitro_enclaves/cpu_pool/
 *			      with a global view and a node<N>/ subdirectory
 *			      per online NUMA node. Must be called after
 *			      misc_register().
 * Return: 0 on success, -errno on failure.
 */
static int ne_cpu_pool_sysfs_init(void)
{
	struct miscdevice *miscdev = ne_devs.ne_misc_dev;
	int nid, rc;

	ne_cpu_pool_kobj = kobject_create_and_add("cpu_pool",
						  &miscdev->this_device->kobj);
	if (!ne_cpu_pool_kobj)
		return -ENOMEM;

	rc = sysfs_create_group(ne_cpu_pool_kobj, &ne_cpu_pool_attr_group);
	if (rc)
		goto err;

	for_each_online_node(nid) {
		char name[16];

		snprintf(name, sizeof(name), "node%d", nid);
		ne_cpu_pool_node_kobj[nid] =
			kobject_create_and_add(name, ne_cpu_pool_kobj);
		if (!ne_cpu_pool_node_kobj[nid]) {
			rc = -ENOMEM;
			goto err;
		}

		rc = sysfs_create_group(ne_cpu_pool_node_kobj[nid],
					&ne_cpu_node_attr_group);
		if (rc)
			goto err;
	}

	return 0;

err:
	ne_cpu_pool_sysfs_exit();
	return rc;
}

/*
 * PCIE slot-accounting sysfs.
 *
 * Userspace capacity planners (EKS / ECS NIP schedulers) need to know
 * how many PCIE-mode enclaves a droplet can host and how many are
 * currently allocated, before deciding whether a launch will fit. Two
 * read-only files are exported at the misc device root:
 *
 *   /sys/class/misc/nitro_enclaves/pcie_slots_total
 *       The hypervisor-advertised slot cap (ne_pci_dev->max_pcie_slots,
 *       read from NE_REG_MAX_PCIE_SLOTS at probe). 0 means the droplet
 *       advertises no PCIE slot pool (legacy hypervisor, no PCIE enclaves).
 *
 *   /sys/class/misc/nitro_enclaves/pcie_slots_in_use
 *       The number of PCIE-mode enclaves currently allocated, counted
 *       live from the driver's enclaves_list. Legacy (non-PCIE)
 *       enclaves do not consume a PCIE slot and are not counted.
 */
static ssize_t pcie_slots_total_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;

	if (!ne_pci_dev)
		return -ENODEV;

	return sysfs_emit(buf, "%u\n", ne_pci_dev->max_pcie_slots);
}

static ssize_t pcie_slots_in_use_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct ne_enclave *ne_enclave;
	unsigned int in_use = 0;

	if (!ne_pci_dev)
		return -ENODEV;

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);
	list_for_each_entry(ne_enclave, &ne_pci_dev->enclaves_list,
			    enclave_list_entry)
		if (ne_enclave->pcie_mode)
			in_use++;
	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	return sysfs_emit(buf, "%u\n", in_use);
}

/*
 * pcie_slots (RW): the unified, user-facing PCIE slot limit.
 *
 * Read: query the device via GET_SLOT_LIMITS, return min(pcie_current_limit,
 * system_ram_current_slots). Write N: loop donating (system-RAM 128 MiB
 * chunks + 2 MiB metadata pages), re-querying GET_SLOT_LIMITS each
 * iteration, until the effective limit >= N or a donation fails.
 *   N > max_pcie_slots   → -EINVAL (above hypervisor hard cap)
 *   N < current limit    → -EINVAL (no shrink)
 *   N == current limit   → 0       (no-op)
 *   donation exhausted   → -ENOMEM
 */
static ssize_t pcie_slots_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct ne_pci_dev_cmd_reply reply;
	struct pci_dev *pdev;
	u32 effective;
	int rc;

	if (!ne_pci_dev || !ne_pci_dev->pdev)
		return -ENODEV;
	pdev = ne_pci_dev->pdev;

	rc = ne_get_slot_limits(pdev, &reply);
	if (rc)
		return rc;

	effective = min_t(u32, reply.slot_limits.pcie_current_limit,
			  reply.slot_limits.system_ram_current_slots);
	return sysfs_emit(buf, "%u\n", effective);
}

static ssize_t pcie_slots_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct ne_pci_dev *ne_pci_dev = ne_devs.ne_pci_dev;
	struct ne_pci_dev_cmd_reply reply;
	struct pci_dev *pdev;
	u32 target, effective;
	int rc;

	if (!ne_pci_dev || !ne_pci_dev->pdev)
		return -ENODEV;
	pdev = ne_pci_dev->pdev;

	rc = kstrtou32(buf, 0, &target);
	if (rc)
		return rc;

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);

	if (target > ne_pci_dev->max_pcie_slots) {
		rc = -EINVAL;
		goto out;
	}

	rc = ne_get_slot_limits(pdev, &reply);
	if (rc)
		goto out;

	effective = min_t(u32, reply.slot_limits.pcie_current_limit,
			  reply.slot_limits.system_ram_current_slots);
	if (target < effective) {
		rc = -EINVAL;		/* shrink unsupported */
		goto out;
	}
	if (target == effective) {
		rc = 0;
		goto out;
	}

	/* Grow both pools until effective limit >= target. */
	while (effective < target) {
		/* Ensure the base page (carve sink) is donated once. */
		if (reply.slot_limits.pcie_current_limit == 0) {
			rc = ne_pcie_base_donate(pdev);
			if (rc)
				goto out;
		}

		/* Grow 128 MiB memory pool if that's the bottleneck. */
		if (reply.slot_limits.system_ram_current_slots <= reply.slot_limits.pcie_current_limit) {
			rc = ne_system_ram_donate_one(pdev);
			if (rc)
				goto out;
		}

		/* Grow 2 MiB metadata pool if that's the bottleneck. */
		if (reply.slot_limits.pcie_current_limit <= reply.slot_limits.system_ram_current_slots) {
			rc = ne_pcie_slot_donate_one(pdev);
			if (rc)
				goto out;
		}

		rc = ne_get_slot_limits(pdev, &reply);
		if (rc)
			goto out;

		effective = min_t(u32, reply.slot_limits.pcie_current_limit,
				  reply.slot_limits.system_ram_current_slots);
	}

	rc = 0;
out:
	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);
	return rc ? rc : count;
}

static struct kobj_attribute pcie_slots_total_attr =
	__ATTR(pcie_slots_total, 0444, pcie_slots_total_show, NULL);
static struct kobj_attribute pcie_slots_in_use_attr =
	__ATTR(pcie_slots_in_use, 0444, pcie_slots_in_use_show, NULL);
static struct kobj_attribute pcie_slots_attr =
	__ATTR(pcie_slots, 0644, pcie_slots_show, pcie_slots_store);

static struct attribute *ne_slots_attrs[] = {
	&pcie_slots_total_attr.attr,
	&pcie_slots_in_use_attr.attr,
	&pcie_slots_attr.attr,
	NULL,
};

static const struct attribute_group ne_slots_attr_group = {
	.attrs = ne_slots_attrs,
};

/**
 * ne_slots_init() - Create the pcie_slots_total / pcie_slots_in_use
 *		     attributes at /sys/class/misc/nitro_enclaves/. Must be
 *		     called after misc_register().
 * Return: 0 on success, -errno on failure.
 */
static int ne_slots_init(void)
{
	return sysfs_create_group(&ne_devs.ne_misc_dev->this_device->kobj,
				  &ne_slots_attr_group);
}

/**
 * ne_slots_exit() - Remove the slot-accounting attributes. Must be called
 *		     before misc_deregister().
 */
static void ne_slots_exit(void)
{
	sysfs_remove_group(&ne_devs.ne_misc_dev->this_device->kobj,
			   &ne_slots_attr_group);
}

/*
 * mem_pool/ sysfs tree: visibility into the NE CMA memory pool that backs
 * enclave donation, DMB, and info-page allocations. Like the CPU pool it can
 * be exhausted per NUMA node (ne_alloc_contig filters regions by node), so a
 * global and a per-node view are exported, in bytes:
 *
 *   /sys/class/misc/nitro_enclaves/mem_pool/{total,in_use,free}
 *   /sys/class/misc/nitro_enclaves/mem_pool/node<N>/{total,in_use,free}
 *
 * A per-node view sums the CMA regions on that node. A region reserved without
 * an explicit @nid has no recorded node, so it is attributed to the node of its
 * base address (ne_cma_node()); every region lands in exactly one bucket and the
 * per-node totals sum to the global total. A node<N>/ directory is created for
 * every online NUMA node; nodes with no pool memory report zero.
 */
static struct kobject *ne_mem_pool_kobj;
static struct kobject *ne_mem_pool_node_kobj[MAX_NUMNODES];

static ssize_t mem_pool_total_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	u64 total, in_use, free_bytes;

	ne_mem_pool_get_stats(NUMA_NO_NODE, &total, &in_use, &free_bytes);
	return sysfs_emit(buf, "%llu\n", total);
}

static ssize_t mem_pool_in_use_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	u64 total, in_use, free_bytes;

	ne_mem_pool_get_stats(NUMA_NO_NODE, &total, &in_use, &free_bytes);
	return sysfs_emit(buf, "%llu\n", in_use);
}

static ssize_t mem_pool_free_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	u64 total, in_use, free_bytes;

	ne_mem_pool_get_stats(NUMA_NO_NODE, &total, &in_use, &free_bytes);
	return sysfs_emit(buf, "%llu\n", free_bytes);
}

static struct kobj_attribute mem_pool_total_attr =
	__ATTR(total, 0444, mem_pool_total_show, NULL);
static struct kobj_attribute mem_pool_in_use_attr =
	__ATTR(in_use, 0444, mem_pool_in_use_show, NULL);
static struct kobj_attribute mem_pool_free_attr =
	__ATTR(free, 0444, mem_pool_free_show, NULL);

static struct attribute *ne_mem_pool_attrs[] = {
	&mem_pool_total_attr.attr,
	&mem_pool_in_use_attr.attr,
	&mem_pool_free_attr.attr,
	NULL,
};

static const struct attribute_group ne_mem_pool_attr_group = {
	.attrs = ne_mem_pool_attrs,
};

static ssize_t mem_node_total_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	u64 total, in_use, free_bytes;

	ne_mem_pool_get_stats(ne_pool_kobj_nid(kobj), &total, &in_use,
			      &free_bytes);
	return sysfs_emit(buf, "%llu\n", total);
}

static ssize_t mem_node_in_use_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	u64 total, in_use, free_bytes;

	ne_mem_pool_get_stats(ne_pool_kobj_nid(kobj), &total, &in_use,
			      &free_bytes);
	return sysfs_emit(buf, "%llu\n", in_use);
}

static ssize_t mem_node_free_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	u64 total, in_use, free_bytes;

	ne_mem_pool_get_stats(ne_pool_kobj_nid(kobj), &total, &in_use,
			      &free_bytes);
	return sysfs_emit(buf, "%llu\n", free_bytes);
}

static struct kobj_attribute mem_node_total_attr =
	__ATTR(total, 0444, mem_node_total_show, NULL);
static struct kobj_attribute mem_node_in_use_attr =
	__ATTR(in_use, 0444, mem_node_in_use_show, NULL);
static struct kobj_attribute mem_node_free_attr =
	__ATTR(free, 0444, mem_node_free_show, NULL);

static struct attribute *ne_mem_node_attrs[] = {
	&mem_node_total_attr.attr,
	&mem_node_in_use_attr.attr,
	&mem_node_free_attr.attr,
	NULL,
};

static const struct attribute_group ne_mem_node_attr_group = {
	.attrs = ne_mem_node_attrs,
};

/**
 * ne_mem_pool_sysfs_exit() - Tear down the mem_pool/ sysfs subtree, including
 *			      every per-node subdirectory. Idempotent.
 */
static void ne_mem_pool_sysfs_exit(void)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		if (ne_mem_pool_node_kobj[nid]) {
			sysfs_remove_group(ne_mem_pool_node_kobj[nid],
					   &ne_mem_node_attr_group);
			kobject_put(ne_mem_pool_node_kobj[nid]);
			ne_mem_pool_node_kobj[nid] = NULL;
		}
	}

	if (ne_mem_pool_kobj) {
		sysfs_remove_group(ne_mem_pool_kobj, &ne_mem_pool_attr_group);
		kobject_put(ne_mem_pool_kobj);
		ne_mem_pool_kobj = NULL;
	}
}

/**
 * ne_mem_pool_sysfs_init() - Create /sys/class/misc/nitro_enclaves/mem_pool/
 *			      with a global view and a node<N>/ subdirectory
 *			      per online NUMA node. Must be called after
 *			      misc_register().
 * Return: 0 on success, -errno on failure.
 */
static int ne_mem_pool_sysfs_init(void)
{
	struct miscdevice *miscdev = ne_devs.ne_misc_dev;
	int nid, rc;

	ne_mem_pool_kobj = kobject_create_and_add("mem_pool",
						  &miscdev->this_device->kobj);
	if (!ne_mem_pool_kobj)
		return -ENOMEM;

	rc = sysfs_create_group(ne_mem_pool_kobj, &ne_mem_pool_attr_group);
	if (rc)
		goto err;

	for_each_online_node(nid) {
		char name[16];

		snprintf(name, sizeof(name), "node%d", nid);
		ne_mem_pool_node_kobj[nid] =
			kobject_create_and_add(name, ne_mem_pool_kobj);
		if (!ne_mem_pool_node_kobj[nid]) {
			rc = -ENOMEM;
			goto err;
		}

		rc = sysfs_create_group(ne_mem_pool_node_kobj[nid],
					&ne_mem_node_attr_group);
		if (rc)
			goto err;
	}

	return 0;

err:
	ne_mem_pool_sysfs_exit();
	return rc;
}

/**
 * ne_pci_probe() - Probe function for the NE PCI device.
 * @pdev:	PCI device to match with the NE PCI driver.
 * @id :	PCI device id table associated with the NE PCI driver.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;

	ne_pci_dev = kzalloc(sizeof(*ne_pci_dev), GFP_KERNEL);
	if (!ne_pci_dev)
		return -ENOMEM;

	rc = pci_enable_device(pdev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in pci dev enable [rc=%d]\n", rc);

		goto free_ne_pci_dev;
	}

	pci_set_master(pdev);

	rc = pci_request_regions_exclusive(pdev, "nitro_enclaves");
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in pci request regions [rc=%d]\n", rc);

		goto disable_pci_dev;
	}

	ne_pci_dev->iomem_base = pci_iomap(pdev, PCI_BAR_NE, 0);
	if (!ne_pci_dev->iomem_base) {
		rc = -ENOMEM;

		dev_err(&pdev->dev, "Error in pci iomap [rc=%d]\n", rc);

		goto release_pci_regions;
	}

	/* Map BAR4 notify window for enclave device kicks (optional) */
	ne_pci_dev->notify_base = pci_iomap(pdev, NE_NOTIFY_BAR, 0);
	if (!ne_pci_dev->notify_base) {
		ne_pci_dev->notify_len = 0;
		dev_info(&pdev->dev, "No notify BAR4, virtqueue kicks unavailable\n");
	} else {
		/*
		 * Cache the BAR4 length so ne_set_vring_call() can bound the
		 * caller-supplied bar4_doorbell_offset against the mapping.
		 * pci_resource_len() reads from the same BAR registers
		 * pci_iomap() consumed, so the value is stable for the
		 * lifetime of the mapping.
		 */
		ne_pci_dev->notify_len = pci_resource_len(pdev, NE_NOTIFY_BAR);
		dev_info(&pdev->dev, "BAR4 notify mapped at %px (resource %pR, len %llu)\n",
			 ne_pci_dev->notify_base,
			 &pdev->resource[NE_NOTIFY_BAR],
			 (unsigned long long)ne_pci_dev->notify_len);
	}

	pci_set_drvdata(pdev, ne_pci_dev);

	rc = ne_setup_msix(pdev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in pci dev msix setup [rc=%d]\n", rc);

		goto iounmap_pci_bar;
	}

	ne_pci_dev_disable(pdev);

	rc = ne_pci_dev_enable(pdev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in ne_pci_dev enable [rc=%d]\n", rc);

		goto teardown_msix;
	}

	rc = ne_mux_setup(pdev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in mux setup [rc=%d]\n", rc);

		goto disable_ne_pci_dev;
	}

	rc = ne_info_events_probe(pdev);
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Error in info-events probe [rc=%d]\n", rc);
		goto teardown_mux;
	}

	atomic_set(&ne_pci_dev->cmd_reply_avail, 0);
	init_waitqueue_head(&ne_pci_dev->cmd_reply_wait_q);
	INIT_LIST_HEAD(&ne_pci_dev->enclaves_list);
	mutex_init(&ne_pci_dev->enclaves_list_mutex);
	mutex_init(&ne_pci_dev->pci_dev_mutex);
	ne_pci_dev->pdev = pdev;

	ne_devs.ne_pci_dev = ne_pci_dev;

	/* Read PCIE slot pool geometry. No donation happens here:
	 * slot pages are donated lazily on NE_CREATE_VM -ENOSPC. Must
	 * follow pci_dev_mutex init so ne_do_request() can run from
	 * the lazy-donate path. */
	ne_pcie_slot_probe_init(pdev);

	ne_pci_dev->nie_enabled = !!ioread32(ne_pci_dev->iomem_base +
					     NE_REG_NIE_ENABLED);
	if (ne_pci_dev->nie_enabled) {
		ne_pci_dev->nie_pages_needed = ioread32(ne_pci_dev->iomem_base +
						       NE_REG_NIE_PAGES_NEEDED);
		dev_info(&pdev->dev, "NIE detected: %u pages needed for metadata\n",
			 ne_pci_dev->nie_pages_needed);
	}
	ne_pci_dev->sharing_ops = ne_init_mem_sharing(ne_pci_dev);

	/* Size the slot-page tracking arrays to hold the eager NIE metadata
	 * pool (nie_pages_needed) plus room for later lazy NE_CREATE_VM
	 * slot-pool growth (bounded by max_pcie_slots). On QEMU the pool was a
	 * handful of pages, but on real Graviton nie_pages_needed reaches
	 * thousands; the old fixed [32] array overflowed and every donation
	 * past page 32 failed with -ENOMEM, blocking enclave creation under
	 * NIE. */
	if (ne_pci_dev->max_pcie_slots) {
		u32 cap = ne_pci_dev->nie_pages_needed +
			  ne_pci_dev->max_pcie_slots;

		ne_pci_dev->pcie_slot_pages =
			kvcalloc(cap, sizeof(*ne_pci_dev->pcie_slot_pages),
				 GFP_KERNEL);
		ne_pci_dev->pcie_slot_cmas =
			kvcalloc(cap, sizeof(*ne_pci_dev->pcie_slot_cmas),
				 GFP_KERNEL);
		if (!ne_pci_dev->pcie_slot_pages || !ne_pci_dev->pcie_slot_cmas) {
			dev_warn(&pdev->dev,
				 "PCIE slot: failed to allocate %u-entry page-tracking arrays; slot donation disabled\n",
				 cap);
			kvfree(ne_pci_dev->pcie_slot_pages);
			kvfree(ne_pci_dev->pcie_slot_cmas);
			ne_pci_dev->pcie_slot_pages = NULL;
			ne_pci_dev->pcie_slot_cmas = NULL;
			ne_pci_dev->pcie_slot_pages_cap = 0;
		} else {
			ne_pci_dev->pcie_slot_pages_cap = cap;
		}
	}

	/* Eagerly establish the baseline pcie_slots limit at probe so a freshly
	 * probed driver (cold boot or post-kexec re-probe) deterministically
	 * advertises the FREE_BASE memory slots, instead of reading 0 until the
	 * first lazy NE_CREATE_VM donation. The hypervisor rejects slot-metadata
	 * donations until the base sink page is present, so commit the base
	 * first, then the first 2 MiB metadata chunk that backs the free slots.
	 * No system-RAM donation here: with zero memory donations the budget
	 * floor is FREE_BASE, so min(metadata, FREE_BASE) = FREE_BASE = the
	 * deterministic baseline. Best-effort: on failure the lazy
	 * NE_CREATE_VM -ENOSPC path still covers it. */
	if (ne_pci_dev->max_pcie_slots) {
		int drc;

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);
		drc = ne_pcie_base_donate(pdev);
		if (!drc && ne_pci_dev->nie_pages_needed) {
			u32 i;

			for (i = 0; i < ne_pci_dev->nie_pages_needed; i++) {
				drc = ne_pcie_slot_donate_one(pdev);
				if (drc) {
					dev_err(&pdev->dev,
						"NIE probe: donate failed at page %u/%u (rc=%d)\n",
						i, ne_pci_dev->nie_pages_needed, drc);
					break;
				}
			}
			if (!drc)
				dev_info(&pdev->dev,
					 "NIE probe: donated %u metadata pages\n", i);
		}
		/* One more to seed the slot pool. */
		if (!drc)
			drc = ne_pcie_slot_donate_one(pdev);
		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);
		if (drc)
			dev_warn(&pdev->dev,
				 "PCIE slot: initial base/metadata donation failed (rc=%d); retried lazily while a reserved pool exists\n",
				 drc);
	}

	/* Only now does the parent have an SRT for Guest.Share to record in. */
	ne_mux_share_bitmaps(pdev);

	rc = misc_register(ne_devs.ne_misc_dev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in misc dev register [rc=%d]\n", rc);

		goto teardown_mux;
	}

	rc = ne_device_pool_init();
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in device pool sysfs init [rc=%d]\n", rc);

		goto deregister_misc;
	}

	rc = ne_slots_init();
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in slot-accounting sysfs init [rc=%d]\n", rc);

		goto pool_exit;
	}

	rc = ne_cpu_pool_sysfs_init();
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in cpu_pool sysfs init [rc=%d]\n", rc);

		goto slots_exit;
	}

	rc = ne_mem_pool_sysfs_init();
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in mem_pool sysfs init [rc=%d]\n", rc);

		goto cpu_pool_exit;
	}

	return 0;

cpu_pool_exit:
	ne_cpu_pool_sysfs_exit();
slots_exit:
	ne_slots_exit();
pool_exit:
	ne_device_pool_exit();
deregister_misc:
	misc_deregister(ne_devs.ne_misc_dev);
teardown_mux:
	ne_devs.ne_pci_dev = NULL;
	ne_mux_debugfs_exit(ne_pci_dev);
	if (ne_pci_dev->mux)
		unregister_reboot_notifier(&ne_pci_dev->shutdown_nb);
	ne_mux_teardown(pdev);
disable_ne_pci_dev:
	ne_devs.ne_pci_dev = NULL;
	ne_pci_dev_disable(pdev);
teardown_msix:
	ne_teardown_msix(pdev);
iounmap_pci_bar:
	pci_set_drvdata(pdev, NULL);
	pci_iounmap(pdev, ne_pci_dev->iomem_base);
release_pci_regions:
	pci_release_regions(pdev);
disable_pci_dev:
	pci_disable_device(pdev);
free_ne_pci_dev:
	kvfree(ne_pci_dev->pcie_slot_pages);
	kvfree(ne_pci_dev->pcie_slot_cmas);
	kfree(ne_pci_dev);

	return rc;
}

/**
 * ne_pci_dev_teardown() - Common teardown shared by remove and shutdown.
 * @pdev:	PCI device associated with the NE PCI driver.
 *
 * Reverses the resource acquisition in ne_pci_probe(). Both the remove and
 * shutdown paths must run all of this: skipping any of the per-device
 * teardown steps in shutdown leaks state that the kernel later complains
 * about.
 *
 * Context: Process context.
 */
static void ne_pci_dev_teardown(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	/*
	 * Remove the debugfs tree first, mirroring the probe-error ordering.
	 * The "kicks"/"mux_vectors" files carry s->private == ne_pci_dev, and
	 * ne_mux_teardown() below frees the surviving bindings synchronously
	 * (and this function later kfree()s ne_pci_dev itself).
	 * debugfs_remove_recursive() drains any in-flight ne_kicks_show()/
	 * ne_mux_vectors_show() reader before it returns, so no reader can be
	 * walking kick_xa or dereferencing ne_pci_dev once the frees happen.
	 */
	ne_mux_debugfs_exit(ne_pci_dev);

	if (ne_pci_dev->mux)
		unregister_reboot_notifier(&ne_pci_dev->shutdown_nb);
	ne_mux_teardown(pdev);

	ne_pci_dev_disable(pdev);

	ne_teardown_msix(pdev);

	pci_set_drvdata(pdev, NULL);

	pci_iounmap(pdev, ne_pci_dev->iomem_base);

	pci_release_regions(pdev);

	pci_disable_device(pdev);

	kvfree(ne_pci_dev->pcie_slot_pages);
	kvfree(ne_pci_dev->pcie_slot_cmas);
	kfree(ne_pci_dev);
}

/**
 * ne_pci_remove() - Remove function for the NE PCI device.
 * @pdev:	PCI device associated with the NE PCI driver.
 *
 * Context: Process context.
 */
static void ne_pci_remove(struct pci_dev *pdev)
{
	ne_mem_pool_sysfs_exit();

	ne_cpu_pool_sysfs_exit();

	ne_slots_exit();

	ne_device_pool_exit();

	misc_deregister(ne_devs.ne_misc_dev);

	ne_devs.ne_pci_dev = NULL;

	ne_pci_dev_teardown(pdev);
}

/**
 * ne_pci_shutdown() - Shutdown function for the NE PCI device.
 * @pdev:	PCI device associated with the NE PCI driver.
 *
 * Context: Process context.
 */
static void ne_pci_shutdown(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	if (!ne_pci_dev)
		return;

	ne_mem_pool_sysfs_exit();

	ne_cpu_pool_sysfs_exit();

	ne_slots_exit();

	ne_device_pool_exit();

	misc_deregister(ne_devs.ne_misc_dev);

	ne_devs.ne_pci_dev = NULL;

	ne_pci_dev_teardown(pdev);
}

/*
 * TODO: Add suspend / resume functions for power management w/ CONFIG_PM, if
 * needed.
 */
/* NE PCI device driver. */
struct pci_driver ne_pci_driver = {
	.name		= "nitro_enclaves",
	.id_table	= ne_pci_ids,
	.probe		= ne_pci_probe,
	.remove		= ne_pci_remove,
	.shutdown	= ne_pci_shutdown,
};
