// SPDX-License-Identifier: GPL-2.0-only
/*
 * virtio transport for vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 *
 * Some of the code is take from Gerd Hoffmann <kraxel@redhat.com>'s
 * early virtio-vsock proof-of-concept bits.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/atomic.h>
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
#include <linux/genalloc.h>
#endif
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_vsock.h>
#include <net/sock.h>
#include <linux/mutex.h>
#include <net/af_vsock.h>

static struct workqueue_struct *virtio_vsock_workqueue;
static struct virtio_vsock __rcu *the_virtio_vsock;
static DEFINE_MUTEX(the_virtio_vsock_mutex); /* protects the_virtio_vsock */
static struct virtio_transport virtio_transport; /* forward declaration */

static int rx_buf_size = -1;
module_param(rx_buf_size, int, 0444);
MODULE_PARM_DESC(rx_buf_size,
	"Size of RX buffers posted to the virtqueue. Larger values reduce "
	"per-packet descriptor overhead for bulk transfers at the cost of "
	"memory. Range: 128 to 65536. Default: ~4K (VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE).");

#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
static int dmb_rx_zc_pct = 50;
module_param(dmb_rx_zc_pct, int, 0444);
MODULE_PARM_DESC(dmb_rx_zc_pct,
	"Percentage of DMB pool dedicated to zero-copy RX buffers. "
	"Remaining pool is available for TX zero-copy. Range: 0-100. Default: 50.");

/*
 * Heap-backed (bounced) RX buffers kept posted on the DMB zero-copy RX
 * virtqueue as a liveness floor.  One is sufficient: it is harvested and
 * re-posted within the same rx_work pass, so the RX vq never drains to
 * empty even when a slow reader has pinned every zero-copy slot.
 */
#define VIRTIO_VSOCK_RX_BOUNCE_FLOOR 1
#endif

struct virtio_vsock {
	struct virtio_device *vdev;
	struct virtqueue *vqs[VSOCK_VQ_MAX];
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
	bool dmb_active;
	size_t dmb_slot_size;		/* aligned buffer size for budget */
	size_t tx_pool_min;		/* min pool avail kept for TX */
	size_t rx_pool_min;		/* min pool avail kept for RX */
	int rx_zc_max;			/* max RX ZC buffers in VQ */
	int rx_zc_posted;		/* ZC buffers currently in VQ */
	size_t rx_bounce_reserve;	/* pool bytes kept free for the floor */
	int rx_bounce_posted;		/* bounced (heap) RX buffers in VQ */
#endif

	/* Virtqueue processing is deferred to a workqueue */
	struct work_struct tx_work;
	struct work_struct rx_work;
	struct work_struct event_work;

	/* The following fields are protected by tx_lock.  vqs[VSOCK_VQ_TX]
	 * must be accessed with tx_lock held.
	 */
	struct mutex tx_lock;
	bool tx_run;

	struct work_struct send_pkt_work;
	struct sk_buff_head send_pkt_queue;

	atomic_t queued_replies;

	/* The following fields are protected by rx_lock.  vqs[VSOCK_VQ_RX]
	 * must be accessed with rx_lock held.
	 */
	struct mutex rx_lock;
	bool rx_run;
	int rx_buf_nr;
	int rx_buf_max_nr;

	/* The following fields are protected by event_lock.
	 * vqs[VSOCK_VQ_EVENT] must be accessed with event_lock held.
	 */
	struct mutex event_lock;
	bool event_run;
	struct virtio_vsock_event event_list[8];

	u32 guest_cid;
	bool seqpacket_allow;

	/* These fields are used only in tx path in function
	 * 'virtio_transport_send_pkt_work()', so to save
	 * stack space in it, place both of them here. Each
	 * pointer from 'out_sgs' points to the corresponding
	 * element in 'out_bufs' - this is initialized in
	 * 'virtio_vsock_probe()'. Both fields are protected
	 * by 'tx_lock'. +1 is needed for packet header.
	 */
	struct scatterlist *out_sgs[MAX_SKB_FRAGS + 1];
	struct scatterlist out_bufs[MAX_SKB_FRAGS + 1];
};

static u32 virtio_transport_get_local_cid(void)
{
	struct virtio_vsock *vsock;
	u32 ret;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		ret = VMADDR_CID_ANY;
		goto out_rcu;
	}

	ret = vsock->guest_cid;
out_rcu:
	rcu_read_unlock();
	return ret;
}

/* Caller need to hold vsock->tx_lock on vq */
static int virtio_transport_send_skb(struct sk_buff *skb, struct virtqueue *vq,
				     struct virtio_vsock *vsock, gfp_t gfp)
{
	int ret, in_sg = 0, out_sg = 0;
	struct scatterlist **sgs;

#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
	/*
	 * DMB-allocated SKBs use premapped submission: the buffer is already
	 * in shared memory, so we set sg_dma_address directly and bypass the
	 * DMA mapping layer entirely.  Non-DMB SKBs (fallback) use the
	 * standard path which bounces through vp_dmb_map_page.
	 */
	if (skb->dmb_head) {
		struct scatterlist dmb_sgs[2];
		void *hdr = virtio_vsock_hdr(skb);
		int num_sg = 0;

		if (skb->len > 0) {
			sg_init_table(dmb_sgs, 2);
			sg_set_buf(&dmb_sgs[0], hdr,
				   sizeof(struct virtio_vsock_hdr));
			sg_dma_address(&dmb_sgs[0]) =
				virtio_dmb_virt_to_dma(vsock->vdev, hdr);
			sg_dma_len(&dmb_sgs[0]) =
				sizeof(struct virtio_vsock_hdr);
			sg_set_buf(&dmb_sgs[1], skb->data, skb->len);
			sg_dma_address(&dmb_sgs[1]) =
				virtio_dmb_virt_to_dma(vsock->vdev,
						       skb->data);
			sg_dma_len(&dmb_sgs[1]) = skb->len;
			num_sg = 2;
		} else {
			sg_init_one(&dmb_sgs[0], hdr,
				    sizeof(struct virtio_vsock_hdr));
			sg_dma_address(&dmb_sgs[0]) =
				virtio_dmb_virt_to_dma(vsock->vdev, hdr);
			sg_dma_len(&dmb_sgs[0]) =
				sizeof(struct virtio_vsock_hdr);
			num_sg = 1;
		}

		ret = virtqueue_add_outbuf_premapped(vq, dmb_sgs, num_sg,
						     skb, gfp);
		if (ret < 0)
			return ret;
		virtio_transport_deliver_tap_pkt(skb);
		return 0;
	}
#endif

	sgs = vsock->out_sgs;
	sg_init_one(sgs[out_sg], virtio_vsock_hdr(skb),
		    sizeof(*virtio_vsock_hdr(skb)));
	out_sg++;

	if (!skb_is_nonlinear(skb)) {
		if (skb->len > 0) {
			sg_init_one(sgs[out_sg], skb->data, skb->len);
			out_sg++;
		}
	} else {
		struct skb_shared_info *si;
		int i;

		/* If skb is nonlinear, then its buffer must contain
		 * only header and nothing more. Data is stored in
		 * the fragged part.
		 */
		WARN_ON_ONCE(skb_headroom(skb) != sizeof(*virtio_vsock_hdr(skb)));

		si = skb_shinfo(skb);

		for (i = 0; i < si->nr_frags; i++) {
			skb_frag_t *skb_frag = &si->frags[i];
			void *va;

			/* We will use 'page_to_virt()' for the userspace page
			 * here, because virtio or dma-mapping layers will call
			 * 'virt_to_phys()' later to fill the buffer descriptor.
			 * We don't touch memory at "virtual" address of this page.
			 */
			va = page_to_virt(skb_frag_page(skb_frag));
			sg_init_one(sgs[out_sg],
				    va + skb_frag_off(skb_frag),
				    skb_frag_size(skb_frag));
			out_sg++;
		}
	}

	ret = virtqueue_add_sgs(vq, sgs, out_sg, in_sg, skb, gfp);
	/* Usually this means that there is no more space available in
	 * the vq
	 */
	if (ret < 0)
		return ret;

	virtio_transport_deliver_tap_pkt(skb);
	return 0;
}

static void
virtio_transport_send_pkt_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, send_pkt_work);
	struct virtqueue *vq;
	bool added = false;
	bool restart_rx = false;

	mutex_lock(&vsock->tx_lock);

	if (!vsock->tx_run)
		goto out;

	vq = vsock->vqs[VSOCK_VQ_TX];

	for (;;) {
		struct sk_buff *skb;
		bool reply;
		int ret;

		skb = virtio_vsock_skb_dequeue(&vsock->send_pkt_queue);
		if (!skb)
			break;

		reply = virtio_vsock_skb_reply(skb);

		ret = virtio_transport_send_skb(skb, vq, vsock, GFP_KERNEL);
		if (ret < 0) {
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue, skb);
			break;
		}

		if (reply) {
			struct virtqueue *rx_vq = vsock->vqs[VSOCK_VQ_RX];
			int val;

			val = atomic_dec_return(&vsock->queued_replies);

			/* Do we now have resources to resume rx processing? */
			if (val + 1 == virtqueue_get_vring_size(rx_vq))
				restart_rx = true;
		}

		added = true;
	}

	if (added)
		virtqueue_kick(vq);

out:
	mutex_unlock(&vsock->tx_lock);

	if (restart_rx)
		queue_work(virtio_vsock_workqueue, &vsock->rx_work);
}

/* Caller need to hold RCU for vsock.
 * Returns 0 if the packet is successfully put on the vq.
 */
static int virtio_transport_send_skb_fast_path(struct virtio_vsock *vsock, struct sk_buff *skb)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_TX];
	int ret;

	/* Inside RCU, can't sleep! */
	ret = mutex_trylock(&vsock->tx_lock);
	if (unlikely(ret == 0))
		return -EBUSY;

	ret = virtio_transport_send_skb(skb, vq, vsock, GFP_ATOMIC);
	if (ret == 0) {
		pr_debug("virtio_transport: fast_path kick VQ TX\n");
		virtqueue_kick(vq);
	} else {
		pr_debug("virtio_transport: fast_path send_skb failed ret=%d\n", ret);
	}

	mutex_unlock(&vsock->tx_lock);

	return ret;
}

static int
virtio_transport_send_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr;
	struct virtio_vsock *vsock;
	int len = skb->len;

	hdr = virtio_vsock_hdr(skb);

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		pr_debug("virtio_transport_send_pkt: no vsock device\n");
		kfree_skb(skb);
		len = -ENODEV;
		goto out_rcu;
	}

	if (le64_to_cpu(hdr->dst_cid) == vsock->guest_cid) {
		pr_debug("virtio_transport_send_pkt: loopback drop dst_cid=%llu guest_cid=%u\n",
			le64_to_cpu(hdr->dst_cid), vsock->guest_cid);
		kfree_skb(skb);
		len = -ENODEV;
		goto out_rcu;
	}

	pr_debug("virtio_transport_send_pkt: sending op=%u src=%u:%u dst=%llu:%u len=%d\n",
		le16_to_cpu(hdr->op),
		vsock->guest_cid, le32_to_cpu(hdr->src_port),
		le64_to_cpu(hdr->dst_cid), le32_to_cpu(hdr->dst_port), len);

	/* If send_pkt_queue is empty, we can safely bypass this queue
	 * because packet order is maintained and (try) to put the packet
	 * on the virtqueue using virtio_transport_send_skb_fast_path.
	 * If this fails we simply put the packet on the intermediate
	 * queue and schedule the worker.
	 */
	if (!skb_queue_empty_lockless(&vsock->send_pkt_queue) ||
	    virtio_transport_send_skb_fast_path(vsock, skb)) {
		if (virtio_vsock_skb_reply(skb))
			atomic_inc(&vsock->queued_replies);

		virtio_vsock_skb_queue_tail(&vsock->send_pkt_queue, skb);
		queue_work(virtio_vsock_workqueue, &vsock->send_pkt_work);
	}

out_rcu:
	rcu_read_unlock();
	return len;
}

static int
virtio_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct virtio_vsock *vsock;
	int cnt = 0, ret;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock) {
		ret = -ENODEV;
		goto out_rcu;
	}

	cnt = virtio_transport_purge_skbs(vsk, &vsock->send_pkt_queue);

	if (cnt) {
		struct virtqueue *rx_vq = vsock->vqs[VSOCK_VQ_RX];
		int new_cnt;

		new_cnt = atomic_sub_return(cnt, &vsock->queued_replies);
		if (new_cnt + cnt >= virtqueue_get_vring_size(rx_vq) &&
		    new_cnt < virtqueue_get_vring_size(rx_vq))
			queue_work(virtio_vsock_workqueue, &vsock->rx_work);
	}

	ret = 0;

out_rcu:
	rcu_read_unlock();
	return ret;
}

static void virtio_vsock_rx_fill(struct virtio_vsock *vsock);

static int virtio_vsock_rx_buf_len(void)
{
	return (rx_buf_size > 0)
		? clamp_t(int, rx_buf_size, 128, VIRTIO_VSOCK_MAX_PKT_BUF_SIZE)
		: VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE;
}

static int virtio_vsock_rx_post_one(struct virtio_vsock *vsock,
				    struct virtqueue *vq, int total_len)
{
	struct scatterlist pkt, *p;
	struct sk_buff *skb;
	int ret;

	skb = virtio_vsock_alloc_linear_skb(total_len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	memset(skb->head, 0, VIRTIO_VSOCK_SKB_HEADROOM);
	sg_init_one(&pkt, virtio_vsock_hdr(skb), total_len);
	p = &pkt;
	ret = virtqueue_add_sgs(vq, &p, 0, 1, skb, GFP_KERNEL);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	vsock->rx_buf_nr++;
	return 0;
}

#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
static void virtio_vsock_rx_fill_dmb(struct virtio_vsock *vsock)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_RX];
	int total_len = virtio_vsock_rx_buf_len();
	size_t slot_size = vsock->dmb_slot_size;
	int ret;

	while (vq->num_free && vsock->rx_zc_posted < vsock->rx_zc_max) {
		struct scatterlist sg;
		struct sk_buff *skb;
		dma_addr_t dma;
		void *buf;

		if (virtio_dmb_avail(vsock->vdev) <=
		    vsock->tx_pool_min + vsock->rx_bounce_reserve)
			break;

		buf = virtio_dmb_alloc(vsock->vdev, slot_size);
		if (!buf)
			break;

		skb = __build_skb(buf, slot_size);
		if (!skb) {
			virtio_dmb_free(vsock->vdev, buf, slot_size);
			break;
		}

		skb->dmb_head = 1;
		skb->unreadable = 1;
		BUILD_BUG_ON(sizeof(struct dmb_skb_free_cb) +
			     sizeof(struct virtio_vsock_skb_cb) > 48);
		DMB_SKB_FREE_CB(skb)->vdev = vsock->vdev;
		DMB_SKB_FREE_CB(skb)->data = buf;
		DMB_SKB_FREE_CB(skb)->size = slot_size;
		DMB_SKB_FREE_CB(skb)->safe_hdr = NULL;

		skb_reserve(skb, VIRTIO_VSOCK_SKB_HEADROOM);

		dma = virtio_dmb_virt_to_dma(vsock->vdev, buf);
		sg_init_one(&sg, buf, total_len);
		sg_dma_address(&sg) = dma;
		sg_dma_len(&sg) = total_len;

		ret = virtqueue_add_inbuf_premapped(vq, &sg, 1, skb,
						    NULL, GFP_KERNEL);
		if (ret < 0) {
			kfree_skb(skb);
			break;
		}

		vsock->rx_zc_posted++;
		vsock->rx_buf_nr++;
	}

	if (vsock->rx_buf_nr > vsock->rx_buf_max_nr)
		vsock->rx_buf_max_nr = vsock->rx_buf_nr;
	virtqueue_kick(vq);
}

/* Replenish heap-backed bounce floor (see VIRTIO_VSOCK_RX_BOUNCE_FLOOR). */
static void virtio_vsock_rx_fill_bounce(struct virtio_vsock *vsock)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_RX];
	int total_len = virtio_vsock_rx_buf_len();
	bool added = false;

	while (vq->num_free &&
	       vsock->rx_bounce_posted < VIRTIO_VSOCK_RX_BOUNCE_FLOOR) {
		if (virtio_vsock_rx_post_one(vsock, vq, total_len) < 0)
			break;

		vsock->rx_bounce_posted++;
		added = true;

		if (vsock->rx_zc_posted >= vsock->rx_zc_max)
			dev_dbg(&vsock->vdev->dev,
				"all %d ZC RX slots pinned, bounce floor active\n",
				vsock->rx_zc_max);
	}

	if (added) {
		if (vsock->rx_buf_nr > vsock->rx_buf_max_nr)
			vsock->rx_buf_max_nr = vsock->rx_buf_nr;
		virtqueue_kick(vq);
	}
}
#else
static inline void virtio_vsock_rx_fill_dmb(struct virtio_vsock *vsock) {}
static inline void virtio_vsock_rx_fill_bounce(struct virtio_vsock *vsock) {}
#endif /* CONFIG_VIRTIO_DMB_ZEROCOPY */

static void virtio_vsock_rx_fill(struct virtio_vsock *vsock)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_RX];
	int total_len = virtio_vsock_rx_buf_len();

	do {
		if (virtio_vsock_rx_post_one(vsock, vq, total_len) < 0)
			break;
	} while (vq->num_free);
	if (vsock->rx_buf_nr > vsock->rx_buf_max_nr)
		vsock->rx_buf_max_nr = vsock->rx_buf_nr;
	virtqueue_kick(vq);
}

static void virtio_vsock_rx_refill(struct virtio_vsock *vsock, bool force)
{
	bool below_watermark = vsock->rx_buf_nr < vsock->rx_buf_max_nr / 2;

#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
	if (vsock->dmb_active && vsock->rx_zc_max > 0) {
		virtio_vsock_rx_fill_bounce(vsock);
		if (force || below_watermark)
			virtio_vsock_rx_fill_dmb(vsock);
		return;
	}
#endif
	if (force || below_watermark)
		virtio_vsock_rx_fill(vsock);
}

static void virtio_transport_tx_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, tx_work);
	struct virtqueue *vq;
	bool added = false;

	mutex_lock(&vsock->tx_lock);

	if (!vsock->tx_run)
		goto out;

	vq = vsock->vqs[VSOCK_VQ_TX];

	do {
		struct sk_buff *skb;
		unsigned int len;

		virtqueue_disable_cb(vq);
		while ((skb = virtqueue_get_buf(vq, &len)) != NULL) {
			virtio_transport_consume_skb_sent(skb, true);
			added = true;
		}
	} while (!virtqueue_enable_cb(vq));

out:
	mutex_unlock(&vsock->tx_lock);

	if (added)
		queue_work(virtio_vsock_workqueue, &vsock->send_pkt_work);
}

/* Is there space left for replies to rx packets? */
static bool virtio_transport_more_replies(struct virtio_vsock *vsock)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_RX];
	int val;

	smp_rmb(); /* paired with atomic_inc() and atomic_dec_return() */
	val = atomic_read(&vsock->queued_replies);

	return val < virtqueue_get_vring_size(vq);
}

/* event_lock must be held */
static int virtio_vsock_event_fill_one(struct virtio_vsock *vsock,
				       struct virtio_vsock_event *event)
{
	struct scatterlist sg;
	struct virtqueue *vq;

	vq = vsock->vqs[VSOCK_VQ_EVENT];

	sg_init_one(&sg, event, sizeof(*event));

	return virtqueue_add_inbuf(vq, &sg, 1, event, GFP_KERNEL);
}

/* event_lock must be held */
static void virtio_vsock_event_fill(struct virtio_vsock *vsock)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(vsock->event_list); i++) {
		struct virtio_vsock_event *event = &vsock->event_list[i];

		virtio_vsock_event_fill_one(vsock, event);
	}

	virtqueue_kick(vsock->vqs[VSOCK_VQ_EVENT]);
}

static void virtio_vsock_reset_sock(struct sock *sk)
{
	/* vmci_transport.c doesn't take sk_lock here either.  At least we're
	 * under vsock_table_lock so the sock cannot disappear while we're
	 * executing.
	 */

	sk->sk_state = TCP_CLOSE;
	sk->sk_err = ECONNRESET;
	sk_error_report(sk);
}

static void virtio_vsock_update_guest_cid(struct virtio_vsock *vsock)
{
	struct virtio_device *vdev = vsock->vdev;
	__le64 guest_cid;

	vdev->config->get(vdev, offsetof(struct virtio_vsock_config, guest_cid),
			  &guest_cid, sizeof(guest_cid));
	vsock->guest_cid = le64_to_cpu(guest_cid);
	pr_debug("virtio_vsock: guest_cid=%u\n", vsock->guest_cid);
}

/* event_lock must be held */
static void virtio_vsock_event_handle(struct virtio_vsock *vsock,
				      struct virtio_vsock_event *event)
{
	switch (le32_to_cpu(event->id)) {
	case VIRTIO_VSOCK_EVENT_TRANSPORT_RESET:
		virtio_vsock_update_guest_cid(vsock);
		vsock_for_each_connected_socket(&virtio_transport.transport,
						virtio_vsock_reset_sock);
		break;
	}
}

static void virtio_transport_event_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, event_work);
	struct virtqueue *vq;

	mutex_lock(&vsock->event_lock);

	if (!vsock->event_run)
		goto out;

	vq = vsock->vqs[VSOCK_VQ_EVENT];

	do {
		struct virtio_vsock_event *event;
		unsigned int len;

		virtqueue_disable_cb(vq);
		while ((event = virtqueue_get_buf(vq, &len)) != NULL) {
			if (len == sizeof(*event))
				virtio_vsock_event_handle(vsock, event);

			virtio_vsock_event_fill_one(vsock, event);
		}
	} while (!virtqueue_enable_cb(vq));

	virtqueue_kick(vsock->vqs[VSOCK_VQ_EVENT]);
out:
	mutex_unlock(&vsock->event_lock);
}

static void virtio_vsock_event_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->event_work);
}

static void virtio_vsock_tx_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->tx_work);
}

static void virtio_vsock_rx_done(struct virtqueue *vq)
{
	struct virtio_vsock *vsock = vq->vdev->priv;

	pr_debug("virtio_vsock_rx_done called\n");
	if (!vsock)
		return;
	queue_work(virtio_vsock_workqueue, &vsock->rx_work);
}

static bool virtio_transport_can_msgzerocopy(int bufs_num)
{
	struct virtio_vsock *vsock;
	bool res = false;

	rcu_read_lock();

	vsock = rcu_dereference(the_virtio_vsock);
	if (vsock) {
		struct virtqueue *vq = vsock->vqs[VSOCK_VQ_TX];

		/* Check that tx queue is large enough to keep whole
		 * data to send. This is needed, because when there is
		 * not enough free space in the queue, current skb to
		 * send will be reinserted to the head of tx list of
		 * the socket to retry transmission later, so if skb
		 * is bigger than whole queue, it will be reinserted
		 * again and again, thus blocking other skbs to be sent.
		 * Each page of the user provided buffer will be added
		 * as a single buffer to the tx virtqueue, so compare
		 * number of pages against maximum capacity of the queue.
		 */
		if (bufs_num <= vq->num_max)
			res = true;
	}

	rcu_read_unlock();

	return res;
}

static bool virtio_transport_msgzerocopy_allow(void)
{
	return true;
}

static bool virtio_transport_seqpacket_allow(u32 remote_cid);

#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
static struct sk_buff *virtio_vsock_dmb_alloc_skb(size_t size, gfp_t gfp)
{
	struct virtio_vsock *vsock;
	struct virtio_device *vdev;
	struct sk_buff *skb;
	size_t alloc_size;
	void *buf;

	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (!vsock || !vsock->dmb_active) {
		rcu_read_unlock();
		return NULL;
	}
	/*
	 * Pin the virtio_device while still under RCU: vsock may be freed by
	 * the removal path once we drop the read lock, so every DMB access
	 * (including the skb free-cb stored after rcu_read_unlock) must use
	 * this local instead of vsock->vdev.
	 */
	vdev = vsock->vdev;

	alloc_size = SKB_DATA_ALIGN(size) +
		     SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	alloc_size = ALIGN(alloc_size, SMP_CACHE_BYTES);

	if (virtio_dmb_avail(vdev) < alloc_size + vsock->rx_pool_min) {
		rcu_read_unlock();
		return NULL;
	}

	buf = virtio_dmb_alloc(vdev, alloc_size);
	if (!buf) {
		rcu_read_unlock();
		return NULL;
	}

	skb = __build_skb(buf, alloc_size);
	if (!skb) {
		virtio_dmb_free(vdev, buf, alloc_size);
		rcu_read_unlock();
		return NULL;
	}
	rcu_read_unlock();

	skb->dmb_head = 1;
	DMB_SKB_FREE_CB(skb)->vdev = vdev;
	DMB_SKB_FREE_CB(skb)->data = buf;
	DMB_SKB_FREE_CB(skb)->size = alloc_size;
	DMB_SKB_FREE_CB(skb)->safe_hdr = NULL;

	skb_reserve(skb, VIRTIO_VSOCK_SKB_HEADROOM);
	return skb;
}
#endif

static struct virtio_transport virtio_transport = {
	.transport = {
		.module                   = THIS_MODULE,

		.get_local_cid            = virtio_transport_get_local_cid,

		.init                     = virtio_transport_do_socket_init,
		.destruct                 = virtio_transport_destruct,
		.release                  = virtio_transport_release,
		.connect                  = virtio_transport_connect,
		.shutdown                 = virtio_transport_shutdown,
		.cancel_pkt               = virtio_transport_cancel_pkt,

		.dgram_bind               = virtio_transport_dgram_bind,
		.dgram_dequeue            = virtio_transport_dgram_dequeue,
		.dgram_enqueue            = virtio_transport_dgram_enqueue,
		.dgram_allow              = virtio_transport_dgram_allow,

		.stream_dequeue           = virtio_transport_stream_dequeue,
		.stream_enqueue           = virtio_transport_stream_enqueue,
		.stream_has_data          = virtio_transport_stream_has_data,
		.stream_has_space         = virtio_transport_stream_has_space,
		.stream_rcvhiwat          = virtio_transport_stream_rcvhiwat,
		.stream_is_active         = virtio_transport_stream_is_active,
		.stream_allow             = virtio_transport_stream_allow,

		.seqpacket_dequeue        = virtio_transport_seqpacket_dequeue,
		.seqpacket_enqueue        = virtio_transport_seqpacket_enqueue,
		.seqpacket_allow          = virtio_transport_seqpacket_allow,
		.seqpacket_has_data       = virtio_transport_seqpacket_has_data,

		.msgzerocopy_allow        = virtio_transport_msgzerocopy_allow,

		.notify_poll_in           = virtio_transport_notify_poll_in,
		.notify_poll_out          = virtio_transport_notify_poll_out,
		.notify_recv_init         = virtio_transport_notify_recv_init,
		.notify_recv_pre_block    = virtio_transport_notify_recv_pre_block,
		.notify_recv_pre_dequeue  = virtio_transport_notify_recv_pre_dequeue,
		.notify_recv_post_dequeue = virtio_transport_notify_recv_post_dequeue,
		.notify_send_init         = virtio_transport_notify_send_init,
		.notify_send_pre_block    = virtio_transport_notify_send_pre_block,
		.notify_send_pre_enqueue  = virtio_transport_notify_send_pre_enqueue,
		.notify_send_post_enqueue = virtio_transport_notify_send_post_enqueue,
		.notify_buffer_size       = virtio_transport_notify_buffer_size,
		.notify_set_rcvlowat      = virtio_transport_notify_set_rcvlowat,

		.unsent_bytes             = virtio_transport_unsent_bytes,

		.read_skb = virtio_transport_read_skb,
	},

	.send_pkt = virtio_transport_send_pkt,
	.can_msgzerocopy = virtio_transport_can_msgzerocopy,
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
	.alloc_skb = virtio_vsock_dmb_alloc_skb,
#endif
};

static bool virtio_transport_seqpacket_allow(u32 remote_cid)
{
	struct virtio_vsock *vsock;
	bool seqpacket_allow;

	seqpacket_allow = false;
	rcu_read_lock();
	vsock = rcu_dereference(the_virtio_vsock);
	if (vsock)
		seqpacket_allow = vsock->seqpacket_allow;
	rcu_read_unlock();

	return seqpacket_allow;
}

static void virtio_transport_rx_work(struct work_struct *work)
{
	struct virtio_vsock *vsock =
		container_of(work, struct virtio_vsock, rx_work);
	struct virtqueue *vq;

	mutex_lock(&vsock->rx_lock);

	if (!vsock->rx_run)
		goto out_nofill;

	vq = vsock->vqs[VSOCK_VQ_RX];

	do {
		virtqueue_disable_cb(vq);
		for (;;) {
			unsigned int len, payload_len;
			struct virtio_vsock_hdr *hdr;
			struct sk_buff *skb;

			if (!virtio_transport_more_replies(vsock)) {
				/* Stop rx until the device processes already
				 * pending replies.  Leave rx virtqueue
				 * callbacks disabled.
				 */
				goto out;
			}

			skb = virtqueue_get_buf(vq, &len);
			if (!skb) {
				pr_debug("virtio_vsock_rx: get_buf NULL\n");
				break;
			}
			pr_debug("virtio_vsock_rx: got buf len=%u\n", len);

			vsock->rx_buf_nr--;
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
			/* Track ZC/bounce counters only when DMB fill is active. */
			if (vsock->dmb_active && vsock->rx_zc_max > 0) {
				if (skb->dmb_head)
					vsock->rx_zc_posted--;
				else
					vsock->rx_bounce_posted--;
			}
#endif

			/* Drop short/long packets */
			if (unlikely(len < sizeof(*hdr) ||
				     len > virtio_vsock_skb_len(skb))) {
				kfree_skb(skb);
				continue;
			}

			hdr = virtio_vsock_hdr(skb);
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
			/*
			 * DMB-backed buffers reside in shared memory
			 * writable by the untrusted parent.  Allocate a
			 * kernel-heap copy of the header so all downstream
			 * consumers (via virtio_vsock_hdr()) read from
			 * memory the parent cannot mutate.
			 */
			if (skb->dmb_head) {
				struct virtio_vsock_hdr *safe;

				safe = kmalloc(sizeof(*safe), GFP_KERNEL);
				if (unlikely(!safe)) {
					kfree_skb(skb);
					continue;
				}
				memcpy(safe, hdr, sizeof(*safe));
				DMB_SKB_FREE_CB(skb)->safe_hdr = safe;

				payload_len = le32_to_cpu(safe->len);
				if (unlikely(payload_len > len - sizeof(*hdr))) {
					kfree_skb(skb);
					continue;
				}
				goto dmb_hdr_done;
			}
#endif
			payload_len = le32_to_cpu(hdr->len);
			if (unlikely(payload_len > len - sizeof(*hdr))) {
				kfree_skb(skb);
				continue;
			}
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
dmb_hdr_done:
#endif
			pr_debug("virtio_vsock_rx: hdr src=%llu:%u dst=%llu:%u op=%u type=%u len=%u\n",
				le64_to_cpu(virtio_vsock_hdr(skb)->src_cid),
				le32_to_cpu(virtio_vsock_hdr(skb)->src_port),
				le64_to_cpu(virtio_vsock_hdr(skb)->dst_cid),
				le32_to_cpu(virtio_vsock_hdr(skb)->dst_port),
				le16_to_cpu(virtio_vsock_hdr(skb)->op),
				le16_to_cpu(virtio_vsock_hdr(skb)->type),
				le32_to_cpu(virtio_vsock_hdr(skb)->len));

			if (payload_len)
				virtio_vsock_skb_put(skb, payload_len);

			virtio_transport_deliver_tap_pkt(skb);
			virtio_transport_recv_pkt(&virtio_transport, skb);
		}
	} while (!virtqueue_enable_cb(vq));

out:
	virtio_vsock_rx_refill(vsock, false);
out_nofill:
	mutex_unlock(&vsock->rx_lock);
}

static int virtio_vsock_vqs_init(struct virtio_vsock *vsock)
{
	struct virtio_device *vdev = vsock->vdev;
	struct virtqueue_info vqs_info[] = {
		{ "rx", virtio_vsock_rx_done },
		{ "tx", virtio_vsock_tx_done },
		{ "event", virtio_vsock_event_done },
	};
	int ret;

	mutex_lock(&vsock->rx_lock);
	vsock->rx_buf_nr = 0;
	vsock->rx_buf_max_nr = 0;
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
	vsock->rx_zc_posted = 0;
	vsock->rx_bounce_posted = 0;
#endif
	mutex_unlock(&vsock->rx_lock);

	atomic_set(&vsock->queued_replies, 0);

	ret = virtio_find_vqs(vdev, VSOCK_VQ_MAX, vsock->vqs, vqs_info, NULL);
	if (ret < 0) {
		pr_err("virtio_vsock: virtio_find_vqs failed: %d\n", ret);
		return ret;
	}

	virtio_vsock_update_guest_cid(vsock);

	virtio_device_ready(vdev);

	return 0;
}

static void virtio_vsock_vqs_start(struct virtio_vsock *vsock)
{
	mutex_lock(&vsock->tx_lock);
	vsock->tx_run = true;
	mutex_unlock(&vsock->tx_lock);

	mutex_lock(&vsock->rx_lock);
	virtio_vsock_rx_refill(vsock, true);
	vsock->rx_run = true;
	mutex_unlock(&vsock->rx_lock);

	mutex_lock(&vsock->event_lock);
	virtio_vsock_event_fill(vsock);
	vsock->event_run = true;
	mutex_unlock(&vsock->event_lock);

	/* virtio_transport_send_pkt() can queue packets once
	 * the_virtio_vsock is set, but they won't be processed until
	 * vsock->tx_run is set to true. We queue vsock->send_pkt_work
	 * when initialization finishes to send those packets queued
	 * earlier.
	 * We don't need to queue the other workers (rx, event) because
	 * as long as we don't fill the queues with empty buffers, the
	 * host can't send us any notification.
	 */
	queue_work(virtio_vsock_workqueue, &vsock->send_pkt_work);
}

static void virtio_vsock_vqs_del(struct virtio_vsock *vsock)
{
	struct virtio_device *vdev = vsock->vdev;
	struct sk_buff *skb;

	/* Reset all connected sockets when the VQs disappear */
	vsock_for_each_connected_socket(&virtio_transport.transport,
					virtio_vsock_reset_sock);

	/* Stop all work handlers to make sure no one is accessing the device,
	 * so we can safely call virtio_reset_device().
	 */
	mutex_lock(&vsock->rx_lock);
	vsock->rx_run = false;
	mutex_unlock(&vsock->rx_lock);

	mutex_lock(&vsock->tx_lock);
	vsock->tx_run = false;
	mutex_unlock(&vsock->tx_lock);

	mutex_lock(&vsock->event_lock);
	vsock->event_run = false;
	mutex_unlock(&vsock->event_lock);

	/* Flush all device writes and interrupts, device will not use any
	 * more buffers.
	 */
	virtio_reset_device(vdev);

	mutex_lock(&vsock->rx_lock);
	while ((skb = virtqueue_detach_unused_buf(vsock->vqs[VSOCK_VQ_RX])))
		kfree_skb(skb);
	mutex_unlock(&vsock->rx_lock);

	mutex_lock(&vsock->tx_lock);
	while ((skb = virtqueue_detach_unused_buf(vsock->vqs[VSOCK_VQ_TX])))
		kfree_skb(skb);
	mutex_unlock(&vsock->tx_lock);

	virtio_vsock_skb_queue_purge(&vsock->send_pkt_queue);

	/* Delete virtqueues and flush outstanding callbacks if any */
	vdev->config->del_vqs(vdev);
}

static int virtio_vsock_probe(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = NULL;
	int ret;
	int i;

	ret = mutex_lock_interruptible(&the_virtio_vsock_mutex);
	if (ret)
		return ret;

	/* Only one virtio-vsock device per guest is supported */
	if (rcu_dereference_protected(the_virtio_vsock,
				lockdep_is_held(&the_virtio_vsock_mutex))) {
		ret = -EBUSY;
		goto out;
	}

	vsock = kzalloc(sizeof(*vsock), GFP_KERNEL);
	if (!vsock) {
		ret = -ENOMEM;
		goto out;
	}

	vsock->vdev = vdev;
#if IS_ENABLED(CONFIG_VIRTIO_DMB_ZEROCOPY)
	vsock->dmb_active = virtio_has_dmb(vdev);
	if (vsock->dmb_active) {
		int total_len = virtio_vsock_rx_buf_len();
		size_t slot_size = SKB_DATA_ALIGN(total_len) +
				   SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		size_t pool_size = virtio_dmb_size(vdev);

		slot_size = ALIGN(slot_size, SMP_CACHE_BYTES);
		vsock->dmb_slot_size = slot_size;

		/*
		 * Partition the pool: ZC RX budget + bounce reserve + TX.
		 * Shrink rx_zc_max if the pool cannot hold the requested
		 * ZC budget alongside the bounce reserve.
		 */
		vsock->rx_bounce_reserve =
			VIRTIO_VSOCK_RX_BOUNCE_FLOOR * PAGE_ALIGN(total_len);

		vsock->rx_zc_max = (pool_size / slot_size) *
				   clamp(dmb_rx_zc_pct, 0, 100) / 100;
		while (vsock->rx_zc_max > 0 &&
		       (size_t)vsock->rx_zc_max * slot_size +
		       vsock->rx_bounce_reserve >= pool_size)
			vsock->rx_zc_max--;

		if (vsock->rx_zc_max == 0) {
			vsock->rx_bounce_reserve = 0;
			dev_warn(&vdev->dev,
				 "DMB pool too small for zero-copy RX; falling back to heap mode (pool=%zu, slot=%zu)\n",
				 pool_size, slot_size);
		}

		vsock->rx_pool_min = (size_t)vsock->rx_zc_max * slot_size +
				     vsock->rx_bounce_reserve;
		vsock->tx_pool_min = pool_size - vsock->rx_pool_min;

		dev_info(&vdev->dev,
			 "DMB zero-copy (pool=%zu, slot=%zu, rx_zc_max=%d/%zu, tx_min=%zu, rx_min=%zu, bounce_reserve=%zu)\n",
			 pool_size, slot_size, vsock->rx_zc_max,
			 pool_size / slot_size, vsock->tx_pool_min,
			 vsock->rx_pool_min, vsock->rx_bounce_reserve);
	}
#endif

	mutex_init(&vsock->tx_lock);
	mutex_init(&vsock->rx_lock);
	mutex_init(&vsock->event_lock);
	skb_queue_head_init(&vsock->send_pkt_queue);
	INIT_WORK(&vsock->rx_work, virtio_transport_rx_work);
	INIT_WORK(&vsock->tx_work, virtio_transport_tx_work);
	INIT_WORK(&vsock->event_work, virtio_transport_event_work);
	INIT_WORK(&vsock->send_pkt_work, virtio_transport_send_pkt_work);

	if (virtio_has_feature(vdev, VIRTIO_VSOCK_F_SEQPACKET))
		vsock->seqpacket_allow = true;

	vdev->priv = vsock;

	ret = virtio_vsock_vqs_init(vsock);
	if (ret < 0)
		goto out;

	for (i = 0; i < ARRAY_SIZE(vsock->out_sgs); i++)
		vsock->out_sgs[i] = &vsock->out_bufs[i];

	rcu_assign_pointer(the_virtio_vsock, vsock);
	virtio_vsock_vqs_start(vsock);

	mutex_unlock(&the_virtio_vsock_mutex);

	return 0;

out:
	kfree(vsock);
	mutex_unlock(&the_virtio_vsock_mutex);
	return ret;
}

static void virtio_vsock_remove(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = vdev->priv;

	mutex_lock(&the_virtio_vsock_mutex);

	vdev->priv = NULL;
	rcu_assign_pointer(the_virtio_vsock, NULL);
	synchronize_rcu();

	virtio_vsock_vqs_del(vsock);

	/* Other works can be queued before 'config->del_vqs()', so we flush
	 * all works before to free the vsock object to avoid use after free.
	 */
	flush_work(&vsock->tx_work);
	flush_work(&vsock->event_work);
	flush_work(&vsock->send_pkt_work);
	flush_work(&vsock->rx_work);

	mutex_unlock(&the_virtio_vsock_mutex);

	kfree(vsock);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_vsock_freeze(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = vdev->priv;

	mutex_lock(&the_virtio_vsock_mutex);

	rcu_assign_pointer(the_virtio_vsock, NULL);
	synchronize_rcu();

	virtio_vsock_vqs_del(vsock);

	mutex_unlock(&the_virtio_vsock_mutex);

	return 0;
}

static int virtio_vsock_restore(struct virtio_device *vdev)
{
	struct virtio_vsock *vsock = vdev->priv;
	int ret;

	mutex_lock(&the_virtio_vsock_mutex);

	/* Only one virtio-vsock device per guest is supported */
	if (rcu_dereference_protected(the_virtio_vsock,
				lockdep_is_held(&the_virtio_vsock_mutex))) {
		ret = -EBUSY;
		goto out;
	}

	ret = virtio_vsock_vqs_init(vsock);
	if (ret < 0)
		goto out;

	rcu_assign_pointer(the_virtio_vsock, vsock);
	virtio_vsock_vqs_start(vsock);

out:
	mutex_unlock(&the_virtio_vsock_mutex);
	return ret;
}
#endif /* CONFIG_PM_SLEEP */

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VSOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_VSOCK_F_SEQPACKET
};

static struct virtio_driver virtio_vsock_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = virtio_vsock_probe,
	.remove = virtio_vsock_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze = virtio_vsock_freeze,
	.restore = virtio_vsock_restore,
#endif
};

static int __init virtio_vsock_init(void)
{
	int ret;

	virtio_vsock_workqueue = alloc_workqueue("virtio_vsock", WQ_PERCPU, 0);
	if (!virtio_vsock_workqueue)
		return -ENOMEM;

	ret = vsock_core_register(&virtio_transport.transport,
				  VSOCK_TRANSPORT_F_G2H);
	if (ret)
		goto out_wq;

	ret = register_virtio_driver(&virtio_vsock_driver);
	if (ret)
		goto out_vci;

	return 0;

out_vci:
	vsock_core_unregister(&virtio_transport.transport);
out_wq:
	destroy_workqueue(virtio_vsock_workqueue);
	return ret;
}

static void __exit virtio_vsock_exit(void)
{
	unregister_virtio_driver(&virtio_vsock_driver);
	vsock_core_unregister(&virtio_transport.transport);
	destroy_workqueue(virtio_vsock_workqueue);
}

module_init(virtio_vsock_init);
module_exit(virtio_vsock_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("virtio transport for vsock");
MODULE_DEVICE_TABLE(virtio, id_table);
