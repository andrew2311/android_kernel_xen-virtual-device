// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio RPMB Front End Driver
 *
 * Copyright (c) 2018-2019 Intel Corporation.
 *
 * Ported from the rpmb_ops interface to rpmb-core: frames are routed
 * with rpmb_descr::route_frames() in the same way as ufs-rpmb.
 */
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rpmb.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/wait.h>

#define VIRTIO_RPMB_TIMEOUT		(30 * HZ)
#define VIRTIO_RPMB_MAX_CAPACITY	0x80	/* 16 MiB in 128 KiB units */

/*
 * Device identifier reported to rpmb-core. OP-TEE uses it as input when
 * deriving the RPMB authentication key, so it MUST NEVER CHANGE: a
 * different value yields a different key and makes an already programmed
 * RPMB region unusable.
 */
static const u8 virtio_rpmb_dev_id[16] = {
	'V', 'I', 'R', 'T', 'I', 'O', '-', 'R',
	'P', 'M', 'B', '-', 'U', 'F', 'S', '0',
};

struct virtio_rpmb_config {
	u8 capacity;
	u8 max_wr_cnt;
	u8 max_rd_cnt;
};

struct virtio_rpmb_info {
	struct virtqueue *vq;
	struct mutex lock; /* one request in flight; protects vq and stale */
	wait_queue_head_t have_data;
	struct rpmb_dev *rdev;
	/*
	 * Buffer of a timed out request. The device still owns it until it
	 * returns it through the virtqueue or the device is reset.
	 */
	void *stale;
};

static void virtio_rpmb_recv_done(struct virtqueue *vq)
{
	struct virtio_rpmb_info *vi = vq->vdev->priv;

	if (!vi) {
		dev_err(&vq->vdev->dev, "Error: no found vi data.\n");
		return;
	}

	wake_up(&vi->have_data);
}

/* Called with vi->lock held. */
static int virtio_rpmb_reclaim_stale(struct virtio_rpmb_info *vi)
{
	unsigned int len;
	void *buf;

	if (!vi->stale)
		return 0;

	while ((buf = virtqueue_get_buf(vi->vq, &len))) {
		if (buf == vi->stale) {
			kfree(vi->stale);
			vi->stale = NULL;
		}
	}

	return vi->stale ? -EBUSY : 0;
}

static int virtio_rpmb_route_frames(struct device *dev, u8 *req,
				    unsigned int req_len, u8 *resp,
				    unsigned int resp_len)
{
	struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtio_rpmb_info *vi = vdev->priv;
	struct rpmb_frame *frm_out = (struct rpmb_frame *)req;
	struct scatterlist frame[3];
	struct scatterlist *sgs[3];
	unsigned int num_out = 0, num_in = 0, i;
	bool need_result_read = true;
	unsigned int len;
	long left;
	size_t out_len;
	u16 req_type;
	u8 *buf, *out, *in;
	void *token;
	int ret;

	if (!vi)
		return -ENODEV;

	/* req_resp is at the end of an RPMB frame. */
	if (req_len < sizeof(*frm_out))
		return -EINVAL;

	req_type = get_unaligned_be16(&frm_out->req_resp);

	switch (req_type) {
	case RPMB_PROGRAM_KEY:
		if (req_len != sizeof(struct rpmb_frame) ||
		    resp_len != sizeof(struct rpmb_frame))
			return -EINVAL;
		break;
	case RPMB_GET_WRITE_COUNTER:
		if (req_len != sizeof(struct rpmb_frame) ||
		    resp_len != sizeof(struct rpmb_frame))
			return -EINVAL;
		need_result_read = false;
		break;
	case RPMB_WRITE_DATA:
		if (req_len % sizeof(struct rpmb_frame) ||
		    resp_len != sizeof(struct rpmb_frame))
			return -EINVAL;
		break;
	case RPMB_READ_DATA:
		if (req_len != sizeof(struct rpmb_frame) ||
		    resp_len % sizeof(struct rpmb_frame))
			return -EINVAL;
		need_result_read = false;
		break;
	default:
		dev_err(dev, "Unknown request type=0x%04x\n", req_type);
		return -EINVAL;
	}

	/*
	 * The device gets a private copy of the frames: after a timeout it
	 * may still access the buffers, which must then outlive the
	 * caller's memory.
	 */
	out_len = req_len;
	if (need_result_read)
		out_len = size_add(out_len, sizeof(struct rpmb_frame));
	buf = kzalloc(size_add(out_len, resp_len), GFP_KERNEL | __GFP_NOWARN);
	if (!buf)
		return -ENOMEM;
	out = buf;
	in = buf + out_len;

	for (i = 0; i < ARRAY_SIZE(sgs); i++)
		sgs[i] = &frame[i];

	memcpy(out, req, req_len);
	sg_init_one(&frame[num_out++], out, req_len);

	if (need_result_read) {
		struct rpmb_frame *frm_rr = (struct rpmb_frame *)(out + req_len);

		put_unaligned_be16(RPMB_RESULT_READ, &frm_rr->req_resp);
		sg_init_one(&frame[num_out++], frm_rr, sizeof(*frm_rr));
	}

	sg_init_one(&frame[num_out + num_in++], in, resp_len);

	mutex_lock(&vi->lock);
	if (!vi->vq) {
		ret = -ENODEV;
		goto out_free;
	}

	ret = virtio_rpmb_reclaim_stale(vi);
	if (ret) {
		dev_err(dev, "Previous request is still owned by the device\n");
		goto out_free;
	}

	ret = virtqueue_add_sgs(vi->vq, sgs, num_out, num_in, buf, GFP_KERNEL);
	if (ret) {
		dev_err(dev, "Failed to queue request: %d\n", ret);
		goto out_free;
	}
	virtqueue_kick(vi->vq);

	left = wait_event_timeout(vi->have_data,
				  (token = virtqueue_get_buf(vi->vq, &len)),
				  VIRTIO_RPMB_TIMEOUT);
	if (!left) {
		dev_err(dev, "Request 0x%04x timed out\n", req_type);
		/* The device still owns buf: keep it until it is returned. */
		vi->stale = buf;
		ret = -ETIMEDOUT;
		goto out_unlock;
	}

	if (token != buf) {
		dev_err(dev, "Unexpected buffer returned by the device\n");
		vi->stale = buf;
		ret = -EIO;
		goto out_unlock;
	}

	if (len < resp_len) {
		dev_err(dev, "Short response: %u of %u bytes\n", len, resp_len);
		ret = -EIO;
		goto out_free;
	}

	memcpy(resp, in, resp_len);
	ret = 0;

out_free:
	kfree(buf);
out_unlock:
	mutex_unlock(&vi->lock);
	return ret;
}

static int virtio_rpmb_dev_init(struct virtio_device *vdev,
				struct virtio_rpmb_info *vi)
{
	struct rpmb_descr descr = {
		.type = RPMB_TYPE_UFS,
		.route_frames = virtio_rpmb_route_frames,
		.dev_id = (u8 *)virtio_rpmb_dev_id,
		.dev_id_len = sizeof(virtio_rpmb_dev_id),
	};
	u8 capacity, max_wr_cnt, max_rd_cnt;

	virtio_cread(vdev, struct virtio_rpmb_config, capacity, &capacity);
	virtio_cread(vdev, struct virtio_rpmb_config, max_wr_cnt, &max_wr_cnt);
	virtio_cread(vdev, struct virtio_rpmb_config, max_rd_cnt, &max_rd_cnt);

	if (!capacity || capacity > VIRTIO_RPMB_MAX_CAPACITY) {
		dev_err(&vdev->dev, "Invalid capacity %u\n", capacity);
		return -EINVAL;
	}

	descr.capacity = capacity;
	/*
	 * Zero means no limit in the virtio spec, but rpmb-core users need a
	 * positive count: fall back to single frame writes.
	 */
	descr.reliable_wr_count = max_wr_cnt ?: 1;

	vi->rdev = rpmb_dev_register(&vdev->dev, &descr);
	if (IS_ERR(vi->rdev))
		return PTR_ERR(vi->rdev);

	dev_dbg(&vdev->dev, "capacity %u x 128 KiB, max_wr_cnt %u, max_rd_cnt %u\n",
		capacity, max_wr_cnt, max_rd_cnt);

	return 0;
}

static int virtio_rpmb_init_vq(struct virtio_device *vdev)
{
	struct virtio_rpmb_info *vi = vdev->priv;
	struct virtqueue *vq;

	vq = virtio_find_single_vq(vdev, virtio_rpmb_recv_done, "request");
	if (IS_ERR(vq)) {
		dev_err(&vdev->dev, "get single vq failed!\n");
		return PTR_ERR(vq);
	}

	mutex_lock(&vi->lock);
	vi->vq = vq;
	mutex_unlock(&vi->lock);

	return 0;
}

static void virtio_rpmb_del_vq(struct virtio_device *vdev)
{
	struct virtio_rpmb_info *vi = vdev->priv;
	void *buf;

	mutex_lock(&vi->lock);
	virtio_reset_device(vdev);
	/* vq is NULL if restore failed to set it up again. */
	if (vi->vq) {
		/*
		 * After the reset the device no longer owns any buffer.
		 * Detach the stale one so that its DMA mapping is released.
		 */
		while ((buf = virtqueue_detach_unused_buf(vi->vq)))
			kfree(buf);
		vdev->config->del_vqs(vdev);
		vi->vq = NULL;
	}
	vi->stale = NULL;
	mutex_unlock(&vi->lock);
}

static void virtio_rpmb_remove(struct virtio_device *vdev)
{
	struct virtio_rpmb_info *vi = vdev->priv;

	rpmb_dev_unregister(vi->rdev);
	virtio_rpmb_del_vq(vdev);

	vdev->priv = NULL;
	mutex_destroy(&vi->lock);
	kfree(vi);
}

static int virtio_rpmb_probe(struct virtio_device *vdev)
{
	struct virtio_rpmb_info *vi;
	int ret;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "Config access disabled\n");
		return -EINVAL;
	}

	vi = kzalloc(sizeof(*vi), GFP_KERNEL);
	if (!vi)
		return -ENOMEM;

	init_waitqueue_head(&vi->have_data);
	mutex_init(&vi->lock);
	vdev->priv = vi;

	ret = virtio_rpmb_init_vq(vdev);
	if (ret)
		goto err_free;

	/* rpmb-core users may send frames as soon as the device registers. */
	virtio_device_ready(vdev);

	ret = virtio_rpmb_dev_init(vdev, vi);
	if (ret) {
		dev_err(&vdev->dev, "create vrpmb device failed: %d\n", ret);
		goto err_del_vq;
	}

	return 0;

err_del_vq:
	virtio_rpmb_del_vq(vdev);
err_free:
	vdev->priv = NULL;
	mutex_destroy(&vi->lock);
	kfree(vi);
	return ret;
}

#ifdef CONFIG_PM_SLEEP
static int virtio_rpmb_freeze(struct virtio_device *vdev)
{
	virtio_rpmb_del_vq(vdev);
	return 0;
}

static int virtio_rpmb_restore(struct virtio_device *vdev)
{
	return virtio_rpmb_init_vq(vdev);
}
#endif

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RPMB, VIRTIO_DEV_ANY_ID },
	{ 0 },
};
MODULE_DEVICE_TABLE(virtio, id_table);

static struct virtio_driver virtio_rpmb_driver = {
	.driver.name =	KBUILD_MODNAME,
	.id_table =	id_table,
	.probe =	virtio_rpmb_probe,
	.remove =	virtio_rpmb_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze =	virtio_rpmb_freeze,
	.restore =	virtio_rpmb_restore,
#endif
};

module_virtio_driver(virtio_rpmb_driver);

MODULE_DESCRIPTION("Virtio rpmb frontend driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
