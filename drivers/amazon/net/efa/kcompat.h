/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2018-2026 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/types.h>


#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

typedef u32 port_t;

#include <rdma/ib_verbs.h>
#include <rdma/uverbs_ioctl.h>

static inline struct ib_device *efa_udata_to_dev(struct ib_udata *udata)
{
	struct uverbs_attr_bundle *bundle =
		rdma_udata_to_uverbs_attr_bundle(udata);

	return bundle->context->device;
}

#define _efa_udata_dbg(udata, fmt, ...) \
	ibdev_dbg(efa_udata_to_dev(udata), fmt, ##__VA_ARGS__)

static inline int _ib_copy_validate_udata_in(struct ib_udata *udata, void *req,
					     size_t kernel_size, size_t minimum_size)
{
	int err;

	if (udata->inlen < minimum_size) {
		_efa_udata_dbg(udata, "System call driver input udata too small\n");
		return -EINVAL;
	}

	if (udata->inlen > kernel_size &&
	    !ib_is_udata_cleared(udata, kernel_size, udata->inlen - kernel_size)) {
		_efa_udata_dbg(udata, "System call driver input udata not zero\n");
		return -EOPNOTSUPP;
	}

	if (!req)
		return 0;

	memset(req, 0, kernel_size);
	err = ib_copy_from_udata(req, udata, min(kernel_size, udata->inlen));
	if (err)
		_efa_udata_dbg(udata, "System call driver input udata EFAULT\n");

	return err;
}

#define ib_copy_validate_udata_in(_udata, _req, _end_member)      \
	_ib_copy_validate_udata_in(_udata, &(_req), sizeof(_req), \
				   offsetofend(typeof(_req), _end_member))

#define ib_copy_validate_udata_in_cm(_udata, _req, _end_member, _valid_cm)    \
	({                                                                    \
		typeof((_req).comp_mask) __valid_cm = _valid_cm;              \
		int ret =                                                     \
			ib_copy_validate_udata_in(_udata, _req, _end_member); \
		if (!ret && ((_req).comp_mask & ~__valid_cm)) {               \
			_efa_udata_dbg(_udata, "System call driver input udata has unsupported comp_mask\n"); \
			ret = -EOPNOTSUPP;                                    \
		}                                                             \
		ret;                                                          \
	})

static inline int ib_is_udata_in_empty(struct ib_udata *udata)
{
	if (!udata || udata->inlen == 0)
		return 0;
	return _ib_copy_validate_udata_in(udata, NULL, 0, 0);
}

static inline int _ib_respond_udata(struct ib_udata *udata, const void *src, size_t len)
{
	size_t copy_len;

	/* 0 length copy_len is a NOP for copy_to_user() and doesn't fail. */
	copy_len = min(len, udata->outlen);
	if (copy_to_user(udata->outbuf, src, copy_len))
		goto err_fault;
	if (copy_len < udata->outlen) {
		if (clear_user(udata->outbuf + copy_len,
			       udata->outlen - copy_len))
			goto err_fault;
	}
	return 0;
err_fault:
	_efa_udata_dbg(udata, "System call driver out udata has EFAULT\n");
	return -EFAULT;
}

#define ib_respond_udata(_udata, _rep) \
	_ib_respond_udata(_udata, &(_rep), sizeof(_rep))

#include <rdma/ib_umem.h>
#include <rdma/uverbs_ioctl.h>

enum ib_uverbs_buffer_type {
	IB_UVERBS_BUFFER_TYPE_DMABUF,
	IB_UVERBS_BUFFER_TYPE_VA,
};

struct ib_uverbs_buffer_desc {
	__u32 type;
	__s32 fd;
	__u32 flags;
	__u32 optional_flags;
	__aligned_u64 addr;
	__aligned_u64 length;
};

static inline struct ib_umem *
ib_umem_get_attr(struct ib_device *device,
		 const struct uverbs_attr_bundle *attrs,
		 u16 attr_id, size_t size, int access)
{
	struct ib_uverbs_buffer_desc desc = {};
	struct ib_umem *umem;
	int ret;

	if (!attrs)
		return NULL;

	ret = uverbs_copy_from(&desc, attrs, attr_id);
	if (ret == -ENOENT)
		return NULL;
	if (ret)
		return ERR_PTR(ret);

	if (desc.flags)
		return ERR_PTR(-EINVAL);

	switch (desc.type) {
	case IB_UVERBS_BUFFER_TYPE_DMABUF:
	{
		struct ib_umem_dmabuf *umem_dmabuf;

		umem_dmabuf = ib_umem_dmabuf_get_pinned(device, desc.addr,
							desc.length, desc.fd,
							access);
		if (IS_ERR(umem_dmabuf))
			return ERR_CAST(umem_dmabuf);
		umem = &umem_dmabuf->umem;
		break;
	}
	case IB_UVERBS_BUFFER_TYPE_VA:
		umem = ib_umem_get(device, desc.addr, desc.length, access);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	if (IS_ERR(umem))
		return umem;

	if (umem->length < size) {
		ib_umem_release(umem);
		return ERR_PTR(-EINVAL);
	}

	return umem;
}

#include <rdma/ib_umem.h>
#include <rdma/uverbs_ioctl.h>

static inline struct ib_umem *
ib_umem_get_cq_buf(struct ib_device *device,
		   const struct uverbs_attr_bundle *attrs,
		   size_t size, int access)
{
	struct ib_umem_dmabuf *umem_dmabuf;
	struct ib_umem *umem;
	u64 buffer_length;
	u64 buffer_offset;
	u64 buffer_va;
	int buffer_fd;
	int ret;

	if (!attrs)
		return NULL;

	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_VA)) {
		ret = uverbs_copy_from(&buffer_va, attrs,
				       UVERBS_ATTR_CREATE_CQ_BUFFER_VA);
		if (ret)
			return ERR_PTR(ret);

		ret = uverbs_copy_from(&buffer_length, attrs,
				       UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH);
		if (ret)
			return ERR_PTR(ret);

		if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_FD) ||
		    uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET))
			return ERR_PTR(-EINVAL);

		umem = ib_umem_get(device, buffer_va, buffer_length, access);
		if (IS_ERR(umem))
			return umem;

	} else if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_FD)) {
		ret = uverbs_get_raw_fd(&buffer_fd, attrs,
					UVERBS_ATTR_CREATE_CQ_BUFFER_FD);
		if (ret)
			return ERR_PTR(ret);

		ret = uverbs_copy_from(&buffer_offset, attrs,
				       UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET);
		if (ret)
			return ERR_PTR(ret);

		ret = uverbs_copy_from(&buffer_length, attrs,
				       UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH);
		if (ret)
			return ERR_PTR(ret);

		if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_VA))
			return ERR_PTR(-EINVAL);

		umem_dmabuf = ib_umem_dmabuf_get_pinned(device, buffer_offset,
							buffer_length,
							buffer_fd, access);
		if (IS_ERR(umem_dmabuf))
			return ERR_CAST(umem_dmabuf);
		umem = &umem_dmabuf->umem;
	} else if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET) ||
		   uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH)) {
		return ERR_PTR(-EINVAL);
	} else {
		return NULL;
	}

	if (umem->length < size) {
		ib_umem_release(umem);
		return ERR_PTR(-EINVAL);
	}

	return umem;
}

enum {
	UVERBS_OBJECT_COMP_CNTR = 19,
};

enum {
	UVERBS_METHOD_QUERY_COMP_CNTR_CAPS = 8,
};

enum uverbs_attrs_query_comp_cntr_caps_attr_ids {
	UVERBS_ATTR_QUERY_COMP_CNTR_CAPS_MAX_COUNTERS,
	UVERBS_ATTR_QUERY_COMP_CNTR_CAPS_MAX_VALUE,
	UVERBS_ATTR_QUERY_COMP_CNTR_CAPS_SUPPORTED_QP_ATTACH_OPS,
};

enum uverbs_methods_comp_cntr {
	UVERBS_METHOD_COMP_CNTR_CREATE,
	UVERBS_METHOD_COMP_CNTR_DESTROY,
	UVERBS_METHOD_COMP_CNTR_MODIFY,
	UVERBS_METHOD_COMP_CNTR_READ,
};

enum uverbs_attrs_create_comp_cntr_cmd_attr_ids {
	UVERBS_ATTR_CREATE_COMP_CNTR_HANDLE,
};

enum uverbs_attrs_destroy_comp_cntr_cmd_attr_ids {
	UVERBS_ATTR_DESTROY_COMP_CNTR_HANDLE,
};

enum uverbs_attrs_modify_comp_cntr_cmd_attr_ids {
	UVERBS_ATTR_MODIFY_COMP_CNTR_HANDLE,
	UVERBS_ATTR_MODIFY_COMP_CNTR_ENTRY,
	UVERBS_ATTR_MODIFY_COMP_CNTR_OP,
	UVERBS_ATTR_MODIFY_COMP_CNTR_VALUE,
};

enum uverbs_attrs_read_comp_cntr_cmd_attr_ids {
	UVERBS_ATTR_READ_COMP_CNTR_HANDLE,
	UVERBS_ATTR_READ_COMP_CNTR_ENTRY,
	UVERBS_ATTR_READ_COMP_CNTR_RESP_VALUE,
};

enum {
	UVERBS_METHOD_QP_ATTACH_COMP_CNTR = 2,
};

enum uverbs_attrs_qp_attach_comp_cntr_cmd_attr_ids {
	UVERBS_ATTR_QP_ATTACH_COMP_CNTR_HANDLE,
	UVERBS_ATTR_QP_ATTACH_COMP_CNTR_CNTR_HANDLE,
	UVERBS_ATTR_QP_ATTACH_COMP_CNTR_OP_MASK,
};

enum ib_uverbs_comp_cntr_entry {
	IB_UVERBS_COMP_CNTR_ENTRY_COMP,
	IB_UVERBS_COMP_CNTR_ENTRY_ERR,
};

enum ib_uverbs_comp_cntr_modify_op {
	IB_UVERBS_COMP_CNTR_MODIFY_OP_SET,
	IB_UVERBS_COMP_CNTR_MODIFY_OP_INC,
};

struct ib_comp_cntr_caps {
	u64 max_value;
	u32 max_counters;
	u32 supported_qp_attach_ops;
};

struct ib_comp_cntr {
	struct ib_device *device;
	struct ib_uobject *uobject;
	u64 comp_count_max_value;
	u64 err_count_max_value;
	atomic_t usecnt;
};

struct ib_qp_attach_comp_cntr_attr {
	u32 op_mask;
};

enum ib_comp_cntr_entry {
	IB_COMP_CNTR_ENTRY_COMP = 0,
	IB_COMP_CNTR_ENTRY_ERR = 1,
};

enum ib_comp_cntr_modify_op {
	IB_COMP_CNTR_MODIFY_OP_SET = 0,
	IB_COMP_CNTR_MODIFY_OP_INC = 1,
};

enum ib_qp_attach_comp_cntr_op {
	IB_QP_ATTACH_COMP_CNTR_OP_SEND = 1 << 0,
	IB_QP_ATTACH_COMP_CNTR_OP_RECV = 1 << 1,
	IB_QP_ATTACH_COMP_CNTR_OP_RDMA_READ = 1 << 2,
	IB_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_READ = 1 << 3,
	IB_QP_ATTACH_COMP_CNTR_OP_RDMA_WRITE = 1 << 4,
	IB_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_WRITE = 1 << 5,
};

#endif /* _KCOMPAT_H_ */
