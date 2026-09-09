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
