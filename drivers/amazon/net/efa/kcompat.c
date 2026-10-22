// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include "kcompat.h"

#include <rdma/uverbs_ioctl.h>
#define UVERBS_MODULE_NAME efa_ib
#include <rdma/uverbs_named_ioctl.h>
#include "efa.h"

const struct uapi_definition efa_kcompat_uapi_defs[] = {
	{},
};

