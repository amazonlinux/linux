/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef _LINUX_NITRO_ENCLAVES_H_
#define _LINUX_NITRO_ENCLAVES_H_

#include <uapi/linux/nitro_enclaves.h>

#ifdef CONFIG_NITRO_ENCLAVES
void __init ne_cma_reserve(void);
#else
static inline void __init ne_cma_reserve(void) { }
#endif

#endif /* _LINUX_NITRO_ENCLAVES_H_ */
