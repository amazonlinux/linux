/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2018-2022 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/types.h>


#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

typedef u8 port_t;

#endif /* _KCOMPAT_H_ */
