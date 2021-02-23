/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_SYSGENID_H
#define _UAPI_LINUX_SYSGENID_H

#include <linux/ioctl.h>

#define SYSGENID_IOCTL			0xE4
#define SYSGENID_SET_WATCHER_TRACKING	_IO(SYSGENID_IOCTL, 1)
#define SYSGENID_WAIT_WATCHERS		_IO(SYSGENID_IOCTL, 2)
#define SYSGENID_TRIGGER_GEN_UPDATE	_IO(SYSGENID_IOCTL, 3)

#ifdef __KERNEL__
void sysgenid_bump_generation(void);
#endif /* __KERNEL__ */

#endif /* _UAPI_LINUX_SYSGENID_H */
