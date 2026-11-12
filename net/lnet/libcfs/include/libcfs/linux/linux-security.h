/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_SECURITY_H
#define __LIBCFS_LINUX_SECURITY_H

#include <linux/security.h>

#ifndef HAVE_SECURITY_INODE_LISTSECURITY_PTR_ARGS
/*
 * Linux commit v7.1-rc1-1-gf71ece9712b7 changed security_inode_listsecurity()
 * to update the buffer pointer and remaining size in place and to return
 * 0 or -errno instead of the copied length. A NULL buffer still requests
 * the needed size, subtracted from the remaining size.
 */
static inline int
compat_security_inode_listsecurity(struct inode *inode, char **buffer,
				   ssize_t *remaining_size)
{
	int len;

	len = security_inode_listsecurity(inode, *buffer,
					  *buffer ? *remaining_size : 0);
	if (len < 0)
		return len;
	if (*buffer) {
		if (len > *remaining_size)
			return -ERANGE;
		*buffer += len;
	}
	*remaining_size -= len;
	return 0;
}
#define security_inode_listsecurity compat_security_inode_listsecurity
#endif /* !HAVE_SECURITY_INODE_LISTSECURITY_PTR_ARGS */

#endif /* __LIBCFS_LINUX_SECURITY_H */
