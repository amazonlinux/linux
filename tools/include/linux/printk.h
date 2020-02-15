/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TOOLS_LINUX_KERNEL_PRINTK_H_
#define _TOOLS_LINUX_KERNEL_PRINTK_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define printk(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define pr_info printk
#define pr_notice printk
#define pr_cont printk

#define pr_warn(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_err pr_warn
#define pr_alert pr_warn
#define pr_emerg pr_warn
#define pr_crit pr_warn

/*
 * Dummy printk for disabled debugging statements to use whilst maintaining
 * gcc's format checking.
 */
#define no_printk(fmt, ...)				\
({							\
	if (0)						\
		printk(fmt, ##__VA_ARGS__);		\
	0;						\
})

/* pr_devel() should produce zero code unless DEBUG is defined */
#ifdef DEBUG
#define pr_devel(fmt, ...) printk
#else
#define pr_devel(fmt, ...) no_printk
#endif

#define pr_debug pr_devel

#endif /* _TOOLS_LINUX_KERNEL_PRINTK_H_ */
