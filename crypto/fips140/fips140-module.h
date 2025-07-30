/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * FIPS 140 Kernel Cryptographic Module - Header File
 */

#ifndef _CRYPTO_FIPS140_MODULE_H
#define _CRYPTO_FIPS140_MODULE_H

#include <linux/completion.h>
#include <linux/sched.h>

/* Completion to signal that self-tests are done */
extern struct completion fips140_tests_done;

/* The thread that is initializing the FIPS module */
extern struct task_struct *fips140_init_thread;

/* FIPS 140-3 service indicator */
bool fips140_is_approved_service(const char *name);

/* FIPS 140-3 module version information */
const char *fips140_module_version(void);

#endif /* _CRYPTO_FIPS140_MODULE_H */
