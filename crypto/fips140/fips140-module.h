/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * FIPS 140 Kernel Cryptographic Module - Header File
 */

#ifndef _CRYPTO_FIPS140_MODULE_H
#define _CRYPTO_FIPS140_MODULE_H

#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/wait.h>

/* FIPS140 synchronization between kernel and module */
extern atomic_t fips140_kernel_level_complete;
extern atomic_t fips140_module_level_complete;
extern wait_queue_head_t fips140_kernel_wq;

void fips140_mark_kernel_level_complete(int level);
bool fips140_is_kernel_level_complete(int level);
bool fips140_is_module_level_complete(int level);
void fips140_mark_module_level_complete(int level);

#endif /* _CRYPTO_FIPS140_MODULE_H */
