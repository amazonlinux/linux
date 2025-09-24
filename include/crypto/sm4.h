/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Common values for the SM4 algorithm
 * Copyright (C) 2018 ARM Limited or its affiliates.
 * Copyright (c) 2021 Tianjia Zhang <tianjia.zhang@linux.alibaba.com>
 */

#ifndef _CRYPTO_SM4_H
#define _CRYPTO_SM4_H

#include <crypto/api.h>
#include <linux/types.h>
#include <linux/crypto.h>

#define SM4_KEY_SIZE	16
#define SM4_BLOCK_SIZE	16
#define SM4_RKEY_WORDS	32

struct sm4_ctx {
	u32 rkey_enc[SM4_RKEY_WORDS];
	u32 rkey_dec[SM4_RKEY_WORDS];
};

DECLARE_CRYPTO_VAR(CONFIG_CRYPTO_SM4, crypto_sm4_fk, const u32, [4]);
DECLARE_CRYPTO_VAR(CONFIG_CRYPTO_SM4, crypto_sm4_ck, const u32, [32]);
DECLARE_CRYPTO_VAR(CONFIG_CRYPTO_SM4, crypto_sm4_sbox, const u8, [256]);

#if defined(CONFIG_CRYPTO_FIPS140_EXTMOD) && !defined(FIPS_MODULE) && IS_BUILTIN(CONFIG_CRYPTO_SM4)
#define crypto_sm4_fk (((const u32*)CRYPTO_VAR_NAME(crypto_sm4_fk)))
#define crypto_sm4_ck (((const u32*)CRYPTO_VAR_NAME(crypto_sm4_ck)))
#define crypto_sm4_sbox (((const u8*)CRYPTO_VAR_NAME(crypto_sm4_sbox)))
#endif

/**
 * sm4_expandkey - Expands the SM4 key as described in GB/T 32907-2016
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4, sm4_expandkey, int,
	(struct sm4_ctx *ctx, const u8 *in_key, unsigned int key_len),
	(ctx, in_key, key_len));

/**
 * sm4_crypt_block - Encrypt or decrypt a single SM4 block
 * @rk:		The rkey_enc for encrypt or rkey_dec for decrypt
 * @out:	Buffer to store output data
 * @in: 	Buffer containing the input data
 */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4, sm4_crypt_block, void,
	(const u32 *rk, u8 *out, const u8 *in),
	(rk, out, in));

#endif
