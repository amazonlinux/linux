/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SM4 common functions for Crypto Extensions
 * Copyright (C) 2022 Tianjia Zhang <tianjia.zhang@linux.alibaba.com>
 */

#include <crypto/api.h>

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_ARM64_CE_BLK, sm4_ce_expand_key, void,
	(const u8 *key, u32 *rkey_enc, u32 *rkey_dec, const u32 *fk, const u32 *ck),
	(key, rkey_enc, rkey_dec, fk, ck));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_ARM64_CE_BLK, sm4_ce_crypt_block, void,
	(const u32 *rkey, u8 *dst, const u8 *src),
	(rkey, dst, src));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_ARM64_CE_BLK, sm4_ce_cbc_enc, void,
	(const u32 *rkey_enc, u8 *dst, const u8 *src, u8 *iv, unsigned int nblocks),
	(rkey_enc, dst, src, iv, nblocks));
