/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ASM_X86_SM4_AVX_H
#define ASM_X86_SM4_AVX_H

#include <crypto/api.h>
#include <linux/types.h>
#include <crypto/sm4.h>

typedef void (*sm4_crypt_func)(const u32 *rk, u8 *dst, const u8 *src, u8 *iv);

struct skcipher_request;
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64, sm4_avx_ecb_encrypt, int,
	(struct skcipher_request *req),
	(req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64, sm4_avx_ecb_decrypt, int,
	(struct skcipher_request *req),
	(req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64, sm4_cbc_encrypt, int,
	(struct skcipher_request *req),
	(req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64, sm4_avx_cbc_decrypt, int,
	(struct skcipher_request *req, unsigned int bsize, sm4_crypt_func func),
	(req, bsize, func));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64, sm4_avx_ctr_crypt, int,
	(struct skcipher_request *req, unsigned int bsize, sm4_crypt_func func),
	(req, bsize, func));

#endif
