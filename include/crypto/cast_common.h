/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_CAST_COMMON_H
#define _CRYPTO_CAST_COMMON_H

#include <crypto/api.h>

DECLARE_CRYPTO_VAR(cast_s1, const u32, [256]);
DECLARE_CRYPTO_VAR(cast_s2, const u32, [256]);
DECLARE_CRYPTO_VAR(cast_s3, const u32, [256]);
DECLARE_CRYPTO_VAR(cast_s4, const u32, [256]);

#if defined(CONFIG_CRYPTO_FIPS140_EXTMOD) && !defined(FIPS_MODULE)
#define cast_s1 (((const u32*)CRYPTO_VAR_NAME(cast_s1)))
#define cast_s2 (((const u32*)CRYPTO_VAR_NAME(cast_s2)))
#define cast_s3 (((const u32*)CRYPTO_VAR_NAME(cast_s3)))
#define cast_s4 (((const u32*)CRYPTO_VAR_NAME(cast_s4)))
#endif

#endif
