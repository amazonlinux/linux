/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * geniv: IV generation
 *
 * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
 */

#ifndef _CRYPTO_INTERNAL_GENIV_H
#define _CRYPTO_INTERNAL_GENIV_H

#include <crypto/api.h>
#include <crypto/internal/aead.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct aead_geniv_ctx {
	spinlock_t lock;
	struct crypto_aead *child;
	u8 salt[] __attribute__ ((aligned(__alignof__(u32))));
};

DECLARE_CRYPTO_API(aead_geniv_alloc, struct aead_instance *,
	(struct crypto_template *tmpl, struct rtattr **tb),
	(tmpl, tb));
DECLARE_CRYPTO_API(aead_init_geniv, int,
	(struct crypto_aead *tfm),
	(tfm));
DECLARE_CRYPTO_API(aead_exit_geniv, void,
	(struct crypto_aead *tfm),
	(tfm));

#endif	/* _CRYPTO_INTERNAL_GENIV_H */
