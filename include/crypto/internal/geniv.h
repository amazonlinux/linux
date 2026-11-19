/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * geniv: IV generation
 *
 * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
 */

#ifndef _CRYPTO_INTERNAL_GENIV_H
#define _CRYPTO_INTERNAL_GENIV_H

#include <crypto/internal/aead.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct aead_geniv_ctx {
	/*
	 * Restored for the certified FIPS sources.  Upstream 2418431211d5
	 * ("crypto: geniv - Remove unused spinlock from struct aead_geniv_ctx")
	 * deleted this member and the spin_lock_init() that goes with it, but
	 * crypto/geniv.c is inside the boundary and still initialises it.  It was
	 * unused then and is unused now -- the init is its only reference in the
	 * whole tree -- so this is layout only, with no locking behaviour.
	 */
	spinlock_t lock;
	struct crypto_aead *child;
	u8 salt[] __attribute__ ((aligned(__alignof__(u32))));
};

struct aead_instance *aead_geniv_alloc(struct crypto_template *tmpl,
				       struct rtattr **tb);
int aead_init_geniv(struct crypto_aead *tfm);
void aead_exit_geniv(struct crypto_aead *tfm);

#endif	/* _CRYPTO_INTERNAL_GENIV_H */
