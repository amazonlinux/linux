/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Public Key Signature Algorithm
 *
 * Copyright (c) 2023 Herbert Xu <herbert@gondor.apana.org.au>
 */
#ifndef _CRYPTO_INTERNAL_SIG_H
#define _CRYPTO_INTERNAL_SIG_H

#include <crypto/api.h>
#include <crypto/algapi.h>
#include <crypto/sig.h>

struct sig_instance {
	void (*free)(struct sig_instance *inst);
	union {
		struct {
			char head[offsetof(struct sig_alg, base)];
			struct crypto_instance base;
		};
		struct sig_alg alg;
	};
};

struct crypto_sig_spawn {
	struct crypto_spawn base;
};

static inline void *crypto_sig_ctx(struct crypto_sig *tfm)
{
	return crypto_tfm_ctx(&tfm->base);
}

/**
 * crypto_register_sig() -- Register public key signature algorithm
 *
 * Function registers an implementation of a public key signature algorithm
 *
 * @alg:	algorithm definition
 *
 * Return: zero on success; error code in case of error
 */
DECLARE_CRYPTO_API(crypto_register_sig, int, (struct sig_alg *alg), (alg));

/**
 * crypto_unregister_sig() -- Unregister public key signature algorithm
 *
 * Function unregisters an implementation of a public key signature algorithm
 *
 * @alg:	algorithm definition
 */
DECLARE_CRYPTO_API(crypto_unregister_sig, void, (struct sig_alg *alg), (alg));

DECLARE_CRYPTO_API(sig_register_instance, int, (struct crypto_template *tmpl, struct sig_instance *inst), (tmpl, inst));

static inline struct sig_instance *sig_instance(struct crypto_instance *inst)
{
	return container_of(&inst->alg, struct sig_instance, alg.base);
}

static inline struct sig_instance *sig_alg_instance(struct crypto_sig *tfm)
{
	return sig_instance(crypto_tfm_alg_instance(&tfm->base));
}

static inline struct crypto_instance *sig_crypto_instance(struct sig_instance
									*inst)
{
	return container_of(&inst->alg.base, struct crypto_instance, alg);
}

static inline void *sig_instance_ctx(struct sig_instance *inst)
{
	return crypto_instance_ctx(sig_crypto_instance(inst));
}

DECLARE_CRYPTO_API(crypto_grab_sig, int, (struct crypto_sig_spawn *spawn, struct crypto_instance *inst, const char *name, u32 type, u32 mask), (spawn, inst, name, type, mask));

static inline struct crypto_sig *crypto_spawn_sig(struct crypto_sig_spawn
								   *spawn)
{
	return crypto_spawn_tfm2(&spawn->base);
}

static inline void crypto_drop_sig(struct crypto_sig_spawn *spawn)
{
	crypto_drop_spawn(&spawn->base);
}

static inline struct sig_alg *crypto_spawn_sig_alg(struct crypto_sig_spawn
								    *spawn)
{
	return container_of(spawn->base.alg, struct sig_alg, base);
}
#endif
