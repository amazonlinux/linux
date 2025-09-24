/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Crypto engine API
 *
 * Copyright (c) 2016 Baolin Wang <baolin.wang@linaro.org>
 */
#ifndef _CRYPTO_ENGINE_H
#define _CRYPTO_ENGINE_H

#include <crypto/api.h>
#include <crypto/aead.h>
#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/skcipher.h>
#include <linux/types.h>

struct crypto_engine;
struct device;

/*
 * struct crypto_engine_op - crypto hardware engine operations
 * @do_one_request: do encryption for current request
 */
struct crypto_engine_op {
	int (*do_one_request)(struct crypto_engine *engine,
			      void *areq);
};

struct aead_engine_alg {
	struct aead_alg base;
	struct crypto_engine_op op;
};

struct ahash_engine_alg {
	struct ahash_alg base;
	struct crypto_engine_op op;
};

struct akcipher_engine_alg {
	struct akcipher_alg base;
	struct crypto_engine_op op;
};

struct kpp_engine_alg {
	struct kpp_alg base;
	struct crypto_engine_op op;
};

struct skcipher_engine_alg {
	struct skcipher_alg base;
	struct crypto_engine_op op;
};

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_transfer_aead_request_to_engine, int,
	(struct crypto_engine *engine, struct aead_request *req),
	(engine, req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_transfer_akcipher_request_to_engine, int,
	(struct crypto_engine *engine, struct akcipher_request *req),
	(engine, req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_transfer_hash_request_to_engine, int,
	(struct crypto_engine *engine, struct ahash_request *req),
	(engine, req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_transfer_kpp_request_to_engine, int,
	(struct crypto_engine *engine, struct kpp_request *req),
	(engine, req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_transfer_skcipher_request_to_engine, int,
	(struct crypto_engine *engine, struct skcipher_request *req),
	(engine, req));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_finalize_aead_request, void,
	(struct crypto_engine *engine, struct aead_request *req, int err),
	(engine, req, err));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_finalize_akcipher_request, void,
	(struct crypto_engine *engine, struct akcipher_request *req, int err),
	(engine, req, err));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_finalize_hash_request, void,
	(struct crypto_engine *engine, struct ahash_request *req, int err),
	(engine, req, err));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_finalize_kpp_request, void,
	(struct crypto_engine *engine, struct kpp_request *req, int err),
	(engine, req, err));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_finalize_skcipher_request, void,
	(struct crypto_engine *engine, struct skcipher_request *req, int err),
	(engine, req, err));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_start, int,
	(struct crypto_engine *engine),
	(engine));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_stop, int,
	(struct crypto_engine *engine),
	(engine));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_alloc_init, struct crypto_engine *,
	(struct device *dev, bool rt),
	(dev, rt));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_alloc_init_and_set, struct crypto_engine *,
	(struct device *dev, bool retry_support, bool rt, int qlen),
	(dev, retry_support, rt, qlen));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_exit, void,
	(struct crypto_engine *engine),
	(engine));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_aead, int,
	(struct aead_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_aead, void,
	(struct aead_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_aeads, int,
	(struct aead_engine_alg *algs, int count),
	(algs, count));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_aeads, void,
	(struct aead_engine_alg *algs, int count),
	(algs, count));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_ahash, int,
	(struct ahash_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_ahash, void,
	(struct ahash_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_ahashes, int,
	(struct ahash_engine_alg *algs, int count),
	(algs, count));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_ahashes, void,
	(struct ahash_engine_alg *algs, int count),
	(algs, count));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_akcipher, int,
	(struct akcipher_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_akcipher, void,
	(struct akcipher_engine_alg *alg),
	(alg));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_kpp, int,
	(struct kpp_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_kpp, void,
	(struct kpp_engine_alg *alg),
	(alg));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_skcipher, int,
	(struct skcipher_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_skcipher, void,
	(struct skcipher_engine_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_register_skciphers, int,
	(struct skcipher_engine_alg *algs, int count),
	(algs, count));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ENGINE, crypto_engine_unregister_skciphers, void,
	(struct skcipher_engine_alg *algs, int count),
	(algs, count));

#endif /* _CRYPTO_ENGINE_H */
