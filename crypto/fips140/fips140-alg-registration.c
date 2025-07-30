// SPDX-License-Identifier: GPL-2.0-only
/*
 * Algorithm registration wrappers for FIPS 140 module
 */

#include <linux/module.h>
#include <linux/completion.h>
#include <crypto/algapi.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/rng.h>

/* Indicates whether the self-tests and integrity check have completed */
DECLARE_COMPLETION(fips140_tests_done);

/* Wrapper functions for algorithm registration */

int fips140_crypto_register_alg(struct crypto_alg *alg)
{
    return crypto_register_alg(alg);
}

int fips140_crypto_register_algs(struct crypto_alg *algs, int count)
{
    return crypto_register_algs(algs, count);
}

int fips140_crypto_register_shash(struct shash_alg *alg)
{
    return crypto_register_shash(alg);
}

int fips140_crypto_register_shashes(struct shash_alg *algs, int count)
{
    return crypto_register_shashes(algs, count);
}

int fips140_crypto_register_ahash(struct ahash_alg *alg)
{
    return crypto_register_ahash(alg);
}

int fips140_crypto_register_ahashes(struct ahash_alg *algs, int count)
{
    return crypto_register_ahashes(algs, count);
}

int fips140_crypto_register_aead(struct aead_alg *alg)
{
    return crypto_register_aead(alg);
}

int fips140_crypto_register_aeads(struct aead_alg *algs, int count)
{
    return crypto_register_aeads(algs, count);
}

int fips140_crypto_register_skcipher(struct skcipher_alg *alg)
{
    return crypto_register_skcipher(alg);
}

int fips140_crypto_register_skciphers(struct skcipher_alg *algs, int count)
{
    return crypto_register_skciphers(algs, count);
}

int fips140_crypto_register_rng(struct rng_alg *alg)
{
    return crypto_register_rng(alg);
}

int fips140_crypto_register_rngs(struct rng_alg *algs, int count)
{
    return crypto_register_rngs(algs, count);
}

/* Instance registration wrappers */
int fips140_aead_register_instance(struct crypto_template *tmpl,
                                   struct aead_instance *inst)
{
    return aead_register_instance(tmpl, inst);
}

int fips140_ahash_register_instance(struct crypto_template *tmpl,
                                    struct ahash_instance *inst)
{
    return ahash_register_instance(tmpl, inst);
}

int fips140_shash_register_instance(struct crypto_template *tmpl,
                                    struct shash_instance *inst)
{
    return shash_register_instance(tmpl, inst);
}

int fips140_skcipher_register_instance(struct crypto_template *tmpl,
                                       struct skcipher_instance *inst)
{
    return skcipher_register_instance(tmpl, inst);
}
