// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cryptographic API.
 *
 * RNG operations.
 *
 * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
 * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
 */

#include <linux/atomic.h>
#include <crypto/internal/rng.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/cryptouser.h>
#include <net/netlink.h>

#include "internal.h"

static DEFINE_MUTEX(crypto_default_rng_lock);
struct crypto_rng *crypto_default_rng;
EXPORT_SYMBOL_GPL(crypto_default_rng);
static int crypto_default_rng_refcnt;

int crypto_rng_reset(struct crypto_rng *tfm, const u8 *seed, unsigned int slen)
{
	struct crypto_alg *alg = tfm->base.__crt_alg;
	u8 *buf = NULL;
	int err;

	if (!seed && slen) {
		buf = kmalloc(slen, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		err = get_random_bytes_wait(buf, slen);
		if (err)
			goto out;
		seed = buf;
	}

	crypto_stats_get(alg);
	err = crypto_rng_alg(tfm)->seed(tfm, seed, slen);
	crypto_stats_rng_seed(alg, err);
out:
	kfree_sensitive(buf);
	return err;
}
EXPORT_SYMBOL_GPL(crypto_rng_reset);

static int crypto_rng_init_tfm(struct crypto_tfm *tfm)
{
	return 0;
}

static unsigned int seedsize(struct crypto_alg *alg)
{
	struct rng_alg *ralg = container_of(alg, struct rng_alg, base);

	return ralg->seedsize;
}

#ifdef CONFIG_NET
static int crypto_rng_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_rng rrng;

	memset(&rrng, 0, sizeof(rrng));

	strscpy(rrng.type, "rng", sizeof(rrng.type));

	rrng.seedsize = seedsize(alg);

	return nla_put(skb, CRYPTOCFGA_REPORT_RNG, sizeof(rrng), &rrng);
}
#else
static int crypto_rng_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

static void crypto_rng_show(struct seq_file *m, struct crypto_alg *alg)
	__maybe_unused;
static void crypto_rng_show(struct seq_file *m, struct crypto_alg *alg)
{
	seq_printf(m, "type         : rng\n");
	seq_printf(m, "seedsize     : %u\n", seedsize(alg));
}

static const struct crypto_type crypto_rng_type = {
	.extsize = crypto_alg_extsize,
	.init_tfm = crypto_rng_init_tfm,
#ifdef CONFIG_PROC_FS
	.show = crypto_rng_show,
#endif
	.report = crypto_rng_report,
	.maskclear = ~CRYPTO_ALG_TYPE_MASK,
	.maskset = CRYPTO_ALG_TYPE_MASK,
	.type = CRYPTO_ALG_TYPE_RNG,
	.tfmsize = offsetof(struct crypto_rng, base),
};

struct crypto_rng *crypto_alloc_rng(const char *alg_name, u32 type, u32 mask)
{
	return crypto_alloc_tfm(alg_name, &crypto_rng_type, type, mask);
}
EXPORT_SYMBOL_GPL(crypto_alloc_rng);

int crypto_get_default_rng(void)
{
	struct crypto_rng *rng;
	int err;

	mutex_lock(&crypto_default_rng_lock);
	if (!crypto_default_rng) {
		rng = crypto_alloc_rng("stdrng", 0, 0);
		err = PTR_ERR(rng);
		if (IS_ERR(rng))
			goto unlock;

		err = crypto_rng_reset(rng, NULL, crypto_rng_seedsize(rng));
		if (err) {
			crypto_free_rng(rng);
			goto unlock;
		}

		crypto_default_rng = rng;
	}

	crypto_default_rng_refcnt++;
	err = 0;

unlock:
	mutex_unlock(&crypto_default_rng_lock);

	return err;
}
EXPORT_SYMBOL_GPL(crypto_get_default_rng);

void crypto_put_default_rng(void)
{
	mutex_lock(&crypto_default_rng_lock);
	crypto_default_rng_refcnt--;
	mutex_unlock(&crypto_default_rng_lock);
}
EXPORT_SYMBOL_GPL(crypto_put_default_rng);

#if defined(CONFIG_CRYPTO_RNG) || defined(CONFIG_CRYPTO_RNG_MODULE)
int crypto_del_default_rng(void)
{
	int err = -EBUSY;

	mutex_lock(&crypto_default_rng_lock);
	if (crypto_default_rng_refcnt)
		goto out;

	crypto_free_rng(crypto_default_rng);
	crypto_default_rng = NULL;

	err = 0;

out:
	mutex_unlock(&crypto_default_rng_lock);

	return err;
}
EXPORT_SYMBOL_GPL(crypto_del_default_rng);
#endif

int crypto_register_rng(struct rng_alg *alg)
{
	struct crypto_alg *base = &alg->base;

	if (alg->seedsize > PAGE_SIZE / 8)
		return -EINVAL;

	base->cra_type = &crypto_rng_type;
	base->cra_flags &= ~CRYPTO_ALG_TYPE_MASK;
	base->cra_flags |= CRYPTO_ALG_TYPE_RNG;

	return crypto_register_alg(base);
}
EXPORT_SYMBOL_GPL(crypto_register_rng);

void crypto_unregister_rng(struct rng_alg *alg)
{
	crypto_unregister_alg(&alg->base);
}
EXPORT_SYMBOL_GPL(crypto_unregister_rng);

int crypto_register_rngs(struct rng_alg *algs, int count)
{
	int i, ret;

	for (i = 0; i < count; i++) {
		ret = crypto_register_rng(algs + i);
		if (ret)
			goto err;
	}

	return 0;

err:
	for (--i; i >= 0; --i)
		crypto_unregister_rng(algs + i);

	return ret;
}
EXPORT_SYMBOL_GPL(crypto_register_rngs);

void crypto_unregister_rngs(struct rng_alg *algs, int count)
{
	int i;

	for (i = count - 1; i >= 0; --i)
		crypto_unregister_rng(algs + i);
}
EXPORT_SYMBOL_GPL(crypto_unregister_rngs);

static ssize_t crypto_devrandom_read(void __user *buf, size_t buflen)
{
	u8 tmp[256];
	ssize_t ret;

	if (!buflen)
		return 0;

	ret = crypto_get_default_rng();
	if (ret)
		return ret;

	for (;;) {
		int err;
		int i;

		i = min_t(int, buflen, sizeof(tmp));
		err = crypto_rng_get_bytes(crypto_default_rng, tmp, i);
		if (err) {
			ret = err;
			break;
		}

		if (copy_to_user(buf, tmp, i)) {
			ret = -EFAULT;
			break;
		}

		buflen -= i;
		buf += i;
		ret += i;

		if (!buflen)
			break;

		if (need_resched()) {
			if (signal_pending(current))
				break;
			schedule();
		}
	}

	crypto_put_default_rng();
	memzero_explicit(tmp, sizeof(tmp));

	return ret;
}

static const struct random_extrng crypto_devrandom_rng = {
	.extrng_read = crypto_devrandom_read,
	.owner = THIS_MODULE,
};

static int __init crypto_rng_init(void)
{
	if (fips_enabled)
		random_register_extrng(&crypto_devrandom_rng);
	return 0;
}

static void __exit crypto_rng_exit(void)
{
	random_unregister_extrng();
}

late_initcall(crypto_rng_init);
module_exit(crypto_rng_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Random Number Generator");
