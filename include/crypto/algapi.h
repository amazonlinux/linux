/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Cryptographic API for algorithms (i.e., low-level API).
 *
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 */
#ifndef _CRYPTO_ALGAPI_H
#define _CRYPTO_ALGAPI_H

#include <crypto/api.h>
#include <crypto/utils.h>
#include <linux/align.h>
#include <linux/cache.h>
#include <linux/crypto.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/*
 * Maximum values for blocksize and alignmask, used to allocate
 * static buffers that are big enough for any combination of
 * algs and architectures. Ciphers have a lower maximum size.
 */
#define MAX_ALGAPI_BLOCKSIZE		160
#define MAX_ALGAPI_ALIGNMASK		127
#define MAX_CIPHER_BLOCKSIZE		16
#define MAX_CIPHER_ALIGNMASK		15

#ifdef ARCH_DMA_MINALIGN
#define CRYPTO_DMA_ALIGN ARCH_DMA_MINALIGN
#else
#define CRYPTO_DMA_ALIGN CRYPTO_MINALIGN
#endif

#define CRYPTO_DMA_PADDING ((CRYPTO_DMA_ALIGN - 1) & ~(CRYPTO_MINALIGN - 1))

/*
 * Autoloaded crypto modules should only use a prefixed name to avoid allowing
 * arbitrary modules to be loaded. Loading from userspace may still need the
 * unprefixed names, so retains those aliases as well.
 * This uses __MODULE_INFO directly instead of MODULE_ALIAS because pre-4.3
 * gcc (e.g. avr32 toolchain) uses __LINE__ for uniqueness, and this macro
 * expands twice on the same line. Instead, use a separate base name for the
 * alias.
 */
#define MODULE_ALIAS_CRYPTO(name)	\
		MODULE_INFO(alias, name);	\
		MODULE_INFO(alias, "crypto-" name)

struct crypto_aead;
struct crypto_instance;
struct module;
struct notifier_block;
struct rtattr;
struct scatterlist;
struct seq_file;
struct sk_buff;
union crypto_no_such_thing;

struct crypto_instance {
	struct crypto_alg alg;

	struct crypto_template *tmpl;

	union {
		/* Node in list of instances after registration. */
		struct hlist_node list;
		/* List of attached spawns before registration. */
		struct crypto_spawn *spawns;
	};

	void *__ctx[] CRYPTO_MINALIGN_ATTR;
};

struct crypto_template {
	struct list_head list;
	struct hlist_head instances;
	struct hlist_head dead;
	struct module *module;

	struct work_struct free_work;

	int (*create)(struct crypto_template *tmpl, struct rtattr **tb);

	char name[CRYPTO_MAX_ALG_NAME];
};

struct crypto_spawn {
	struct list_head list;
	struct crypto_alg *alg;
	union {
		/* Back pointer to instance after registration.*/
		struct crypto_instance *inst;
		/* Spawn list pointer prior to registration. */
		struct crypto_spawn *next;
	};
	const struct crypto_type *frontend;
	u32 mask;
	bool dead;
	bool registered;
};

struct crypto_queue {
	struct list_head list;
	struct list_head *backlog;

	unsigned int qlen;
	unsigned int max_qlen;
};

struct crypto_attr_alg {
	char name[CRYPTO_MAX_ALG_NAME];
};

struct crypto_attr_type {
	u32 type;
	u32 mask;
};

/*
 * Algorithm registration interface.
 */
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_register_alg, int,
	(struct crypto_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_unregister_alg, void,
	(struct crypto_alg *alg),
	(alg));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_register_algs, int,
	(struct crypto_alg *algs, int count),
	(algs, count));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_unregister_algs, void,
	(struct crypto_alg *algs, int count),
	(algs, count));

DECLARE_CRYPTO_API(CONFIG_CRYPTO, crypto_mod_put, void,
	(struct crypto_alg *alg),
	(alg));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_register_template, int,
	(struct crypto_template *tmpl),
	(tmpl));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_register_templates, int,
	(struct crypto_template *tmpls, int count),
	(tmpls, count));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_unregister_template, void,
	(struct crypto_template *tmpl),
	(tmpl));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_unregister_templates, void,
	(struct crypto_template *tmpls, int count),
	(tmpls, count));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_lookup_template, struct crypto_template *,
	(const char *name),
	(name));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_register_instance, int,
	(struct crypto_template *tmpl, struct crypto_instance *inst),
	(tmpl, inst));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_unregister_instance, void,
	(struct crypto_instance *inst),
	(inst));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_grab_spawn, int,
	(struct crypto_spawn *spawn, struct crypto_instance *inst, const char *name, u32 type, u32 mask),
	(spawn, inst, name, type, mask));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_drop_spawn, void,
	(struct crypto_spawn *spawn),
	(spawn));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_spawn_tfm, struct crypto_tfm *,
	(struct crypto_spawn *spawn, u32 type, u32 mask),
	(spawn, type, mask));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_spawn_tfm2, void *,
	(struct crypto_spawn *spawn),
	(spawn));

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_get_attr_type, struct crypto_attr_type *,
	(struct rtattr **tb),
	(tb));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_check_attr_type, int,
	(struct rtattr **tb, u32 type, u32 *mask_ret),
	(tb, type, mask_ret));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_attr_alg_name, const char *,
	(struct rtattr *rta),
	(rta));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, __crypto_inst_setname, int,
	(struct crypto_instance *inst, const char *name, const char *driver, struct crypto_alg *alg),
	(inst, name, driver, alg));

#define crypto_inst_setname(inst, name, ...) \
	CONCATENATE(crypto_inst_setname_, COUNT_ARGS(__VA_ARGS__))( \
		inst, name, ##__VA_ARGS__)
#define crypto_inst_setname_1(inst, name, alg) \
	__crypto_inst_setname(inst, name, name, alg)
#define crypto_inst_setname_2(inst, name, driver, alg) \
	__crypto_inst_setname(inst, name, driver, alg)

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_init_queue, void,
	(struct crypto_queue *queue, unsigned int max_qlen),
	(queue, max_qlen));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_enqueue_request, int,
	(struct crypto_queue *queue, struct crypto_async_request *request),
	(queue, request));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_enqueue_request_head, void,
	(struct crypto_queue *queue, struct crypto_async_request *request),
	(queue, request));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_dequeue_request, struct crypto_async_request *,
	(struct crypto_queue *queue),
	(queue));
static inline unsigned int crypto_queue_len(struct crypto_queue *queue)
{
	return queue->qlen;
}

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_inc, void,
	(u8 *a, unsigned int size),
	(a, size));

static inline void *crypto_tfm_ctx(struct crypto_tfm *tfm)
{
	return tfm->__crt_ctx;
}

static inline void *crypto_tfm_ctx_align(struct crypto_tfm *tfm,
					 unsigned int align)
{
	if (align <= crypto_tfm_ctx_alignment())
		align = 1;

	return PTR_ALIGN(crypto_tfm_ctx(tfm), align);
}

static inline unsigned int crypto_dma_align(void)
{
	return CRYPTO_DMA_ALIGN;
}

static inline unsigned int crypto_dma_padding(void)
{
	return (crypto_dma_align() - 1) & ~(crypto_tfm_ctx_alignment() - 1);
}

static inline void *crypto_tfm_ctx_dma(struct crypto_tfm *tfm)
{
	return crypto_tfm_ctx_align(tfm, crypto_dma_align());
}

static inline struct crypto_instance *crypto_tfm_alg_instance(
	struct crypto_tfm *tfm)
{
	return container_of(tfm->__crt_alg, struct crypto_instance, alg);
}

static inline void *crypto_instance_ctx(struct crypto_instance *inst)
{
	return inst->__ctx;
}

static inline struct crypto_async_request *crypto_get_backlog(
	struct crypto_queue *queue)
{
	return queue->backlog == &queue->list ? NULL :
	       container_of(queue->backlog, struct crypto_async_request, list);
}

static inline u32 crypto_requires_off(struct crypto_attr_type *algt, u32 off)
{
	return (algt->type ^ off) & algt->mask & off;
}

/*
 * When an algorithm uses another algorithm (e.g., if it's an instance of a
 * template), these are the flags that should always be set on the "outer"
 * algorithm if any "inner" algorithm has them set.
 */
#define CRYPTO_ALG_INHERITED_FLAGS	\
	(CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK |	\
	 CRYPTO_ALG_ALLOCATES_MEMORY)

/*
 * Given the type and mask that specify the flags restrictions on a template
 * instance being created, return the mask that should be passed to
 * crypto_grab_*() (along with type=0) to honor any request the user made to
 * have any of the CRYPTO_ALG_INHERITED_FLAGS clear.
 */
static inline u32 crypto_algt_inherited_mask(struct crypto_attr_type *algt)
{
	return crypto_requires_off(algt, CRYPTO_ALG_INHERITED_FLAGS);
}

DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_register_notifier, int,
	(struct notifier_block *nb),
	(nb));
DECLARE_CRYPTO_API(CONFIG_CRYPTO_ALGAPI2, crypto_unregister_notifier, int,
	(struct notifier_block *nb),
	(nb));

/* Crypto notification events. */
enum {
	CRYPTO_MSG_ALG_REQUEST,
	CRYPTO_MSG_ALG_REGISTER,
	CRYPTO_MSG_ALG_LOADED,
};

static inline void crypto_request_complete(struct crypto_async_request *req,
					   int err)
{
	req->complete(req->data, err);
}

static inline u32 crypto_tfm_alg_type(struct crypto_tfm *tfm)
{
	return tfm->__crt_alg->cra_flags & CRYPTO_ALG_TYPE_MASK;
}

static inline bool crypto_tfm_req_virt(struct crypto_tfm *tfm)
{
	return tfm->__crt_alg->cra_flags & CRYPTO_ALG_REQ_VIRT;
}

static inline u32 crypto_request_flags(struct crypto_async_request *req)
{
	return req->flags & ~CRYPTO_TFM_REQ_ON_STACK;
}

#endif	/* _CRYPTO_ALGAPI_H */
