// SPDX-License-Identifier: GPL-2.0

#include <linux/crc32c.h>
#include <linux/xxhash.h>
#include <crypto/sha2.h>
#include <crypto/blake2b.h>
#include <linux/unaligned.h>
#include "messages.h"
#include "fs.h"
#include "accessors.h"
#include "volumes.h"

/* Minimal blake2b implementation for btrfs checksums */
static const u64 blake2b_iv[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const u8 blake2b_sigma[12][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static void blake2b_compress(struct blake2b_state *S, const u8 *block)
{
	u64 m[16], v[16];
	int i;

	for (i = 0; i < 16; i++)
		m[i] = get_unaligned_le64(block + i * 8);

	for (i = 0; i < 8; i++)
		v[i] = S->h[i];
	v[ 8] = blake2b_iv[0];
	v[ 9] = blake2b_iv[1];
	v[10] = blake2b_iv[2];
	v[11] = blake2b_iv[3];
	v[12] = S->t[0] ^ blake2b_iv[4];
	v[13] = S->t[1] ^ blake2b_iv[5];
	v[14] = S->f[0] ^ blake2b_iv[6];
	v[15] = S->f[1] ^ blake2b_iv[7];

#define G(r,i,a,b,c,d) \
	do { \
		a = a + b + m[blake2b_sigma[r][2*i+0]]; \
		d = ror64(d ^ a, 32); \
		c = c + d; \
		b = ror64(b ^ c, 24); \
		a = a + b + m[blake2b_sigma[r][2*i+1]]; \
		d = ror64(d ^ a, 16); \
		c = c + d; \
		b = ror64(b ^ c, 63); \
	} while (0)

#define ROUND(r) \
	do { \
		G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
		G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
		G(r,2,v[ 2],v[ 6],v[10],v[14]); \
		G(r,3,v[ 3],v[ 7],v[11],v[15]); \
		G(r,4,v[ 0],v[ 5],v[10],v[15]); \
		G(r,5,v[ 1],v[ 6],v[11],v[12]); \
		G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
		G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
	} while (0)

	ROUND(0); ROUND(1); ROUND(2); ROUND(3);
	ROUND(4); ROUND(5); ROUND(6); ROUND(7);
	ROUND(8); ROUND(9); ROUND(10); ROUND(11);

#undef G
#undef ROUND

	for (i = 0; i < 8; i++)
		S->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_increment_counter(struct blake2b_state *S, u64 inc)
{
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

static void blake2b_256(const u8 *data, size_t len, u8 *out)
{
	struct blake2b_state S;
	u8 buf[128] = {0};
	size_t i;

	__blake2b_init(&S, 32, 0);
	S.t[0] = S.t[1] = 0;
	S.f[0] = S.f[1] = 0;

	while (len > 128) {
		blake2b_increment_counter(&S, 128);
		blake2b_compress(&S, data);
		data += 128;
		len -= 128;
	}

	blake2b_increment_counter(&S, len);
	S.f[0] = -1;
	memcpy(buf, data, len);
	blake2b_compress(&S, buf);

	for (i = 0; i < 4; i++)
		put_unaligned_le64(S.h[i], out + i * 8);
}

static const struct btrfs_csums {
	u16		size;
	const char	name[10];
} btrfs_csums[] = {
	[BTRFS_CSUM_TYPE_CRC32] = { .size = 4, .name = "crc32c" },
	[BTRFS_CSUM_TYPE_XXHASH] = { .size = 8, .name = "xxhash64" },
	[BTRFS_CSUM_TYPE_SHA256] = { .size = 32, .name = "sha256" },
	[BTRFS_CSUM_TYPE_BLAKE2] = { .size = 32, .name = "blake2b" },
};

/* This exists for btrfs-progs usages. */
u16 btrfs_csum_type_size(u16 type)
{
	return btrfs_csums[type].size;
}

int btrfs_super_csum_size(const struct btrfs_super_block *s)
{
	u16 t = btrfs_super_csum_type(s);

	/* csum type is validated at mount time. */
	return btrfs_csum_type_size(t);
}

const char *btrfs_super_csum_name(u16 csum_type)
{
	/* csum type is validated at mount time. */
	return btrfs_csums[csum_type].name;
}

size_t __attribute_const__ btrfs_get_num_csums(void)
{
	return ARRAY_SIZE(btrfs_csums);
}

void btrfs_csum(u16 csum_type, const u8 *data, size_t len, u8 *out)
{
	switch (csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		put_unaligned_le32(~crc32c(~0, data, len), out);
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		put_unaligned_le64(xxh64(data, len, 0), out);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256(data, len, out);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2:
		blake2b_256(data, len, out);
		break;
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

void btrfs_csum_init(struct btrfs_csum_ctx *ctx, u16 csum_type)
{
	ctx->csum_type = csum_type;
	switch (ctx->csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		ctx->crc32 = ~0;
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		xxh64_reset(&ctx->xxh64, 0);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256_init(&ctx->sha256);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2:
		__blake2b_init(&ctx->blake2b, 32, 0);
		ctx->blake2b.t[0] = ctx->blake2b.t[1] = 0;
		ctx->blake2b.f[0] = ctx->blake2b.f[1] = 0;
		ctx->buflen = 0;
		break;
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

void btrfs_csum_update(struct btrfs_csum_ctx *ctx, const u8 *data, size_t len)
{
	switch (ctx->csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		ctx->crc32 = crc32c(ctx->crc32, data, len);
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		xxh64_update(&ctx->xxh64, data, len);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256_update(&ctx->sha256, data, len);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2: {
		size_t offset = 0;
		
		/* Fill buffer if we have partial data */
		if (ctx->buflen > 0) {
			size_t to_copy = min(128 - ctx->buflen, len);
			memcpy(ctx->buf + ctx->buflen, data, to_copy);
			ctx->buflen += to_copy;
			offset += to_copy;
			
			if (ctx->buflen == 128) {
				blake2b_increment_counter(&ctx->blake2b, 128);
				blake2b_compress(&ctx->blake2b, ctx->buf);
				ctx->buflen = 0;
			}
		}
		
		/* Process full blocks */
		while (offset + 128 <= len) {
			blake2b_increment_counter(&ctx->blake2b, 128);
			blake2b_compress(&ctx->blake2b, data + offset);
			offset += 128;
		}
		
		/* Buffer remaining data */
		if (offset < len) {
			memcpy(ctx->buf, data + offset, len - offset);
			ctx->buflen = len - offset;
		}
		break;
	}
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

void btrfs_csum_final(struct btrfs_csum_ctx *ctx, u8 *out)
{
	switch (ctx->csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
		put_unaligned_le32(~ctx->crc32, out);
		break;
	case BTRFS_CSUM_TYPE_XXHASH:
		put_unaligned_le64(xxh64_digest(&ctx->xxh64), out);
		break;
	case BTRFS_CSUM_TYPE_SHA256:
		sha256_final(&ctx->sha256, out);
		break;
	case BTRFS_CSUM_TYPE_BLAKE2: {
		u8 buf[128] = {0};
		int i;
		
		blake2b_increment_counter(&ctx->blake2b, ctx->buflen);
		ctx->blake2b.f[0] = -1;
		memcpy(buf, ctx->buf, ctx->buflen);
		blake2b_compress(&ctx->blake2b, buf);
		
		for (i = 0; i < 4; i++)
			put_unaligned_le64(ctx->blake2b.h[i], out + i * 8);
		break;
	}
	default:
		/* Checksum type is validated at mount time. */
		BUG();
	}
}

/*
 * We support the following block sizes for all systems:
 *
 * - 4K
 *   This is the most common block size. For PAGE SIZE > 4K cases the subpage
 *   mode is used.
 *
 * - PAGE_SIZE
 *   The straightforward block size to support.
 *
 * And extra support for the following block sizes based on the kernel config:
 *
 * - MIN_BLOCKSIZE
 *   This is either 4K (regular builds) or 2K (debug builds)
 *   This allows testing subpage routines on x86_64.
 */
bool __attribute_const__ btrfs_supported_blocksize(u32 blocksize)
{
	/* @blocksize should be validated first. */
	ASSERT(is_power_of_2(blocksize) && blocksize >= BTRFS_MIN_BLOCKSIZE &&
	       blocksize <= BTRFS_MAX_BLOCKSIZE);

	if (blocksize == PAGE_SIZE || blocksize == SZ_4K || blocksize == BTRFS_MIN_BLOCKSIZE)
		return true;
#ifdef CONFIG_BTRFS_EXPERIMENTAL
	/*
	 * For bs > ps support it's done by specifying a minimal folio order
	 * for filemap, thus implying large data folios.
	 * For HIGHMEM systems, we can not always access the content of a (large)
	 * folio in one go, but go through them page by page.
	 *
	 * A lot of features don't implement a proper PAGE sized loop for large
	 * folios, this includes:
	 *
	 * - compression
	 * - verity
	 * - encoded write
	 *
	 * Considering HIGHMEM is such a pain to deal with and it's going
	 * to be deprecated eventually, just reject HIGHMEM && bs > ps cases.
	 */
	if (IS_ENABLED(CONFIG_HIGHMEM) && blocksize > PAGE_SIZE)
		return false;
	return true;
#endif
	return false;
}

/*
 * Start exclusive operation @type, return true on success.
 */
bool btrfs_exclop_start(struct btrfs_fs_info *fs_info,
			enum btrfs_exclusive_operation type)
{
	bool ret = false;

	spin_lock(&fs_info->super_lock);
	if (fs_info->exclusive_operation == BTRFS_EXCLOP_NONE) {
		fs_info->exclusive_operation = type;
		ret = true;
	}
	spin_unlock(&fs_info->super_lock);

	return ret;
}

/*
 * Conditionally allow to enter the exclusive operation in case it's compatible
 * with the running one.  This must be paired with btrfs_exclop_start_unlock()
 * and btrfs_exclop_finish().
 *
 * Compatibility:
 * - the same type is already running
 * - when trying to add a device and balance has been paused
 * - not BTRFS_EXCLOP_NONE - this is intentionally incompatible and the caller
 *   must check the condition first that would allow none -> @type
 */
bool btrfs_exclop_start_try_lock(struct btrfs_fs_info *fs_info,
				 enum btrfs_exclusive_operation type)
{
	spin_lock(&fs_info->super_lock);
	if (fs_info->exclusive_operation == type ||
	    (fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED &&
	     type == BTRFS_EXCLOP_DEV_ADD))
		return true;

	spin_unlock(&fs_info->super_lock);
	return false;
}

void btrfs_exclop_start_unlock(struct btrfs_fs_info *fs_info)
{
	spin_unlock(&fs_info->super_lock);
}

void btrfs_exclop_finish(struct btrfs_fs_info *fs_info)
{
	spin_lock(&fs_info->super_lock);
	WRITE_ONCE(fs_info->exclusive_operation, BTRFS_EXCLOP_NONE);
	spin_unlock(&fs_info->super_lock);
	sysfs_notify(&fs_info->fs_devices->fsid_kobj, NULL, "exclusive_operation");
}

void btrfs_exclop_balance(struct btrfs_fs_info *fs_info,
			  enum btrfs_exclusive_operation op)
{
	switch (op) {
	case BTRFS_EXCLOP_BALANCE_PAUSED:
		spin_lock(&fs_info->super_lock);
		ASSERT(fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE ||
		       fs_info->exclusive_operation == BTRFS_EXCLOP_DEV_ADD ||
		       fs_info->exclusive_operation == BTRFS_EXCLOP_NONE ||
		       fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED);
		fs_info->exclusive_operation = BTRFS_EXCLOP_BALANCE_PAUSED;
		spin_unlock(&fs_info->super_lock);
		break;
	case BTRFS_EXCLOP_BALANCE:
		spin_lock(&fs_info->super_lock);
		ASSERT(fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED);
		fs_info->exclusive_operation = BTRFS_EXCLOP_BALANCE;
		spin_unlock(&fs_info->super_lock);
		break;
	default:
		btrfs_warn(fs_info,
			"invalid exclop balance operation %d requested", op);
	}
}

void __btrfs_set_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag,
			     const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info,
				"setting incompat feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void __btrfs_clear_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag,
			       const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info,
				"clearing incompat feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void __btrfs_set_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag,
			      const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info,
				"setting compat-ro feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}

void __btrfs_clear_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag,
				const char *name)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info,
				"clearing compat-ro feature flag for %s (0x%llx)",
				name, flag);
		}
		spin_unlock(&fs_info->super_lock);
		set_bit(BTRFS_FS_FEATURE_CHANGED, &fs_info->flags);
	}
}
