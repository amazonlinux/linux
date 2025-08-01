// SPDX-License-Identifier: GPL-2.0
/*
 * FIPS 140 wrappers for unexported kernel functions
 *
 * This file provides exported wrappers for kernel functions that are not
 * exported but are needed by crypto algorithms in the FIPS module.
 * These functions are compiled into the main kernel and exported for use
 * by the FIPS module.
 */

#include <linux/export.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <keys/system_keyring.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/static_call.h>

#ifdef CONFIG_RAID6_PQ
#include <linux/raid/pq.h>

/*
 * RAID6 symbol wrappers
 * These are needed by async_tx operations
 */
int fips140_raid6_2data_recov(int disks, size_t bytes, int faila, int failb, void **ptrs)
{
	return raid6_2data_recov(disks, bytes, faila, failb, ptrs);
}
EXPORT_SYMBOL_GPL(fips140_raid6_2data_recov);

int fips140_raid6_datap_recov(int disks, size_t bytes, int faila, void **ptrs)
{
	return raid6_datap_recov(disks, bytes, faila, ptrs);
}
EXPORT_SYMBOL_GPL(fips140_raid6_datap_recov);

const struct raid6_calls *fips140_raid6_call = &raid6_call;
EXPORT_SYMBOL_GPL(fips140_raid6_call);

const u8 *fips140_raid6_gfexp = raid6_gfexp;
EXPORT_SYMBOL_GPL(fips140_raid6_gfexp);

const u8 *fips140_raid6_gfmul = raid6_gfmul;
EXPORT_SYMBOL_GPL(fips140_raid6_gfmul);

const u8 *fips140_raid6_gfinv = raid6_gfinv;
EXPORT_SYMBOL_GPL(fips140_raid6_gfinv);

const u8 *fips140_raid6_gfexi = raid6_gfexi;
EXPORT_SYMBOL_GPL(fips140_raid6_gfexi);

const void *fips140_raid6_empty_zero_page = &raid6_empty_zero_page;
EXPORT_SYMBOL_GPL(fips140_raid6_empty_zero_page);
#endif /* CONFIG_RAID6_PQ */

#ifdef CONFIG_ZSTD_COMPRESS
#include <linux/zstd.h>

/*
 * ZSTD symbol wrappers
 * These are needed by zstd compression algorithms
 */
size_t fips140_zstd_cctx_workspace_bound(const zstd_compression_parameters *cparams)
{
	return zstd_cctx_workspace_bound(cparams);
}
EXPORT_SYMBOL_GPL(fips140_zstd_cctx_workspace_bound);

zstd_cctx *fips140_zstd_init_cctx(void *workspace, size_t workspace_size)
{
	return zstd_init_cctx(workspace, workspace_size);
}
EXPORT_SYMBOL_GPL(fips140_zstd_init_cctx);

size_t fips140_zstd_compress_cctx(zstd_cctx *cctx, void *dst, size_t dst_capacity,
				  const void *src, size_t src_size, const zstd_parameters *parameters)
{
	return zstd_compress_cctx(cctx, dst, dst_capacity, src, src_size, parameters);
}
EXPORT_SYMBOL_GPL(fips140_zstd_compress_cctx);

zstd_parameters fips140_zstd_get_params(int compression_level, unsigned long long estimated_src_size)
{
	return zstd_get_params(compression_level, estimated_src_size);
}
EXPORT_SYMBOL_GPL(fips140_zstd_get_params);
#endif /* CONFIG_ZSTD_COMPRESS */

#if defined(CONFIG_LZ4_COMPRESS) && !IS_MODULE(CONFIG_LZ4_COMPRESS)
#include <linux/lz4.h>

/*
 * LZ4 compression symbol wrappers
 * Only needed when LZ4_COMPRESS is built-in (=y)
 * These are needed by lz4 compression algorithms
 */
int fips140_LZ4_compress_default(const char *src, char *dst, int srcSize, int dstCapacity)
{
	return LZ4_compress_default(src, dst, srcSize, dstCapacity);
}
EXPORT_SYMBOL_GPL(fips140_LZ4_compress_default);

int fips140_LZ4_compress_HC(const char *src, char *dst, int srcSize, int dstCapacity, int compressionLevel)
{
	return LZ4_compress_HC(src, dst, srcSize, dstCapacity, compressionLevel);
}
EXPORT_SYMBOL_GPL(fips140_LZ4_compress_HC);
#endif /* CONFIG_LZ4_COMPRESS && !IS_MODULE(CONFIG_LZ4_COMPRESS) */

#if defined(CONFIG_LZ4_DECOMPRESS) && !IS_MODULE(CONFIG_LZ4_DECOMPRESS)
#include <linux/lz4.h>

/*
 * LZ4 decompression symbol wrappers
 * Only needed when LZ4_DECOMPRESS is built-in (=y)
 */
int fips140_LZ4_decompress_safe(const char *src, char *dst, int compressedSize, int dstCapacity)
{
	return LZ4_decompress_safe(src, dst, compressedSize, dstCapacity);
}
EXPORT_SYMBOL_GPL(fips140_LZ4_decompress_safe);
#endif /* CONFIG_LZ4_DECOMPRESS && !IS_MODULE(CONFIG_LZ4_DECOMPRESS) */

/*
 * Wrapper for restrict_link_by_builtin_trusted
 * This function restricts linking to keys in the builtin trusted keyring
 */
int fips140_restrict_link_by_builtin_trusted(struct key *keyring,
					     const struct key_type *type,
					     const union key_payload *payload,
					     struct key *restriction_key)
{
	return restrict_link_by_builtin_trusted(keyring, type, payload, restriction_key);
}
EXPORT_SYMBOL_GPL(fips140_restrict_link_by_builtin_trusted);

/*
 * Wrapper for might_resched static call
 * This function handles potential rescheduling points
 */
void fips140___SCK__might_resched(void)
{
	might_resched();
}
EXPORT_SYMBOL_GPL(fips140___SCK__might_resched);

/*
 * Wrapper for preempt_schedule static call
 * This function handles preemptive scheduling
 */
void fips140___SCK__preempt_schedule(void)
{
	preempt_schedule();
}
EXPORT_SYMBOL_GPL(fips140___SCK__preempt_schedule);
