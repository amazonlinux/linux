// SPDX-License-Identifier: GPL-2.0
/*
 * DAMON-based Access/Contiguity-aware Memory Auto-scaling
 *
 * Let user specifies min/max memory of the system and acceptable level of
 * memory pressure stall level.  While respecting those, automatically scale
 * the memory of the system up and down by scale_downing memory from the system
 * and report it to the host when the system is having memory pressure level
 * under the threshold, and vice versa, respectively.
 *
 * At this moment, the scaling is not implemented, hence this is just a memory
 * pressure-aware proactive reclamation module.
 *
 * Author: SeongJae Park <sj@kernel.org>
 */

/* ACMA is PoC level at the moment.  Don't build it in real */
#ifdef DO_BUILD_ACMA

#define pr_fmt(fmt) "damon-acma: " fmt

#include <linux/damon.h>
#include <linux/kstrtox.h>
#include <linux/module.h>

#include "modules-common.h"

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "damon_acma."

/*
 * Enable or disable DAMON_ACMA.
 *
 * You can enable DAMON_ACMA by setting the value of this parameter as ``Y``.
 * Setting it as ``N`` disables DAMON_ACMA.  Note that DAMON_ACMA could do no
 * real monitoring and memory auto-scaling due to the watermarks-based
 * activation condition.  Refer to below descriptions for the watermarks
 * parameter for this.
 */
static bool enabled __read_mostly;

/*
 * Make DAMON_ACMA reads the input parameters again, except ``enabled``.
 *
 * Input parameters that updated while DAMON_ACMA is running are not
 * applied by default.  Once this parameter is set as ``Y``, DAMON_ACMA
 * reads values of parametrs except ``enabled`` again.  Once the re-reading is
 * done, this parameter is set as ``N``.  If invalid parameters are found while
 * the re-reading, DAMON_ACMA will be disabled.
 */
static bool commit_inputs __read_mostly;
module_param(commit_inputs, bool, 0600);

/*
 * Desired level of memory pressure-stall time in microseconds.
 *
 * While keeping the caps that set by other quotas, DAMON_RECLAIM automatically
 * increases and decreases the effective level of the quota aiming this level of
 * memory pressure is incurred.  System-wide ``some`` memory PSI in microseconds
 * per quota reset interval (``quota_reset_interval_ms``) is collected and
 * compared to this value to see if the aim is satisfied.  Value zero means
 * disabling this auto-tuning feature.
 *
 * 1 ms/ 1 second (0.1%) by default.  Inspired by the PSI threshold of TMO
 * (https://dl.acm.org/doi/10.1145/3503222.3507731).
 */
static unsigned long quota_mem_pressure_us __read_mostly = 1000;
module_param(quota_mem_pressure_us, ulong, 0600);

static struct damos_quota damon_acma_quota = {
	/* Use up to 15 ms per 1 sec for scaling, by default */
	.ms = 15,
	.sz = 0,
	.reset_interval = 1000,
	/* Within the quota, mark hotter regions accessed first. */
	.weight_sz = 0,
	.weight_nr_accesses = 1,
	.weight_age = 0,
};
DEFINE_DAMON_MODULES_DAMOS_TIME_QUOTA(damon_acma_quota);

static struct damos_watermarks damon_acma_wmarks = {
	.metric = DAMOS_WMARK_NONE,
};

static struct damon_attrs damon_acma_mon_attrs = {
	.sample_interval = 1000000,	/* 1 second */
	.aggr_interval = 20000000,	/* 20 seconds */
	.ops_update_interval = 0,
	.min_nr_regions = 10,
	.max_nr_regions = 1000,
};
DEFINE_DAMON_MODULES_MON_ATTRS_PARAMS(damon_acma_mon_attrs);

/*
 * Start of the target memory region in physical address.
 *
 * The start physical address of memory region that DAMON_ACMA will do work
 * against.  By default, biggest System RAM is used as the region.
 */
static unsigned long monitor_region_start __read_mostly;
module_param(monitor_region_start, ulong, 0600);

/*
 * End of the target memory region in physical address.
 *
 * The end physical address of memory region that DAMON_ACMA will do work
 * against.  By default, biggest System RAM is used as the region.
 */
static unsigned long monitor_region_end __read_mostly;
module_param(monitor_region_end, ulong, 0600);

/*
 * PID of the DAMON thread
 *
 * If DAMON_ACMA is enabled, this becomes the PID of the worker thread.
 * Else, -1.
 */
static int kdamond_pid __read_mostly = -1;
module_param(kdamond_pid, int, 0400);

static struct damos_stat damon_acma_reclaim_stat;
DEFINE_DAMON_MODULES_DAMOS_STATS_PARAMS(damon_acma_reclaim_stat,
		acma_reclaim_tried_regions, acma_reclaim_succ_regions,
		acma_reclaim_quota_exceeds);

static struct damos_access_pattern damon_acma_stub_pattern = {
	/* Find regions having PAGE_SIZE or larger size */
	.min_sz_region = PAGE_SIZE,
	.max_sz_region = ULONG_MAX,
	/* no matter its access frequency */
	.min_nr_accesses = 0,
	.max_nr_accesses = UINT_MAX,
	/* no matter its age */
	.min_age_region = 0,
	.max_age_region = UINT_MAX,
};

static struct damon_ctx *ctx;
static struct damon_target *target;

static struct damos *damon_acma_new_scheme(
		struct damos_access_pattern *pattern, enum damos_action action)
{
	struct damos_quota quota = damon_acma_quota;

	return damon_new_scheme(
			pattern,
			action,
			/* work for every second */
			1000000,
			/* under the quota. */
			&quota,
			/* (De)activate this according to the watermarks. */
			&damon_acma_wmarks);
}

static void damon_acma_copy_quota_status(struct damos_quota *dst,
		struct damos_quota *src)
{
	dst->total_charged_sz = src->total_charged_sz;
	dst->total_charged_ns = src->total_charged_ns;
	dst->charged_sz = src->charged_sz;
	dst->charged_from = src->charged_from;
	dst->charge_target_from = src->charge_target_from;
	dst->charge_addr_from = src->charge_addr_from;
}

static int damon_acma_set_scheme_quota(struct damos *scheme, struct damos *old,
		damos_quota_goal_metric goal_metric)
{
	if (old)
		damon_acma_copy_quota_status(&scheme->quota, &old->quota);
	goal = damos_new_quota_goal(goal_metric, quota_mem_pressure_us);
	if (!goal)
		return -ENOMEM;
	damos_add_quota_goal(&scheme->quota, goal);
	return 0;
}

/*
 * Reclaim cold pages on entire physical address space
 */
static struct damos *damon_acma_new_reclaim_scheme(struct damos *old)
{
	struct damos_access_pattern pattern = damon_acma_stub_pattern;
	struct damos *scheme;
	int err;

	pattern.max_nr_accesses = 0;
	scheme = damon_acma_new_scheme(&pattern, DAMOS_PAGEOUT);
	if (!scheme)
		return NULL;
	err = damon_acma_set_scheme_quota(scheme, old,
			DAMOS_QUOTA_SOME_MEM_PSI_US);
	if (err) {
		damon_destroy_scheme(scheme);
		return NULL;
	}
	return scheme;
}

static int damon_acma_apply_parameters(void)
{
	struct damos *scheme, *reclaim_scheme;
	struct damos *old_reclaim_scheme = NULL;
	struct damos_quota_goal *goal;
	int err = 0;

	err = damon_set_attrs(ctx, &damon_acma_mon_attrs);
	if (err)
		return err;

	damon_for_each_scheme(scheme, ctx)
		old_reclaim_scheme = scheme;

	reclaim_scheme = damon_acma_new_reclaim_scheme(old_reclaim_scheme);
	if (!reclaim_scheme)
		return -ENOMEM;
	damon_set_schemes(ctx, &reclaim_scheme, 1);

	return damon_set_region_biggest_system_ram_default(target,
					&monitor_region_start,
					&monitor_region_end);
}

static int damon_acma_turn(bool on)
{
	int err;

	if (!on) {
		err = damon_stop(&ctx, 1);
		if (!err)
			kdamond_pid = -1;
		return err;
	}

	err = damon_acma_apply_parameters();
	if (err)
		return err;

	err = damon_start(&ctx, 1, true);
	if (err)
		return err;
	kdamond_pid = ctx->kdamond->pid;
	return 0;
}

static int damon_acma_enabled_store(const char *val,
		const struct kernel_param *kp)
{
	bool is_enabled = enabled;
	bool enable;
	int err;

	err = kstrtobool(val, &enable);
	if (err)
		return err;

	if (is_enabled == enable)
		return 0;

	/* Called before init function.  The function will handle this. */
	if (!ctx)
		goto set_param_out;

	err = damon_acma_turn(enable);
	if (err)
		return err;

set_param_out:
	enabled = enable;
	return err;
}

static const struct kernel_param_ops enabled_param_ops = {
	.set = damon_acma_enabled_store,
	.get = param_get_bool,
};

module_param_cb(enabled, &enabled_param_ops, &enabled, 0600);
MODULE_PARM_DESC(enabled,
	"Enable or disable DAMON_ACMA (default: disabled)");

static int damon_acma_handle_commit_inputs(void)
{
	int err;

	if (!commit_inputs)
		return 0;

	err = damon_acma_apply_parameters();
	commit_inputs = false;
	return err;
}

static int damon_acma_after_aggregation(struct damon_ctx *c)
{
	struct damos *s;

	/* update the stats parameter */
	damon_for_each_scheme(s, c) {
		switch (s->action) {
		case DAMOS_LRU_RECLAIM:
			damon_acma_reclaim_stat = s->stat;
			break;
		default:
			break;
	}

	return damon_acma_handle_commit_inputs();
}

static int damon_acma_after_wmarks_check(struct damon_ctx *c)
{
	return damon_acma_handle_commit_inputs();
}

static int __init damon_acma_init(void)
{
	int err = damon_modules_new_paddr_ctx_target(&ctx, &target);

	if (err)
		return err;

	ctx->callback.after_wmarks_check = damon_acma_after_wmarks_check;
	ctx->callback.after_aggregation = damon_acma_after_aggregation;

	/* 'enabled' has set before this function, probably via command line */
	if (enabled)
		err = damon_acma_turn(true);

	return err;
}

module_init(damon_acma_init);

#endif	/* DO_BUILD_ACMA */
