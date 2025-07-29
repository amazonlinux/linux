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
