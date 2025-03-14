/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <unistd.h>
#include "ddsp_vtimelocal_fail.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct ddsp_vtimelocal_fail *skel;

	skel = ddsp_vtimelocal_fail__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(ddsp_vtimelocal_fail__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct ddsp_vtimelocal_fail *skel = ctx;
	struct bpf_link *link;

	link = bpf_map__attach_struct_ops(skel->maps.ddsp_vtimelocal_fail_ops);
	SCX_FAIL_IF(!link, "Failed to attach struct_ops");

	sleep(1);

	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));
	bpf_link__destroy(link);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct ddsp_vtimelocal_fail *skel = ctx;

	ddsp_vtimelocal_fail__destroy(skel);
}

struct scx_test ddsp_vtimelocal_fail = {
	.name = "ddsp_vtimelocal_fail",
	.description = "Verify we gracefully fail, and fall back to using a "
		       "built-in DSQ, if we do a direct vtime dispatch to a "
		       "built-in DSQ from DSQ in ops.select_cpu()",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&ddsp_vtimelocal_fail)
