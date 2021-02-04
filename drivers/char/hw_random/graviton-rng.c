// SPDX-License-Identifier: GPL-2.0
/*
 * AWS Graviton TRNG driver
 *
 * Copyright (C) 2019 Amazon Corp.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/arm-smccc.h>
#include <linux/device.h>
#include <linux/hw_random.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/acpi.h>
#include <linux/psci.h>
#include <linux/module.h>

#define ARM_SMCCC_SIP_GRAVITON_FEATURE_PROBE				\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32,	\
			   ARM_SMCCC_OWNER_SIP, 0x00ff)
#define AWS_GRAVITON_UUID \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32, \
			   ARM_SMCCC_OWNER_SIP, 0xFF01)
#define AWS_GRAVITON_GET_VER \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32, \
			   ARM_SMCCC_OWNER_SIP, 0xFF03)

#define AWS_GRAVITON_GET_RND \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64, \
			   ARM_SMCCC_OWNER_SIP, 0x60)
#define AWS_GRAVITON_GET_RND_LEGACY \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32, \
			   ARM_SMCCC_OWNER_SIP, 0x60)

/**
 *  UID of the Graviton TRNG API: eb4af8a0-89d4-49c9-bc8c5b38dc54308e
 */
#define GRVTN_TRNG_UUID_0		0xa0f83aeb
#define GRVTN_TRNG_UUID_1		0xc949d489
#define GRVTN_TRNG_UUID_2		0x385b8cbc
#define GRVTN_TRNG_UUID_3		0x8e3054dc

struct grvtn_rng {
	u64 call_id;
	struct hwrng rng;
};

static void grvtn_smccc_conduit(u64 call_id, struct arm_smccc_res *res)
{
	if (acpi_psci_use_hvc())
		arm_smccc_1_1_hvc(call_id, res);
	else
		arm_smccc_1_1_smc(call_id, res);
}

static int grvtn_probe_sip_feature(unsigned long feature)
{
	struct arm_smccc_res res = {};

	if (acpi_psci_use_hvc())
		arm_smccc_1_1_hvc(ARM_SMCCC_SIP_GRAVITON_FEATURE_PROBE,
			feature, 0, &res);
	else
		arm_smccc_1_1_smc(ARM_SMCCC_SIP_GRAVITON_FEATURE_PROBE,
			feature, 0, &res);

	return res.a0;
}

static int grvtn_trng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct grvtn_rng *priv = (struct grvtn_rng *)rng->priv;
	struct arm_smccc_res res;
	int err = 0;
	/* timeout after one waiting period */
	int iter_remain = 2;
	size_t count = max > sizeof(ulong) * 2 ? sizeof(ulong) * 2 : max;
	size_t total = count;

	do {
		if (err && wait)
			/* Nominal wait is 5us */
			udelay(err);

		grvtn_smccc_conduit(priv->call_id, &res);

		/* In the unlikely event of rolling back to legacy after probe was issued */
		if (unlikely((res.a0 == SMCCC_RET_NOT_SUPPORTED) && (priv->call_id != AWS_GRAVITON_GET_RND_LEGACY))) {
			grvtn_smccc_conduit(AWS_GRAVITON_GET_RND_LEGACY, &res);
			priv->call_id = AWS_GRAVITON_GET_RND_LEGACY;
		}

		err = (int) res.a0;

		if (err < 0)
			return err;

		iter_remain--;
	} while (iter_remain && err && wait);

	if (err)
		return 0;

	if (count > sizeof(ulong)) {
		memcpy(buf, &res.a1, sizeof(ulong));
		count -= sizeof(ulong);
		buf += sizeof(ulong);
	}
	memcpy(buf, &res.a2, count);
	return total;
}

static int grvtn_trng_probe(struct platform_device *pdev)
{
	int version;
	int err;
	struct arm_smccc_res res;
	struct grvtn_rng *priv;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->rng.name = "graviton";
	priv->rng.read = grvtn_trng_read;
	priv->rng.priv = (unsigned long)priv;
	priv->rng.quality = 1024; /* all bits are sourced from a HW TRNG */
	priv->call_id = AWS_GRAVITON_GET_RND_LEGACY; /* default mode is legacy */

	grvtn_smccc_conduit(AWS_GRAVITON_UUID, &res);

	if (res.a0 != GRVTN_TRNG_UUID_0 || res.a1 != GRVTN_TRNG_UUID_1 ||
	    res.a2 != GRVTN_TRNG_UUID_2 || res.a3 != GRVTN_TRNG_UUID_3) {
		dev_err(&pdev->dev, "failed to match UUID\n");
		return -ENXIO;
	}

	grvtn_smccc_conduit(AWS_GRAVITON_GET_VER, &res);
	dev_info(&pdev->dev, "Graviton TRNG, SMC version %d.%d\n",
		(u32)res.a0, (u32)res.a1);

	version = grvtn_probe_sip_feature(AWS_GRAVITON_GET_RND);
	if (version > 0)
		priv->call_id = AWS_GRAVITON_GET_RND;

	platform_set_drvdata(pdev, priv);
	err = devm_hwrng_register(&pdev->dev, &priv->rng);
	if (err)
		dev_err(&pdev->dev, "failed to register hwrng");
	return err;
}

static const struct acpi_device_id grvtn_trng_acpi_match[] = {
	{ "AMZN0010", },
	{}
};

MODULE_DEVICE_TABLE(acpi, grvtn_trng_acpi_match);

static struct platform_driver grvtn_trng_driver = {
	.probe  = grvtn_trng_probe,
	.driver = {
		.name = "graviton-rng",
		.owner = THIS_MODULE,
		.acpi_match_table = ACPI_PTR(grvtn_trng_acpi_match),
	},
};

module_platform_driver(grvtn_trng_driver);

MODULE_AUTHOR("Amazon.com, Inc. or it's affiliates");
MODULE_DESCRIPTION("Graviton TRNG driver");
MODULE_LICENSE("GPL v2");
