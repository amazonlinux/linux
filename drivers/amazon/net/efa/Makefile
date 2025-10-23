# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2024-2025 Amazon.com, Inc. or its affiliates. All rights reserved.
#
# Makefile for Amazon Elastic Fabric Adapter (EFA) device driver.
#

obj-$(CONFIG_AMAZON_EFA_INFINIBAND) += efa.o

efa-y := efa_com.o efa_com_cmd.o efa_nvmem_v1.o efa_nvmem_v2.o efa_main.o efa_neuronmem.o efa_p2p.o
efa-y += efa_verbs.o efa_data_verbs.o

efa-$(CONFIG_SYSFS) += efa_sysfs.o
