# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright 2024 Amazon.com, Inc. or its affiliates. All rights reserved.
#
# Makefile for Amazon Elastic Fabric Adapter (EFA) device driver.
#

obj-$(CONFIG_AMAZON_EFA_INFINIBAND) += efa.o

efa-y := efa_com.o efa_com_cmd.o efa_gdr.o efa_main.o efa_neuron.o efa_p2p.o
efa-y += efa_verbs.o

efa-$(CONFIG_SYSFS) += efa_sysfs.o
