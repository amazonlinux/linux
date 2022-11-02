#
# Makefile for the Elastic Fabric Adapter (EFA) device drivers.
# EFA Source is: https://github.com/amzn/amzn-drivers.

obj-$(CONFIG_AMAZON_EFA_INFINIBAND) += efa.o

efa-y := efa_com.o efa_com_cmd.o efa_gdr.o efa_main.o efa_verbs.o

efa-$(CONFIG_SYSFS) += efa_sysfs.o

ccflags-y += -include $(srctree)/drivers/amazon/net/efa/config.h
