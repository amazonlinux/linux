#
# Makefile for the Elastic Network Adapter (ENA) device drivers.
# ENA Source is: https://github.com/amzn/amzn-drivers.
# Current ENA source is based on ena_linux_2.12.0 tag.
#

obj-$(CONFIG_AMAZON_ENA_ETHERNET) += ena.o

ena-y := ena_netdev.o ena_ethtool.o ena_lpc.o ena_phc.o ena_xdp.o dim.o \
	 net_dim.o ena_com.o ena_eth_com.o

ena-$(CONFIG_SYSFS) += ena_sysfs.o

ifdef TEST_AF_XDP
	ccflags-y += -DENA_TEST_AF_XDP
endif

ccflags-y += -DENA_PHC_INCLUDE

ccflags-y += -include $(srctree)/drivers/amazon/net/ena/config.h
