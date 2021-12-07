#
# Makefile for the Elastic Network Adapter (ENA) device drivers.
# ENA Source is: https://github.com/amzn/amzn-drivers.
# Current ENA source is based on ena_linux_2.4.0 tag.
#

obj-$(CONFIG_AMAZON_ENA_ETHERNET) += ena.o

ena-y := ena_netdev.o ena_com.o ena_eth_com.o ena_ethtool.o net_dim.o \
	dim.o ena_lpc.o

ena-$(CONFIG_SYSFS) += ena_sysfs.o
