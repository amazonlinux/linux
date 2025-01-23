obj-$(CONFIG_LUSTRE_LNET_SELFTEST)	+= lnet_selftest.o

lnet_selftest-y 	:= console.o conrpc.o conctl.o framework.o timer.o
lnet_selftest-y		+= rpc.o module.o ping_test.o brw_test.o

include $(srctree)/net/lnet/Makefile.rules
