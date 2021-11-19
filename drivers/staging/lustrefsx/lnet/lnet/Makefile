obj-$(CONFIG_LUSTREFSX_LNET)	+= lnet.o

lnet-y 		:= api-ni.o config.o nidstrings.o
lnet-y		+= lib-me.o lib-msg.o lib-eq.o lib-md.o lib-ptl.o
lnet-y		+= lib-socket.o lib-move.o module.o lo.o
lnet-y		+= router.o router_proc.o acceptor.o peer.o net_fault.o

include $(srctree)/drivers/staging/lustrefsx/Makefile.rules
