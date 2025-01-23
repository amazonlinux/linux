obj-$(CONFIG_LUSTRE_LNET)	+= lnet.o

lnet-y 		:= api-ni.o config.o nidstrings.o lnet_rdma.o
lnet-y		+= lib-me.o lib-msg.o lib-md.o lib-ptl.o
lnet-y		+= lib-socket.o lib-move.o module.o lo.o
lnet-y		+= router.o acceptor.o peer.o net_fault.o udsp.o
lnet-y		+= lib-cpt.o lnet_debugfs.o lock.o

include $(srctree)/net/lnet/Makefile.rules
