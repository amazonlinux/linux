obj-$(CONFIG_LUSTREFSX_LIBCFS)	+= libcfs.o

libcfs-linux-objs	:= linux-tracefile.o linux-debug.o linux-prim.o
libcfs-linux-objs	+= linux-curproc.o linux-module.o
libcfs-linux-objs	+= linux-crypto.o linux-crypto-adler.o
libcfs-linux-objs	+= linux-crypto-crc32.o linux-hash.o linux-wait.o

libcfs-linux-objs	:= $(addprefix linux/,$(libcfs-linux-objs))

libcfs-all-objs		:= debug.o fail.o module.o tracefile.o watchdog.o
libcfs-all-objs		+= libcfs_string.o hash.o prng.o workitem.o
libcfs-all-objs		+= libcfs_cpu.o libcfs_mem.o libcfs_lock.o heap.o

libcfs-y		+= $(libcfs-linux-objs) $(libcfs-all-objs)

ccflags-y		+= -I$(src)

include $(srctree)/drivers/staging/lustrefsx/Makefile.rules
