obj-$(CONFIG_LUSTREFSX_FS)	+= obdclass.o

obdclass-linux-objs := linux-module.o linux-obdo.o linux-sysctl.o
obdclass-linux-objs := $(addprefix linux/,$(obdclass-linux-objs))

obdclass-y := $(obdclass-linux-objs)
obdclass-y += llog.o llog_cat.o llog_obd.o llog_swab.o llog_osd.o
obdclass-y += class_obd.o debug.o genops.o uuid.o llog_ioctl.o
obdclass-y += lprocfs_status.o lprocfs_counters.o
obdclass-y += lustre_handles.o lustre_peer.o local_storage.o
obdclass-y += statfs_pack.o obdo.o obd_config.o obd_mount.o
obdclass-y += lu_object.o dt_object.o
obdclass-y += cl_object.o cl_page.o cl_lock.o cl_io.o lu_ref.o
obdclass-y += linkea.o kernelcomm.o

include $(srctree)/drivers/staging/lustrefsx/Makefile.rules
