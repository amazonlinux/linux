obj-$(CONFIG_LUSTRE_FS)	+= obdclass.o

obdclass-y := llog.o llog_cat.o llog_obd.o llog_swab.o llog_osd.o
obdclass-y += class_obd.o genops.o llog_ioctl.o
obdclass-y += lprocfs_status.o lprocfs_counters.o
obdclass-y += lustre_handles.o lustre_peer.o local_storage.o
obdclass-y += statfs_pack.o obdo.o obd_config.o obd_mount.o obd_sysfs.o
obdclass-y += lu_object.o dt_object.o
obdclass-y += cl_object.o cl_page.o cl_lock.o cl_io.o lu_ref.o
obdclass-y += linkea.o kernelcomm.o jobid.o 
obdclass-y += integrity.o obd_cksum.o
obdclass-y += lu_tgt_descs.o lu_tgt_pool.o
obdclass-y += range_lock.o interval_tree.o

include $(srctree)/fs/lustre/Makefile.rules
