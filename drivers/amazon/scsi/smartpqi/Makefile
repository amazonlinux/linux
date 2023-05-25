# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_AMAZON_SCSI_SMARTPQI) += smartpqi.o
smartpqi-objs := smartpqi_init.o smartpqi_sis.o smartpqi_sas_transport.o smartpqi_kernel_compat.o
EXTRA_CFLAGS += -DKCLASS5D
EXTRA_CFLAGS += -DKFEATURE_HAS_SCSI_CMD_PRIV
