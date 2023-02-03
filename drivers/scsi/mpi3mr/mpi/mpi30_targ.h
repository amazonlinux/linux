/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright 2016-2022 Broadcom Inc. All rights reserved.
 */
#ifndef MPI30_TARG_H
#define MPI30_TARG_H     1
struct mpi3_target_ssp_cmd_buffer {
	u8                         frame_type;
	u8                         reserved01;
	__le16                     initiator_connection_tag;
	__le32                     hashed_source_sas_address;
	__le16                     reserved08;
	__le16                     flags;
	__le32                     reserved0c;
	__le16                     tag;
	__le16                     target_port_transfer_tag;
	__le32                     data_offset;
	u8                         logical_unit_number[8];
	u8                         reserved20;
	u8                         task_attribute;
	u8                         reserved22;
	u8                         additional_cdb_length;
	u8                         cdb[16];
};
struct mpi3_target_ssp_task_buffer {
	u8                         frame_type;
	u8                         reserved01;
	__le16                     initiator_connection_tag;
	__le32                     hashed_source_sas_address;
	__le16                     reserved08;
	__le16                     flags;
	__le32                     reserved0c;
	__le16                     tag;
	__le16                     target_port_transfer_tag;
	__le32                     data_offset;
	u8                         logical_unit_number[8];
	__le16                     reserved20;
	u8                         task_management_function;
	u8                         reserved23;
	__le16                     managed_task_tag;
	__le16                     reserved26;
	__le32                     reserved28[3];
};
#define MPI3_TARGET_FRAME_TYPE_COMMAND                      (0x06)
#define MPI3_TARGET_FRAME_TYPE_TASK                         (0x16)
#define MPI3_TARGET_HASHED_SAS_ADDRESS_MASK                 (0xffffff00)
#define MPI3_TARGET_HASHED_SAS_ADDRESS_SHIFT                (8)
struct mpi3_target_cmd_buf_post_base_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	u8                         buffer_post_flags;
	u8                         reserved0b;
	__le16                     min_reply_queue_id;
	__le16                     max_reply_queue_id;
	__le64                     base_address;
	__le16                     cmd_buffer_length;
	__le16                     total_cmd_buffers;
	__le32                     reserved1c;
};
#define MPI3_CMD_BUF_POST_BASE_FLAGS_DLAS_MASK              (0x0c)
#define MPI3_CMD_BUF_POST_BASE_FLAGS_DLAS_SYSTEM            (0x00)
#define MPI3_CMD_BUF_POST_BASE_FLAGS_DLAS_IOCUDP            (0x04)
#define MPI3_CMD_BUF_POST_BASE_FLAGS_DLAS_IOCCTL            (0x08)
#define MPI3_CMD_BUF_POST_BASE_FLAGS_AUTO_POST_ALL          (0x01)
#define MPI3_CMD_BUF_POST_BASE_MIN_BUF_LENGTH               (0x34)
#define MPI3_CMD_BUF_POST_BASE_MAX_BUF_LENGTH               (0x3fc)
struct mpi3_target_cmd_buf_post_list_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     reserved0a;
	u8                         cmd_buffer_count;
	u8                         reserved0d[3];
	__le16                     io_index[2];
};
struct mpi3_target_cmd_buf_post_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	u8                         cmd_buffer_count;
	u8                         reserved11[3];
	__le16                     io_index[2];
};
struct mpi3_target_assist_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     dev_handle;
	__le32                     flags;
	__le16                     reserved10;
	__le16                     queue_tag;
	__le16                     io_index;
	__le16                     initiator_connection_tag;
	__le32                     skip_count;
	__le32                     data_length;
	__le32                     port_transfer_length;
	__le32                     primary_reference_tag;
	__le16                     primary_application_tag;
	__le16                     primary_application_tag_mask;
	__le32                     relative_offset;
	union mpi3_sge_union          sgl[5];
};
#define MPI3_TARGET_ASSIST_MSGFLAGS_METASGL_VALID           (0x80)
#define MPI3_TARGET_ASSIST_FLAGS_REPOST_CMD_BUFFER          (0x00200000)
#define MPI3_TARGET_ASSIST_FLAGS_AUTO_STATUS                (0x00100000)
#define MPI3_TARGET_ASSIST_FLAGS_DATADIRECTION_MASK         (0x000c0000)
#define MPI3_TARGET_ASSIST_FLAGS_DATADIRECTION_WRITE        (0x00040000)
#define MPI3_TARGET_ASSIST_FLAGS_DATADIRECTION_READ         (0x00080000)
#define MPI3_TARGET_ASSIST_FLAGS_DMAOPERATION_MASK          (0x00030000)
#define MPI3_TARGET_ASSIST_FLAGS_DMAOPERATION_HOST_PI       (0x00010000)
#define MPI3_TARGET_ASSIST_METASGL_INDEX                    (4)
struct mpi3_target_status_send_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     dev_handle;
	__le16                     response_iu_length;
	__le16                     flags;
	__le16                     reserved10;
	__le16                     queue_tag;
	__le16                     io_index;
	__le16                     initiator_connection_tag;
	__le32                     ioc_use_only18[6];
	__le32                     ioc_use_only30[4];
	union mpi3_sge_union          sgl;
};
#define MPI3_TSS_FLAGS_REPOST_CMD_BUFFER                (0x0020)
#define MPI3_TSS_FLAGS_AUTO_SEND_GOOD_STATUS            (0x0010)
struct mpi3_target_standard_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le32                     transfer_count;
};
struct mpi3_target_mode_abort_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	u8                         abort_type;
	u8                         reserved0b;
	__le16                     request_queue_id_to_abort;
	__le16                     host_tag_to_abort;
	__le16                     dev_handle;
	__le16                     reserved12;
};
#define MPI3_TARGET_MODE_ABORT_ALL_CMD_BUFFERS              (0x00)
#define MPI3_TARGET_MODE_ABORT_EXACT_IO_REQUEST             (0x01)
#define MPI3_TARGET_MODE_ABORT_ALL_COMMANDS                 (0x02)
struct mpi3_target_mode_abort_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le32                     abort_count;
};
#endif
