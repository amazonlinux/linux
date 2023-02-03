/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright 2016-2022 Broadcom Inc. All rights reserved.
 */
#ifndef MPI30_TOOL_H
#define MPI30_TOOL_H     1
struct mpi3_tool_clean_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	u8                         tool;
	u8                         reserved0b;
	__le32                     area;
};
#define MPI3_TOOLBOX_TOOL_CLEAN                             (0x01)
#define MPI3_TOOLBOX_TOOL_ISTWI_READ_WRITE                  (0x02)
#define MPI3_TOOLBOX_TOOL_DIAGNOSTIC_CLI                    (0x03)
#define MPI3_TOOLBOX_TOOL_LANE_MARGINING                    (0x04)
#define MPI3_TOOLBOX_TOOL_RECOVER_DEVICE                    (0x05)
#define MPI3_TOOLBOX_TOOL_LOOPBACK                          (0x06)
#define MPI3_TOOLBOX_CLEAN_AREA_BIOS_BOOT_SERVICES          (0x00000008)
#define MPI3_TOOLBOX_CLEAN_AREA_ALL_BUT_MFG                 (0x00000002)
#define MPI3_TOOLBOX_CLEAN_AREA_NVSTORE                     (0x00000001)
struct mpi3_tool_istwi_read_write_request {
	__le16                               host_tag;
	u8                                   ioc_use_only02;
	u8                                   function;
	__le16                               ioc_use_only04;
	u8                                   ioc_use_only06;
	u8                                   msg_flags;
	__le16                               change_count;
	u8                                   tool;
	u8                                   flags;
	u8                                   dev_index;
	u8                                   action;
	__le16                               reserved0e;
	__le16                               tx_data_length;
	__le16                               rx_data_length;
	__le32                               reserved14[3];
	struct mpi3_man11_istwi_device_format    istwi_device;
	union mpi3_sge_union                    sgl;
};
#define MPI3_TOOLBOX_ISTWI_FLAGS_AUTO_RESERVE_RELEASE       (0x80)
#define MPI3_TOOLBOX_ISTWI_FLAGS_ADDRESS_MODE_MASK          (0x04)
#define MPI3_TOOLBOX_ISTWI_FLAGS_ADDRESS_MODE_DEVINDEX      (0x00)
#define MPI3_TOOLBOX_ISTWI_FLAGS_ADDRESS_MODE_DEVICE_FIELD  (0x04)
#define MPI3_TOOLBOX_ISTWI_FLAGS_PAGE_ADDRESS_MASK          (0x03)
#define MPI3_TOOLBOX_ISTWI_ACTION_RESERVE_BUS               (0x00)
#define MPI3_TOOLBOX_ISTWI_ACTION_RELEASE_BUS               (0x01)
#define MPI3_TOOLBOX_ISTWI_ACTION_RESET                     (0x02)
#define MPI3_TOOLBOX_ISTWI_ACTION_READ_DATA                 (0x03)
#define MPI3_TOOLBOX_ISTWI_ACTION_WRITE_DATA                (0x04)
#define MPI3_TOOLBOX_ISTWI_ACTION_SEQUENCE                  (0x05)
struct mpi3_tool_istwi_read_write_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le16                     istwi_status;
	__le16                     reserved12;
	__le16                     tx_data_count;
	__le16                     rx_data_count;
};
struct mpi3_tool_diagnostic_cli_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	u8                         tool;
	u8                         reserved0b;
	__le32                     command_data_length;
	__le32                     response_data_length;
	__le32                     reserved14[3];
	union mpi3_sge_union          sgl;
};
struct mpi3_tool_diagnostic_cli_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le32                     returned_data_length;
};
struct mpi3_tool_lane_margin_request {
	__le16                               host_tag;
	u8                                   ioc_use_only02;
	u8                                   function;
	__le16                               ioc_use_only04;
	u8                                   ioc_use_only06;
	u8                                   msg_flags;
	__le16                               change_count;
	u8                                   tool;
	u8                                   reserved0b;
	u8                                   action;
	u8                                   switch_port;
	__le16                               dev_handle;
	u8                                   start_lane;
	u8                                   num_lanes;
	__le16                               reserved12;
	__le32                               reserved14[3];
	union mpi3_sge_union                    sgl;
};
#define MPI3_TOOLBOX_LM_ACTION_ENTER                         (0x00)
#define MPI3_TOOLBOX_LM_ACTION_EXIT                          (0x01)
#define MPI3_TOOLBOX_LM_ACTION_READ                          (0x02)
#define MPI3_TOOLBOX_LM_ACTION_WRITE                         (0x03)
struct mpi3_lane_margin_element {
	__le16                               control;
	__le16                               status;
};
struct mpi3_tool_lane_margin_reply {
	__le16                               host_tag;
	u8                                   ioc_use_only02;
	u8                                   function;
	__le16                               ioc_use_only04;
	u8                                   ioc_use_only06;
	u8                                   msg_flags;
	__le16                               ioc_use_only08;
	__le16                               ioc_status;
	__le32                               ioc_log_info;
	__le32                               returned_data_length;
};
struct mpi3_tool_recover_device_request {
	__le16                               host_tag;
	u8                                   ioc_use_only02;
	u8                                   function;
	__le16                               ioc_use_only04;
	u8                                   ioc_use_only06;
	u8                                   msg_flags;
	__le16                               change_count;
	u8                                   tool;
	u8                                   reserved0b;
	u8                                   action;
	u8                                   reserved0d;
	__le16                               dev_handle;
};
#define MPI3_TOOLBOX_RD_ACTION_START                        (0x01)
#define MPI3_TOOLBOX_RD_ACTION_GET_STATUS                   (0x02)
#define MPI3_TOOLBOX_RD_ACTION_ABORT                        (0x03)
struct mpi3_tool_recover_device_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	u8                         status;
	u8                         reserved11;
	__le16                     reserved1c;
};
#define MPI3_TOOLBOX_RD_STATUS_NOT_NEEDED                   (0x01)
#define MPI3_TOOLBOX_RD_STATUS_NEEDED                       (0x02)
#define MPI3_TOOLBOX_RD_STATUS_IN_PROGRESS                  (0x03)
#define MPI3_TOOLBOX_RD_STATUS_ABORTING                     (0x04)
struct mpi3_tool_loopback_request {
	__le16                               host_tag;
	u8                                   ioc_use_only02;
	u8                                   function;
	__le16                               ioc_use_only04;
	u8                                   ioc_use_only06;
	u8                                   msg_flags;
	__le16                               change_count;
	u8                                   tool;
	u8                                   reserved0b;
	__le32                               reserved0c;
	__le64                               phys;
};
struct mpi3_tool_loopback_reply {
	__le16                               host_tag;
	u8                                   ioc_use_only02;
	u8                                   function;
	__le16                               ioc_use_only04;
	u8                                   ioc_use_only06;
	u8                                   msg_flags;
	__le16                               ioc_use_only08;
	__le16                               ioc_status;
	__le32                               ioc_log_info;
	__le64                               tested_phys;
	__le64                               failed_phys;
};
struct mpi3_diag_buffer_post_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     reserved0a;
	u8                         type;
	u8                         reserved0d;
	__le16                     reserved0e;
	__le64                     address;
	__le32                     length;
	__le32                     reserved1c;
};
#define MPI3_DIAG_BUFFER_POST_MSGFLAGS_SEGMENTED            (0x01)
#define MPI3_DIAG_BUFFER_TYPE_TRACE                         (0x01)
#define MPI3_DIAG_BUFFER_TYPE_FW                            (0x02)
#define MPI3_DIAG_BUFFER_TYPE_DRIVER                        (0x10)
#define MPI3_DIAG_BUFFER_TYPE_FDL                           (0x20)
#define MPI3_DIAG_BUFFER_MIN_PRODUCT_SPECIFIC               (0xf0)
#define MPI3_DIAG_BUFFER_MAX_PRODUCT_SPECIFIC               (0xff)
struct mpi3_driver_buffer_header {
	__le32                     signature;
	__le16                     header_size;
	__le16                     rtt_file_header_offset;
	__le32                     flags;
	__le32                     circular_buffer_size;
	__le32                     logical_buffer_end;
	__le32                     logical_buffer_start;
	__le32                     ioc_use_only18[2];
	__le32                     reserved20[760];
	__le32                     reserved_rttrace[256];
};
#define MPI3_DRIVER_DIAG_BUFFER_HEADER_SIGNATURE_CIRCULAR                (0x43495243)
#define MPI3_DRIVER_DIAG_BUFFER_HEADER_FLAGS_CIRCULAR_BUF_FORMAT_MASK    (0x00000003)
#define MPI3_DRIVER_DIAG_BUFFER_HEADER_FLAGS_CIRCULAR_BUF_FORMAT_ASCII   (0x00000000)
#define MPI3_DRIVER_DIAG_BUFFER_HEADER_FLAGS_CIRCULAR_BUF_FORMAT_RTTRACE (0x00000001)
struct mpi3_diag_buffer_manage_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     reserved0a;
	u8                         type;
	u8                         action;
	__le16                     reserved0e;
};
#define MPI3_DIAG_BUFFER_ACTION_RELEASE                     (0x01)
#define MPI3_DIAG_BUFFER_ACTION_PAUSE                       (0x02)
#define MPI3_DIAG_BUFFER_ACTION_RESUME                      (0x03)
struct mpi3_diag_buffer_upload_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     reserved0a;
	u8                         type;
	u8                         flags;
	__le16                     reserved0e;
	__le64                     context;
	__le32                     reserved18;
	__le32                     reserved1c;
	union mpi3_sge_union          sgl;
};
#define MPI3_DIAG_BUFFER_UPLOAD_FLAGS_FORMAT_MASK           (0x01)
#define MPI3_DIAG_BUFFER_UPLOAD_FLAGS_FORMAT_DECODED        (0x00)
#define MPI3_DIAG_BUFFER_UPLOAD_FLAGS_FORMAT_ENCODED        (0x01)
struct mpi3_diag_buffer_upload_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le64                     context;
	__le32                     returned_data_length;
	__le32                     reserved1c;
};
#endif
