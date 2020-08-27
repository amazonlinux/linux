/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* have ah core allocation */
/* #undef HAVE_AH_CORE_ALLOCATION */

/* have device ops alloc_pd without ucontext */
/* #undef HAVE_ALLOC_PD_NO_UCONTEXT */

/* have bitfield.h */
#define HAVE_BITFIELD_H 1

/* have core mmap xarray */
/* #undef HAVE_CORE_MMAP_XA */

/* have cq core allocation */
/* #undef HAVE_CQ_CORE_ALLOCATION */

/* rdma_ah_init_attr exists */
/* #undef HAVE_CREATE_AH_INIT_ATTR */

/* create_ah doesn't have udata */
/* #undef HAVE_CREATE_AH_NO_UDATA */

/* create_ah has rdma_attr */
#define HAVE_CREATE_AH_RDMA_ATTR 1

/* create_ah has udata */
#define HAVE_CREATE_AH_UDATA 1

/* create_cq has attr param */
#define HAVE_CREATE_CQ_ATTR 1

/* have device ops create_cq without ucontext */
/* #undef HAVE_CREATE_CQ_NO_UCONTEXT */

/* create/destroy_ah has flags */
/* #undef HAVE_CREATE_DESTROY_AH_FLAGS */

/* have device ops dealloc pd has udata */
/* #undef HAVE_DEALLOC_PD_UDATA */

/* have device ops dereg mr udata */
/* #undef HAVE_DEREG_MR_UDATA */

/* have device ops destroy cq udata */
/* #undef HAVE_DESTROY_CQ_UDATA */

/* have device ops destroy qp udata */
/* #undef HAVE_DESTROY_QP_UDATA */

/* dev has parent field */
#define HAVE_DEV_PARENT 1

/* driver_id field exists */
/* #undef HAVE_DRIVER_ID */

/* efa gdr enabled */
/* #undef HAVE_EFA_GDR */

/* get_port_immutable exists */
#define HAVE_GET_PORT_IMMUTABLE 1

/* have hw_stats */
#define HAVE_HW_STATS 1

/* have ibdev print */
/* #undef HAVE_IBDEV_PRINT */

/* have ibdev ratelimited print */
/* #undef HAVE_IBDEV_PRINT_RATELIMITED */

/* IB_ACCESS_OPTIONAL exists */
/* #undef HAVE_IB_ACCESS_OPTIONAL */

/* ib_device_ops has common fields */
/* #undef HAVE_IB_DEVICE_OPS_COMMON */

/* struct ib_device_ops exists */
/* #undef HAVE_IB_DEV_OPS */

/* have ib_is_udata_cleared */
#define HAVE_IB_IS_UDATA_CLEARED 1

/* ib_modify_qp_is_ok has four params */
/* #undef HAVE_IB_MODIFY_QP_IS_OK_FOUR_PARAMS */

/* ib_mr has length field */
#define HAVE_IB_MR_LENGTH 1

/* ib_mtu_int_to_enum exists */
#define HAVE_IB_MTU_INT_TO_ENUM 1

/* have ib port phys state link up */
/* #undef HAVE_IB_PORT_PHYS_STATE_LINK_UP */

/* have driver qpt */
/* #undef HAVE_IB_QPT_DRIVER */

/* query_device has udata */
#define HAVE_IB_QUERY_DEVICE_UDATA 1

/* ib_register_device has name param */
/* #undef HAVE_IB_REGISTER_DEVICE_NAME_PARAM */

/* ib_register_device has two params */
/* #undef HAVE_IB_REGISTER_DEVICE_TWO_PARAMS */

/* ib_umem_find_single_pg_size exists */
/* #undef HAVE_IB_UMEM_FIND_SINGLE_PG_SIZE */

/* have ib_umem_get device param */
/* #undef HAVE_IB_UMEM_GET_DEVICE_PARAM */

/* ib_umem_get has no dmasync parameter */
/* #undef HAVE_IB_UMEM_GET_NO_DMASYNC */

/* ib_umem_get has udata */
/* #undef HAVE_IB_UMEM_GET_UDATA */

/* have void destroy cq */
/* #undef HAVE_IB_VOID_DESTROY_CQ */

/* have kvzalloc */
#define HAVE_KVZALLOC 1

/* ib_device_attr has max_send_recv_sge */
/* #undef HAVE_MAX_SEND_RCV_SGE */

/* have no kverbs drivers */
/* #undef HAVE_NO_KVERBS_DRIVERS */

/* have pci_irq_vector */
#define HAVE_PCI_IRQ_VECTOR 1

/* have amazon pci id */
/* #undef HAVE_PCI_VENDOR_ID_AMAZON */

/* have pd core allocation */
/* #undef HAVE_PD_CORE_ALLOCATION */

/* have device ops const wr in post verbs */
/* #undef HAVE_POST_CONST_WR */

/* have unspecified node type */
/* #undef HAVE_RDMA_NODE_UNSPECIFIED */

/* rdma_user_mmap_io exists */
/* #undef HAVE_RDMA_USER_MMAP_IO */

/* safe ib_alloc_device exists */
/* #undef HAVE_SAFE_IB_ALLOC_DEVICE */

/* for_each_sg_dma_page exists */
/* #undef HAVE_SG_DMA_PAGE_ITER */

/* have ucontext core allocation */
/* #undef HAVE_UCONTEXT_CORE_ALLOCATION */

/* rdma_udata_to_drv_context exists */
/* #undef HAVE_UDATA_TO_DRV_CONTEXT */

/* ib umem scatterlist exists */
#define HAVE_UMEM_SCATTERLIST_IF 1

/* have upstream efa */
/* #undef HAVE_UPSTREAM_EFA */

/* have uverbs command header fix */
#define HAVE_UVERBS_CMD_HDR_FIX 1

/* Name of package */
#define PACKAGE "efa"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "efa"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "efa 1.9.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "efa"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.9.0"

/* Version number of package */
#define VERSION "1.9.0"
