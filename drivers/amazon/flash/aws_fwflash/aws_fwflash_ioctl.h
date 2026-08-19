/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AWS_FWFLASH_IOCTL_H
#define _AWS_FWFLASH_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define AWS_FWFLASH_IOC_MAGIC 'F'

/* SMI trigger: input registers + output registers */
struct aws_fwflash_smi_args {
    uint16_t command;    /* AL value (SMI command byte) */
    uint16_t port;       /* DX value (IO port, must be 0xB2) */
    uint32_t ecx_in;    /* ECX input (comm buffer physical address low 32 bits) */
    /* Output registers after SMI */
    uint64_t eax_out;
    uint64_t ebx_out;
    uint64_t ecx_out;
    uint64_t edx_out;
};

/* Physical memory map/unmap */
struct aws_fwflash_phys_region {
    uint64_t phys_addr;  /* Physical address to map */
    uint64_t size;       /* Size of region in bytes */
};

/* Physical memory read/write */
struct aws_fwflash_phys_io {
    uint64_t phys_addr;  /* Physical address */
    uint64_t size;       /* Number of bytes to transfer */
    uint64_t user_buf;   /* Userspace buffer pointer (cast to uint64_t) */
};

#define AWS_FWFLASH_IOCTL_SMI        _IOWR(AWS_FWFLASH_IOC_MAGIC, 1, struct aws_fwflash_smi_args)
#define AWS_FWFLASH_IOCTL_MAP_PHYS   _IOW(AWS_FWFLASH_IOC_MAGIC, 2, struct aws_fwflash_phys_region)
#define AWS_FWFLASH_IOCTL_READ_PHYS  _IOW(AWS_FWFLASH_IOC_MAGIC, 3, struct aws_fwflash_phys_io)
#define AWS_FWFLASH_IOCTL_WRITE_PHYS _IOW(AWS_FWFLASH_IOC_MAGIC, 4, struct aws_fwflash_phys_io)
#define AWS_FWFLASH_IOCTL_UNMAP_PHYS _IOW(AWS_FWFLASH_IOC_MAGIC, 5, struct aws_fwflash_phys_region)

#endif /* _AWS_FWFLASH_IOCTL_H */
