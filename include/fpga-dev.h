#ifndef __LINUX_FPGA_DEV_H
#define __LINUX_FPGA_DEV_H

#include <linux/types.h>
//#include <linux/compiler.h>

#include <fpga.h>

#define FPGA_IP_RESOURCE	0x00000001
#define FPGA_IP_FUNCS		0x00000002
#define FPGA_IP_RDWR		0x00000100
#define FPGA_IP_BLOCK		0x00000200

struct fpga_ip_resource_ioctl_data {
	struct {
		__u64 start;
		__u64 size;
	} resources[FPGA_NUM_RESOURCES_MAX];
	__u32 num_resources;
};

struct fpga_ip_rdwr_ioctl_data {
	__u32 index;
	__u64 where;
	__u32 size;
	__u8 rw;
	union fpga_reg_data reg;
};

struct fpga_ip_block_ioctl_data {
	__u32 index;
	__u64 where;
	__u32 size;
	__u8 rw;
	__u8 *block;
};

#endif /* __LINUX_FPGA_DEV_H */
