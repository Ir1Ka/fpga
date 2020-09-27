#ifndef __LINUX_FPGA_DEV_H
#define __LINUX_FPGA_DEV_H

#include <linux/types.h>

#include <fpga.h>

enum {
	FPGA_DEV_TYPE_RESOURCE,
	FPGA_DEV_TYPE_FUNCS,
	FPGA_DEV_TYPE_REG,
	FPGA_DEV_TYPE_BLOCK,
};

enum {
	FPGA_DEV_OP_RD,
	FPGA_DEV_OP_WR,
};

/* 31:24 type, 23:20 op,  9:0 size.*/

#define FPGA_DEV_CMD_TYPE_SHIFT		24
#define FPGA_DEV_CMD_TYPE_BITES		8
#define FPGA_DEV_CMD_TYPE_MASK		((1 << FPGA_DEV_CMD_TYPE_BITES) - 1)
#define FPGA_DEV_CMD_OP_SHIFT		20
#define FPGA_DEV_CMD_OP_BITES		1
#define FPGA_DEV_CMD_OP_MASK		((1 << FPGA_DEV_CMD_OP_BITES) - 1)
#define FPGA_DEV_CMD_IDX_SHIFT		10
#define FPGA_DEV_CMD_IDX_BITES		6
#define FPGA_DEV_CMD_IDX_MASK		((1 << FPGA_DEV_CMD_IDX_BITES) - 1)
#define FPGA_DEV_CMD_SIZE_SHIFT		0
#define FPGA_DEV_CMD_SIZE_BITES		10
#define FPGA_DEV_CMD_SIZE_MASK		((1 << FPGA_DEV_CMD_SIZE_BITES) - 1)

#define FPGA_DEV_CMD(type, op, idx, size)				\
	(((type & FPGA_DEV_CMD_TYPE_MASK) << FPGA_DEV_CMD_TYPE_SHIFT) |	\
	 ((op	& FPGA_DEV_CMD_OP_MASK	) << FPGA_DEV_CMD_OP_SHIFT  ) |	\
	 ((idx	& FPGA_DEV_CMD_IDX_MASK	) << FPGA_DEV_CMD_IDX_SHIFT ) |	\
	 ((size & FPGA_DEV_CMD_SIZE_MASK) << FPGA_DEV_CMD_SIZE_SHIFT))
#define FPGA_DEV_CMD_TYPE(cmd)	((cmd >> FPGA_DEV_CMD_TYPE_SHIFT) & FPGA_DEV_CMD_TYPE_MASK)
#define FPGA_DEV_CMD_OP(cmd)	((cmd >> FPGA_DEV_CMD_OP_SHIFT  ) & FPGA_DEV_CMD_OP_MASK  )
#define FPGA_DEV_CMD_IDX(cmd)	((cmd >> FPGA_DEV_CMD_IDX_SHIFT ) & FPGA_DEV_CMD_IDX_MASK )
#define FPGA_DEV_CMD_SIZE(cmd)	((cmd >> FPGA_DEV_CMD_OP_SHIFT  ) & FPGA_DEV_CMD_OP_MASK  )

struct fpga_dev_resource {
	__u64 start;
	__u64 size;
};

struct fpga_dev_rdwr {
	__u64 where;
	union fpga_reg_data reg;
};

struct fpga_dev_block {
	__u64 where;
	void *block;
};

#endif /* __LINUX_FPGA_DEV_H */
