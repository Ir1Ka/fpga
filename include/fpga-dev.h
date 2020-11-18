#ifndef __LINUX_FPGA_DEV_H
#define __LINUX_FPGA_DEV_H

#include <linux/types.h>

#include <fpga.h>

/*
 * IOCTL cmd field:
 * 1. 31:27 (5 bits) type.
 * 2. remain bits depend on type, refer `FPGA_DEV_TYPE_*`.
 */

#define FPGA_DEV_CMD_TYPE_SHIFT		27
#define FPGA_DEV_CMD_TYPE_BITES		5
#define FPGA_DEV_CMD_TYPE_MASK		((0x1u << FPGA_DEV_CMD_TYPE_BITES) - 1)

#define __FPGA_DEV_CMD_TYPE(_type)	\
	((_type & FPGA_DEV_CMD_TYPE_MASK) << FPGA_DEV_CMD_TYPE_SHIFT)
#define FPGA_DEV_CMD_TYPE(_cmd)		\
	((_cmd >> FPGA_DEV_CMD_TYPE_SHIFT) & FPGA_DEV_CMD_TYPE_MASK)

enum FPGA_DEV_IOCTL_TYPE {
	/*
	 * cmd field:
	 *	1. 5:0 (6 bits) resource number.
	 */
	FPGA_DEV_TYPE_RESOURCE,

#define FPGA_DEV_CMD_RESOURCE_NUM_SHIFT	0
#define FPGA_DEV_CMD_RESOURCE_NUM_BITS	6
#define FPGA_DEV_CMD_RESOURCE_NUM_MASK	((0x1u << FPGA_DEV_CMD_RESOURCE_NUM_BITS) - 1)
#define __FPGA_DEV_CMD_RESOURCE_NUM(_num)	\
	((_num & FPGA_DEV_CMD_RESOURCE_NUM_MASK) << FPGA_DEV_CMD_RESOURCE_NUM_SHIFT)
#define FPGA_DEV_CMD_RESOURCE_NUM(_cmd)		\
	((_cmd >> FPGA_DEV_CMD_RESOURCE_NUM_SHIFT) & FPGA_DEV_CMD_RESOURCE_NUM_MASK)

#define FPGA_DEV_RESOURCE_CMD(_num)			\
	(__FPGA_DEV_CMD_TYPE(FPGA_DEV_TYPE_RESOURCE) |	\
	 __FPGA_DEV_CMD_RESOURCE_NUM(_num))

	/*
	 * cmd field:
	 */
	FPGA_DEV_TYPE_FUNC,

#define FPGA_DEV_FUNC_CMD		__FPGA_DEV_CMD_TYPE(FPGA_DEV_TYPE_FUNC)

	/*
	 * cmd field:
	 *	1. 26:26 (1 bits) op, read/write.
	 *	2. 25:23 (3 bits) register type (byte, word, dword and qword).
	 *	3. 22:8 (15 bits) register number.
	 *	3. 5:0 (6 bits) index, index resource in fpga ip. Similar to resource number.
	 */
	FPGA_DEV_TYPE_REG,

#define FPGA_DEV_CMD_REG_OP_READ	0
#define FPGA_DEV_CMD_REG_OP_WRITE	1
#define FPGA_DEV_CMD_REG_OP_SHIFT	26
#define FPGA_DEV_CMD_REG_OP_BITS	1
#define FPGA_DEV_CMD_REG_OP_MASK	((0x1u << FPGA_DEV_CMD_REG_OP_BITS) - 1)
#define __FPGA_DEV_CMD_REG_OP(_op)	\
	((_op & FPGA_DEV_CMD_REG_OP_MASK) << FPGA_DEV_CMD_REG_OP_SHIFT)
#define FPGA_DEV_CMD_REG_OP(_cmd)	\
	((_cmd >> FPGA_DEV_CMD_REG_OP_SHIFT) & FPGA_DEV_CMD_REG_OP_MASK)

#define FPGA_DEV_CMD_REG_TYPE_BYTE	0
#define FPGA_DEV_CMD_REG_TYPE_WORD	1
#define FPGA_DEV_CMD_REG_TYPE_DWORD	2
#define FPGA_DEV_CMD_REG_TYPE_QWORD	3
#define FPGA_DEV_CMD_REG_TYPE_SHIFT	23
#define FPGA_DEV_CMD_REG_TYPE_BITS	3
#define FPGA_DEV_CMD_REG_TYPE_MASK	((0x1u << FPGA_DEV_CMD_REG_TYPE_SHIFT) - 1)
#define __FPGA_DEV_CMD_REG_TYPE(_reg_type)	\
	((_reg_type & FPGA_DEV_CMD_REG_TYPE_MASK) << FPGA_DEV_CMD_REG_TYPE_SHIFT)
#define FPGA_DEV_CMD_REG_TYPE(_cmd)		\
	((_cmd >> FPGA_DEV_CMD_REG_TYPE_SHIFT) & FPGA_DEV_CMD_REG_TYPE_MASK)

#define FPGA_DEV_CMD_REG_NUM_SHIFT	8
#define FPGA_DEV_CMD_REG_NUM_BITS	15
#define FPGA_DEV_CMD_REG_NUM_MASK	((0x1u << FPGA_DEV_CMD_REG_NUM_BITS) - 1)
#define __FPGA_DEV_CMD_REG_NUM(_num)	\
	((_num & FPGA_DEV_CMD_REG_NUM_MASK) << FPGA_DEV_CMD_REG_NUM_SHIFT)
#define FPGA_DEV_CMD_REG_NUM(_cmd)	\
	((_cmd >> FPGA_DEV_CMD_REG_NUM_SHIFT) & FPGA_DEV_CMD_REG_NUM_MASK)

#define FPGA_DEV_CMD_REG_IDX_SHIFT	0
#define FPGA_DEV_CMD_REG_IDX_BITS	FPGA_DEV_CMD_RESOURCE_NUM_BITS
#define FPGA_DEV_CMD_REG_IDX_MASK	((0x1u << FPGA_DEV_CMD_REG_IDX_BITS) - 1)
#define __FPGA_DEV_CMD_REG_IDX(_idx)	\
	((_idx & FPGA_DEV_CMD_REG_IDX_MASK) << FPGA_DEV_CMD_REG_IDX_SHIFT)
#define FPGA_DEV_CMD_REG_IDX(_cmd)	\
	((_cmd >> FPGA_DEV_CMD_REG_IDX_SHIFT) & FPGA_DEV_CMD_REG_IDX_MASK)

#define __FPGA_DEV_REG_CMD(_op, _num, _reg_type, _idx)	\
	(__FPGA_DEV_CMD_TYPE(FPGA_DEV_TYPE_REG) |	\
	 __FPGA_DEV_CMD_REG_OP(_op) |			\
	 __FPGA_DEV_CMD_REG_NUM(_num) |			\
	 __FPGA_DEV_CMD_REG_TYPE(_reg_type) |		\
	 __FPGA_DEV_CMD_REG_IDX(_idx))
#define FPGA_DEV_REG_CMD(_op, _reg_type, _idx)		\
	__FPGA_DEV_REG_CMD(_op, 1, _reg_type, _idx)

	/*
	 * cmd field:
	 *	1. 26:26 (1 bits) op, read/write. Same as `FPGA_DEV_TYPE_REG`.
	 *	2. 25:14 (12 bits) block size.
	 *	3. 5:0 (6 bits) index, index resource in fpga ip. Same as `FPGA_DEV_TYPE_REG`.
	 */
	FPGA_DEV_TYPE_BLOCK,

#define FPGA_DEV_CMD_BLOCK_OP_READ	FPGA_DEV_CMD_REG_OP_READ
#define FPGA_DEV_CMD_BLOCK_OP_WRITE	FPGA_DEV_CMD_REG_OP_WRITE
#define FPGA_DEV_CMD_BLOCK_OP_SHIFT	FPGA_DEV_CMD_REG_OP_SHIFT
#define FPGA_DEV_CMD_BLOCK_OP_BITS	FPGA_DEV_CMD_REG_OP_BITS
#define FPGA_DEV_CMD_BLOCK_OP_MASK	((0x1u << FPGA_DEV_CMD_BLOCK_OP_BITS) - 1)
#define __FPGA_DEV_CMD_BLOCK_OP(_op)	\
	((_op & FPGA_DEV_CMD_NLOCK_OP_MASK) << FPGA_DEV_CMD_BLOCK_OP_SHIFT)
#define FPGA_DEV_CMD_BLOCK_OP(_cmd)	\
	((_cmd >> FPGA_DEV_CMD_BLOCK_OP_SHIFT) & FPGA_DEV_CMD_BLOCK_OP_MASK)

#define FPGA_DEV_CMD_BLOCK_SIZE_SHIFT	14
#define FPGA_DEV_CMD_BLOCK_SIZE_BITS	12
#define FPGA_DEV_CMD_BLOCK_SIZE_MASK	((0x1u << FPGA_DEV_CMD_BLOCK_SIZE_SHIFT) - 1)
#define __FPGA_DEV_CMD_BLOCK_SIZE(_block_size)	\
	((_block_size & FPGA_DEV_CMD_BLOCK_SIZE_MASK) << FPGA_DEV_CMD_BLOCK_SIZE_SHIFT)
#define FPGA_DEV_CMD_BLOCK_SIZE(_cmd)		\
	((_cmd >> FPGA_DEV_CMD_BLOCK_SIZE_SHIFT) & FPGA_DEV_CMD_BLOCK_SIZE_MASK)

#define FPGA_DEV_CMD_BLOCK_IDX_SHIFT	FPGA_DEV_CMD_REG_IDX_SHIFT
#define FPGA_DEV_CMD_BLOCK_IDX_BITS	FPGA_DEV_CMD_REG_IDX_BITS
#define FPGA_DEV_CMD_BLOCK_IDX_MASK	((0x1u << FPGA_DEV_CMD_BLOCK_IDX_BITS) - 1)
#define __FPGA_DEV_CMD_BLOCK_IDX(_idx)	\
	((_idx & FPGA_DEV_CMD_BLOCK_IDX_MASK) << FPGA_DEV_CMD_BLOCK_IDX_SHIFT)
#define FPGA_DEV_CMD_BLOCK_IDX(_cmd)	\
	((_cmd >> FPGA_DEV_CMD_BLOCK_IDX_SHIFT) & FPGA_DEV_CMD_BLOCK_IDX_MASK)

#define FPGA_DEV_BLOCK_CMD(_op, _block_size, _idx)	\
	(__FPGA_DEV_CMD_TYPE(FPGA_DEV_TYPE_BLOCK) |	\
	 __FPGA_DEV_CMD_BLOCK_OP(_op) |			\
	 __FPGA_DEV_CMD_BLOCK_SIZE(_block_size) |	\
	 __FPGA_DEV_CMD_BLOCK_IDX(_idx))
};

struct fpga_dev_resource {
	__u64 start;
	__u64 size;
};

struct fpga_dev_rdwr {
	__u64 where;
	union {
		__u8 value8[0];
		__u16 value16[0];
		__u32 value32[0];
		__u64 value64[0];
	};
};

struct fpga_dev_block {
	__u64 where;
	void *block;
};

#endif /* __LINUX_FPGA_DEV_H */
