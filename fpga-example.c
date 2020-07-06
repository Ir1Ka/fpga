/**
 * fpga-example.c - implements a FPGA emulator as an example
 * Copyright (C) 2020 IriKa <qiujie.jq@gmail.com>
 */

#define pr_fmt(fmt)	"fpga-example: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>

#include <fpga.h>

#define VERSION		"v0.1.0"
#define DEV_NAME	"fpga example"

#define MAX_REG_SPACE_SIZE	0x100000
static unsigned int reg_space_size = 0x1000;
module_param(reg_space_size, uint, S_IRUGO);
MODULE_PARM_DESC(reg_space_size, "The FPGA register space size (bytes). "
				 "Default 0x1000, maximum 0x100000.");

static int reg_xfer_example(struct fpga *fpga, u64 addr, char rw, int size,
			    union fpga_reg_data *reg)
{
	void *reg_space = fpga_get_data(fpga);
	resource_size_t reg_space_size = resource_size(&fpga->resource);
	u64 where = addr - fpga_addr(fpga);

	if (unlikely(!reg_space))
		return -EIO;

	if (unlikely(addr % size))
		return -EIO;

	if (unlikely(where + size > reg_space_size))
		return -EIO;

	where /= size;

	switch (size) {
	case 1:
		if (rw == FPGA_READ)
			reg->byte = *((u8 *)reg_space + where);
		else
			*((u8 *)reg_space + where) = reg->byte;
		break;
	case 2:
		if (rw == FPGA_READ)
			reg->word = le16_to_cpup((__le16 *)reg_space + where);
		else
			*((__le16 *)reg_space + where) = cpu_to_le16(reg->word);
		break;
	case 4:
		if (rw == FPGA_READ)
			reg->dword = le32_to_cpup((__le32 *)reg_space + where);
		else
			*((__le32 *)reg_space + where) = cpu_to_le32(reg->dword);
		break;
	case 8:
		if (rw == FPGA_READ)
			reg->qword = le64_to_cpup((__le64 *)reg_space + where);
		else
			*((__le64 *)reg_space + where) = cpu_to_le64(reg->qword);
		break;
	default:
		return -EIO;
	}

	return 0;
}

static int block_xfer_example(struct fpga *fpga, u64 addr, char rw, int size,
			      u8 *block)
{
	void *reg_space = fpga_get_data(fpga);
	resource_size_t reg_space_size = resource_size(&fpga->resource);
	u64 where = addr - fpga_addr(fpga);

	if (unlikely(!reg_space))
		return -EIO;

	if (where + size > reg_space_size)
		size = reg_space_size - where;

	if (rw == FPGA_READ)
		memcpy(block, reg_space + where, size);
	else
		memcpy(reg_space + where, block, size);

	return size;
}

static u32 functionality_example(struct fpga *fpga)
{
	return FPGA_FUNC_BYTE |
	       FPGA_FUNC_WORD |
	       FPGA_FUNC_DWORD |
	       FPGA_FUNC_QWORD |
	       FPGA_FUNC_BLOCK;
}

static struct fpga_algorithm algo_example = {
	.reg_xfer = reg_xfer_example,
	.block_xfer = block_xfer_example,
	.functionality = functionality_example,
};

static struct fpga fpga_example = {
	.owner = THIS_MODULE,
	.algo = &algo_example,
	.timeout = 10,
	.retries = 5,
	.name = DEV_NAME,
	.default_size = 4,
};

static int __init fpga_init(void)
{
	int ret;
	void *reg_space;

	if (reg_space_size > MAX_REG_SPACE_SIZE)
		return -EINVAL;

	reg_space = kmalloc(reg_space_size, GFP_KERNEL);
	if (!reg_space)
		return -ENOMEM;

	fpga_set_data(&fpga_example, reg_space);
	fpga_example.resource.start = 0x0;
	fpga_example.resource.end = reg_space_size +
				    fpga_example.resource.start - 1;
	fpga_example.resource.flags = IORESOURCE_MEM;

	ret = fpga_add(&fpga_example);
	if (ret)
		kfree(fpga_get_data(&fpga_example));
	return ret;
}

static void __exit fpga_exit(void)
{
	void *reg_space = fpga_get_data(&fpga_example);
	fpga_del(&fpga_example);
	if (reg_space)
		kfree(reg_space);
}

module_init(fpga_init);
module_exit(fpga_exit);

MODULE_AUTHOR("IriKa <qiujie.jq@gmail.com>");
MODULE_DESCRIPTION("An FPGA/CPLD driver emulator as an example");
MODULE_LICENSE("GPL");
MODULE_ALIAS("fpga-example");
MODULE_VERSION(VERSION);
