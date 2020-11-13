/**
 * fpga-example.c - implements a FPGA emulator as an example
 *
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

#define VERSION		CONFIG_FPGA_CORE_VERSION
#define DEV_NAME	"fpga example"

#define MAX_REG_SPACE_SIZE	0x100000
static unsigned int reg_space_size = 0x1000;
module_param(reg_space_size, uint, S_IRUGO);
MODULE_PARM_DESC(reg_space_size, "The FPGA register space size (bytes). "
				 "Default 0x1000, maximum 0x100000.");

#define le8_to_cpup(_p) (*(u8 *)(_p))
#define __FPGA_EXAMPLE_RD(_bits)						\
int fpga_example_read ## _bits (struct fpga *fpga, u64 addr, u ## _bits *reg)	\
{										\
	void *regs = fpga_get_data(fpga);					\
	u64 where = (addr) - fpga_addr(fpga);					\
	if (unlikely(!reg)) return -EFAULT;					\
	*reg = le ## _bits ## _to_cpup(regs + where);				\
	return 0;								\
}
#define cpu_to_le8(_b)	(_b)
#define ___FPGA_EXAMPLE_WR(_bits)						\
int fpga_example_write ## _bits (struct fpga *fpga, u64 addr, u ## _bits reg)	\
{										\
	void *regs = fpga_get_data(fpga);					\
	u64 where = (addr) - fpga_addr(fpga);					\
	*((typeof(reg) *)(regs + where)) = cpu_to_le ## _bits (reg);		\
	return 0;								\
}

#define FPGA_EXAMPLE_RDWR(_bits)		\
	static __FPGA_EXAMPLE_RD(_bits)		\
	static ___FPGA_EXAMPLE_WR(_bits)	\

FPGA_EXAMPLE_RDWR(8)
FPGA_EXAMPLE_RDWR(16)
FPGA_EXAMPLE_RDWR(32)
FPGA_EXAMPLE_RDWR(64)

static ssize_t fpga_example_read_block(struct fpga *fpga, u64 addr, size_t size, u8 *block)
{
	void *regs = fpga_get_data(fpga);
	u64 where = addr - fpga_addr(fpga);
	if (unlikely(check_fpga_addr(&fpga->resource, addr, size)))
		return -EFAULT;
	if (unlikely(!block))
		return -EFAULT;
	memcpy(block, regs + where, size);
	return size;
}

static ssize_t fpga_example_write_block(struct fpga *fpga, u64 addr, size_t size, u8 *block)
{
	void *regs = fpga_get_data(fpga);
	u64 where = addr - fpga_addr(fpga);
	if (unlikely(check_fpga_addr(&fpga->resource, addr, size)))
		return -EFAULT;
	if (unlikely(!block))
		return -EFAULT;
	memcpy(regs + where, block, size);
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

static struct fpga_operations ops_example = {
	.read8 = fpga_example_read8,
	.write8 = fpga_example_write8,

	.read16 = fpga_example_read16,
	.write16 = fpga_example_write16,

	.read32 = fpga_example_read32,
	.write32 = fpga_example_write32,

	.read64 = fpga_example_read64,
	.write64 = fpga_example_write64,

	.read_block = fpga_example_read_block,
	.write_block = fpga_example_write_block,

	.functionality = functionality_example,
};

static struct fpga fpga_example = {
	.owner = THIS_MODULE,
	.ops = &ops_example,
	.timeout = 10,
	.retries = 5,
	.name = DEV_NAME,
};

static BITS_ATTR_RW_D(qword, test_4b, 0, 4, false, 0x0);
static BITS_ATTR_RW_D(qword, test_4b_flip, 0, 4, true, 0x0);
static BITS_ATTR_RW_D(qword, test_4b_4, 4, 4, false, 0x0);
static BITS_ATTR_RW_D(qword, test_8b, 0, 8, false, 0x0);
static BITS_ATTR_RW_D(qword, test_16b, 0, 16, false, 0x0);
static BITS_ATTR_RW_D(qword, test_32b, 0, 32, false, 0x0);
static BITS_ATTR_RW_D(qword, test, 0, 64, false, 0x0);

static struct attribute *test_reg_attrs[] = {
	&bits_attr_test_4b.dev_attr.attr,
	&bits_attr_test_4b_flip.dev_attr.attr,
	&bits_attr_test_4b_4.dev_attr.attr,
	&bits_attr_test_8b.dev_attr.attr,
	&bits_attr_test_16b.dev_attr.attr,
	&bits_attr_test_32b.dev_attr.attr,
	&bits_attr_test.dev_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(test_reg);

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
	fpga_example.resource.resource.start = 0x0;
	fpga_example.resource.resource.end = reg_space_size +
				    fpga_example.resource.resource.start - 1;
	fpga_example.resource.resource.flags = IORESOURCE_MEM;
	fpga_example.resource.vp = (void __iomem *)reg_space;

	fpga_example.dev.groups = test_reg_groups;

	ret = fpga_add(&fpga_example);
	if (ret)
		goto err_free_reg_space;

	return 0;

err_free_reg_space:
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
