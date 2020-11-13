/**
 * fpga-core-region.c - support region for the FPGA/CPLD driver framework
 *
 * Copyright (C) 2020 IriKa <qiujie.jq@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include <fpga.h>
#include <fpga-region.h>

#include "fpga-core.h"

#define __FPGA_REGION_RW(_name, _bits, _type)				\
int fpga_region_ ## _name ## _bits (struct fpga *fpga,			\
				    u64 addr, u ## _bits _type reg)	\
{									\
	struct fpga_region *region = to_fpga_region(fpga);		\
	struct fpga *parent = region->parent;				\
	return fpga_ ## _name ## _bits (parent, addr, reg);		\
}
#define FPGA_REGION_RW(_bits)		\
static __FPGA_REGION_RW(read, _bits, *)	\
static __FPGA_REGION_RW(write, _bits,)

FPGA_REGION_RW(8)
FPGA_REGION_RW(16)
FPGA_REGION_RW(32)
FPGA_REGION_RW(64)

#define __FPGA_REGION_RW_BLOCK(_name)					\
ssize_t fpga_region_ ## _name ## _block(struct fpga *fpga, u64 addr,	\
					size_t size, u8 *block)		\
{									\
	struct fpga_region *region = to_fpga_region(fpga);		\
	struct fpga *parent = region->parent;				\
	return fpga_ ## _name ## _block(parent, addr, size, block);	\
}

static __FPGA_REGION_RW_BLOCK(read)
static __FPGA_REGION_RW_BLOCK(write)

static u32 fpga_region_functionality(struct fpga *fpga)
{
	struct fpga_region *region = to_fpga_region(fpga);
	struct fpga *parent = region->parent;
	return fpga_get_functionality(parent);
}

struct fpga *fpga_root(struct device *dev)
{
	struct device *fpga;
	struct fpga *root, *parent;

	for (fpga = dev; fpga; fpga = fpga->parent) {
		if (fpga->type == &fpga_type)
			break;
	}
	if (!fpga)
		return NULL;

	root = to_fpga(fpga);
	while ((parent = fpga_parent_is_fpga(root)))
		root = parent;

	return root;
}
EXPORT_SYMBOL(fpga_root);

static int fpga_region_fill_ops(struct fpga *parent, struct fpga_region *region)
{
	struct fpga_operations *ops = &region->ops;

	if (fpga_check_functionality(parent, FPGA_FUNC_READ_BYTE) && !ops->read8)
		ops->read8 = fpga_region_read8;
	if (fpga_check_functionality(parent, FPGA_FUNC_WRITE_BYTE) && !ops->write8)
		ops->write8 = fpga_region_write8;

	if (fpga_check_functionality(parent, FPGA_FUNC_READ_WORD) && !ops->read16)
		ops->read16 = fpga_region_read16;
	if (fpga_check_functionality(parent, FPGA_FUNC_WRITE_WORD) && !ops->write16)
		ops->write16 = fpga_region_write16;

	if (fpga_check_functionality(parent, FPGA_FUNC_READ_DWORD) && !ops->read32)
		ops->read32 = fpga_region_read32;
	if (fpga_check_functionality(parent, FPGA_FUNC_WRITE_DWORD) && !ops->write32)
		ops->write32 = fpga_region_write32;

	if (fpga_check_functionality(parent, FPGA_FUNC_READ_QWORD) && !ops->read64)
		ops->read64 = fpga_region_read64;
	if (fpga_check_functionality(parent, FPGA_FUNC_WRITE_QWORD) && !ops->write64)
		ops->write64 = fpga_region_write64;

	if (fpga_check_functionality(parent, FPGA_FUNC_READ_BLOCK) && !ops->read_block)
		ops->read_block = fpga_region_read_block;
	if (fpga_check_functionality(parent, FPGA_FUNC_WRITE_BLOCK) && !ops->write_block)
		ops->write_block = fpga_region_write_block;

	if (fpga_get_functionality(parent) & FPGA_FUNC_DIRECT && !region->fpga.resource.vp)
		return -EINVAL;

	if (!ops->functionality)
		ops->functionality = fpga_region_functionality;

	return 0;
}

struct fpga_region *
fpga_region_alloc(struct fpga *parent, struct device *dev, u32 force_nr,
		  struct fpga_resource *resource, int sizeof_priv,
		  struct fpga_operations *ops)
{
	struct fpga_region *region;
	int ret;

	region = kzalloc(sizeof(*region) + sizeof_priv, GFP_KERNEL);
	if (!region)
		return NULL;

	if (sizeof_priv)
		region->priv = region + 1;
	region->parent = parent;
	region->dev = dev;

	snprintf(region->fpga.name, sizeof(region->fpga.name),
		 "fpga-%d-region (addr 0x%08llx)",
		 fpga_id(parent), resource->resource.start);
	region->fpga.owner = THIS_MODULE;
	region->fpga.ops = &region->ops;
	region->fpga.dev.parent = &parent->dev;
	region->fpga.retries = parent->retries;
	region->fpga.timeout = parent->timeout;

	region->fpga.resource.resource.start = resource->resource.start;
	region->fpga.resource.resource.end = resource->resource.end;
	region->fpga.resource.resource.flags = resource->resource.flags;
	region->fpga.resource.vp = resource->vp;
	ret = request_resource(&resource->resource, &region->fpga.resource.resource);
	if (unlikely(ret)) {
			dev_err(&parent->dev, "Invalid region register resource "
					    "0x%08llx - 0x%08llx\n",
				region->fpga.resource.resource.start,
				region->fpga.resource.resource.end);
			goto err_free_region;
	}

	region->fpga.__addr = region->fpga.resource.resource.start;
	region->fpga.__block_size = 0;

	region->fpga.dev.of_node = of_node_get(dev->of_node);

	if (ops)
		memcpy(&region->ops, ops, sizeof(*ops));
	ret = fpga_region_fill_ops(parent, region);
	if (unlikely(ret)) {
		dev_err(&parent->dev, "failed to fill region fpga operations\n");
		goto err_of_node_put;
	}

	if (force_nr) {
		region->fpga.nr = force_nr;
		ret = fpga_add_numbered(&region->fpga);
		if (ret < 0) {
			dev_err(&parent->dev, "Failed to add region 0x%08llx "
					      "as fpga %u (error=%d)\n",
				region->fpga.resource.resource.start, force_nr, ret);
			goto err_of_node_put;
		}
	} else {
		ret = fpga_add(&region->fpga);
		if (ret < 0) {
			dev_err(&parent->dev, "Failed to add region 0x%08llx "
					      "(error=%d)\n",
				region->fpga.resource.resource.start, ret);
			goto err_of_node_put;
		}
	}

	WARN(sysfs_create_link(&region->fpga.dev.kobj, &region->dev->kobj,
			       "region"),
	     "Cannot create symlink to region\n");

	WARN(sysfs_create_link(&region->dev->kobj, &region->fpga.dev.kobj,
			       "fpga"),
	     "Cannot create symlink to fpga (0x%08llx)\n",
	     fpga_addr(&region->fpga));

	dev_info(&parent->dev, "Added fpga %d under fpga %d\n",
		 fpga_id(&region->fpga), fpga_id(parent));

	return region;

err_of_node_put:
	of_node_put(region->fpga.dev.of_node);
	release_resource(&region->fpga.resource.resource);
err_free_region:
	kfree(region);
	return NULL;
}
EXPORT_SYMBOL(fpga_region_alloc);

void fpga_region_free(struct fpga_region *region)
{
	if (!region)
		return;

	sysfs_remove_link(&region->dev->kobj, "fpga");
	sysfs_remove_link(&region->fpga.dev.kobj, "region");
	fpga_del(&region->fpga);
	release_resource(&region->fpga.resource.resource);
	of_node_put(region->fpga.dev.of_node);
	kfree(region);
}
EXPORT_SYMBOL(fpga_region_free);
