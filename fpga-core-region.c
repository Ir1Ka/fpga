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

static int fpga_region_reg_xfer(struct fpga *fpga, u64 addr, char rw, int size,
				union fpga_reg_data *data)
{
	struct fpga_region *region = to_fpga_region(fpga);
	struct fpga *parent = region->parent;

	return fpga_reg_xfer(parent, addr, rw, size, data);
}

static int fpga_region_block_xfer(struct fpga *fpga, u64 addr, char rw,
				  int size, u8 *data)
{
	struct fpga_region *region = to_fpga_region(fpga);
	struct fpga *parent = region->parent;

	return fpga_block_xfer(parent, addr, rw, size, data);
}

static u32 fpga_region_functionality(struct fpga *fpga)
{
	struct fpga_region *region = to_fpga_region(fpga);
	struct fpga *parent = region->parent;

	return parent->algo->functionality(parent);
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

struct fpga_region *
fpga_region_alloc(struct fpga *parent, struct device *dev, u32 force_nr,
		  struct resource *resource, int sizeof_priv,
		  int (*reg_xfer)(struct fpga *, u64, char, int,
				  union fpga_reg_data *),
		  int (*block_xfer)(struct fpga *, u64, char, int, u8 *),
		  u32 (*functionality)(struct fpga *))
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

	if (reg_xfer)
		region->algo.reg_xfer = reg_xfer;
	else
		region->algo.reg_xfer = fpga_region_reg_xfer;
	if (block_xfer)
		region->algo.block_xfer = block_xfer;
	else
		region->algo.block_xfer = fpga_region_block_xfer;
	if (functionality)
		region->algo.functionality = functionality;
	else
		region->algo.functionality = fpga_region_functionality;

	snprintf(region->fpga.name, sizeof(region->fpga.name),
		 "fpga-%d-region (addr 0x%08llx)",
		 fpga_id(parent), resource->start);
	region->fpga.owner = THIS_MODULE;
	region->fpga.algo = &region->algo;
	region->fpga.dev.parent = &parent->dev;
	region->fpga.retries = parent->retries;
	region->fpga.timeout = parent->timeout;
	memcpy(&region->fpga.resource, resource, sizeof(*resource));
	// FIXME:
	region->fpga.__addr = region->fpga.resource.start;
	region->fpga.__block_size = 0;

	region->fpga.dev.of_node = of_node_get(dev->of_node);

	if (force_nr) {
		region->fpga.nr = force_nr;
		ret = fpga_add_numbered(&region->fpga);
		if (ret < 0) {
			dev_err(&parent->dev, "Failed to add region 0x%08llx "
					      "as fpga %u (error=%d)\n",
				region->fpga.resource.start, force_nr, ret);
			goto err_free_region;
		}
	} else {
		ret = fpga_add(&region->fpga);
		if (ret < 0) {
			dev_err(&parent->dev, "Failed to add region 0x%08llx "
					      "(error=%d)\n",
				region->fpga.resource.start, ret);
			goto err_free_region;
		}
	}

	WARN(sysfs_create_link(&region->fpga.dev.kobj, &region->dev->kobj,
			       "region"),
	     "Cannot create symlink to region\n");

	WARN(sysfs_create_link(&region->dev->kobj, &region->fpga.dev.kobj,
			       "fpga"),
	     "Cannot create symlink to fpga (0x%08llx)",
	     fpga_addr(&region->fpga));

	dev_info(&parent->dev, "Added fpga %d under fpga %d\n",
		 fpga_id(&region->fpga), fpga_id(parent));

	return region;

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
	of_node_put(region->fpga.dev.of_node);
	kfree(region);
}
EXPORT_SYMBOL(fpga_region_free);
