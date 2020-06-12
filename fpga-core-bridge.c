/**
 * fpga-core-of.c - support bridge for the FPGA/CPLD driver framework
 *
 * Copyright (C) 2003-2020, Semptian Co., Ltd.
 * Designed by IriKa <qiujie@semptian.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include <fpga.h>
#include <fpga-bridge.h>

#include "fpga-core.h"

static int fpga_bridge_reg_xfer(struct fpga *fpga, u64 addr, char rw, int size,
				union fpga_reg_data *data)
{
	struct fpga_bridge *bridge = to_fpga_bridge(fpga);
	struct fpga *parent = bridge->parent;

	return fpga_reg_xfer(parent, addr, rw, size, data);
}

static int fpga_bridge_block_xfer(struct fpga *fpga, u64 addr, char rw,
				  int size, u8 *data)
{
	struct fpga_bridge *bridge = to_fpga_bridge(fpga);
	struct fpga *parent = bridge->parent;

	return fpga_block_xfer(parent, addr, rw, size, data);
}

static u32 fpga_bridge_functionality(struct fpga *fpga)
{
	struct fpga_bridge *bridge = to_fpga_bridge(fpga);
	struct fpga *parent = bridge->parent;

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

struct fpga_bridge *
fpga_bridge_alloc(struct fpga *parent, struct device *dev, u32 force_nr,
		  struct resource *resource, int sizeof_priv,
		  int (*reg_xfer)(struct fpga *, u64, char, int,
				  union fpga_reg_data *),
		  int (*block_xfer)(struct fpga *, u64, char, int, u8 *),
		  u32 (*functionality)(struct fpga *))
{
	struct fpga_bridge *bridge;
	int ret;

	bridge = kzalloc(sizeof(*bridge) + sizeof_priv, GFP_KERNEL);
	if (!bridge)
		return NULL;

	if (sizeof_priv)
		bridge->priv = bridge + 1;
	bridge->parent = parent;
	bridge->dev = dev;

	if (reg_xfer)
		bridge->algo.reg_xfer = reg_xfer;
	else
		bridge->algo.reg_xfer = fpga_bridge_reg_xfer;
	if (block_xfer)
		bridge->algo.block_xfer = block_xfer;
	else
		bridge->algo.block_xfer = fpga_bridge_block_xfer;
	if (functionality)
		bridge->algo.functionality = functionality;
	else
		bridge->algo.functionality = fpga_bridge_functionality;

	snprintf(bridge->fpga.name, sizeof(bridge->fpga.name),
		 "fpga-%d-bridge (addr 0x%08llx)",
		 fpga_id(parent), resource->start);
	bridge->fpga.owner = THIS_MODULE;
	bridge->fpga.algo = &bridge->algo;
	bridge->fpga.dev.parent = &parent->dev;
	bridge->fpga.retries = parent->retries;
	bridge->fpga.timeout = parent->timeout;
	memcpy(&bridge->fpga.resource, resource, sizeof(*resource));
	// FIXME:
	bridge->fpga.__addr = bridge->fpga.resource.start;
	bridge->fpga.__size = parent->__size;

	bridge->fpga.dev.of_node = of_node_get(dev->of_node);

	if (force_nr) {
		bridge->fpga.nr = force_nr;
		ret = fpga_add_numbered(&bridge->fpga);
		if (ret < 0) {
			dev_err(&parent->dev, "Failed to add bridge 0x%08llx "
					      "as fpga %u (error=%d)\n",
				bridge->fpga.resource.start, force_nr, ret);
			goto err_free_bridge;
		}
	} else {
		ret = fpga_add(&bridge->fpga);
		if (ret < 0) {
			dev_err(&parent->dev, "Failed to add bridge 0x%08llx "
					      "(error=%d)\n",
				bridge->fpga.resource.start, ret);
			goto err_free_bridge;
		}
	}

	WARN(sysfs_create_link(&bridge->fpga.dev.kobj, &bridge->dev->kobj,
			       "bridge"),
	     "Cannot create symlink to bridge\n");

	WARN(sysfs_create_link(&bridge->dev->kobj, &bridge->fpga.dev.kobj,
			       "fpga"),
	     "Cannot create symlink to fpga (0x%08llx)",
	     fpga_addr(&bridge->fpga));

	dev_info(&parent->dev, "Added fpga %d under fpga %d\n",
		 fpga_id(&bridge->fpga), fpga_id(parent));

	return bridge;

err_free_bridge:
	kfree(bridge);
	return NULL;
}
EXPORT_SYMBOL(fpga_bridge_alloc);

void fpga_bridge_free(struct fpga_bridge *bridge)
{
	if (!bridge)
		return;

	sysfs_remove_link(&bridge->dev->kobj, "fpga");
	sysfs_remove_link(&bridge->fpga.dev.kobj, "bridge");
	fpga_del(&bridge->fpga);
	of_node_put(bridge->fpga.dev.of_node);
	kfree(bridge);
}
EXPORT_SYMBOL(fpga_bridge_free);
