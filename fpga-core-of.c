/**
 * fpga-core-of.c - support dt for the FPGA/CPLD driver framework
 *
 * Copyright (C) 2020 IriKa <qiujie.jq@gmail.com>
 */

#define pr_fmt(fmt)	"fpga-core-of: " fmt

#include <linux/device.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/sysfs.h>
#include <linux/of_address.h>

#include <fpga.h>

#include "fpga-core.h"

static int of_dev_or_parent_node_match(struct device *dev, const void *data)
{
	if (dev->of_node == data)
		return 1;

	if (dev->parent)
		return dev->parent->of_node == data;

	return 0;
}

struct fpga_ip *of_fpga_find_ip_by_node(struct device_node *node)
{
	struct device *dev;
	struct fpga_ip *ip;

	dev = bus_find_device_by_of_node(&fpga_bus_type, node);
	if (!dev)
		return NULL;

	ip = fpga_verify_ip(dev);
	if (!ip)
		put_device(dev);

	return ip;
}
EXPORT_SYMBOL(of_fpga_find_ip_by_node);

struct fpga *of_fpga_find_by_node(struct device_node *node)
{
	struct device *dev;
	struct fpga *fpga;

	dev = bus_find_device(&fpga_bus_type, NULL, node, of_dev_or_parent_node_match);
	if (!dev)
		return NULL;
	fpga = fpga_verify(dev);
	if (!fpga)
		put_device(dev);

	return fpga;
}
EXPORT_SYMBOL(of_fpga_find_by_node);

struct fpga *of_fpga_get_by_node(struct device_node *node)
{
	struct fpga *fpga;

	fpga = of_fpga_find_by_node(node);
	if (!fpga)
		return NULL;

	if (!try_module_get(fpga->owner)) {
		put_device(&fpga->dev);
		fpga = NULL;
	}

	return fpga;
}
EXPORT_SYMBOL(of_fpga_get_by_node);

static const struct of_device_id *
of_fpga_match_ip_sysfs(const struct of_device_id *matches, struct fpga_ip *ip)
{
	const char *name;

	for (; matches->compatible[0]; matches++) {
		if (sysfs_streq(ip->name, matches->compatible))
			return matches;

		name = strchr(matches->compatible, ',');
		if (!name)
			name = matches->compatible;
		else name++;

		if (sysfs_streq(ip->name, name))
			return matches;
	}

	return NULL;
}

const struct of_device_id *
of_fpga_match_ip_id(const struct of_device_id *matches, struct fpga_ip *ip)
{
	const struct of_device_id *match;

	if (!ip || !matches)
		return NULL;

	match = of_match_device(matches, &ip->dev);
	if (match)
		return match;

	return of_fpga_match_ip_sysfs(matches, ip);
}
EXPORT_SYMBOL(of_fpga_match_ip_id);

int of_fpga_get_ip_info(struct device *dev, struct device_node *node,
			struct fpga_ip_info *info)
{
	unsigned int cnt = 0;

	memset(info, 0, sizeof *info);

	if (of_modalias_node(node, info->type, sizeof info->type) < 0) {
		dev_err(dev, "of_fpga: Modalias failure on %pOF\n", node);
		return -EINVAL;
	}

#if IS_ENABLED(CONFIG_PPC)
#warning Using DTS on the PowerPC architecture to describe FPGA may	\
	not work perperly!
#endif
	if (IS_ENABLED(CONFIG_PPC))
		dev_warn(dev, "Using DTS on the PowerPC architecture to "
			      "describe FPGA may not work perperly!\n");

	while (!of_address_to_resource(node, cnt, &info->resources[cnt])) {
		if (cnt > FPGA_NUM_RESOURCES_MAX) {
			dev_err(dev, "of_fpga: Max support %d resources\n",
				FPGA_NUM_RESOURCES_MAX);
			return -EINVAL;
		}
		cnt++;
	}
	if (cnt <= 0) {
		dev_err(dev, "of_fpga: At least 1 reg segment\n");
		return -EINVAL;
	}
	info->num_resources = cnt;

	info->of_node = node;
	info->fwnode = of_fwnode_handle(node);

	return 0;
}
EXPORT_SYMBOL(of_fpga_get_ip_info);

static struct fpga_ip *of_fpga_register_ip(struct fpga *fpga,
					   struct device_node *node)
{
	struct fpga_ip *ip;
	struct fpga_ip_info info;
	int ret;

	dev_dbg(&fpga->dev, "of_fpga: register %pOF\n", node);

	ret = of_fpga_get_ip_info(&fpga->dev, node, &info);
	if (ret)
		return ERR_PTR(ret);

	ip = __fpga_new_ip(fpga, &info);
	if (IS_ERR(ip))
		dev_err(&fpga->dev, "of_fpga: Failure registering %pOF\n",
			node);

	return ip;
}

void of_fpga_register_ips(struct fpga *fpga)
{
	struct device_node *bus, *node;
	struct fpga_ip *ip;

	if (!fpga->dev.of_node)
		return;

	dev_dbg(&fpga->dev, "of_fpga: Walking child nodes\n");

	bus = of_node_get(fpga->dev.of_node);

	for_each_available_child_of_node(bus, node) {
		if (of_node_test_and_set_flag(node, OF_POPULATED))
			continue;

		ip = of_fpga_register_ip(fpga, node);
		if (IS_ERR(ip)) {
			dev_err(&fpga->dev, "Fail to create IP for %pOF\n",
				node);
			of_node_clear_flag(node, OF_POPULATED);
		}
	}

	of_node_put(bus);
}
