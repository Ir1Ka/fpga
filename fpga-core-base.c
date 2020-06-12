/**
 * fpga-core-base.c - implements for the FPGA/CPLD driver framework
 *
 * Copyright (C) 2003-2020, Semptian Co., Ltd.
 * Designed by IriKa <qiujie@semptian.com>
 */

#define pr_fmt(fmt)	"fpga-core: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/property.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/pm_runtime.h>
#include <linux/tracepoint.h>

#include <fpga.h>
#include <fpga-bridge.h>

#include "fpga-core.h"

#ifndef CONFIG_FPGA_CORE_VERSION
#define CONFIG_FPGA_CORE_VERSION	"v0.1.0"
#endif

static DEFINE_MUTEX(core_lock);
static DEFINE_IDR(fpga_idr);

static bool is_registered = false;

const struct fpga_ip_id *fpga_match_ip_id(const struct fpga_ip_id *ids,
					  const struct fpga_ip *ip)
{
	const struct fpga_ip_id *id;

	if (!ids || !ip)
		return NULL;

	id = &ids[0];

	while (id->name[0]) {
		if (strcmp(ip->name, id->name) == 0)
			return id;
		id++;
	}
	return NULL;
}
EXPORT_SYMBOL(fpga_match_ip_id);

static int fpga_ip_match(struct device *dev, struct device_driver *drv)
{
	struct fpga_ip *ip = fpga_verify_ip(dev);
	struct fpga_ip_driver *driver;

	if (of_fpga_match_ip_id(drv->of_match_table, ip))
		return 1;

	driver = to_fpga_ip_driver(drv);

	if (fpga_match_ip_id(driver->id_table, ip))
		return 1;

	return 0;
}

static int fpga_ip_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct fpga_ip *ip = to_fpga_ip(dev);
	int rc;

	rc = of_device_uevent_modalias(dev, env);
	if (rc != -ENODEV)
		return rc;

	return add_uevent_var(env, "MODALIAS=%s%s", FPGA_IP_MODULE_PREFIX,
			      ip->name);
}

static int fpga_ip_probe(struct device *dev)
{
	struct fpga_ip *ip = fpga_verify_ip(dev);
	struct fpga_ip_driver *driver;
	int status;

	if (!ip)
		return 0;

	driver = to_fpga_ip_driver(dev->driver);

	if (!driver->id_table &&
	    !of_fpga_match_ip_id(dev->driver->of_match_table, ip))
		return -ENODEV;

	dev_dbg(dev, "probe\n");

	if (!driver->probe)
		status = driver->probe(ip,
				       fpga_match_ip_id(driver->id_table, ip));
	else
		status = -EINVAL;

	if (status)
		goto err_out;

	return 0;

err_out:
	device_init_wakeup(&ip->dev, false);
	return status;
}

static int fpga_ip_remove(struct device *dev)
{
	struct fpga_ip *ip = fpga_verify_ip(dev);
	struct fpga_ip_driver *driver;
	int status = 0;

	if (!ip || !dev->driver)
		return 0;

	driver = to_fpga_ip_driver(dev->driver);
	if (driver->remove) {
		dev_dbg(dev, "remove\n");
		status = driver->remove(ip);
	}

	device_init_wakeup(&ip->dev, false);

	return status;
}

static void fpga_ip_shutdown(struct device *dev)
{
	struct fpga_ip *ip = fpga_verify_ip(dev);
	struct fpga_ip_driver *driver;

	if (!ip || !dev->driver)
		return;

	driver = to_fpga_ip_driver(dev->driver);
	if (driver->shutdown)
		driver->shutdown(ip);
}

static void fpga_ip_dev_release(struct device *dev)
{
	kfree(to_fpga_ip(dev));
}

static ssize_t
name_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", dev->type == &fpga_ip_type ?
		       to_fpga_ip(dev)->name : to_fpga(dev)->name);
}
static DEVICE_ATTR_RO(name);

static ssize_t
modalias_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga_ip *ip = fpga_verify_ip(dev);
	int len;

	len = of_device_modalias(dev, buf, PAGE_SIZE);
	if (len != -ENODEV)
		return len;

	return sprintf(buf, "%s%s\n", FPGA_IP_MODULE_PREFIX, ip->name);
}
static DEVICE_ATTR_RO(modalias);

static struct attribute *fpga_ip_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_modalias.attr,
	NULL,
};
ATTRIBUTE_GROUPS(fpga_ip);

struct bus_type fpga_bus_type = {
	.name		= "fpga",
	.match		= fpga_ip_match,
	.probe		= fpga_ip_probe,
	.remove		= fpga_ip_remove,
	.shutdown	= fpga_ip_shutdown,
};
EXPORT_SYMBOL(fpga_bus_type);

struct device_type fpga_ip_type = {
	.groups		= fpga_ip_groups,
	.uevent		= fpga_ip_uevent,
	.release	= fpga_ip_dev_release,
};

struct fpga_ip *fpga_verify_ip(struct device *dev)
{
	return (dev->type == &fpga_ip_type) ? to_fpga_ip(dev) : NULL;
}
EXPORT_SYMBOL(fpga_verify_ip);

static int fpga_compare_resource(const void *lhs, const void *rhs)
{
	const struct resource *lhs_resource = lhs;
	const struct resource *rhs_resource = rhs;

	if (lhs_resource->start < rhs_resource->start) return -1;
	if (lhs_resource->start > rhs_resource->start) return 1;
	return 0;
}

static struct resource *fpga_sort_resource(struct resource *resources)
{
	unsigned int num_resources = 0;

	while (resource_size(&resources[num_resources]) > 0) {
		num_resources++;
		if (num_resources >= FPGA_NUM_RESOURCES_MAX)
			return NULL;
	}
	if (num_resources == 0)
		return NULL;

	sort(resources, num_resources, sizeof resources[0],
	     fpga_compare_resource, NULL);

	return resources;
}

static void fpga_ip_set_name(struct fpga *fpga, struct fpga_ip *ip,
			     struct fpga_ip_info const *info)
{
	if (info && info->dev_name) {
		dev_set_name(&ip->dev, "ip-%s", info->dev_name);
		return;
	}

	dev_set_name(&ip->dev, "%d-%08llx", fpga_id(fpga),
		     fpga_ip_first_addr(ip));
}

struct fpga_ip *
__fpga_new_ip(struct fpga *fpga, struct fpga_ip_info const *info)
{
	struct fpga_ip *ip;
	unsigned int num_resources = 0;
	int status;

	if (!fpga || !info)
		return ERR_PTR(-EINVAL);

	while (resource_size(&info->resources[num_resources]) > 0) {
		num_resources++;
		if (num_resources >= FPGA_NUM_RESOURCES_MAX) {
			dev_err(&fpga->dev, "Max support %d resources\n",
				FPGA_NUM_RESOURCES_MAX - 1);
			return ERR_PTR(-EINVAL);
		}
	}

	if (num_resources == 0) {
		dev_err(&fpga->dev, "At least 1 resource\n");
		return ERR_PTR(-EINVAL);
	}

	ip = kzalloc(sizeof *ip + sizeof info->resources[0] * num_resources,
		     GFP_KERNEL);
	if (!ip)
		return ERR_PTR(-ENOMEM);

	ip->fpga = fpga;
	ip->dev.platform_data = info->platform_data;

	strlcpy(ip->name, info->type, sizeof ip->name);

	ip->num_resources = num_resources;
	memcpy(&ip->resources, info->resources,
	       ip->num_resources * sizeof info->resources[0]);
	while (num_resources > 0) {
		struct resource *resource = &ip->resources[num_resources - 1];

		status = insert_resource(&fpga->resource, resource);
		if (status) {
			dev_err(&fpga->dev, "Invalid register resource "
					    "0x%08llx - 0x%08llx\n",
				resource->start, resource->end);
			goto out_err_remove_resource;
		}
		num_resources--;
	}

	ip->dev.parent = &ip->fpga->dev;
	ip->dev.bus = &fpga_bus_type;
	ip->dev.type = &fpga_ip_type;
	ip->dev.of_node = of_node_get(info->of_node);
	ip->dev.fwnode = info->fwnode;

	fpga_ip_set_name(fpga, ip, info);

	if (info->properties) {
		status = device_add_properties(&ip->dev, info->properties);
		if (status) {
			dev_err(&fpga->dev,
				"Failed to add properties to IP %s: %d\n",
				ip->name, status);
			goto out_err_put_of_node;
		}
	}

	status = device_register(&ip->dev);
	if (status)
		goto out_err_free_props;

	dev_dbg(&fpga->dev, "FPGA IP [%s] registered with bus id %s\n",
		ip->name, dev_name(&ip->dev));

	return ip;

out_err_free_props:
	if (info->properties)
		device_remove_properties(&ip->dev);
out_err_put_of_node:
	of_node_put(info->of_node);

	dev_err(&fpga->dev, "Failed to register FPGA IP %s at 0x%08llx (%d)\n",
		ip->name, fpga_ip_first_addr(ip), status);

	num_resources = 0;
out_err_remove_resource:
	while (num_resources < ip->num_resources)
		remove_resource(&ip->resources[num_resources]);
	kfree(ip);
	return ERR_PTR(status);
}
EXPORT_SYMBOL(__fpga_new_ip);

void fpga_unregister_ip(struct fpga_ip *ip)
{
	if (IS_ERR_OR_NULL(ip))
		return;

	if (ip->dev.of_node) {
		of_node_clear_flag(ip->dev.of_node, OF_POPULATED);
		of_node_put(ip->dev.of_node);
	}

	device_unregister(&ip->dev);
}
EXPORT_SYMBOL(fpga_unregister_ip);

static void fpga_dev_release(struct device *dev)
{
	struct fpga *fpga = to_fpga(dev);
	complete(&fpga->dev_released);
}

unsigned int fpga_depth(struct fpga *fpga)
{
	unsigned int depth = 0;

	while ((fpga = fpga_parent_is_fpga(fpga)))
		depth++;

	WARN_ONCE(depth >= MAX_LOCKDEP_SUBCLASSES,
		  "FPGA depth exceeds lockdep subclass limit\n");

	return depth;
}
EXPORT_SYMBOL(fpga_depth);

static ssize_t
new_device_store(struct device *dev, struct device_attribute *attr,
		 const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	struct fpga_ip_info info = {};
	unsigned int num_resources = 0;
	struct fpga_ip *ip;
	char *blank, *colon, end = '\0';
	int res;

	blank = strchr(buf, ' ');
	if (!blank) {
		dev_err(dev, "%s: Missing parameters\n", "new_device");
		return -EINVAL;
	}
	if (blank - buf > FPGA_IP_NAME_SIZE - 1) {
		dev_err(dev, "%s: Invalid IP name\n", "new_device");
		return -EINVAL;
	}
	memcpy(info.type, buf, blank - buf);

	colon = blank + 1;
	while ((colon = strchr(++colon, ':')))
		num_resources++;

	if (num_resources < 1 || FPGA_NUM_RESOURCES_MAX <= num_resources) {
		dev_err(dev, "%s: Cannot parse IP resources\n", "new_device");
		return -EINVAL;
	}

	switch (num_resources) {
	case 1:
		res = sscanf(++blank, "0x%llx:0x%llx"
				      "%c",
			     &info.resources[0].start, &info.resources[0].end,
			     &end);
		break;
	case 2:
		res = sscanf(++blank, "0x%llx:0x%llx "
				      "0x%llx:0x%llx "
				      "%c",
			     &info.resources[0].start, &info.resources[0].end,
			     &info.resources[1].start, &info.resources[1].end,
			     &end);
		break;
	case 3:
		res = sscanf(++blank, "0x%llx:0x%llx "
				      "0x%llx:0x%llx "
				      "0x%llx:0x%llx "
				      "%c",
			     &info.resources[0].start, &info.resources[0].end,
			     &info.resources[1].start, &info.resources[1].end,
			     &info.resources[2].start, &info.resources[2].end,
			     &end);
		break;
	case FPGA_NUM_RESOURCES_MAX - 1:
		res = sscanf(++blank, "0x%llx:0x%llx "
				      "0x%llx:0x%llx "
				      "0x%llx:0x%llx "
				      "0x%llx:0x%llx"
				      "%c",
			     &info.resources[0].start, &info.resources[0].end,
			     &info.resources[1].start, &info.resources[1].end,
			     &info.resources[2].start, &info.resources[2].end,
			     &info.resources[3].start, &info.resources[3].end,
			     &end);
		break;
	}
	if (res / 2 != num_resources || (res % 2 != 0 && end != '\n')) {
		dev_err(dev, "%s: Cannot parse IP resources\n", "new_device");
		return -EINVAL;
	}

	/* The register addr is based on its FPGA. */
	while (num_resources-- > 0)
		info.resources[num_resources].start += fpga->resource.start;

	fpga_sort_resource(info.resources);

	ip = __fpga_new_ip(fpga, &info);
	if (IS_ERR(ip))
		return PTR_ERR(ip);

	mutex_lock(&fpga->userspace_ips_lock);
	list_add_tail(&ip->detected, &fpga->userspace_ips);
	mutex_unlock(&fpga->userspace_ips_lock);

	dev_info(dev, "%s: Instantiated device %s at 0x%08llx\n", "new_device",
		 info.type, fpga_ip_first_addr(ip));

	return count;
}
static DEVICE_ATTR_WO(new_device);

static ssize_t
delete_device_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	struct fpga_ip *ip, *next;
	resource_size_t first_addr;
	char end;
	int res;

	res = sscanf(buf, "0x%llx%c", &first_addr, &end);
	if (res < 1) {
		dev_err(dev, "%s: Cannot parse IP address\n", "delete_device");
		return -EINVAL;
	}
	if (res > 1 && end != '\n') {
		dev_err(dev, "%s: Extra parameters\n", "delete_device");
		return -EINVAL;
	}

	res = -ENOENT;
	mutex_lock_nested(&fpga->userspace_ips_lock, fpga_depth(fpga));
	list_for_each_entry_safe(ip, next, &fpga->userspace_ips, detected) {
		resource_size_t _first_addr;
		/* The register addr is based on its FPGA. */
		_first_addr = fpga_ip_first_addr(ip) - fpga->resource.start;
		if (_first_addr == first_addr) {
			dev_info(dev, "%s: Deleting device %s at 0x%08llx\n",
				 "delete_device", ip->name,
				 fpga_ip_first_addr(ip));
			list_del(&ip->detected);
			fpga_unregister_ip(ip);
			res = count;
			break;
		}
	}
	mutex_unlock(&fpga->userspace_ips_lock);

	if (res < 0)
		dev_err(dev, "%s: Cannot find device in list\n",
			"delete_device");
	return res;
}
static DEVICE_ATTR_IGNORE_LOCKDEP(delete_device, S_IWUSR, NULL,
				  delete_device_store);

static ssize_t __addr_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;
	char end;
	int res;

	res = sscanf(buf, "0x%llx%c", &addr, &end);
	if (res < 1) {
		dev_err(dev, "%s: Invalid reg address\n", "__addr");
		return -EINVAL;
	}
	if (res > 1 && end != '\n') {
		dev_err(dev, "%s: Extra parameters\n", "__addr");
		return -EINVAL;
	}

	write_lock(&fpga->__rwlock);
	fpga->__addr = addr;
	write_unlock(&fpga->__rwlock);

	return count;
}

static ssize_t __addr_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	ssize_t res;

	read_lock(&fpga->__rwlock);
	res = sprintf(buf, "0x%llx\n", fpga->__addr);
	read_unlock(&fpga->__rwlock);

	return res;
}
static DEVICE_ATTR(__addr, 0600, __addr_show, __addr_store);

static ssize_t __size_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	int size;
	char end;
	int res;

	res = sscanf(buf, "%d%c", &size, &end);
	if (res < 1) {
		dev_err(dev, "%s: Invalid reg size\n", "__size");
		return -EINVAL;
	}
	if (res > 1 && end != '\n') {
		dev_err(dev, "%s: Extra parameters\n", "__size");
		return -EINVAL;
	}

	write_lock(&fpga->__rwlock);
	fpga->__size = size;
	write_unlock(&fpga->__rwlock);

	return count;
}

static ssize_t __size_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	ssize_t res;

	read_lock(&fpga->__rwlock);
	res = sprintf(buf, "%d\n", fpga->__size);
	read_unlock(&fpga->__rwlock);

	return res;
}
static DEVICE_ATTR(__size, 0600, __size_show, __size_store);

static int fpga_reg_sscanf(union fpga_reg_data *data, int size, const char *buf)
{
	int res;
	char end;

	switch (size) {
	case 1:
		res = sscanf(buf, "0x%hhx%c", &data->byte, &end);
		break;
	case 2:
		res = sscanf(buf, "0x%hx%c", &data->word, &end);
		break;
	case 4:
		res = sscanf(buf, "0x%x%c", &data->dword, &end);
		break;
	case 8:
		res = sscanf(buf, "0x%llx%c", &data->qword, &end);
		break;
	default:
		{
			const char *c = &buf[0];
			int cnt = 0;
			while (cnt < size) {
				res = sscanf(c, "0x%hhx%c", &data->block[cnt++],
					     &end);
				if (res < 1 || res == 1 || end == '\n')
					break;
				if (end != ' ')
					return -2;

				while (*c++ != ' ') ;
			}
			if (res < 1) cnt--;
			return cnt != size ? -1 : 0;
		}
	}

	if (res < 1)
		return -1;
	else if (res > 1 && end != '\n')
		return -2;
	return 0;
}

static ssize_t __reg_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;
	int size;
	union fpga_reg_data data;
	int res;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	size = fpga->__size;
	read_unlock(&fpga->__rwlock);

	res = fpga_reg_sscanf(&data, size, buf);
	if (res < 0) {
		if (res == -1)
			dev_err(dev, "%s: Invalid reg size\n", "__reg");
		else if (res == -2)
			dev_err(dev, "%s: Extra parameters\n", "__reg");
		return -EINVAL;
	}

	res = fpga_reg_xfer(fpga, addr, FPGA_WRITE, size, &data);

	return res ? res : count;
}

static int fpga_reg_print(union fpga_reg_data *data, int size, char *buf)
{
	switch (size) {
	case 1:
		return sprintf(buf, "0x%02hhx\n", data->byte);
	case 2:
		return sprintf(buf, "0x%04hx\n", data->word);
	case 4:
		return sprintf(buf, "0x%08x\n", data->dword);
	case 8:
		return sprintf(buf, "0x%016llx\n", data->qword);
	default:
		{
			int idx = 0, i;
			for (i = 0; i < size; i++)
				idx += sprintf(buf + idx, "0x%02hhx%c",
					       data->block[i],
					       i == size - 1 ? '\n' : ' ');
			return idx;
		}
	}
}

static ssize_t __reg_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;
	int size;
	union fpga_reg_data data;
	ssize_t res;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	size = fpga->__size;
	read_unlock(&fpga->__rwlock);

	res = fpga_reg_xfer(fpga, addr, FPGA_READ, size, &data);
	if (res)
		return res;

	return fpga_reg_print(&data, size, buf);
}
static DEVICE_ATTR(__reg, 0600, __reg_show, __reg_store);

static struct attribute *fpga_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_new_device.attr,
	&dev_attr_delete_device.attr,
	&dev_attr___addr.attr,
	&dev_attr___size.attr,
	&dev_attr___reg.attr,
	NULL,
};
ATTRIBUTE_GROUPS(fpga);

struct device_type fpga_type = {
	.groups = fpga_groups,
	.release = fpga_dev_release,
};
EXPORT_SYMBOL(fpga_type);

struct fpga *fpga_verify(struct device *dev)
{
	return (dev->type == &fpga_type) ? to_fpga(dev) : NULL;
}
EXPORT_SYMBOL(fpga_verify);

static int fpga_register(struct fpga *fpga)
{
	int res = -EINVAL;

	if (WARN_ON(!is_registered)) {
		res = -EAGAIN;
		goto out_err;
	}

	if (WARN(!fpga->name[0], "FPGA has no name"))
		goto out_err;

	if (!fpga->algo) {
		pr_err("FPGA '%s': no algo supplied\n", fpga->name);
		goto out_err;
	}

	mutex_init(&fpga->userspace_ips_lock);
	INIT_LIST_HEAD(&fpga->userspace_ips);
	rwlock_init(&fpga->__rwlock);

	if (fpga->timeout <= 0)
		fpga->timeout = HZ;

	dev_set_name(&fpga->dev, "fpga-%d", fpga->nr);
	fpga->dev.bus = &fpga_bus_type;
	fpga->dev.type = &fpga_type;
	res = device_register(&fpga->dev);
	if (res) {
		pr_err("FPGA '%s': Cannot register device (%d)\n", fpga->name,
		       res);
		goto out_err;
	}

	dev_dbg(&fpga->dev, "FPGA [%s] registered\n", fpga->name);

	pm_runtime_no_callbacks(&fpga->dev);
	pm_suspend_ignore_children(&fpga->dev, true);
	pm_runtime_enable(&fpga->dev);

	of_fpga_register_ips(fpga);

	return 0;

out_err:
	mutex_lock(&core_lock);
	idr_remove(&fpga_idr, fpga->nr);
	mutex_unlock(&core_lock);
	return res;
}

static int __fpga_add_numbered(struct fpga *fpga)
{
	int id;

	mutex_lock(&core_lock);
	id = idr_alloc(&fpga_idr, fpga, fpga->nr, fpga->nr + 1, GFP_KERNEL);
	mutex_unlock(&core_lock);
	if (WARN(id < 0, "Could not get idr"))
		return id == -ENOSPC ? -EBUSY : id;

	return fpga_register(fpga);
}

int fpga_add(struct fpga *fpga)
{
	int id;

	mutex_lock(&core_lock);
	id = idr_alloc(&fpga_idr, fpga, 0, 0, GFP_KERNEL);
	mutex_unlock(&core_lock);
	if (WARN(id < 0, "Could not get idr"))
		return id;

	fpga->nr = id;

	return fpga_register(fpga);
}
EXPORT_SYMBOL(fpga_add);

int fpga_add_numbered(struct fpga *fpga)
{
	if (fpga->nr == -1)
		return fpga_add(fpga);

	return __fpga_add_numbered(fpga);
}
EXPORT_SYMBOL(fpga_add_numbered);

static int __unregister_ip(struct device *dev, void *dummy)
{
	fpga_unregister_ip(fpga_verify_ip(dev));
	return 0;
}

void fpga_del(struct fpga *fpga)
{
	struct fpga *found;
	struct fpga_ip *ip, *next;

	mutex_lock(&core_lock);
	found = idr_find(&fpga_idr, fpga->nr);
	mutex_unlock(&core_lock);
	if (found != fpga) {
		pr_debug("Attempting to delete unregistered FPGA [%s]\n",
			 fpga->name);
		return;
	}

	mutex_lock_nested(&fpga->userspace_ips_lock, fpga_depth(fpga));
	list_for_each_entry_safe(ip, next, &fpga->userspace_ips, detected) {
		dev_dbg(&fpga->dev, "Removing %s at 0x%08llx\n", ip->name,
			fpga_ip_first_addr(ip));
		list_del(&ip->detected);
		fpga_unregister_ip(ip);
	}
	mutex_unlock(&fpga->userspace_ips_lock);

	device_for_each_child(&fpga->dev, NULL, __unregister_ip);

	dev_dbg(&fpga->dev, "FPGA [%s] unregistered\n", fpga->name);

	pm_runtime_disable(&fpga->dev);

	init_completion(&fpga->dev_released);
	device_unregister(&fpga->dev);
	wait_for_completion(&fpga->dev_released);

	mutex_lock(&core_lock);
	idr_remove(&fpga_idr, fpga->nr);
	mutex_unlock(&core_lock);

	memset(&fpga->dev, 0, sizeof fpga->dev);
}
EXPORT_SYMBOL(fpga_del);

int fpga_for_each_dev(void *data, int (*fn)(struct device *dev, void *data))
{
	int res;

	mutex_lock(&core_lock);
	res = bus_for_each_dev(&fpga_bus_type, NULL, data, fn);
	mutex_unlock(&core_lock);

	return res;
}
EXPORT_SYMBOL(fpga_for_each_dev);

int fpga_register_ip_driver(struct module *owner, struct fpga_ip_driver *driver)
{
	int res;

	if (WARN_ON(!is_registered))
		return -EAGAIN;

	driver->driver.owner = owner;
	driver->driver.bus = &fpga_bus_type;
	INIT_LIST_HEAD(&driver->ips);

	res = driver_register(&driver->driver);
	if (res)
		return res;

	pr_debug("Driver [%s] registered\n", driver->driver.name);

	return 0;
}
EXPORT_SYMBOL(fpga_register_ip_driver);

void fpga_del_ip_driver(struct fpga_ip_driver *driver)
{
	driver_unregister(&driver->driver);
	pr_debug("Driver [%s] unregistered\n", driver->driver.name);
}
EXPORT_SYMBOL(fpga_del_ip_driver);

static int __init fpga_core_init(void)
{
	int retval;

	retval = bus_register(&fpga_bus_type);
	if (retval)
		return retval;

	is_registered = true;

	return 0;
}

static void __exit fpga_core_exit(void)
{
	bus_unregister(&fpga_bus_type);
	tracepoint_synchronize_unregister();
}

#ifdef MODULE
module_init(fpga_core_init);
#else
postcore_initcall(fpga_core_init);
#endif
module_exit(fpga_core_exit);

int fpga_reg_xfer_locked(struct fpga *fpga, u64 addr, char rw, int size,
			 union fpga_reg_data *data)
{
	unsigned long orig_jiffies;
	int ret, try;

	if (WARN_ON(!data))
		return -EINVAL;

	orig_jiffies = jiffies;
	for (ret = 0, try = 0; try <= fpga->retries; try++) {
		ret = fpga->algo->reg_xfer(fpga, addr, rw, size, data);

		if (ret != -EAGAIN)
			break;

		if (time_after(jiffies, orig_jiffies + fpga->timeout))
			break;
	}

	return ret;
}
EXPORT_SYMBOL(fpga_reg_xfer_locked);

int fpga_reg_xfer(struct fpga *fpga, u64 addr, char rw, int size,
		  union fpga_reg_data *data)
{
	return fpga_reg_xfer_locked(fpga, addr, rw, size, data);
}
EXPORT_SYMBOL(fpga_reg_xfer);

#define FPGA_REG_READ(size, type, _size)				\
int fpga_reg_read_ ## size (const struct fpga_ip *ip,			\
			    int index, u64 where, type *value)		\
{									\
	union fpga_reg_data data;					\
	u64 addr;							\
	int ret;							\
	addr = ip->resources[index].start + where;			\
	ret = fpga_reg_xfer(ip->fpga, addr, FPGA_READ, _size, &data);	\
	if (ret)							\
		return ret;						\
	*value = data.size;						\
	return 0;							\
}									\
EXPORT_SYMBOL(fpga_reg_read_ ## size)

#define FPGA_REG_WRITE(size, type, _size)				\
int fpga_reg_write_ ## size (const struct fpga_ip *ip,			\
			     int index, u64 where, type value)		\
{									\
	union fpga_reg_data data;					\
	u64 addr;							\
	addr = ip->resources[index].start + where;			\
	data.size = value;						\
	return fpga_reg_xfer(ip->fpga, addr, FPGA_WRITE, _size, &data);	\
}									\
EXPORT_SYMBOL(fpga_reg_write_ ## size);

FPGA_REG_READ(byte, u8, 1);
FPGA_REG_WRITE(byte, u8, 1);
FPGA_REG_READ(word, u16, 2);
FPGA_REG_WRITE(word, u16, 2);
FPGA_REG_READ(dword, u32, 4);
FPGA_REG_WRITE(dword, u32, 4);
FPGA_REG_READ(qword, u64, 8);
FPGA_REG_WRITE(qword, u64, 8);

int fpga_reg_read_block(const struct fpga_ip *ip, int index, u64 where,
			int size, u8 *value)
{
	union fpga_reg_data data;
	u64 addr;
	int ret;

	addr = ip->resources[index].start + where;

	ret = fpga_reg_xfer(ip->fpga, addr, FPGA_READ, size, &data);
	if (ret)
		return ret;

	memcpy(value, data.block, size);
	return 0;
}
EXPORT_SYMBOL(fpga_reg_read_block);

int fpga_reg_write_block(const struct fpga_ip *ip, int index, u64 where,
			 int size, u8 *value)
{
	union fpga_reg_data data;
	u64 addr;

	addr = ip->resources[index].start + where;
	memcpy(data.block, value, size);

	return fpga_reg_xfer(ip->fpga, addr, FPGA_WRITE, size, &data);
}
EXPORT_SYMBOL(fpga_reg_write_block);

struct fpga *fpga_get(int nr)
{
	struct fpga *fpga;

	mutex_lock(&core_lock);
	fpga = idr_find(&fpga_idr, nr);
	if (!fpga)
		goto exit;

	if (try_module_get(fpga->owner))
		get_device(&fpga->dev);
	else
		fpga = NULL;

exit:
	mutex_unlock(&core_lock);
	return fpga;
}
EXPORT_SYMBOL(fpga_get);

void fpga_put(struct fpga *fpga)
{
	if (!fpga)
		return;
	put_device(&fpga->dev);
	module_put(fpga->owner);
}
EXPORT_SYMBOL(fpga_put);

MODULE_AUTHOR("IriKa <qiujie@semptian.com>");
MODULE_DESCRIPTION("Semptian FPGA/CPLD driver framework");
MODULE_LICENSE("GPL");
MODULE_ALIAS("fpga-core");
MODULE_VERSION(CONFIG_FPGA_CORE_VERSION);
