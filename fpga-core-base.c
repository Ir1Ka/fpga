/**
 * fpga-core-base.c - implements for the FPGA/CPLD driver framework
 *
 * Copyright (C) 2020 IriKa <qiujie.jq@gmail.com>
 */

#define pr_fmt(fmt)	"fpga-core: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/pm_runtime.h>
#include <linux/tracepoint.h>

#include <fpga.h>
#include <fpga-region.h>

#include "fpga-core.h"

static bool reg_access_enabled = false;
module_param(reg_access_enabled, bool, S_IRUGO);
MODULE_PARM_DESC(reg_access_enabled, "Enable FPGA register access from sysfs. "
				     "Default disable.");

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

	if (driver->probe)
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
	int i = 0;
	struct fpga_ip *ip = to_fpga_ip(dev);

	while (i < ip->num_resources)
		release_resource(&ip->resources[i++].resource);

	kfree(ip);
}

static ssize_t
name_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", dev->type == &fpga_ip_type ?
		       to_fpga_ip(dev)->name : to_fpga(dev)->name);
}
static DEVICE_ATTR(name, S_IRUGO, name_show, NULL);

static ssize_t resource_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga *fpga;
	struct fpga_ip *ip;
	const struct fpga_resource *res = NULL;
	unsigned int max = 0;
	unsigned int i;
	int idx = 0;

	fpga = fpga_verify(dev);
	ip = fpga_verify_ip(dev);

	if (fpga) {
		res = &fpga->resource;
		max = 1;
	} else if (ip) {
		res = ip->resources;
		max = ip->num_resources;
	}

	if (!res || !max)
		return -ENODEV;

	for (i = 0; i < max; i++)
		idx += snprintf(buf + idx, PAGE_SIZE - idx, "0x%016llx 0x%016llx 0x%016llx\n",
				(unsigned long long)res[i].resource.start,
				(unsigned long long)res[i].resource.end,
				(unsigned long long)res[i].resource.flags);

	return idx;
}
static DEVICE_ATTR(resource, S_IRUGO, resource_show, NULL);

static ssize_t
modalias_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga_ip *ip = to_fpga_ip(dev);

	return sprintf(buf, "%s%s\n", FPGA_IP_MODULE_PREFIX, ip->name);
}
static DEVICE_ATTR(modalias, S_IRUGO, modalias_show, NULL);

static void remove_callback(struct device *dev)
{
	struct fpga_ip *ip = to_fpga_ip(dev);
	struct fpga *fpga = ip->fpga;
	struct fpga_ip *cur, *next;
	int res;

	res = -ENOENT;
	mutex_lock_nested(&fpga->userspace_ips_lock, fpga_depth(fpga));
	list_for_each_entry_safe(cur, next, &fpga->userspace_ips, detected) {
		/* The register addr is based on its FPGA. */
		if (ip == cur) {
			dev_info(dev, "%s: Deleting device %s at 0x%08llx\n",
				 "remove", ip->name,
				 fpga_ip_first_addr(ip));
			list_del(&ip->detected);
			fpga_unregister_ip(ip);
			res = 0;
			break;
		}
	}
	mutex_unlock(&fpga->userspace_ips_lock);

	if (res < 0)
		dev_err(dev, "%s: Cannot find device in list\n",
			"remove");
}

static ssize_t remove_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	unsigned long val;
	int res;

	res = strict_strtoul(buf, 0, &val);
	if (res)
		return res;

	if (!val)
		return count;

	res = device_schedule_callback(dev, remove_callback);

	return res ? res : count;
}
static DEVICE_ATTR(remove, S_IWUSR, NULL, remove_store);

static struct attribute *fpga_ip_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_modalias.attr,
	&dev_attr_remove.attr,
	&dev_attr_resource.attr,
	NULL,
};
static const struct attribute_group fpga_ip_group = {
	.attrs = fpga_ip_attrs,
};
static const struct attribute_group *fpga_ip_groups[] = {
	&fpga_ip_group,
	NULL,
};

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

static void fpga_ip_set_name(struct fpga *fpga, struct fpga_ip *ip,
			     struct fpga_ip_info const *info)
{
	if (info && info->dev_name) {
		dev_set_name(&ip->dev, "%s", info->dev_name);
		return;
	}

	dev_set_name(&ip->dev, "%d-%08llx", fpga_id(fpga),
		     fpga_ip_first_addr(ip) - fpga_addr(fpga));
}

struct fpga_ip_info *fpga_alloc_ip_info(const char *type, unsigned int num_resources, gfp_t flags)
{
	struct fpga_ip_info *info;

	info = kzalloc(sizeof(*info) + num_resources * sizeof(info->resources[0]), flags);
	if (unlikely(!info))
		return NULL;
	info->num_resources = num_resources;

	if (type && type[0])
		snprintf(info->type, sizeof(info->type), "%s", type);

	return info;
}
EXPORT_SYMBOL(fpga_alloc_ip_info);

void fpga_free_ip_info(struct fpga_ip_info *info)
{
	kfree(info);
}
EXPORT_SYMBOL(fpga_free_ip_info);

struct fpga_ip *
__fpga_new_ip(struct fpga *fpga, struct fpga_ip_info const *info)
{
	struct fpga_ip *ip;
	u32 functionality = fpga_get_functionality(fpga);
	int aligned;
	unsigned int num_resources = info->num_resources;
	int i;
	int status;

	if (!fpga || !info)
		return ERR_PTR(-EINVAL);

	if (num_resources <= 0) {
		dev_err(&fpga->dev, "At least 1 resource\n");
		return ERR_PTR(-EINVAL);
	}

	if (functionality & FPGA_FUNC_BYTE)
		aligned = 0x0;
	else if (functionality & FPGA_FUNC_WORD)
		aligned = 0x1;
	else if (functionality & FPGA_FUNC_DWORD)
		aligned = 0x3;
	else if (functionality & FPGA_FUNC_QWORD)
		aligned = 0x7;
	/* BLOCK */
	else
		aligned = 0x0;

	for (i = 0; i < num_resources; i++) {
		if (info->resources[i].resource.end < info->resources[i].resource.start) {
			dev_err(&fpga->dev, "Invalid resource\n");
			return ERR_PTR(-EINVAL);
		}

		if ((info->resources[i].resource.start & aligned) ||
		    (resource_size((struct resource *)&info->resources[i].resource) & aligned)) {
			dev_err(&fpga->dev, "resources are not aligned\n");
			return ERR_PTR(-EINVAL);
		}
	}

	ip = kzalloc(sizeof *ip + sizeof info->resources[0] * num_resources,
		     GFP_KERNEL);
	if (!ip)
		return ERR_PTR(-ENOMEM);

	ip->fpga = fpga;
	ip->dev.platform_data = info->platform_data;

	if (info->type[0])
		strlcpy(ip->name, info->type, sizeof ip->name);
	else
		strlcpy(ip->name, "dummy-ip", sizeof ip->name);

	ip->num_resources = num_resources;
	memcpy(&ip->resources, info->resources,
	       ip->num_resources * sizeof info->resources[0]);

	while (num_resources > 0) {
		struct fpga_resource *resource = &ip->resources[num_resources - 1];

		resource->resource.flags = fpga->resource.resource.flags;
		status = request_resource(&fpga->resource.resource, &resource->resource);
		if (status) {
			dev_err(&fpga->dev, "Invalid register resource "
					    "0x%08llx - 0x%08llx\n",
				resource->resource.start, resource->resource.end);
			goto out_err_remove_resource;
		}
		num_resources--;

		if (fpga->resource.vp) {
			resource_size_t offset;

			offset = fpga->resource.resource.start - resource->resource.start;
			resource->vp = fpga->resource.vp + offset;
		}
	}

	ip->dev.parent = &ip->fpga->dev;
	ip->dev.bus = &fpga_bus_type;
	ip->dev.type = &fpga_ip_type;
	ip->dev.of_node = of_node_get(info->of_node);

	fpga_ip_set_name(fpga, ip, info);

	status = device_register(&ip->dev);
	if (status)
		goto out_err_put_of_node;

	dev_dbg(&fpga->dev, "FPGA IP [%s] registered with bus id %s\n",
		ip->name, dev_name(&ip->dev));

	return ip;

out_err_put_of_node:
	of_node_put(info->of_node);

	dev_err(&fpga->dev, "Failed to register FPGA IP %s at 0x%08llx (%d)\n",
		ip->name, fpga_ip_first_addr(ip), status);

	num_resources = 0;
out_err_remove_resource:
	while (num_resources < ip->num_resources)
		release_resource(&ip->resources[num_resources++].resource);
	kfree(ip);
	return ERR_PTR(status);
}
EXPORT_SYMBOL(__fpga_new_ip);

void fpga_unregister_ip(struct fpga_ip *ip)
{
	if (unlikely(!ip) || IS_ERR(ip))
		return;

	of_node_put(ip->dev.of_node);

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

/* format: "<ip-name> <r0>,<r0_size>[[:<r1>,<r1_size>]...]" */
static int fpga_get_ip_info_from_str(struct fpga *fpga,
				     const char *buf, struct fpga_ip_info **infop)
{
	struct fpga_ip_info *info;
	unsigned int num_resources;
	struct fpga_resource *r;
	char type[sizeof(info->type)];
	const char *blank, *comma, *colon;
	char tmp[32];
	int len;
	int res;

	blank = strchr(buf, ' ');
	if (!blank)
		return -EINVAL;
	if (blank - buf > FPGA_IP_NAME_SIZE - 1)
		return -EINVAL;
	len = blank - buf;
	snprintf(type, sizeof(type), "%*.*s", len, len, buf);

	num_resources = 0;
	for (comma = blank + 1; (comma = strchr(comma, ',')); comma++)
		num_resources++;

	info = fpga_alloc_ip_info(type, num_resources, GFP_KERNEL);
	if (unlikely(!info))
		return -ENOMEM;

	for (r = &info->resources[0], colon = blank; colon; r++) {
		resource_size_t size;

		colon++;
		comma = strchr(colon, ',');
		if (!comma) {
			res = -EINVAL;
			goto err_out;
		}
		len = comma - colon;
		snprintf(tmp, sizeof tmp, "%*.*s", len, len, colon);
		res = strict_strtoull(tmp, 0, &r->resource.start);
		if (res)
			goto err_out;

		comma++;
		colon = strchr(comma, ':');
		if (!colon)
			/* If no colon, use whole remain string. */
			len = strlen(comma);
		else
			len = colon - comma;
		snprintf(tmp, sizeof tmp, "%*.*s", len, len, comma);
		res = strict_strtoull(tmp, 0, &size);
		if (res)
			goto err_out;

		/* The register addr is based on its FPGA. */
		r->resource.start += fpga_addr(fpga);
		r->resource.end = r->resource.start + size - 1;
	}

	*infop = info;

	return 0;

err_out:
	fpga_free_ip_info(info);
	return  res;
}

/**
 * echo <IP info string> > /sys/bus/fpga/fpga-0/new_ip
 *
 * The <IP info string> refer ``fpga_get_ip_info_from_str``.
 */
static ssize_t new_ip_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	struct fpga_ip_info *info = NULL;
	struct fpga_ip *ip;
	int res;

	res = fpga_get_ip_info_from_str(fpga, buf, &info);
	if (res)
		goto out;

	ip = __fpga_new_ip(fpga, info);
	if (IS_ERR(ip)) {
		res = PTR_ERR(ip);
		goto out;
	}

	mutex_lock(&fpga->userspace_ips_lock);
	list_add_tail(&ip->detected, &fpga->userspace_ips);
	mutex_unlock(&fpga->userspace_ips_lock);

	dev_info(dev, "%s: Instantiated device %s at 0x%08llx\n", "new_ip",
		 info->type, fpga_ip_first_addr(ip));

out:
	if (info)
		fpga_free_ip_info(info);
	return res ? res : count;
}
static DEVICE_ATTR(new_ip, S_IWUSR, NULL, new_ip_store);

static ssize_t
delete_ip_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	struct fpga_ip *ip, *next;
	resource_size_t first_addr;
	int res;

	res = strict_strtoull(buf, 0, &first_addr);
	if (res)
		return res;

	res = -ENOENT;
	mutex_lock_nested(&fpga->userspace_ips_lock, fpga_depth(fpga));
	list_for_each_entry_safe(ip, next, &fpga->userspace_ips, detected) {
		resource_size_t _first_addr;
		/* The register addr is based on its FPGA. */
		_first_addr = fpga_ip_first_addr(ip) - fpga_addr(fpga);
		if (_first_addr == first_addr) {
			dev_info(dev, "%s: Deleting device %s at 0x%08llx\n",
				 "delete_ip", ip->name,
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
			"delete_ip");
	return res;
}
static DEVICE_ATTR(delete_ip, S_IWUSR, NULL, delete_ip_store);

static struct attribute *fpga_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_new_ip.attr,
	&dev_attr_delete_ip.attr,
	&dev_attr_resource.attr,
	NULL,
};
static const struct attribute_group fpga_group = {
	.attrs = fpga_attrs,
};
static const struct attribute_group *fpga_groups[] = {
	&fpga_group,
	NULL,
};

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

static ssize_t addr_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;
	int res;

	res = strict_strtoull(buf, 0, &addr);
	if (res)
		return res;

	addr += fpga_addr(fpga);

	if (is_valid_fpga_addr(&fpga->resource, addr, 1)) {
		dev_err(dev, "%s: The addr is too large\n", "__addr");
		return -EINVAL;
	}

	write_lock(&fpga->__rwlock);
	fpga->__addr = addr;
	write_unlock(&fpga->__rwlock);

	return count;
}

static ssize_t addr_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	read_unlock(&fpga->__rwlock);

	return sprintf(buf, "0x%08llx\n", addr - fpga_addr(fpga));
}
static DEVICE_ATTR(addr, 0600, addr_show, addr_store);

static inline int fpga_strtoreg(union fpga_reg_data *reg, int size, const char *buf)
{
	unsigned long long val;
	int res;

	res = strict_strtoull(buf, 0, &val);
	if (res)
		return res;

	switch (size) {
	case 1:
		reg->byte = val;
		break;
	case 2:
		reg->word = val;
		break;
	case 4:
		reg->dword = val;
		break;
	case 8:
		reg->qword = val;
		break;
	default:
		return -EIO;
	}

	return 0;
}

static inline int fpga_reg_print(union fpga_reg_data *reg, int size, char *buf)
{
	switch (size) {
	case 1:
		return sprintf(buf, "0x%02hhx\n", reg->byte);
	case 2:
		return sprintf(buf, "0x%04hx\n", reg->word);
	case 4:
		return sprintf(buf, "0x%08x\n", reg->dword);
	case 8:
		return sprintf(buf, "0x%016llx\n", reg->qword);
	default:
		return -EIO;
	}
}

static int fpga_reg_store(struct fpga *fpga, int size, const char *buf, size_t count)
{
	u64 addr;
	union fpga_reg_data reg;
	ssize_t res;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	read_unlock(&fpga->__rwlock);

	res = fpga_strtoreg(&reg, size, buf);
	if (res)
		return res;

	res = fpga_reg_xfer(fpga, addr, FPGA_WRITE, size, &reg);

	return res ? res : count;
}

static int fpga_reg_show(struct fpga *fpga, int size, char *buf)
{
	u64 addr;
	union fpga_reg_data reg;
	ssize_t res;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	read_unlock(&fpga->__rwlock);

	res = fpga_reg_xfer(fpga, addr, FPGA_READ, size, &reg);
	if (res)
		return res;

	return fpga_reg_print(&reg, size, buf);
}

#define FPGA_REG_ATTR(type)						\
static ssize_t type ## _store(struct device *dev,			\
			      struct device_attribute *attr,		\
			      const char *buf, size_t count)		\
{									\
	return fpga_reg_store(to_fpga(dev), sizeof(type), buf, count);	\
}									\
static ssize_t type ## _show(struct device *dev,			\
			     struct device_attribute *attr,		\
			     char *buf)					\
{									\
	return fpga_reg_show(to_fpga(dev), sizeof(type), buf);		\
}									\
static DEVICE_ATTR(type, 0600, type ## _show, type ## _store)		\

FPGA_REG_ATTR(byte);
FPGA_REG_ATTR(word);
FPGA_REG_ATTR(dword);
FPGA_REG_ATTR(qword);

static ssize_t block_size_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	unsigned long size;
	int res;

	res = strict_strtoul(buf, 0, &size);
	if (res)
		return res;

	if (!size || size > FPGA_BLOCK_SIZE_MAX)
		return -EINVAL;

	write_lock(&fpga->__rwlock);
	fpga->__block_size = size;
	write_unlock(&fpga->__rwlock);

	return count;
}

static ssize_t block_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	unsigned int size;

	read_lock(&fpga->__rwlock);
	size = fpga->__block_size;
	read_unlock(&fpga->__rwlock);

	return sprintf(buf, "%u\n", size);
}
static DEVICE_ATTR(block_size, 0600, block_size_show, block_size_store);

static int fpga_strtoblock(u8 *block, int size, const char *buf)
{
	unsigned long val;
	const char *blank, *blank_n;
	int i;
	char tmp[16];
	int len;
	int res;

	for (blank = buf - 1, i = 0; blank && i < size; blank = blank_n, i++) {
		blank++;
		blank_n = strchr(blank, ' ');
		if (!blank_n)
			len = strlen(blank);
		else
			len = blank_n - blank;
		snprintf(tmp, sizeof tmp, "%*.*s", len, len, blank);
		res = strict_strtoul(tmp, 0, &val);
		if (res)
			return res;
		block[i] = val;
	}

	return blank || i != size ? -EINVAL : 0;
}

static ssize_t block_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;
	int block_size;
	u8 block[FPGA_BLOCK_SIZE_MAX];
	int res;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	block_size = fpga->__block_size;
	read_unlock(&fpga->__rwlock);

	if (block_size <= 0 || block_size > ARRAY_SIZE(block))
		return -EIO;

	res = fpga_strtoblock(block, block_size, buf);
	if (res)
		return res;

	res = fpga_block_xfer(fpga, addr, FPGA_WRITE, block_size, block);
	if (res < 0)
		return res;

	return res != block_size ? -EIO : count;
}

static int fpga_block_print(u8 *block, int size, char *buf)
{
	int idx = 0, i;
	for (i = 0; i < size; i++)
		idx += sprintf(buf + idx, "0x%02hhx%c", block[i],
			       i == size - 1 ? '\n' : ' ');
	return idx;
}

static ssize_t block_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	u64 addr;
	int block_size;
	u8 block[FPGA_BLOCK_SIZE_MAX];
	ssize_t res;

	read_lock(&fpga->__rwlock);
	addr = fpga->__addr;
	block_size = fpga->__block_size;
	read_unlock(&fpga->__rwlock);

	if (block_size <= 0 || block_size > ARRAY_SIZE(block))
		return -EIO;

	res = fpga_block_xfer(fpga, addr, FPGA_READ, block_size, block);
	if (res < 0)
		return res;
	else if (res != block_size)
		return -EIO;

	return fpga_block_print(block, block_size, buf);
}
static DEVICE_ATTR(block, 0600, block_show, block_store);

static struct attribute *fpga_reg_access_attrs[] = {
	&dev_attr_addr.attr,
	&dev_attr_byte.attr,
	&dev_attr_word.attr,
	&dev_attr_dword.attr,
	&dev_attr_qword.attr,
	&dev_attr_block_size.attr,
	&dev_attr_block.attr,
	NULL,
};
static const struct attribute_group fpga_reg_access_group = {
	.attrs = fpga_reg_access_attrs,
};

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
		pr_err("FPGA '%s': No algo supplied\n", fpga->name);
		goto out_err;
	}

	if (!fpga->algo->reg_xfer || !fpga->algo->functionality) {
		pr_err("FPGA '%s': Invalid algo supplied\n", fpga->name);
		goto out_err;
	}

	mutex_init(&fpga->userspace_ips_lock);
	INIT_LIST_HEAD(&fpga->userspace_ips);

	fpga->__addr = fpga_addr(fpga);
	fpga->__block_size = 0;
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

	if (reg_access_enabled) {
		res = sysfs_create_group(&fpga->dev.kobj, &fpga_reg_access_group);
		if (res) {
			pr_err("FPGA '%s': Cannot create reg access attributes "
			       "(%d)\n", fpga->name, res);
			goto out_err_unregister_fpga;
		}
	}

	dev_dbg(&fpga->dev, "FPGA [%s] registered\n", fpga->name);

	pm_suspend_ignore_children(&fpga->dev, true);
	pm_runtime_enable(&fpga->dev);

	of_fpga_register_ips(fpga);

	return 0;

out_err_unregister_fpga:
	init_completion(&fpga->dev_released);
	device_unregister(&fpga->dev);
	wait_for_completion(&fpga->dev_released);
out_err:
	mutex_lock(&core_lock);
	idr_remove(&fpga_idr, fpga->nr);
	mutex_unlock(&core_lock);
	return res;
}

static int __fpga_add_numbered(struct fpga *fpga)
{
	int id;
	int res;

	if (idr_pre_get(&fpga_idr, GFP_KERNEL) == 0)
		return -ENOMEM;

	mutex_lock(&core_lock);
	res = idr_get_new_above(&fpga_idr, fpga, fpga->nr, &id);
	if (!res && id != fpga->nr) {
		res = -EBUSY;
		idr_remove(&fpga_idr, id);
	}
	mutex_unlock(&core_lock);
	if (WARN(res, "Could not get idr"))
		return res == -ENOSPC ? -EBUSY : res;

	return fpga_register(fpga);
}

int fpga_add(struct fpga *fpga)
{
	int id;
	int res;

	if (idr_pre_get(&fpga_idr, GFP_KERNEL) == 0)
		return -ENOMEM;

	mutex_lock(&core_lock);
	res = idr_get_new(&fpga_idr, fpga, &id);
	mutex_unlock(&core_lock);
	if (WARN(res < 0, "Could not get idr"))
		return res;

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

	if (reg_access_enabled)
		sysfs_remove_group(&fpga->dev.kobj, &fpga_reg_access_group);

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

static const struct fpga_ip_id dummy_ip_id_table[] =
{
	{ .name = "dummy-ip", },
	{},
};

static int dummy_ip_probe(struct fpga_ip *ip, const struct fpga_ip_id *id)
{
	int i;

	for (i = 0; i < ip->num_resources; i++)
		dev_dbg(&ip->dev, "[%d]: 0x%08llx ~ 0x%08llx\n", i,
			ip->resources[i].resource.start, ip->resources[i].resource.end);

	dev_dbg(&ip->dev, "%s probe\n", ip->name);
	return 0;
}

static int dummy_ip_remove(struct fpga_ip *ip)
{
	dev_dbg(&ip->dev, "%s remove\n", ip->name);
	return 0;
}

static  struct fpga_ip_driver dummy_ip_driver = {
	.id_table = dummy_ip_id_table,
	.probe = dummy_ip_probe,
	.remove = dummy_ip_remove,
	.driver = {
		.name = "dummy-ip",
	},
};

static int __init fpga_core_init(void)
{
	int retval;

	retval = bus_register(&fpga_bus_type);
	if (retval)
		return retval;

	is_registered = true;

	retval = fpga_add_ip_driver(&dummy_ip_driver);
	if (retval)
		goto unregister_bus;

	retval = fpga_dev_init();
	if (retval)
		goto del_dummy_ip_driver;

	return 0;

del_dummy_ip_driver:
	fpga_del_ip_driver(&dummy_ip_driver);
unregister_bus:
	bus_unregister(&fpga_bus_type);
	return retval;
}

static void __exit fpga_core_exit(void)
{
	fpga_dev_exit();
	fpga_del_ip_driver(&dummy_ip_driver);
	bus_unregister(&fpga_bus_type);
	tracepoint_synchronize_unregister();
}

#ifdef MODULE
module_init(fpga_core_init);
#else
postcore_initcall(fpga_core_init);
#endif
module_exit(fpga_core_exit);

static int fpga_reg_check_functionality(struct fpga *fpga, char rw, int size)
{
	u32 functionality;

	switch (size) {
	case 1:
		if (rw == FPGA_READ)
			functionality = FPGA_FUNC_READ_BYTE;
		else
			functionality = FPGA_FUNC_WRITE_BYTE;
		break;
	case 2:
		if (rw == FPGA_READ)
			functionality = FPGA_FUNC_READ_WORD;
		else
			functionality = FPGA_FUNC_WRITE_WORD;
		break;
	case 4:
		if (rw == FPGA_READ)
			functionality = FPGA_FUNC_READ_DWORD;
		else
			functionality = FPGA_FUNC_WRITE_DWORD;
		break;
	case 8:
		if (rw == FPGA_READ)
			functionality = FPGA_FUNC_READ_QWORD;
		else
			functionality = FPGA_FUNC_WRITE_QWORD;
		break;
	default:
		return -EIO;
	}

	return fpga_check_functionality(fpga, functionality) ? 0 : -EIO;
}

int fpga_reg_xfer_locked(struct fpga *fpga, u64 addr, char rw, int size,
			 union fpga_reg_data *reg)
{
	unsigned long orig_jiffies;
	int ret, try;
	struct fpga_resource *r = &fpga->resource;

	ret = fpga_reg_check_functionality(fpga, rw, size);
	if (unlikely(ret))
		return ret;

	if (WARN_ON(is_valid_fpga_addr(r, addr, size)))
		return -EFAULT;

	if (WARN_ON(!reg))
		return -EINVAL;

	orig_jiffies = jiffies;
	for (ret = 0, try = 0; try <= fpga->retries; try++) {
		ret = fpga->algo->reg_xfer(fpga, addr, rw, size, reg);

		if (ret != -EAGAIN)
			break;

		if (time_after(jiffies, orig_jiffies + fpga->timeout))
			break;
	}

	return ret;
}
EXPORT_SYMBOL(fpga_reg_xfer_locked);

int fpga_reg_xfer(struct fpga *fpga, u64 addr, char rw, int size,
		  union fpga_reg_data *reg)
{
	return fpga_reg_xfer_locked(fpga, addr, rw, size, reg);
}
EXPORT_SYMBOL(fpga_reg_xfer);

static int fpga_block_check_functionality(struct fpga *fpga, char rw, int size)
{
	u32 functionality;

	if (size <= 0 || size > FPGA_BLOCK_SIZE_MAX)
		return -EIO;

	if (rw == FPGA_READ)
		functionality = FPGA_FUNC_READ_BLOCK;
	else
		functionality = FPGA_FUNC_WRITE_BLOCK;

	return fpga_check_functionality(fpga, functionality) ? 0 : -EIO;
}

int fpga_block_xfer_locked(struct fpga *fpga, u64 addr, char rw, int size,
			   u8 *block)
{
	unsigned long orig_jiffies;
	int ret, try;
	struct fpga_resource *r = &fpga->resource;

	ret = fpga_block_check_functionality(fpga, rw, size);
	if (unlikely(ret))
		return ret;

	if (WARN_ON(is_valid_fpga_addr(r, addr, 1)))
		return -EIO;

	if (WARN_ON(!block))
		return -EINVAL;

	if (WARN_ON(!fpga->algo->block_xfer))
		return -EIO;

	orig_jiffies = jiffies;
	for (ret = 0, try = 0; try <= fpga->retries; try++) {
		ret = fpga->algo->block_xfer(fpga, addr, rw, size, block);

		if (ret != -EAGAIN)
			break;

		if (time_after(jiffies, orig_jiffies + fpga->timeout))
			break;
	}

	return ret;
}
EXPORT_SYMBOL(fpga_block_xfer_locked);

int fpga_block_xfer(struct fpga *fpga, u64 addr, char rw, int size, u8 *block)
{
	return fpga_block_xfer_locked(fpga, addr, rw, size, block);
}
EXPORT_SYMBOL(fpga_block_xfer);

int fpga_reg_read(const struct fpga_ip *ip, int size, int index, u64 where,
		  union fpga_reg_data *reg)
{
	u64 addr;

	addr = ip->resources[index].resource.start + where;
	if (unlikely(is_valid_fpga_addr(&ip->resources[index], addr, size)))
		return -EFAULT;

	return fpga_reg_xfer(ip->fpga, addr, FPGA_READ, size, reg);
}

int fpga_reg_write(const struct fpga_ip *ip, int size, int index, u64 where,
		   union fpga_reg_data reg)
{
	u64 addr;

	addr = ip->resources[index].resource.start + where;
	if (unlikely(is_valid_fpga_addr(&ip->resources[index], addr, size)))
		return -EFAULT;

	return fpga_reg_xfer(ip->fpga, addr, FPGA_WRITE, size, &reg);
}

#define FPGA_REG_RW(type)						\
int fpga_reg_read_ ## type (const struct fpga_ip *ip,			\
			    int index, u64 where, type *value)		\
{									\
	union fpga_reg_data reg;					\
	int ret;							\
	ret = fpga_reg_read(ip, sizeof(type), index, where, &reg);	\
	if (ret) return ret;						\
	*value = reg.type;						\
	return 0;							\
}									\
EXPORT_SYMBOL(fpga_reg_read_ ## type);					\
int fpga_reg_write_ ## type (const struct fpga_ip *ip,			\
			     int index, u64 where, type value)		\
{									\
	union fpga_reg_data reg = { .type = value };			\
	return fpga_reg_write(ip, sizeof(type), index, where, reg);	\
}									\
EXPORT_SYMBOL(fpga_reg_write_ ## type)

FPGA_REG_RW(byte);
FPGA_REG_RW(word);
FPGA_REG_RW(dword);
FPGA_REG_RW(qword);

int fpga_read_block(const struct fpga_ip *ip, int index, u64 where, int size,
		    u8 *value)
{
	u64 addr;

	addr = ip->resources[index].resource.start + where;

	return fpga_block_xfer(ip->fpga, addr, FPGA_READ, size, value);
}
EXPORT_SYMBOL(fpga_read_block);

int fpga_write_block(const struct fpga_ip *ip, int index, u64 where,  int size,
		     u8 *value)
{
	u64 addr;

	addr = ip->resources[index].resource.start + where;

	return fpga_block_xfer(ip->fpga, addr, FPGA_WRITE, size, value);
}
EXPORT_SYMBOL(fpga_write_block);

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

/* For Overflow, such as 8(u8), 16(u16), 32(u32), 64(u64) */
#define REG_BITS_MASK(_reg, _bits)					\
	((((typeof(_reg))0x1 << (_bits - 1)) << 1) - 1)

#define REG_BITS_SET(_reg, _req, _off, _bits, _flip)			\
({									\
	typeof(_off) __off = _off;					\
	typeof(_reg) __reg = _reg;					\
	typeof(_req) __req = (_req) << __off;				\
	typeof(_bits) __bits = _bits;					\
	typeof(_flip) __flip = _flip;					\
	typeof(_reg) __mask = REG_BITS_MASK(__reg, __bits) << __off;	\
	if (__flip) __req = ~__req;					\
	__req &= __mask;						\
	__reg &= ~__mask;						\
	__reg |= __req;							\
	__reg;								\
 })

#define REG_BITS_OVERFLOW(_reg, _bits)					\
	(_reg > REG_BITS_MASK(_reg, _bits))

ssize_t bits_attr_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	struct fpga *fpga = to_fpga(dev);
	struct bits_attribute *bits_attr = to_bits_attr(attr);
	u16 off = bits_attr->off;
	u16 bits = bits_attr->bits;
	bool flip = bits_attr->flip;
	u64 where = bits_attr->where;
	int size = bits_attr->size;
	union fpga_reg_data reg, req;
	unsigned long long t;
	int res;

	if (unlikely(!bits ||
		     off >= size * 8 ||
		     off + bits > size * 8))
		return -EIO;

	res = fpga_reg_xfer(fpga, where, FPGA_READ, size, &reg);
	if (unlikely(res))
		return res;

	res = strict_strtoull(buf, 0, &t);
	if (res)
		return res;
	if (REG_BITS_OVERFLOW(t, bits))
		return -EINVAL;

	switch (size) {
	case 1:
		req.byte = t;
		reg.byte = REG_BITS_SET(reg.byte, req.byte, off, bits, flip);
		break;
	case 2:
		req.word = t;
		reg.word = REG_BITS_SET(reg.word, req.word, off, bits, flip);
		break;
	case 4:
		req.dword = t;
		reg.dword = REG_BITS_SET(reg.dword, req.dword, off, bits, flip);
		break;
	case 8:
		req.qword = t;
		reg.qword = REG_BITS_SET(reg.qword, req.qword, off, bits, flip);
		break;
	default:
		return -EIO;
	}

	res = fpga_reg_xfer(fpga, where, FPGA_WRITE, size, &reg);
	return res ? res : count;
}
EXPORT_SYMBOL(bits_attr_store);

#define REG_BITS_GET(_reg, _off, _bits, _flip)				\
({									\
	typeof(_off) __off = _off;					\
	typeof(_reg) __reg = (_reg) >> __off;				\
	typeof(_bits) __bits = _bits;					\
	typeof(_flip) __flip = _flip;					\
	typeof(_reg) __mask = REG_BITS_MASK(__reg, __bits);		\
	if (__flip) __reg = ~__reg;					\
	__reg &= __mask;						\
	__reg;								\
 })

ssize_t bits_attr_show(struct device *dev, struct device_attribute *attr,
		       char *buf)
{
	struct fpga *fpga = to_fpga(dev);
	struct bits_attribute *bits_attr = to_bits_attr(attr);
	u16 off = bits_attr->off;
	u16 bits = bits_attr->bits;
	bool flip = bits_attr->flip;
	u64 where = bits_attr->where;
	int size = bits_attr->size;
	union fpga_reg_data reg;
	int res;

	if (unlikely(!bits ||
		     off >= size * 8 ||
		     off + bits > size * 8))
		return -EIO;

	res = fpga_reg_xfer(fpga, where, FPGA_READ, size, &reg);
	if (unlikely(res))
		return res;

	switch (size) {
	case 1:
		reg.byte = REG_BITS_GET(reg.byte, off, bits, flip);
		return sprintf(buf, "0x%0*hhx\n", (bits - 1) / 4 + 1, reg.byte);
	case 2:
		reg.word = REG_BITS_GET(reg.word, off, bits, flip);
		return sprintf(buf, "0x%0*hx\n", (bits - 1) / 4 + 1, reg.word);
	case 4:
		reg.dword = REG_BITS_GET(reg.dword, off, bits, flip);
		return sprintf(buf, "0x%0*x\n", (bits - 1) / 4 + 1, reg.dword);
	case 8:
		reg.qword = REG_BITS_GET(reg.qword, off, bits, flip);
		return sprintf(buf, "0x%0*llx\n", (bits - 1) / 4 + 1, reg.qword);
	default:
		return -EIO;
	}
}
EXPORT_SYMBOL(bits_attr_show);

MODULE_AUTHOR("IriKa <qiujie.jq@gmail.com>");
MODULE_DESCRIPTION("FPGA/CPLD driver framework");
MODULE_LICENSE("GPL");
MODULE_ALIAS("fpga-core");
MODULE_VERSION(CONFIG_FPGA_CORE_VERSION);
