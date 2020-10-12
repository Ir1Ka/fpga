/**
 * fpga-core-dev.c - FPGA IP userspace driver entry
 *
 * Copyright (C) 2020 IriKa <qiujie.jq@gmail.com>
 */

#define pr_fmt(fmt)	"fpga-dev: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include <fpga.h>
#include <fpga-dev.h>

#include "fpga-core.h"

struct fpga_dev {
	struct list_head list;
	struct fpga *fpga;
	struct device dev;
	struct cdev cdev;
};
#define to_fpga_dev(_d)	container_of(_d, struct fpga_dev, dev)

struct fpga_ip_dev {
	struct fpga_ip *ip;
	struct fpga *fpga;
	struct fpga_ip_info info;
};

#define FPGA_MINORS	(MINORMASK + 1)
static LIST_HEAD(fpga_dev_list);
static DEFINE_SPINLOCK(fpga_dev_lock);

static unsigned int fpga_major = 0;
module_param(fpga_major, uint, S_IRUGO);
MODULE_PARM_DESC(fpga_major, "Specify fpga char device major. "
			     "Default dynamic.");

static struct fpga_dev *fpga_dev_get_by_minor(unsigned index)
{
	struct fpga_dev *fpga_dev;

	spin_lock(&fpga_dev_lock);
	list_for_each_entry(fpga_dev, &fpga_dev_list, list) {
		if(fpga_dev->fpga->nr == index)
			goto  found;
	}
	fpga_dev = NULL;

found:
	spin_unlock(&fpga_dev_lock);
	return fpga_dev;
}

static struct fpga_dev *get_free_fpga_dev(struct fpga *fpga)
{
	struct fpga_dev *fpga_dev;

	fpga_dev = kzalloc(sizeof *fpga_dev, GFP_KERNEL);
	if (!fpga_dev)
		return ERR_PTR(-ENOMEM);
	fpga_dev->fpga = fpga;

	spin_lock(&fpga_dev_lock);
	list_add_tail(&fpga_dev->list, &fpga_dev_list);
	spin_unlock(&fpga_dev_lock);
	return fpga_dev;
}

static void put_fpga_dev(struct fpga_dev *fpga_dev, bool del_cdev)
{
	spin_lock(&fpga_dev_lock);
	list_del(&fpga_dev->list);
	spin_unlock(&fpga_dev_lock);
	if (del_cdev)
		cdev_device_del(&fpga_dev->cdev, &fpga_dev->dev);
	put_device(&fpga_dev->dev);
}

static ssize_t name_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct fpga_dev *fpga_dev = fpga_dev_get_by_minor(MINOR(dev->devt));

	if (!fpga_dev)
		return -ENODEV;
	return sprintf(buf, "%s\n", fpga_dev->fpga->name);
}
static DEVICE_ATTR_RO(name);

static struct attribute *fpga_attrs[] = {
	&dev_attr_name.attr,
	NULL,
};
ATTRIBUTE_GROUPS(fpga);

static long fpgadev_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct fpga_ip_dev *ip_dev = file->private_data;
	struct fpga_ip *ip;
	u32 type = FPGA_DEV_CMD_TYPE(cmd);
	u32 op = FPGA_DEV_CMD_OP(cmd);
	u32 idx = FPGA_DEV_CMD_IDX(cmd);
	u32 size = FPGA_DEV_CMD_SIZE(cmd);
	int ret = 0;

	dev_dbg(&ip_dev->fpga->dev, "ioctl, cmd 0x%08x, arg 0x%08lx\n", cmd, arg);

	switch (type) {
	case FPGA_DEV_TYPE_RESOURCE:
	{
		struct fpga_dev_resource res[FPGA_NUM_RESOURCES_MAX];
		int i;

		if (unlikely(ip_dev->ip))
			return -ENODEV;

		if (size > FPGA_NUM_RESOURCES_MAX)
			return -EINVAL;

		if (copy_from_user(res, (struct fpga_dev_resource __user *)arg,
				   size * sizeof(*res)))
			return -EFAULT;

		for (i = 0; i < size; i++) {
			struct resource *r = &ip_dev->info.resources[i].resource;

			r->start = res[i].start;
			r->end = r->start + res[i].size - 1;
		}

		ip_dev->info.num_resources = size;

		ip = __fpga_new_ip(ip_dev->fpga, &ip_dev->info);
		if (IS_ERR(ip))
			return PTR_ERR(ip);
		ip_dev->ip = ip;
		break;
	}

	case FPGA_DEV_TYPE_FUNCS:
	{
		__u32 funcs;

		funcs = fpga_get_functionality(ip_dev->fpga);
		ret = put_user(funcs, (__u32 __user *)arg);
		break;
	}

	case FPGA_DEV_TYPE_REG:
	{
		struct fpga_dev_rdwr __user *rdwr_arg;
		struct fpga_dev_rdwr rdwr;

		ip = ip_dev->ip;
		if (unlikely(!ip))
			return -ENODEV;

		rdwr_arg = (struct fpga_dev_rdwr __user *)arg;

		if (unlikely(copy_from_user(&rdwr, rdwr_arg, sizeof(rdwr))))
			return -EFAULT;

		if (op == FPGA_DEV_OP_RD) {
			ret = fpga_reg_read(ip, size, idx, rdwr.where, &rdwr.reg);
			if (unlikely(ret))
				return ret;

			if (unlikely(copy_to_user(&rdwr_arg->reg, &rdwr.reg, sizeof(rdwr.reg))))
				ret = -EFAULT;
		} else {
			ret = fpga_reg_write(ip, size, idx, rdwr.where, rdwr.reg);
		}
		break;
	}

	case FPGA_DEV_TYPE_BLOCK:
	{
		struct fpga_dev_block __user *block_arg;
		struct fpga_dev_block block;
		u8 data[FPGA_BLOCK_SIZE_MAX];

		ip = ip_dev->ip;
		if (unlikely(!ip))
			return -ENODEV;

		if (size > FPGA_BLOCK_SIZE_MAX)
			return -EINVAL;

		block_arg = (struct fpga_dev_block __user *)arg;

		if (unlikely(copy_from_user(&block, block_arg, sizeof(block))))
			return -EFAULT;

		if (op == FPGA_DEV_OP_RD) {
			ret = fpga_read_block(ip, idx, block.where, size, data);
			if (unlikely(ret))
				return ret;

			if (unlikely(copy_to_user((void __user *)block.block, data, size)))
				ret = -EFAULT;
		} else {
			if (unlikely(copy_from_user(data, (void __user *)block.block, size)))
				return -EFAULT;

			ret = fpga_write_block(ip, idx, block.where, size, data);
		}
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

#if IS_ENABLED(CONFIG_COMPAT)
static long compat_fpgadev_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	return fpgadev_ioctl(file, cmd, arg);
}
#else
#defien compat_fpgadev_ioctl	NULL
#endif

static int fpgadev_open(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(inode);
	struct fpga_ip_dev *ip_dev;
	struct fpga *fpga;

	fpga = fpga_get(minor);
	if (!fpga)
		return -ENODEV;

	ip_dev = kzalloc(sizeof *ip_dev, GFP_KERNEL);
	if (!ip_dev) {
		fpga_put(fpga);
		return -ENOMEM;
	}

	ip_dev->fpga = fpga;
	file->private_data = ip_dev;

	return 0;
}

static int fpgadev_release(struct inode *inode, struct file *file)
{
	struct fpga_ip_dev *ip_dev = file->private_data;

	if (ip_dev->ip)
		fpga_unregister_ip(ip_dev->ip);

	fpga_put(ip_dev->fpga);
	kfree(ip_dev);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations fpgadev_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.unlocked_ioctl = fpgadev_ioctl,
	.compat_ioctl = compat_fpgadev_ioctl,
	.mmap = NULL,
	.open = fpgadev_open,
	.release = fpgadev_release,
};

static struct class *fpga_dev_class;

static void fpgadev_dev_release(struct device *dev)
{
	struct fpga_dev *fpga_dev;

	fpga_dev = to_fpga_dev(dev);
	kfree(fpga_dev);
}

static int fpgadev_attach(struct device *dev, void *dummy)
{
	struct fpga *fpga;
	struct fpga_dev *fpga_dev;
	int res;

	fpga = fpga_verify(dev);
	if (!fpga)
		return 0;

	fpga_dev = get_free_fpga_dev(fpga);
	if (IS_ERR(fpga_dev))
		return PTR_ERR(fpga_dev);

	cdev_init(&fpga_dev->cdev, &fpgadev_fops);
	fpga_dev->cdev.owner = THIS_MODULE;

	device_initialize(&fpga_dev->dev);
	fpga_dev->dev.devt = MKDEV(fpga_major, fpga->nr);
	fpga_dev->dev.class = fpga_dev_class;
	fpga_dev->dev.parent = &fpga->dev;
	fpga_dev->dev.release = fpgadev_dev_release;
	dev_set_name(&fpga_dev->dev, "fpga-%d", fpga->nr);

	res = cdev_device_add(&fpga_dev->cdev, &fpga_dev->dev);
	if (res) {
		put_fpga_dev(fpga_dev, false);
		return res;
	}

	pr_debug("fpga-dev: fpga [%s] registered as minor %d\n",
		 fpga->name, fpga->nr);
	return 0;
}

static int fpgadev_detach(struct device *dev, void *dummy)
{
	struct fpga *fpga;
	struct fpga_dev *fpga_dev;

	fpga = fpga_verify(dev);
	if (!fpga)
		return 0;

	fpga_dev = fpga_dev_get_by_minor(fpga->nr);
	if (!fpga_dev)
		return 0;

	put_fpga_dev(fpga_dev, true);

	pr_debug("fpga-dev: fpga [%s] unregistered\n", fpga->name);
	return 0;
}

static int fpgadev_notifier_call(struct notifier_block *nb,
				 unsigned long action, void *data)
{
	struct device *dev = data;

	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		return fpgadev_attach(dev, NULL);
	case BUS_NOTIFY_DEL_DEVICE:
		return fpgadev_detach(dev, NULL);
	}

	return 0;
}

static struct notifier_block fpgadev_notifier = {
	.notifier_call = fpgadev_notifier_call,
};

int __init fpga_dev_init(void)
{
	dev_t dev;
	int res;

	pr_info("fpga /dev entries initialing\n");

	if (fpga_major)
		res = register_chrdev_region(MKDEV(fpga_major, 0), FPGA_MINORS, "fpga");
	else
		res = alloc_chrdev_region(&dev, 0, FPGA_MINORS, "fpga");
	if (res)
		goto out;

	if (!fpga_major)
		fpga_major = MAJOR(dev);

	fpga_dev_class = class_create(THIS_MODULE, "fpga-dev");
	if (IS_ERR(fpga_dev_class)) {
		res = PTR_ERR(fpga_dev_class);
		goto out_unreg_chrdev;
	}
	fpga_dev_class->dev_groups = fpga_groups;

	res = bus_register_notifier(&fpga_bus_type, &fpgadev_notifier);
	if (res)
		goto out_unreg_class;

	fpga_for_each_dev(NULL, fpgadev_attach);

	return 0;

out_unreg_class:
	class_destroy(fpga_dev_class);
out_unreg_chrdev:
	unregister_chrdev_region(MKDEV(fpga_major, 0), FPGA_MINORS);
out:
	pr_err("fpga /dev entries init failed\n");
	return 0;
}

void __exit fpga_dev_exit(void)
{
	bus_unregister_notifier(&fpga_bus_type, &fpgadev_notifier);
	fpga_for_each_dev(NULL, fpgadev_detach);
	class_destroy(fpga_dev_class);
	unregister_chrdev_region(MKDEV(fpga_major, 0), FPGA_MINORS);
}
