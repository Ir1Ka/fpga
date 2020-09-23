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

static void cdev_set_parent(struct cdev *p, struct kobject *kobj)
{
	WARN_ON(!kobj->state_initialized);
	p->kobj.parent = kobj;
}

static int cdev_device_add(struct cdev *cdev, struct device *dev)
{
	int rc = 0;

	if (dev->devt) {
		cdev_set_parent(cdev, &dev->kobj);

		rc = cdev_add(cdev, dev->devt, 1);
		if (rc)
			return rc;
	}

	rc = device_add(dev);
	if (rc)
		cdev_del(cdev);

	return rc;
}

static void cdev_device_del(struct cdev *cdev, struct device *dev)
{
	device_del(dev);
	if (dev->devt)
		cdev_del(cdev);
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

static struct device_attribute fpga_attrs[] = {
	__ATTR(name, S_IRUGO, name_show, NULL),
	{ },
};

static long fpgadev_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct fpga_ip_dev *ip_dev = file->private_data;
	struct fpga_ip *ip;

	dev_dbg(&ip_dev->fpga->dev, "ioctl, cmd 0x%08x, arg 0x%08lx\n", cmd, arg);

	switch (cmd) {
	case FPGA_IP_RESOURCE:
	{
		struct fpga_ip_resource_ioctl_data resource_arg;
		int i;

		if (unlikely(ip_dev->ip))
			return -ENODEV;

		if (copy_from_user(&resource_arg,
				   (struct fpga_ip_resource_ioctl_data __user *)arg,
				   sizeof resource_arg))
			return -EFAULT;

		for (i = 0; i < resource_arg.num_resources; i++) {
			struct resource *r = &ip_dev->info.resources[i];

			if (i >= FPGA_NUM_RESOURCES_MAX)
				return -EINVAL;

			r->start = resource_arg.resources[i].start;
			r->end = r->start + resource_arg.resources[i].size - 1;
		}

		ip_dev->info.num_resources = resource_arg.num_resources;

		ip = __fpga_new_ip(ip_dev->fpga, &ip_dev->info);
		if (IS_ERR(ip))
			return PTR_ERR(ip);
		ip_dev->ip = ip;
		break;
	}

	case FPGA_IP_FUNCS:
	{
		__u32 funcs;

		funcs = fpga_get_functionality(ip_dev->fpga);
		return put_user(funcs, (__u32 __user *)arg);
	}

	case FPGA_IP_RDWR:
	{
		struct fpga_ip_rdwr_ioctl_data __user *rdwr;
		struct fpga_ip_rdwr_ioctl_data _rdwr;
		u64 addr;
		int ret;

		ip = ip_dev->ip;
		if (unlikely(!ip))
			return -ENODEV;

		rdwr = (struct fpga_ip_rdwr_ioctl_data __user *)arg;

		if (copy_from_user(&_rdwr, rdwr, sizeof _rdwr))
			return -EFAULT;

		addr = ip->resources[_rdwr.index].start + _rdwr.where;
		ret = fpga_reg_xfer(ip->fpga, addr, _rdwr.rw, _rdwr.size,
				    &_rdwr.reg);
		if (unlikely(ret))
			return ret;

		if (_rdwr.rw == FPGA_READ &&
		    copy_to_user(&rdwr->reg, &_rdwr.reg, sizeof _rdwr.reg))
			return -EFAULT;
		break;
	}

	case FPGA_IP_BLOCK:
	{
		struct fpga_ip_block_ioctl_data __user *block;
		struct fpga_ip_block_ioctl_data _block;
		u8 data[FPGA_BLOCK_SIZE_MAX];
		u64 addr;
		int ret;

		ip = ip_dev->ip;
		if (unlikely(!ip))
			return -ENODEV;

		block = (struct fpga_ip_block_ioctl_data __user *)arg;

		if (copy_from_user(&_block, block, sizeof _block))
			return -EFAULT;

		addr = ip->resources[_block.index].start + _block.where;
		ret = fpga_block_xfer(ip->fpga, addr, _block.rw, _block.size, data);
		if (unlikely(ret))
			return ret;

		if (_block.rw == FPGA_READ &&
		    copy_to_user((__u8 __user*)&_block.block, data, _block.size))
			return -EFAULT;
		break;
	}

	default:
		return -ENOTTY;
	}
	return 0;
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
	fpga_dev_class->dev_attrs = fpga_attrs;

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
