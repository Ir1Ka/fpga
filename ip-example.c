/**
 * ip-example.c - implements a FPGA IP emulator as an example
 *
 * Copyright (C) 2020 IriKa <qiujie.jq@gmail.com>
 */

#define pr_fmt(fmt) "ip-example: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>

#include <fpga.h>

#define VERSION		"v0.1.0"
#define DEV_NAME	"ip example"

static const struct fpga_ip_id ip_id_table[] =
{
	{
		.name = "ip-emulator",
		.driver_data = 0,
	},
	{},
};

static int ip_probe(struct fpga_ip *ip, const struct fpga_ip_id *id)
{
	int i;

	for (i = 0; i < ip->num_resources; i++)
		dev_info(&ip->dev, "[%d]: 0x%08llx ~ 0x%08llx\n", i,
			 ip->resources[i].start, ip->resources[i].end);

	dev_dbg(&ip->dev, "%s probe\n", DEV_NAME);

	return 0;
}

static int ip_remove(struct fpga_ip *ip)
{
	dev_dbg(&ip->dev, "%s remove\n", DEV_NAME);
	return 0;
}

static struct fpga_ip_driver ip_driver = {
	.id_table = ip_id_table,
	.probe = ip_probe,
	.remove = ip_remove,
	.driver = {
		.name = "ip-emulator",
	},
};

static int __init ip_init(void)
{
	return fpga_add_ip_driver(&ip_driver);
}

static void __exit ip_exit(void)
{
	fpga_del_ip_driver(&ip_driver);
}

module_init(ip_init);
module_exit(ip_exit);

MODULE_AUTHOR("Irika <qiujie.jq@gmail.com>");
MODULE_DESCRIPTION("An IP driver emulator as an example");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip-example");
MODULE_VERSION(VERSION);

