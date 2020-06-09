/**
 * fpga-core-base.c - implements for the FPGA/CPLD driver framework entry
 *
 * Copyright (C) 2003-2020, Semptian Co., Ltd.
 * Designed by IriKa <qiujie@semptian.com>
 */
#include <linux/module.h>

#include <fpga-core.h>

#ifndef CORE_VERSION
#define CORE_VERSION	"v0.1.0"
#endif

static int __init fpga_core_init(void)
{
	return 0;
}

static void __exit fpga_core_exit(void)
{
}

#ifdef MODULE
module_init(fpga_core_init);
#else
postcore_initcall(fpga_core_init);
#endif
module_exit(fpga_core_exit);

MODULE_AUTHOR("IriKa <qiujie@semptian.com>");
MODULE_DESCRIPTION("Semptian FPGA/CPLD driver framework");
MODULE_LICENSE("GPL");
MODULE_ALIAS("fpga-core");
MODULE_VERSION(CORE_VERSION);
