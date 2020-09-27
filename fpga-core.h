#ifndef __LINUX_FPGA_CORE_H
#define __LINUX_FPGA_CORE_H

#if defined(__KERNEL) || defined(__KERNEL__)
#include <linux/init.h>

#include <fpga.h>

struct fpga;

#if IS_ENABLED(CONFIG_OF)

void of_fpga_register_ips(struct fpga *fpga);

#else

static inline void of_fpga_register_ips(struct fpga *fpga) { }

#endif /* CONFIG_OF */

int fpga_reg_read(const struct fpga_ip *ip, int size, int index, u64 where,
		  union fpga_reg_data *reg);
int fpga_reg_write(const struct fpga_ip *ip, int size, int index, u64 where,
		   union fpga_reg_data reg);

int __init fpga_dev_init(void);
void __exit fpga_dev_exit(void);

#endif /* __KERNEL */

#endif /* __LINUX_FPGA_CORE_H */
