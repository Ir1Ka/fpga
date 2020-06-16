#ifndef __LINUX_FPGA_CORE_H
#define __LINUX_FPGA_CORE_H

#if defined(__KERNEL) || defined(__KERNEL__)

struct fpga;

#if IS_ENABLED(CONFIG_OF)

void of_fpga_register_ips(struct fpga *fpga);

#else

static inline void of_fpga_register_ips(struct fpga *fpga) { }

#endif /* CONFIG_OF */

#endif /* __KERNEL */

#endif /* __LINUX_FPGA_CORE_H */
