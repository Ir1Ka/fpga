#ifndef __LINUX_SEMP_FPGA_BRIDGE_H
#define __LINUX_SEMP_FPGA_BRIDGE_H

#if defined(__KERNEL) || defined(__KERNEL__)
#include <linux/types.h>
#include <linux/ioport.h>

#include <fpga.h>

struct fpga_bridge {
	struct fpga *parent;
	struct device *dev;

	void *priv;

	struct fpga fpga;
	struct fpga_algorithm algo;
};
#define to_fpga_bridge(_fpga) container_of(_fpga, struct fpga_bridge, fpga)

struct fpga_bridge *
fpga_bridge_alloc(struct fpga *parent, struct device *dev, u32 force_nr,
		  struct resource *resource, int sizeof_priv);
void fpga_bridge_free(struct fpga_bridge *bridge);

static inline void *fpga_bridge_priv(struct fpga_bridge *bridge)
{
	return bridge->priv;
}

struct fpga *fpga_root(struct device *dev);

#endif /* __KERNEL */

#endif /* __LINUX_SEMP_FPGA_BRIDGE_H */
