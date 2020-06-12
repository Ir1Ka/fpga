ifneq ($(KERNELRELEASE),)

obj-m += fpga-core.o
fpga-core-objs := fpga-core-base.o
fpga-core-objs += fpga-core-bridge.o
fpga-core-$(CONFIG_OF) += fpga-core-of.o

ccflags-y := -I$(PWD)/include

ifneq ($(FPGA_CORE_VERSION),)
ccflags-y += -DCONFIG_FPGA_CORE_VERSION='"$(FPGA_CORE_VERSION)"'
endif

else # KERNELRELEASE

.PHONY: all
.PHONY: clean

all: fpga-core

KDIR := /lib/modules/$(shell uname -r)/build

fpga-core:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean: fpga-core-clean
fpga-core-clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

endif # KERNELRELEASE
