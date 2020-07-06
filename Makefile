_CURDIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

ifneq ($(KERNELRELEASE),)

# fpga driver core framework
obj-m += fpga-core.o
fpga-core-objs := fpga-core-base.o
fpga-core-objs += fpga-core-region.o
fpga-core-$(CONFIG_OF) += fpga-core-of.o

# fpga example
obj-m += fpga-example.o

# ip example
obj-m += ip-example.o

ccflags-y := -I$(_CURDIR)/include

# DEBUG flags
ifneq ($(DEBUG),)
ccflags-y += -g
endif

ifneq ($(FPGA_CORE_VERSION),)
ccflags-y += -DCONFIG_FPGA_CORE_VERSION='"$(FPGA_CORE_VERSION)"'
endif

else # KERNELRELEASE

.PHONY: all
.PHONY: clean

all:

KDIR := /lib/modules/$(shell uname -r)/build

all: modules
modules:
	$(MAKE) -C $(KDIR) M=$(_CURDIR) modules

clean: modules-clean
modules-clean:
	$(MAKE) -C $(KDIR) M=$(_CURDIR) clean

endif # KERNELRELEASE
