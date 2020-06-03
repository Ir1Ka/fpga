ifneq ($(KERNELRELEASE),)

obj-m += fpga-core.o
fpga-core-objs := fpga-core-base.o

ccflags-y := -I$(PWD)/include
ifneq ($(CORE_VERSION),)
ccflags-y += -DCORE_VERSION='"$(CORE_VERSION)"'
endif

else

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
