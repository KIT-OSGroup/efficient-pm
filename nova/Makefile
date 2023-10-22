#
# Makefile for the linux NOVA filesystem routines.
#
#
KERNEL_TREE ?= /lib/modules/$(shell uname -r)/build
SRC_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

obj-m += nova.o

nova-y := balloc.o bbuild.o checksum.o dax.o dir.o file.o gc.o inode.o ioctl.o \
	journal.o log.o mprotect.o namei.o parity.o rebuild.o snapshot.o stats.o \
	super.o symlink.o sysfs.o perf.o


.PHONY: install clean tools

nova.ko:
	+make -C $(KERNEL_TREE) M=$(SRC_DIR) modules KBUILD_EXTRA_SYMBOLS=`pwd`/../module/Module.symvers

install:
	+make -C $(KERNEL_TREE) M=$(SRC_DIR) modules_install

clean:
	+make -C $(KERNEL_TREE) M=$(SRC_DIR) clean

compile_commands.json:
	$(KERNEL_TREE)/scripts/clang-tools/gen_compile_commands.py -d $(KERNEL_TREE) .
