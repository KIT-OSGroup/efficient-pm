KERNEL_TREE ?= /lib/modules/$(shell uname -r)/build
SRC_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
CP := cp

obj-m += eff_pmem.o

.PHONY: install clean tools

eff_pmem.ko: eff_pmem.c ep_test.h ep_trace.h
	+make -C $(KERNEL_TREE) M=$(SRC_DIR) modules

ep_trace.h: ep_trace.h.in
	sed 's|^#define TRACE_INCLUDE_PATH .*|#define TRACE_INCLUDE_PATH $(SRC_DIR)|' $< > $@

install:
	+make -C $(KERNEL_TREE) M=$(SRC_DIR) modules_install

clean:
	rm -f ep_trace.h
	+make -C $(KERNEL_TREE) M=$(SRC_DIR) clean

tools:
	+make -C $(SRC_DIR)/tools all KERNEL_TREE=$(KERNEL_TREE)

compile_commands.json:
	$(KERNEL_TREE)/scripts/clang-tools/gen_compile_commands.py -d $(KERNEL_TREE) .
