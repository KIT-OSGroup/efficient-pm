KERNEL_TREE ?= /lib/modules/$(shell uname -r)/build
CFLAGS += -g -O2 -Werror -Wall -I. -I$(KERNEL_TREE)/tools/include -I../module 
LDFLAGS += -pthread
TARGETS = ep_test ep_verify
OFILES = ep_test.o perf_helper.o

targets: $(TARGETS) all

all: $(TARGETS)

ep_test: $(OFILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

ep_verify: ep_verify.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) $(TARGETS) $(OFILES)

.PHONY: all clean $(TARGETS)
