#ifndef EP_TEST_H
#define EP_TEST_H

#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/types.h>

#define EFF_PMEM_TEST_SETUP _IOW('p', 1, struct eff_pmem_test)
#define EFF_PMEM_TEST_WRITE _IOW('p', 2, struct eff_pmem_test)

struct eff_pmem_test {
	__u64 addr;
	__u64 size;
	__u64 off;
	char diskname[32];
	int is_open;
};

#endif /* EP_TEST_H */
