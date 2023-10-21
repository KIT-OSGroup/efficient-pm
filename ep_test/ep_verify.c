#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/random.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include <linux/types.h>

#include "ep_test.h"

#define RANDOM_SIZE 64

void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [options] <device>\n", argv0);
	fprintf(stderr, "  -o <offset>: offset to write at on PMEM\n");
	fprintf(stderr, "  -s <size>: amount of data to write and verify\n");
}

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;
	size_t i;
	char *test_buf, *pmem_buf;
	char diskname[32 + 1] = { 0 };
	char dev_buf[sizeof(diskname) + sizeof("/dev/")] = { 0 };
	size_t disk_size;
	int test_fd, disk_fd;
	size_t random_size;
	struct eff_pmem_test ep_test_setup, ep_test_write;

	int opt;
	size_t offset = 0;
	size_t test_size = 4096;

	while ((opt = getopt(argc, argv, "o:s:h")) != -1) {
		switch (opt) {
		case 'o':
			offset = atoll(optarg);
			break;
		case 's':
			test_size = atoll(optarg);
			break;
		default:
			usage(argv[0]);
			goto out;
		}
	}
	if (optind != argc - 1) {
		usage(argv[0]);
		goto out;
	}
	strncpy(diskname, basename(argv[optind]), sizeof(diskname) - 1);

	test_fd = open("/sys/kernel/debug/eff_pmem/eff_pmem_test", O_WRONLY);
	if (test_fd == -1) {
		perror("failed to open eff_pmem_test");
		goto out;
	}

	test_buf = malloc(test_size);
	if (!test_buf) {
		perror("failed to allocate test_buf");
		goto close_test;
	}
	/* Fill with random bytes */
	random_size = MIN(test_size, RANDOM_SIZE);
	if (getrandom(test_buf, random_size, 0) != random_size) {
		perror("failed to get random bytes");
		goto free_test_buf;
	}
	for (i = RANDOM_SIZE; i < test_size; i += RANDOM_SIZE) {
		memcpy(test_buf + i, test_buf, MIN(test_size - i, RANDOM_SIZE));
	}
	// printf("%x\n", *(unsigned int *) test_buf);

	/* TODO: Probably don't actually need the disk size */
	snprintf(dev_buf, sizeof(dev_buf) - 1, "/dev/%s", diskname);
	disk_fd = open(dev_buf, 0);
	if (disk_fd == -1 || ioctl(disk_fd, BLKGETSIZE64, &disk_size)) {
		perror("failed to open disk");
		goto free_test_buf;
	}

	ep_test_setup = (struct eff_pmem_test){
		.is_open = true,
	};
	memcpy(&ep_test_setup.diskname, diskname,
	       (sizeof(((struct eff_pmem_test *)0)->diskname)));

	if (ioctl(test_fd, EFF_PMEM_TEST_SETUP, &ep_test_setup)) {
		perror("failed to setup test");
		goto close_disk;
	}

	ep_test_write = (struct eff_pmem_test){
		.addr = (u64)test_buf,
		.size = test_size,
		.off = offset,
	};
	if (ioctl(test_fd, EFF_PMEM_TEST_WRITE, &ep_test_write)) {
		fprintf(stderr, "ioctl failed (off: %llu): %s\n",
			ep_test_write.off, strerror(errno));
	}

	ep_test_setup = (struct eff_pmem_test){ .is_open = false };
	if (ioctl(test_fd, EFF_PMEM_TEST_SETUP, &ep_test_setup)) {
		perror("WARNING: end_test failed");
	}

	/* Verify that contents match. */
	pmem_buf = mmap(NULL, test_size + (offset % 4096), PROT_READ, MAP_SHARED, disk_fd, (offset >> 12) << 12);
	if (pmem_buf == MAP_FAILED) {
		perror("failed to map PMEM");
		goto close_disk;
	}
	if (memcmp(test_buf, pmem_buf + (offset % 4096), test_size) != 0) {
		fprintf(stderr, "ERROR: Copied contents do not match\n");
		goto unmap_pmem;
	}

	// printf("%x\n", *(unsigned int *) pmem_buf);

	ret = EXIT_SUCCESS;

unmap_pmem:
	munmap(pmem_buf, test_size);
close_disk:
	close(disk_fd);
free_test_buf:
	free(test_buf);
close_test:
	close(test_fd);
out:
	return ret;
}
