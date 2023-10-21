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
#include <time.h>
#include <unistd.h>

#include <linux/fs.h>
#include <linux/perf_event.h>

#include "ep_test.h"
#include "perf_helper.h"

#define MiB (1ULL << 20)
#define KiB (1ULL << 10)
#define NANOSECOND 1000000000

#define USAGE_FMT                                                              \
	"Usage: %s [-ivp] [-t nthreads] [-b blocksize] [-c count] [-r runtime]" \
	"device\n"

static int test_fd;
static volatile int exit_threads = 0;
static volatile int inf = 0;
static volatile int verbose = 0;
static volatile int perf;
static int running_threads = 0;

struct ep_test_thread_args {
	int tid;
	int c;
	int inf;
	u64 bs;
	u64 off;
	u64 bwrap;
	char *addr;

	// results
	struct ep_teast_thread_res {
		uintptr_t blocks_written;
		double runtime;

		// only used when running with -v
		uint64_t perf_instr;
		uint64_t perf_cycle;
	} res;
};

static int parse_size(char *str, uint64_t *val);

static void cleanup_test_thread(void *data)
{
	__atomic_fetch_sub(&running_threads, 1, __ATOMIC_SEQ_CST);
}

static void *ep_test_thread(void *data)
{
	struct ep_test_thread_args *args = (struct ep_test_thread_args *)data;
	struct eff_pmem_test ep_test_write = {
		.addr = (u64)args->addr,
		.size = args->bs,
	};
	unsigned int c;
	uintptr_t bc = 0;
	struct perf_helper ph;
	struct perf_helper_event e_cycle = HEVENT(PERF_COUNT_HW_CPU_CYCLES);
	struct perf_helper_event e_instr = HEVENT(PERF_COUNT_HW_INSTRUCTIONS);
	struct perf_event_attr pea = { .disabled = 1, .exclude_user = 1 };
	struct timespec start, t;

	pthread_cleanup_push(cleanup_test_thread, NULL);

	clock_gettime(CLOCK_REALTIME, &start);

	if (perf) {
		if (perf_helper_init(&ph, &pea, &e_cycle, &e_instr))
			goto err_exit;
		if (perf_helper_start(&ph))
			goto cleanup_perf;
	}

	for (c = 0; (c < args->c || inf) && !exit_threads; c++) {
		ep_test_write.off = args->off + ((c % args->bwrap) * args->bs);
		if (ioctl(test_fd, EFF_PMEM_TEST_WRITE, &ep_test_write)) {
			fprintf(stderr,
				"(tid %d): ioctl failed (off: %llu): %s\n",
				args->tid, ep_test_write.off, strerror(errno));
			break;
		}
		bc++;
	}

	if (perf) {
		if (perf_helper_stop(&ph))
			goto cleanup_perf;

		args->res.perf_cycle = e_cycle.res;
		args->res.perf_instr = e_instr.res;
	}

	clock_gettime(CLOCK_REALTIME, &t);
	args->res.runtime = (t.tv_sec - start.tv_sec) +
			    ((double)t.tv_nsec - start.tv_nsec) / NANOSECOND;

	args->res.blocks_written = bc;

	pthread_exit((void *)bc);

cleanup_perf:
	perf_helper_cleanup(&ph);
err_exit:
	pthread_exit((void *)0);

	pthread_cleanup_pop(1);
}

static void handle_INT(int sig)
{
	exit_threads = 1;
}

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	int nthreads = 1, cthreads = 0, c = 1, r = -1, thread_c, opt, fd_zero,
	    disk_fd;
	u64 bs = 128 * KiB, bc = 0, thread_off, cycle = 0, instr = 0;
	char diskname[32 + 1] = { 0 };
	char dev_buf[sizeof(diskname) + sizeof("/dev/")] = { 0 };
	size_t disk_size;
	pthread_t *threads = NULL;
	uintptr_t thread_ret;
	const char *f_zero = "/dev/zero";
	char *b = NULL;
	struct eff_pmem_test ep_test_setup;
	struct ep_test_thread_args *thread_args;
	struct ep_teast_thread_res *cur_res;
	struct sigaction sigact = { .sa_handler = handle_INT };
	struct timespec start, t;
	double diff, t_runtime = 0;

	sigaction(SIGINT, &sigact, NULL);

	while ((opt = getopt(argc, argv, "t:b:c:r:ivp")) != -1) {
		switch (opt) {
		case 't':
			nthreads = atoi(optarg);
			break;
		case 'b':
			if (parse_size(optarg, &bs)) {
				fprintf(stderr, USAGE_FMT, argv[0]);
				goto out;
			}
			break;
		case 'c':
			c = atoi(optarg);
			break;
		case 'r':
			r = atoi(optarg);
			break;
		case 'i':
			inf = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'p':
			perf = 1;
			break;
		default:
			fprintf(stderr, USAGE_FMT, argv[0]);
			goto out;
		}
	}

	if (optind != argc - 1) {
		fprintf(stderr, USAGE_FMT, argv[0]);
		goto out;
	}

	strncpy(diskname, basename(argv[optind]), sizeof(diskname) - 1);

	test_fd = open("/sys/kernel/debug/eff_pmem/eff_pmem_test", O_WRONLY);
	if (test_fd == -1) {
		perror("failed to open eff_pmem_test");
		goto out;
	}

	fd_zero = open(f_zero, O_RDONLY);
	if (fd_zero == -1) {
		perror("failed to open /dev/zero");
		goto close_test;
	}

	b = mmap(NULL, bs, PROT_READ, MAP_PRIVATE, fd_zero, 0);
	if (b == MAP_FAILED) {
		perror("failed to mmap /dev/zero");
		goto close_rng;
	}

	snprintf(dev_buf, sizeof(dev_buf) - 1, "/dev/%s", diskname);
	disk_fd = open(dev_buf, 0);
	if (disk_fd == -1 || ioctl(disk_fd, BLKGETSIZE64, &disk_size)) {
		perror("failed to open disk");
		goto unmap_block;
	}
	close(disk_fd);

	if (c == -1) {
		c = disk_size / bs;
	}

	if (c < 1) {
		fprintf(stderr, "invalid count\n");
		goto unmap_block;
	}

	if (!(threads = malloc(sizeof(pthread_t) * nthreads)) ||
	    !(thread_args =
		      malloc(sizeof(struct ep_test_thread_args) * nthreads))) {
		perror("failed to allocate memory");
		goto unmap_block;
	}

	ep_test_setup = (struct eff_pmem_test){
		.is_open = true,
	};
	memcpy(&ep_test_setup.diskname, diskname,
	       (sizeof(((struct eff_pmem_test *)0)->diskname)));

	if (ioctl(test_fd, EFF_PMEM_TEST_SETUP, &ep_test_setup)) {
		perror("failed to setup test");
		goto free_threads;
	}

	thread_off = disk_size / nthreads;
	thread_c = (c + nthreads - 1) / nthreads;

	clock_gettime(CLOCK_REALTIME, &start);

	for (cthreads = 0; cthreads < nthreads; cthreads++) {
		thread_args[cthreads] = (struct ep_test_thread_args){
			.tid = cthreads,
			.addr = b,
			.bs = bs,
			.c = (c >= thread_c) ? thread_c : c,
			.off = thread_off * cthreads,
			.bwrap = thread_off / bs,
		};
		c -= thread_args[cthreads].c;
		if (pthread_create(&threads[cthreads], NULL, ep_test_thread,
				   &thread_args[cthreads])) {
			fprintf(stderr, "failed to start thread %d\n",
				cthreads);
			cthreads--;
			break;
		}
		__atomic_fetch_add(&running_threads, 1, __ATOMIC_SEQ_CST);
	}

	if (r > 0) {
		do {
			usleep(100 * 1000); // sleep 100ms
			clock_gettime(CLOCK_REALTIME, &t);
			diff = (t.tv_sec - start.tv_sec) +
			       ((double)t.tv_nsec - start.tv_nsec) / NANOSECOND;
		} while (diff < r && !exit_threads &&
			 __atomic_load_n(&running_threads, __ATOMIC_SEQ_CST) !=
				 0);

		exit_threads = 1;
	}

	for (int i = 0; i < cthreads; i++) {
		pthread_join(threads[i], (void **)&thread_ret);

		cur_res = &thread_args[i].res;

		assert(thread_ret == cur_res->blocks_written);

		bc += thread_ret;
		t_runtime += cur_res->runtime;

		if (perf) {
			instr += cur_res->perf_instr;
			cycle += cur_res->perf_cycle;
		}

		if (verbose) {
			fprintf(stdout, "--- thread %d ---\n", i);
			fprintf(stdout, "thread_id=%d\n", i);
			fprintf(stdout, "blocks=%" PRIuPTR "\n", thread_ret);
			fprintf(stdout, "bytes=%lu\n", thread_ret * bs);
			fprintf(stdout, "bw=%f B/s\n",
				(cur_res->blocks_written * bs) /
					cur_res->runtime);
			fprintf(stdout, "runtime=%f s\n", cur_res->runtime);
			if (perf) {
				fprintf(stdout, "instructions=%" PRIu64 "\n",
					cur_res->perf_instr);
				fprintf(stdout, "cycles=%" PRIu64 "\n",
					cur_res->perf_cycle);
			}
			fprintf(stdout, "\n");
		}
	}

	fprintf(stdout, "--- summary ---\n");
	fprintf(stdout, "nthreads=%d\n", cthreads);
	fprintf(stdout, "blocks=%lu\n", bc);
	fprintf(stdout, "blocksize=%lu\n", bs);
	fprintf(stdout, "bytes=%lu\n", bc * bs);
	fprintf(stdout, "bw=%f B/s\n", (bc * bs) / (t_runtime / nthreads));
	fprintf(stdout, "avg_runtime=%f s\n", t_runtime / nthreads);

	if (perf) {
		fprintf(stdout, "instructions=%" PRIu64 "\n", instr);
		fprintf(stdout, "cycles=%" PRIu64 "\n", cycle);
	}

	ret = EXIT_SUCCESS;

	//end_test:
	ep_test_setup = (struct eff_pmem_test){ .is_open = false };
	if (ioctl(test_fd, EFF_PMEM_TEST_SETUP, &ep_test_setup)) {
		perror("WARNING: end_test failed");
	}
free_threads:
	free(threads);
	free(thread_args);
unmap_block:
	munmap(b, bs);
close_rng:
	close(fd_zero);
close_test:
	close(test_fd);
out:
	return ret;
}

static int parse_size(char *str, uint64_t *val)
{
	int ret;
	char *end = str;

	errno = 0;
	*val = strtoul(str, &end, 0);

	if (errno) {
		ret = errno;
		goto err;
	}

	// str invalid
	if (end == str) {
		ret = -1;
		goto err;
	}

	switch (strlen(end)) {
	case 0:
		goto out;
	case 1:
		break;
	default:
		// unexpected modifier length
		ret = -1;
		goto err;
	}

	switch (*end) {
	case 'k':
	case 'K':
		*val <<= 10;
		break;
	case 'm':
	case 'M':
		*val <<= 20;
		break;
	case 'g':
	case 'G':
		*val <<= 30;
		break;
	default:
		ret = -1;
		goto err;
	}

out:
	return 0;

err:
	return ret;
}
