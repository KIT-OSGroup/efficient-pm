#ifndef EP_TEST_PERF_HELPER_H
#define EP_TEST_PERF_HELPER_H

#include <linux/perf_event.h>

/*
 * Helper for capturing multiple HW events using perf_event_open
 */

#define perf_helper_init(ph, pea, ...)                                         \
	__perf_helper_init(ph, pea, __VA_ARGS__, NULL)
#define HEVENT(_config)                                                        \
	((struct perf_helper_event){ .config = _config, .res = 0, .__fd = -1 })

struct perf_helper_event {
	__u64 config;
	uint64_t res;

	int __fd;
	struct perf_event_attr pea;
};

struct perf_helper {
	struct perf_event_attr pea;
	struct perf_helper_event **evs;
	size_t n_evs;
	size_t n_evs_valid;
	int group_fd;
};

int __perf_helper_init(struct perf_helper *ph, struct perf_event_attr *pea,
		       ...);
int perf_helper_start(struct perf_helper *ph);
int perf_helper_stop(struct perf_helper *ph);
int perf_helper_cleanup(struct perf_helper *ph);

#endif /* EP_TEST_PERF_HELPER_H */
