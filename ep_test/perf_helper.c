#include "perf_helper.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct read_format {
	u64 nr;
	struct {
		u64 value;
		u64 id;
	} values[];
};

int __perf_helper_init(struct perf_helper *ph, struct perf_event_attr *p, ...)
{
	size_t argc = 0;
	struct perf_helper_event *cur = NULL;
	va_list ap, ap_copy;
	int ret = 0;

	*ph = (struct perf_helper){
		.evs = NULL,
		.n_evs = 0,
		.n_evs_valid = 0,
		.group_fd = -1,
	};

	va_start(ap, p);
	va_copy(ap_copy, ap);

	//asume the argument list is NULL terminated and count arguments
	while ((cur = va_arg(ap_copy, struct perf_helper_event *)))
		argc++;

	va_end(ap_copy);

	if (argc == 0) {
		fprintf(stderr, "no events to set up\n");
		ret = 1;
		goto cleanup_ap;
	}

	ph->n_evs = argc;

	if (!(ph->evs = calloc(argc, sizeof(struct perf_helper_event *)))) {
		fprintf(stderr, "perf helper failed to allocate memory\n");
		ret = ENOMEM;
		goto cleanup_ap;
	}

	// copy perf_helper_event pointer to evs
	for (size_t i = 0; (cur = va_arg(ap, struct perf_helper_event *)); i++)
		ph->evs[i] = cur;

	ph->pea = *p;

	ph->pea.type = PERF_TYPE_HARDWARE;
	ph->pea.size = sizeof(ph->pea);
	ph->pea.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;

	assert(ph->n_evs > 0);

	ph->evs[0]->pea = ph->pea;
	// setup event group
	if ((ret = syscall(__NR_perf_event_open, &ph->evs[0]->pea, 0, -1, -1,
			   0)) == -1) {
		fprintf(stderr, "Failed to setup perf event 0\n");
		goto cleanup_fds;
	}
	ph->evs[0]->__fd = ret;
	ph->group_fd = ph->evs[0]->__fd;
	ph->n_evs_valid++;

	// remaining events
	for (size_t i = 1; i < ph->n_evs; i++) {
		ph->evs[i]->pea = ph->pea;
		ph->evs[i]->pea.config = ph->evs[i]->config;
		if ((ret = syscall(__NR_perf_event_open, &ph->evs[i]->pea, 0,
				   -1, ph->group_fd, 0)) == -1) {
			fprintf(stderr, "Failed to setup perf event %zu: %s\n",
				i, strerror(errno));
			goto cleanup_fds;
		}
		ph->evs[i]->__fd = ret;
		ph->n_evs_valid++;
	}

	if ((ret = ioctl(ph->group_fd, PERF_EVENT_IOC_RESET,
			 PERF_IOC_FLAG_GROUP))) {
		fprintf(stderr, "failed to reset group: %s\n", strerror(errno));
		goto cleanup_fds;
	}

	return ret;

cleanup_fds:
	perf_helper_cleanup(ph);
cleanup_ap:
	va_end(ap);

	return ret;
}

int perf_helper_start(struct perf_helper *ph)
{
	int ret;

	if ((ret = ioctl(ph->group_fd, PERF_EVENT_IOC_ENABLE,
			 PERF_IOC_FLAG_GROUP))) {
		fprintf(stderr, "failed to enable group: %s\n",
			strerror(errno));
		goto err;
	}

	return 0;

err:
	return ret;
}

int perf_helper_stop(struct perf_helper *ph)
{
	int ret;
	ssize_t bytes;
	char buf[4096];
	struct read_format *rf = (struct read_format *)buf;

	if ((ret = ioctl(ph->group_fd, PERF_EVENT_IOC_DISABLE,
			 PERF_IOC_FLAG_GROUP))) {
		fprintf(stderr, "failed to disable group: %s\n", strerror(ret));
		goto err;
	}

	if ((bytes = read(ph->group_fd, buf, sizeof(buf))) <= 0) {
		ret = errno;
		fprintf(stderr, "failed to read result form event group: %s\n",
			strerror(errno));
		goto err;
	}

	if (rf->nr != ph->n_evs_valid) {
		ret = 1;
		fprintf(stderr,
			"unexpected number of events read from event group\n");
		goto err;
	}

	for (size_t i = 0; i < rf->nr; i++) {
		ph->evs[i]->res = rf->values[i].value;
	}

	return 0;
err:
	return ret;
}

int perf_helper_cleanup(struct perf_helper *ph)
{
	while (ph->n_evs_valid > 0) {
		close(ph->evs[--ph->n_evs_valid]->__fd);
	}
	assert(ph->n_evs_valid == 0);
	free(ph->evs);
	return 0;
}
