#include <linux/init.h>
#include <linux/module.h>


#include <linux/cpu.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/dax.h>
#include <linux/blkdev.h>
#include <linux/kprobes.h>

#include <linux/debugfs.h>

#include "ep_test.h"

#define CREATE_TRACE_POINTS
#include "ep_trace.h"

/* Accounting */

static DEFINE_PER_CPU_SHARED_ALIGNED(size_t, bytes_copied);
static DEFINE_PER_CPU_SHARED_ALIGNED(size_t, max_bytes_on_cpu);

/* enable accounting of writes for conditional offloading? */
static unsigned int ep_account_writes = 0;
module_param(ep_account_writes, uint, S_IRUGO|S_IWUSR);

/* accounting period in milliseconds */
static unsigned int ep_period_ms = 1000;
module_param(ep_period_ms, uint, S_IRUGO|S_IWUSR);

/* maximum on-CPU bandwidth in MiB/s */
static unsigned int ep_max_bw = 800;
module_param(ep_max_bw, uint, S_IRUGO|S_IWUSR);

/* threshold for switching to copy offloading in MiB/s */
static unsigned int ep_offload_thresh_bw = 500;
module_param(ep_offload_thresh_bw, uint, S_IRUGO|S_IWUSR);

/* use get_user_pages? */
static unsigned int ep_use_gup = 1;
module_param(ep_use_gup, uint, S_IRUGO|S_IWUSR);

/* time the the next period starts, in jiffies */
static unsigned long next_period;
/* time the current period started */
static ktime_t cur_period;

/* lock for period reset */
static DEFINE_SPINLOCK(period_lock);

/* semaphore for EP_MODE_MEMCPY_SEM */
static struct semaphore memcpy_sem;
/* maximum writers for EP_MODE_MEMCPY_SEM  */
static unsigned int ep_max_memcpy_sem = 3;
module_param(ep_max_memcpy_sem, uint, S_IRUGO|S_IWUSR);

/* resulting statistics (per period) */
static size_t pmem_write_bytes_period, pmem_write_bandwidth;
static bool write_oncpu;

/* callers need to hold period_lock */
static void finish_accounting_period(void)
{
	int cpu;
	size_t *max_ptr, *copied_ptr, copied;
	int active_cpus;
	s64 delta;
	
	/* check again - another thread might have reset the period */
	if (!time_after(jiffies, next_period))
		goto unlock;

	pmem_write_bytes_period = 0;
	active_cpus = 0;
	for_each_present_cpu(cpu) {
		max_ptr = per_cpu_ptr(&max_bytes_on_cpu, cpu);
		copied_ptr = per_cpu_ptr(&bytes_copied, cpu);
		/* TODO: is xchg sufficiently atomic here? */
		copied = xchg(copied_ptr, 0);
		pmem_write_bytes_period += copied;
		/* count and mark active CPUs for per-cpu write quota */
		if (copied == 0) {
			*max_ptr = 0;
		} else {
			*max_ptr = max(*max_ptr, (size_t) 1);
			active_cpus++;
		}
	}
	/* second pass: assign per-cpu write quotas */
	for_each_present_cpu(cpu) {
		max_ptr = per_cpu_ptr(&max_bytes_on_cpu, cpu);
		if (*max_ptr) {
			*max_ptr = ((size_t) ep_max_bw << 20) * ep_period_ms / 1000 / active_cpus;
		}
	}
	delta = ktime_ms_delta(ktime_get(), cur_period);
	pmem_write_bandwidth = pmem_write_bytes_period * 1000 / delta;
	write_oncpu = (pmem_write_bandwidth >> 20) < ep_offload_thresh_bw;
	cur_period = ktime_get();
	next_period = jiffies + msecs_to_jiffies(ep_period_ms);
	pr_debug("eff_pmem: finish period, bw=%lu write_oncpu=%d active_cpus=%d max_percpu=%lu\n", pmem_write_bandwidth >> 20, write_oncpu, active_cpus, active_cpus ? ((size_t) ep_max_bw << 20) * ep_period_ms / 1000 / active_cpus : 0);
unlock:
	spin_unlock(&period_lock);
}

/* record a write to PMEM, returns true if write should be offloaded */
static inline bool ep_record_write(size_t len)
{
	size_t total;

	/* current period over? */
	if (time_after(jiffies, next_period) && spin_trylock(&period_lock)) {
		finish_accounting_period();
	}
	/* record write */
	total = this_cpu_add_return(bytes_copied, len);
	return !write_oncpu && total > this_cpu_read(max_bytes_on_cpu);
}

enum {
	EP_MODE_MEMCPY,
	EP_MODE_DMA,
	EP_MODE_WORKER,
	EP_MODE_MEMCPY_USER,
	EP_MODE_MEMCPY_SEM,
};

static int ep_mode = EP_MODE_MEMCPY_USER;
module_param(ep_mode, int, S_IRUGO|S_IWUSR);

/* Minimum size to copy asynchronously */
static unsigned int min_size = 4096;
module_param(min_size, uint, S_IRUGO|S_IWUSR);

enum {
	EP_SRC_ADDR,
	EP_SRC_PAGES,
};

/* Copy source, to support copies from userspace */
struct ep_src {
	int type;
	const void *addr;   /* EP_SRC_ADDR */
	struct page **pages; /* EP_SRC_PAGES */
	int num_pages;
};

/* get number of pages spanning given address range */
static inline size_t num_spanning_pages(const void *addr, size_t len)
{
	const unsigned long page_addr = ((unsigned long)addr & PAGE_MASK);

	return DIV_ROUND_UP(len + (unsigned long)addr - page_addr, PAGE_SIZE);
}

static int ep_write_pmem_memcpy(void *dst, struct ep_src src, size_t len)
{
	size_t offset, to_copy;
	struct page **pages;
	switch (src.type) {
	case EP_SRC_ADDR:
		memcpy_flushcache(dst, src.addr, len);
		break;
	case EP_SRC_PAGES:
		/* src pointer may not be aligned on a page boundary */
		offset = offset_in_page(src.addr);
		pages = src.pages;
		/* copy one page at a time */
		while (len > 0) {
			BUG_ON(src.num_pages-- <= 0);
			to_copy = min(len, PAGE_SIZE - offset);
			pr_debug("ep: copy dst=%p src=%p offset=%zu to_copy=%zu", dst, page_to_virt(*pages), offset, to_copy);
			memcpy_flushcache(dst, page_to_virt(*pages) + offset, to_copy);
			dst += to_copy;
			len -= to_copy;
			pages++;
			offset = 0;
		}
		break;
	default:
		BUG();
	}
	
	return (0);
}

static int ep_write_pmem_memcpy_user(void *dst, const void *src, size_t len)
{
	/* same function as used by NOVA */
	/* TODO: does not flush unaligned buffers correctly */
	__copy_from_user_inatomic_nocache(dst, src, len);
	return (0);
}

#define EP_MAX_DMA_CHANS 4
static unsigned int ep_dma_nchans;
module_param(ep_dma_nchans, uint, S_IRUGO|S_IWUSR);

struct {
	bool initialized;
	struct semaphore semaphore;
	spinlock_t spinlock;
	size_t nchans;
	struct dma_chan *chans[EP_MAX_DMA_CHANS];
	bool chan_used[EP_MAX_DMA_CHANS];
} ep_dma_state;


static int ep_write_pmem_dma_init_fini(bool is_fini)
{
	int ret;
	size_t i;
	dma_cap_mask_t cap_mask;
	struct dma_chan *chan;

	if (is_fini) {
		BUG_ON(!ep_dma_state.initialized);
		ret = 0;
		goto fini_all;
	}

	BUG_ON(ep_dma_state.initialized);

	if (ep_dma_nchans < 0) {
		pr_err("ep_dma_nchans parameter must be > 0\n");
		ret = -EINVAL;
		goto fini_memset;
	}
	if (ep_dma_nchans > EP_MAX_DMA_CHANS) {
		pr_err("ep_dma_nchans parameter must be < %d\n", EP_MAX_DMA_CHANS);
		ret = -EINVAL;
		goto fini_memset;
	}
	sema_init(&ep_dma_state.semaphore, ep_dma_nchans);

	spin_lock_init(&ep_dma_state.spinlock);

	for (i = 0; i < ep_dma_nchans; i++) {
		pr_debug("initializing dma chan #%lu\n", i);
		dma_cap_zero(cap_mask);
		dma_cap_set(DMA_MEMCPY, cap_mask);
		chan = dma_request_channel(cap_mask, NULL, NULL);
		if (!chan) {
			pr_err("cannot get dma channel\n");
			ret = -ENXIO;
			goto fini_release_chans;
		}
		pr_debug("found dma chan #%lu: %s\n", i, dma_chan_name(chan));
		ep_dma_state.chans[ep_dma_state.nchans++] = chan;
	}


	ep_dma_state.initialized = true;
	return 0;

fini_all:
fini_release_chans:

	// XXX assert sema unused

	for (i = 0; i < ep_dma_state.nchans; i++)
		dma_release_channel(ep_dma_state.chans[i]);

fini_memset:
	memset(&ep_dma_state, 0, sizeof(ep_dma_state));

	return ret;
}


struct ep_dma_chan {
	struct dma_chan *chan;
	int idx;
};

noinline static void get_chan(struct ep_dma_chan *ret)
{
	size_t i;

	down(&ep_dma_state.semaphore);
	while (true) {
		spin_lock(&ep_dma_state.spinlock);
		for (i = 0; i < ep_dma_state.nchans; i++) {
			if (!ep_dma_state.chan_used[i]) {
				ep_dma_state.chan_used[i] = true;
				spin_unlock(&ep_dma_state.spinlock);
				ret->chan = ep_dma_state.chans[i];
				ret->idx = i;
				return;
			}
		}
		BUG();
	}
}

noinline static void put_chan(struct ep_dma_chan *chan)
{
	spin_lock(&ep_dma_state.spinlock);
	ep_dma_state.chan_used[chan->idx] = false;
	spin_unlock(&ep_dma_state.spinlock);
	up(&ep_dma_state.semaphore);
	memset(chan, 0, sizeof(*chan));
}

struct ep_write_pmem_dma_cb_data {
	struct completion *completion;
	enum dmaengine_tx_result tx_result;
	atomic_t outstanding;
};


static void ep_write_pmem_dma_cb(void *data,
				 const struct dmaengine_result *res)
{

	struct ep_write_pmem_dma_cb_data *cb_data = data;
	int outstanding = atomic_add_return(-1, &cb_data->outstanding);
	BUG_ON(outstanding < 0);
	/* TODO: we lose information if multiple errors happen */
	if (res) {
		enum dmaengine_tx_result dma_err = res->result;
		cb_data->tx_result = dma_err;
	}
	if (outstanding == 0)
		complete(cb_data->completion);
}

noinline void ep_write_pmem_dma_wait_time(ktime_t ns) {
	asm volatile ("" ::: "memory");
}

static int enqueue_dma(struct dma_chan *chan, char *dst, struct page *src_page, size_t src_offset, size_t len, struct ep_write_pmem_dma_cb_data *cb_data)
{
	int ret;
	struct device *dma_device = chan->device->dev;
	struct dmaengine_unmap_data *unmap;
	struct dma_async_tx_descriptor *tx;
	dma_cookie_t cookie;

	/* inspired by ntb_perf.c */
	unmap = dmaengine_get_unmap_data(dma_device, 2, GFP_NOWAIT);
	if (!unmap) {
		ret = -ENOMEM;
		goto out_err;
	}

	unmap->len = len;
	unmap->addr[0] = dma_map_page(dma_device, src_page, src_offset, len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_device, unmap->addr[0])) {
		pr_err("ep_write_pmem_dma: cannot map (src)\n");
		ret = -EINVAL;
		goto out_unmap;
	}
	unmap->to_cnt++; /* only set it now so that dmaengine_unmap won't try to unmap a dma_mapping_error */
	pr_debug("ep: mapped src=%p to src_dma=%llx", page_to_virt(src_page), unmap->addr[0]);

	unmap->addr[1] = dma_map_single(dma_device, dst, len, DMA_FROM_DEVICE);
	if (dma_mapping_error(dma_device, unmap->addr[1])) {
		pr_err("ep_write_pmem_dma: cannot map (dst)\n");
		ret = -EINVAL;
		goto out_unmap;
	}
	unmap->from_cnt++; /* only set it now so that dmaengine_unmap won't try to unmap a dma_mapping_error */
	pr_debug("ep: mapped dst=%p to dst_dma=%llx", dst, unmap->addr[1]);

	tx = dmaengine_prep_dma_memcpy(chan, unmap->addr[1], unmap->addr[0], len,
		DMA_PREP_INTERRUPT| /* not sure if necessary */
		DMA_CTRL_ACK /* not sure if necessary */ );
	if (!tx) {
		pr_err("ep_write_pmem_dma: cannot prep_dma_memcpy\n");
		ret = -EIO;
		goto out_unmap;
	}

	tx->callback_result = ep_write_pmem_dma_cb;
	tx->callback_param = cb_data;

	dma_set_unmap(tx, unmap); /* tx has ref on unmap after this */

	cookie = dmaengine_submit(tx);
	if (dma_submit_error(cookie)) {
		pr_err("ep_write_pmem_dma: cannot submit\n");
		ret = -ENXIO;
		goto out_unmap;
	}
	ret = 0;

out_unmap:
	dmaengine_unmap_put(unmap); /* submit is no ownership transfer! */

out_err:

	return ret;
}

static int ep_write_pmem_dma(void *dst, struct ep_src src, size_t len)
{
	int ret;
	struct ep_dma_chan ep_chan;
	struct dma_chan *chan;
	struct device *dma_device;
	DECLARE_COMPLETION_ONSTACK(dma_done);
	ktime_t pre;
	ktime_t delta;
	int outstanding;
	struct ep_write_pmem_dma_cb_data cb_data;
	struct page **pages;
	size_t offset, to_copy;
	char *dma_dst;

	if (src.type == EP_SRC_ADDR)
		return -ENOTSUPP;
	BUG_ON(src.type != EP_SRC_PAGES);

	BUG_ON(!ep_dma_state.initialized);

	/* get one of the pre-allocated channels */
	get_chan(&ep_chan);
	chan = ep_chan.chan;
	BUG_ON(!chan);
	pr_debug("ep_write_pmem_dma: using chan %s\n", dma_chan_name(chan));

	wmb(); /* writes to src must be architecturally visible by now */

	/*
	 * Get a src and dst DMA address, then do a DMA memcpy of the zeroes to offset 0 of the PMEM blockdev.
	 *
	 * We use the DMA channel's `struct device` as the DMA "slave" device because
	 * this is a main-memory-to-main-memory copy, and thus, any DMA controller
	 * with support for DMA_MEMCPY will do.
	 *
	 * It seems like this functionality has existed as an encapsulated abstraction
	 * in earlier kernel versions, e.g.,
	 * dma_async_memcpy_buf_to_buf from v3.10 https://elixir.bootlin.com/linux/v3.10/source/drivers/dma/dmaengine.c#L893
	 *
	 * But nowadays it seems like we have to do it ourselves, e.g., using dmaengine_prep_dma_memcpy.
	 * Like the ntb_perf.c in https://elixir.bootlin.com/linux/v5.13.1/source/drivers/ntb/test/ntb_perf.c#L825
	 */
	dma_device = chan->device->dev;

	cb_data = (struct ep_write_pmem_dma_cb_data) {
		.completion = &dma_done,
		.outstanding = ATOMIC_INIT(src.num_pages),
	};

	/* src pointer may not be aligned on a page boundary */
	dma_dst = dst;
	offset = offset_in_page(src.addr);
	pages = src.pages;
	/* copy one page at a time */
	while (len > 0) {
		BUG_ON(src.num_pages-- <= 0);
		to_copy = min(len, PAGE_SIZE - offset);
		pr_debug("ep: dma copy dst=%p src=%p offset=%zu to_copy=%zu", dma_dst, page_to_virt(*pages), offset, to_copy);
		ret = enqueue_dma(chan, dma_dst, *pages, offset, to_copy, &cb_data);
		if (ret < 0) {
			goto out_put_chan;
		}
		dma_dst += to_copy;
		len -= to_copy;
		pages++;
		offset = 0;
	}
	/* there mustn't be more pages than len will span (outstanding) */
	BUG_ON(src.num_pages != 0);

	dma_async_issue_pending(chan);


	pre = ktime_get();
	wait_for_completion(&dma_done);
	delta = ktime_get() - pre;
	ep_write_pmem_dma_wait_time(delta);


	outstanding = atomic_read(&cb_data.outstanding);
	BUG_ON(outstanding != 0);

	switch (cb_data.tx_result) {
	case DMA_TRANS_READ_FAILED:
	case DMA_TRANS_WRITE_FAILED:
	case DMA_TRANS_ABORTED:
		/* XXX look at ntb_transport.c for examples of what to do */
		pr_err("dma error: %d\n", cb_data.tx_result);
		ret = -EIO;
		break;

	case DMA_TRANS_NOERROR:
	default:
		ret = 0;
		break;
	}

out_put_chan:
	put_chan(&ep_chan);

	pr_debug("pmem_linuxdma_init returning %d\n", ret);

	BUG_ON(ret > 0);
	return ret;
}


static char *worker_cpus = "";
module_param(worker_cpus, charp, S_IRUGO);

struct {
	bool initialized;
	struct workqueue_struct *wq;
	struct workqueue_attrs *attrs;
} ep_worker_state;

static int ep_write_pmem_worker_init_fini(bool is_fini)
{
	int ret;

	if (is_fini) {
		BUG_ON(!ep_worker_state.initialized);
		ret = 0;
		goto fini_all;
	}

	/* TODO: Figure out correct value for max_active */
	if ((ep_worker_state.wq = alloc_workqueue("ep_worker", WQ_UNBOUND | WQ_SYSFS, 0)) == NULL) {
		ret = -ENOMEM;
		goto fini_ret;
	}

	if ((ep_worker_state.attrs = alloc_workqueue_attrs()) == NULL) {
		ret = -ENOMEM;
		goto fini_wq;
	}

	if ((ret = cpulist_parse(worker_cpus, ep_worker_state.attrs->cpumask)) < 0) {
		pr_err("invalid worker_cpus=\n");
		goto fini_attrs;
	}

	/* TODO: unclear what this does */
	ep_worker_state.attrs->no_numa = true;

	cpus_read_lock();
	ret = apply_workqueue_attrs(ep_worker_state.wq, ep_worker_state.attrs);
	cpus_read_unlock();
	if (ret < 0) {
		pr_err("cannot apply workqueue attrs\n");
		goto fini_attrs;
	}

	ep_worker_state.initialized = true;

	return 0;

fini_all:

fini_attrs:
	free_workqueue_attrs(ep_worker_state.attrs);

fini_wq:
	destroy_workqueue(ep_worker_state.wq);

fini_ret:
	return ret;
}

struct ep_write_work {
	struct work_struct work;
	void *dst;
	struct ep_src src;
	size_t len;
};

static void ep_write_pmem_workfn(struct work_struct *work)
{
	struct ep_write_work *ww = (struct ep_write_work *) work;
	ep_write_pmem_memcpy(ww->dst, ww->src, ww->len);
}

static int ep_write_pmem_worker(void *dst, struct ep_src src, size_t len)
{
	/* TODO: Is it okay to have a work_struct on the stack? */
	struct ep_write_work ww = (struct ep_write_work) {
		.dst = dst,
		.src = src,
		.len = len,
	};
	INIT_WORK(&ww.work, ep_write_pmem_workfn);
	BUG_ON(!queue_work(ep_worker_state.wq, &ww.work));
	flush_work(&ww.work);
	return 0;
}

static int ep_write_pmem_memcpy_sem(void *dst, const void *src, size_t len)
{
	trace_ep_write_pmem_memcpy_sem(dst, src, len);
	down(&memcpy_sem);

	trace_ep_write_pmem_memcpy_sem_write(dst, src, len);
	__copy_from_user_inatomic_nocache(dst, src, len);
	trace_ep_write_pmem_memcpy_sem_write_done(dst, src, len);

	up(&memcpy_sem);
	trace_ep_write_pmem_memcpy_sem_done(dst, src, len);

	return 0;
}

int ep_write_pmem(void *dst, const void *src, size_t len)
{
	int ret;
	int mode = ep_mode;
	bool offload = true;
	struct ep_src ep_src = { .type = EP_SRC_ADDR, .addr = src, .pages = NULL};
	void *src_kernel = NULL;
	struct page **src_pages = NULL;
	int nr_pages;

	if (ep_account_writes)
		offload = ep_record_write(len);

	if (len < min_size || !offload) {
		mode = EP_MODE_MEMCPY_USER;
	}

	/* When copying from userspace, we need to pin or copy the pages involved
	 * so that we can access them from a kernel thread or DMA. */
	if (mode != EP_MODE_MEMCPY_USER && mode != EP_MODE_MEMCPY_SEM && access_ok(src, len)) {
		if (ep_use_gup) {
			nr_pages = num_spanning_pages(src, len);

			src_pages = kmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
			if (src_pages == NULL) {
				ret = -ENOMEM;
				goto err_return;
			}
			ep_src.pages = src_pages;

			ep_src.type = EP_SRC_PAGES;
			ep_src.num_pages = pin_user_pages_fast((unsigned long) src, nr_pages, 0, ep_src.pages);
			if (ep_src.num_pages < 0) {
				ret = ep_src.num_pages;
				goto err_return;
			}
			pr_debug("ep_write_pmem: gup returned %u pages", ep_src.num_pages);
		} else {
			src_kernel = kmalloc(len, GFP_KERNEL);
			if (src_kernel == NULL) {
				ret = -ENOMEM;
				goto err_return;
			}
			BUG_ON(__copy_from_user(src_kernel, src, len) > 0);
			ep_src.addr = src_kernel;
		}
	} 

	if (mode == EP_MODE_DMA && ep_src.type == EP_SRC_ADDR) {
		/* DMA-mapping kernel memory is not allowed */
		mode = EP_MODE_MEMCPY;
	}

	pr_debug("ep_write_pmem: dst=%px src=%px len=%lu%s\n", dst, src, len, mode == EP_MODE_MEMCPY || mode == EP_MODE_MEMCPY_USER ? " (on-CPU)" : "");
	
	switch (mode) {
		case EP_MODE_MEMCPY:
			ret = ep_write_pmem_memcpy(dst, ep_src, len);
			break;
		case EP_MODE_DMA:
			ret = ep_write_pmem_dma(dst, ep_src, len);
			break;
		case EP_MODE_WORKER:
			ret = ep_write_pmem_worker(dst, ep_src, len);
			break;
		case EP_MODE_MEMCPY_USER:
			ret = ep_write_pmem_memcpy_user(dst, ep_src.addr, len);
			break;
		case EP_MODE_MEMCPY_SEM:
			ret = ep_write_pmem_memcpy_sem(dst, ep_src.addr, len);
			break;
		default:
			pr_err("invalid value for ep_mode: %d\n", mode);
			ret = -EINVAL;
			break;
	}

	while (ep_src.num_pages-- > 0) {
		unpin_user_page(*(ep_src.pages++));
	}
	kfree(src_kernel);
	kfree(src_pages);
	
err_return:
	BUG_ON(ret > 0);
	WARN_ON(ret < 0);
	return ret;
}

EXPORT_SYMBOL(ep_write_pmem);

#ifdef CONFIG_EFFICIENT_PMEM_TEST


/*
 * By not using the lock, there is a race condition between the setup and write.
 * If performance is of concern, the locking can be left out. This should only
 * be used for testing. In this case, user space has to ensure that write and
 * setup ioctls are properly synchronized.
 * 
 * The user space tool of ep_test should work without locking.
 */
#ifdef CONFIG_EFFICIENT_PMEM_TEST_USE_LOCK

#define ep_test_lock_setup(lock) write_lock((lock))
#define ep_test_unlock_setup(lock) write_unlock((lock))
#define ep_test_lock_write(lock) read_lock((lock))
#define ep_test_unlock_write(lock) read_unlock((lock))

#else

#define ep_test_lock_setup(lock)
#define ep_test_unlock_setup(lock)
#define ep_test_lock_write(lock)
#define ep_test_unlock_write(lock)

#endif /* CONFIG_EFFICIENT_PMEM_TEST_USE_LOCK */


static struct block_device *test_blkd = NULL;
static struct dax_device *test_daxd = NULL;
static void *test_pmem_vaddr = NULL;
static pfn_t test_pmem_pfn = { 0 };
static long test_pmem_npages = 0;

static DEFINE_RWLOCK(ep_test_lock);

static long eff_pmem_test_setup(const char *path, bool is_open)
{
	long ret;

	if (!is_open) {
		ret = 0;
		pr_debug("eff_pmem_test_setup: close\n");
		goto fini_all;
	}

	pr_debug("eff_pmem_test_setup: open\n");

	if (test_blkd) {
		// blkdev already open
		ret = -EBUSY;
		goto err_return;
	}

	if (IS_ERR(test_blkd = blkdev_get_by_path(
			   path, FMODE_EXCL | FMODE_WRITE, THIS_MODULE))) {
		ret = PTR_ERR(test_blkd);
		pr_err("failed to open blkdev (%ld)\n", ret);
		goto cleanup_vars;
	}

	if (!(test_daxd = fs_dax_get_by_bdev(test_blkd))) {
		pr_err("failed to get dax dev by bdev\n");
		ret = -EPERM;
		goto free_blkdev;
	}

	if (!dax_supported(test_daxd, test_blkd, PAGE_SIZE, 0,
				bdev_nr_sectors(test_blkd))) {
		pr_err("dax not supported\n");
		ret = -EPERM;
		goto free_blkdev;
	}

	test_pmem_npages = dax_direct_access(test_daxd, 0, LONG_MAX / PAGE_SIZE,
					     &test_pmem_vaddr, &test_pmem_pfn);
	if (test_pmem_npages <= 0) {
		pr_err("dax_direct_access failed\n");
		ret = test_pmem_npages;
		goto free_daxdev;
	}

	BUG_ON(!test_pmem_vaddr);

	return 0;

fini_all:
free_daxdev:
	fs_put_dax(test_daxd);
free_blkdev:
	blkdev_put(test_blkd, FMODE_EXCL | FMODE_WRITE);
cleanup_vars:
	test_daxd = NULL;
	test_blkd = NULL;
	test_pmem_vaddr = NULL;
	test_pmem_npages = 0;
	test_pmem_pfn = (pfn_t){ 0 };
err_return:
	return ret;
}

static long eff_pmem_test_write(u64 addr, u64 size, u64 off)
{
	long ret;

	if (!test_daxd) {
		ret = -ENODEV;
		goto out;
	}

	BUG_ON(!test_pmem_vaddr);

	if (test_pmem_npages * PAGE_SIZE < off + size - 1) {
		pr_err("eff_pmem_test_write: invalid offset\n");
		ret = -ENOSPC;
		goto out;
	}

	ret = ep_write_pmem(test_pmem_vaddr + off, (void *)addr, size);

out:
	return ret;
}

static long __eff_pmem_test(unsigned int cmd, struct eff_pmem_test *ep_test)
{
	long ret;
	char buf[sizeof_field(struct eff_pmem_test, diskname) +
		 sizeof("/dev/")] = { 0 };

	switch (cmd) {
	case EFF_PMEM_TEST_SETUP:
		ep_test_lock_setup(&ep_test_lock);
		snprintf(buf, sizeof(buf), "/dev/%s", ep_test->diskname);
		ret = eff_pmem_test_setup(buf, ep_test->is_open);
		ep_test_unlock_setup(&ep_test_lock);
		break;
	case EFF_PMEM_TEST_WRITE:
		ep_test_lock_write(&ep_test_lock);
		ret = eff_pmem_test_write(ep_test->addr, ep_test->size,
					  ep_test->off);
		ep_test_unlock_write(&ep_test_lock);
		break;
	default:
		BUG();
	}

	return ret;
}

static long eff_pmem_test(struct file *filep, unsigned int cmd,
			  unsigned long arg)
{
	long ret;
	struct eff_pmem_test ep_test;

	switch (cmd) {
	case EFF_PMEM_TEST_SETUP:
	case EFF_PMEM_TEST_WRITE:
		break;
	default:
		return -EINVAL;
	}

	if (copy_from_user(&ep_test, (void __user *)arg, sizeof(ep_test)))
		return -EFAULT;

	if ((ret = __eff_pmem_test(cmd, &ep_test)))
		return ret;

	return 0;
}

static const struct file_operations _fops_test = {
	.open = nonseekable_open,
	.unlocked_ioctl = eff_pmem_test,
};
#endif /* CONFIG_EFFICIENT_PMEM_TEST */

static struct dentry *ep_debugfs_dir;

static int ep_debugfs_init_fini(bool is_fini)
{
	int ret;

	if (is_fini) {
		ret = 0;
		goto fini_all;
	}
	
	ep_debugfs_dir = debugfs_create_dir("eff_pmem", NULL);
	if (IS_ERR(ep_debugfs_dir)) {
		ret = PTR_ERR(ep_debugfs_dir);
		goto err_return;
	}
	
	debugfs_create_bool("write_oncpu", S_IRUGO, ep_debugfs_dir, &write_oncpu);
	debugfs_create_size_t("pmem_write_bytes_period", S_IRUGO, ep_debugfs_dir, &pmem_write_bytes_period);
	debugfs_create_size_t("pmem_write_bandwidth", S_IRUGO, ep_debugfs_dir, &pmem_write_bandwidth);

#ifdef CONFIG_EFFICIENT_PMEM_TEST
	debugfs_create_file("eff_pmem_test", S_IWUSR | S_IRUSR, ep_debugfs_dir, NULL, &_fops_test);
#endif /* CONFIG_EFFICIENT_PMEM_TEST */
	
	return 0;
fini_all:
	debugfs_remove_recursive(ep_debugfs_dir);
err_return:
	return ret;
}

static int ep_write_pmem_memcpy_sem_init_fini(bool is_fini)
{
	int ret;

	if (is_fini) {
		ret = 0;
		goto fini_all;
	}

	sema_init(&memcpy_sem, ep_max_memcpy_sem);

	return 0;

fini_all:
	return ret;
}

static int ep_init_fini(bool is_fini)
{
	int ret;

	if (is_fini) {
		ret = 0;
		goto fini_all;
	}

	if ((ret = ep_write_pmem_dma_init_fini(false)))
		goto err_return;

	if ((ret = ep_write_pmem_worker_init_fini(false)))
		goto err_dma_init_fini;
	
	if ((ret = ep_debugfs_init_fini(false)))
		goto err_pmem_worker_init_fini;

	if ((ret = ep_write_pmem_memcpy_sem_init_fini(false)))
		goto err_memcpy_sem_init_fini;

	return 0;

fini_all:
	BUG_ON(ep_debugfs_init_fini(true));
err_memcpy_sem_init_fini:
	BUG_ON(ep_write_pmem_memcpy_sem_init_fini(true));
err_pmem_worker_init_fini:
	BUG_ON(ep_write_pmem_worker_init_fini(true));
err_dma_init_fini:
	BUG_ON(ep_write_pmem_dma_init_fini(true));
err_return:
	return ret;
}

static int ep_init(void)
{
	return ep_init_fini(false);
}

static void ep_exit(void)
{
	BUG_ON(ep_init_fini(true));
}

MODULE_LICENSE("Dual BSD/GPL");
module_init(ep_init);
module_exit(ep_exit);
