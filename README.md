Analyzing and Improving CPU and Energy Efficiency of PM File Systems
====================================================================

Source code for our DIMES'23 paper: https://dl.acm.org/doi/10.1145/3609308.3625265


Efficient PM Copy
-----------------

The source code of our efficient PM copy routines is in `module/`.  To build
it, you need a Linux 5.15 kernel with `linux-5.15.diff` applied.

We provide a patched kernel that includes NOVA support at https://github.com/KIT-OSGroup/linux/tree/ep-base
Build, install and boot into that kernel as usual.
Then, build our `eff_pmem` module and patched NOVA as follows:

```
make -C module
make -C nova
```

Insert `eff_pmem.ko` with appropriate parameters.

```
insmod module/eff_pmem.ko ep_max_memcpy_sem=2 worker_cpus=0,1 ep_dma_nchans=2 ep_mode=3
```

- `ep_max_memcpy_sem`: Number of parallel writers the semaphore allows
- `worker_cpus`: Set of CPUs for the workqueue worker threads
- `ep_dma_nchans`: Number of I/OAT DMA channels
- `ep_mode`: Which variant to use. See `EP_MODE_*` constants in `module/eff_pmem.c`. 3: normal copy, 4: Semaphore, 2: Workqueue, 1: DMA

You can also change `ep_mode` later by writing to `/sys/module/eff_pmem/parameters/ep_mode`.

Finally, load and use NOVA as usual (`insmod nova/nova.ko`).
