// SPDX-License-Identifier: GPL-2.0
/*
 * Primary bucket allocation code
 *
 * Copyright 2012 Google, Inc.
 *
 * Allocation in bcache is done in terms of buckets:
 *
 * Each bucket has associated an 8 bit gen; this gen corresponds to the gen in
 * btree pointers - they must match for the pointer to be considered valid.
 *
 * Thus (assuming a bucket has no dirty data or metadata in it) we can reuse a
 * bucket simply by incrementing its gen.
 *
 * The gens (along with the priorities; it's really the gens are important but
 * the code is named as if it's the priorities) are written in an arbitrary list
 * of buckets on disk, with a pointer to them in the journal header.
 *
 * When we invalidate a bucket, we have to write its new gen to disk and wait
 * for that write to complete before we use it - otherwise after a crash we
 * could have pointers that appeared to be good but pointed to data that had
 * been overwritten.
 *
 * Since the gens and priorities are all stored contiguously on disk, we can
 * batch this up: We fill up the free_inc list with freshly invalidated buckets,
 * call prio_write(), and when prio_write() finishes we pull buckets off the
 * free_inc list and optionally discard them.
 *
 * free_inc isn't the only freelist - if it was, we'd often to sleep while
 * priorities and gens were being written before we could allocate. c->free is a
 * smaller freelist, and buckets on that list are always ready to be used.
 *
 * If we've got discards enabled, that happens when a bucket moves from the
 * free_inc list to the free list.
 *
 * There is another freelist, because sometimes we have buckets that we know
 * have nothing pointing into them - these we can reuse without waiting for
 * priorities to be rewritten. These come from freed btree nodes and buckets
 * that garbage collection discovered no longer had valid keys pointing into
 * them (because they were overwritten). That's the unused list - buckets on the
 * unused list move to the free list, optionally being discarded in the process.
 *
 * It's also important to ensure that gens don't wrap around - with respect to
 * either the oldest gen in the btree or the gen on disk. This is quite
 * difficult to do in practice, but we explicitly guard against it anyways - if
 * a bucket is in danger of wrapping around we simply skip invalidating it that
 * time around, and we garbage collect or rewrite the priorities sooner than we
 * would have otherwise.
 *
 * bch_bucket_alloc() allocates a single bucket from a specific cache.
 *
 * bch_bucket_alloc_set() allocates one or more buckets from different caches
 * out of a cache set. 在cache_set之外从不同的cache中分配一个或者多个buckets
 *
 * free_some_buckets() drives all the processes described above. It's called
 * from bch_bucket_alloc() and a few other places that need to make sure free
 * buckets are ready.
 *
 * invalidate_buckets_(lru|fifo)() find buckets that are available to be
 * invalidated, and then invalidate them and stick them on the free_inc list -
 * in either lru or fifo order.
 */

#include <errno.h>
#include <stdlib.h>

#include "bcache.h"
#include "btree.h"
#include "list.h"
#include "bset.h"
#include "atomic.h"
#include "util.h"

#define MAX_OPEN_BUCKETS 128
/* Bucket heap / gen */

uint8_t bch_inc_gen(struct cache *ca, struct bucket *b)
{
  uint8_t ret = ++b->gen;

  ca->set->need_gc = max(ca->set->need_gc, bucket_gc_gen(b));
  /*WARN_ON_ONCE(ca->set->need_gc > BUCKET_GC_GEN_MAX);*/

  return ret;
}

//TODO
void bch_rescale_priorities(struct cache_set *c, int sectors)
{
  struct cache *ca;
  struct bucket *b;
  unsigned next = c->nbuckets * c->sb.bucket_size / 1024;
  unsigned i;
  int r;

  atomic_sub(sectors, &c->rescale);

  do {
    r = atomic_read(&c->rescale);

    if (r >= 0)
      return;
  } while (atomic_cmpxchg(&c->rescale, r, r + next) != r);

  pthread_mutex_lock(&c->bucket_lock);

  c->min_prio = USHRT_MAX;

  for_each_cache(ca, c, i)
    for_each_bucket(b, ca)
    if (b->prio &&
        b->prio != BTREE_PRIO &&
        !atomic_read(&b->pin)) {
      b->prio--;
      c->min_prio = min(c->min_prio, b->prio);
    }

  pthread_mutex_unlock(&c->bucket_lock);
}

/*
 * Background allocation thread: scans for buckets to be invalidated,
 * invalidates them, rewrites prios/gens (marking them as invalidated on disk),
 * then optionally issues discard commands to the newly free buckets, then puts
 * them on the various freelists.
 */

static inline bool can_inc_bucket_gen(struct bucket *b)
{
  return bucket_gc_gen(b) < BUCKET_GC_GEN_MAX;
}

bool bch_can_invalidate_bucket(struct cache *ca, struct bucket *b)
{
  BUG_ON(!ca->set->gc_mark_valid);

  return (!GC_MARK(b) || GC_MARK(b) == GC_MARK_RECLAIMABLE) &&
        !atomic_read(&b->pin) && can_inc_bucket_gen(b);
}

//TODO
void __bch_invalidate_one_bucket(struct cache *ca, struct bucket *b)
{
  //lockdep_assert_held(&ca->set->bucket_lock);
  CACHE_DEBUGLOG(CAT_RELEASE_BUCKET, "release bucket %p ( %ld GC_MOVE %d GC_MARK %d prio %d gc_sectors_used %lu pin %d) \n",
                b, (b-ca->buckets), GC_MOVE(b), GC_MARK(b), b->prio, GC_SECTORS_USED(b), atomic_read(&b->pin));
  BUG_ON(GC_MARK(b) && GC_MARK(b) != GC_MARK_RECLAIMABLE);

  //if (GC_SECTORS_USED(b))
  //	trace_bcache_invalidate(ca, b - ca->buckets);

  bch_inc_gen(ca, b);
  b->prio = INITIAL_PRIO;
  atomic_inc(&b->pin); //TODO
}

static void bch_invalidate_one_bucket(struct cache *ca, struct bucket *b)
{
  __bch_invalidate_one_bucket(ca, b);
  fifo_push(&ca->free_inc, b - ca->buckets);
}

/*
 * Determines what order we're going to reuse buckets, smallest bucket_prio()
 * first: we also take into account the number of sectors of live data in that
 * bucket, and in order for that multiply to make sense we have to scale bucket
 *
 * Thus, we scale the bucket priorities so that the bucket with the smallest
 * prio is worth 1/8th of what INITIAL_PRIO is worth.
 */

#define bucket_prio(b)                                                  \
  ({                                                                    \
   unsigned min_prio = (INITIAL_PRIO - ca->set->min_prio) / 8;          \
                                                                        \
   (b->prio - ca->set->min_prio + min_prio) * GC_SECTORS_USED(b);       \
   })

#define bucket_max_cmp(l, r)    (bucket_prio(l) < bucket_prio(r))
#define bucket_min_cmp(l, r)    (bucket_prio(l) > bucket_prio(r))

static void invalidate_buckets_lru(struct cache *ca)
{
  struct bucket *b;
  ssize_t i;

  ca->heap.used = 0;

  for_each_bucket(b, ca) {
    if (!bch_can_invalidate_bucket(ca, b))
      continue;

    if (!heap_full(&ca->heap))
      heap_add(&ca->heap, b, bucket_max_cmp);
    else if (bucket_max_cmp(b, heap_peek(&ca->heap))) {
      ca->heap.data[0] = b;
      heap_sift(&ca->heap, 0, bucket_max_cmp);
    }
  }

  for (i = ca->heap.used / 2 - 1; i >= 0; --i)
    heap_sift(&ca->heap, i, bucket_min_cmp);

  while (!fifo_full(&ca->free_inc)) {
    if (!heap_pop(&ca->heap, b, bucket_min_cmp)) {
      /*
       * We don't want to be calling invalidate_buckets()
       * multiple times when it can't do anything
       */
      //TODO
      ca->invalidate_needs_gc = 1;
      wake_up_gc(ca->set); /* 若ca->free_inc未满，则wake_up_gc */
      return;
    }

    bch_invalidate_one_bucket(ca, b);
  }
}

static void invalidate_buckets_fifo(struct cache *ca)
{
  struct bucket *b;
  size_t checked = 0;

  while (!fifo_full(&ca->free_inc)) {
    if (ca->fifo_last_bucket <  ca->sb.first_bucket ||
        ca->fifo_last_bucket >= ca->sb.nbuckets)
      ca->fifo_last_bucket = ca->sb.first_bucket;

    b = ca->buckets + ca->fifo_last_bucket++;

    if (bch_can_invalidate_bucket(ca, b))
      bch_invalidate_one_bucket(ca, b);

    if (++checked >= ca->sb.nbuckets) {
      ca->invalidate_needs_gc = 1;
      wake_up_gc(ca->set); //TODO
      return;
    }
  }
}

static void invalidate_buckets_random(struct cache *ca)
{
  struct bucket *b;
  size_t checked = 0;

  while (!fifo_full(&ca->free_inc)) {
    size_t n;
    get_random_bytes(&n, sizeof(n)); // TODO

    n %= (size_t) (ca->sb.nbuckets - ca->sb.first_bucket);
    n += ca->sb.first_bucket;

    b = ca->buckets + n;

    if (bch_can_invalidate_bucket(ca, b))
      bch_invalidate_one_bucket(ca, b);

    if (++checked >= ca->sb.nbuckets / 2) {
      ca->invalidate_needs_gc = 1;
      wake_up_gc(ca->set); //TODO
      return;
    }
  }
}

static void invalidate_buckets(struct cache *ca)
{
  BUG_ON(ca->invalidate_needs_gc);
  CACHE_DEBUGLOG(CAT_ALLOC,"cache replacement %d \n",CACHE_REPLACEMENT(&ca->sb));
  switch (CACHE_REPLACEMENT(&ca->sb)) {
  case CACHE_REPLACEMENT_LRU:
    invalidate_buckets_lru(ca);
    break;
  case CACHE_REPLACEMENT_FIFO:
    invalidate_buckets_fifo(ca);
    break;
  case CACHE_REPLACEMENT_RANDOM:
    invalidate_buckets_random(ca);
    break;
  }
}

#define allocator_wait(ca, cond)                                        \
  do {                                                                  \
    while(1) {                                                          \
      pthread_mutex_lock(&ca->alloc_mut);                               \
      if (cond)                                                         \
        break;                                                          \
                                                                        \
      pthread_mutex_unlock(&ca->set->bucket_lock);                      \
      pthread_cond_wait(&ca->alloc_cond, &ca->alloc_mut);               \
      pthread_mutex_unlock(&ca->alloc_mut);                             \
      pthread_mutex_lock(&ca->set->bucket_lock);                        \
    }                                                                   \
    pthread_mutex_unlock(&ca->alloc_mut);                               \
  } while (0)

void wake_up_reserve_cond(struct cache *ca)
{
  pthread_cond_signal(&ca->set->btree_cache_wait_cond);
  pthread_cond_signal(&ca->set->bucket_wait_cond);
}

static int bch_allocator_push(struct cache *ca, long bucket)
{
  unsigned i;
  bool ret = false;

  /* Prios/gens are actually the most important reserve */
  if (fifo_push(&ca->free[RESERVE_PRIO], bucket)) {
    CACHE_DEBUGLOG(CAT_ALLOC, "fifo_push bucket %ld to free[prio] success,goto wake up\n",
                bucket);
    ret = true;
    goto wake_up;
  }
  for (i = 0; i < RESERVE_NR; i++)
    if (fifo_push(&ca->free[i], bucket)) {
      CACHE_DEBUGLOG(CAT_ALLOC, "fifo_push bucket %ld to free[%d] success,goto wake up\n",
                bucket, i);

      ret = true;
      goto wake_up;
  }
  CACHE_DEBUGLOG(CAT_ALLOC, "fifo_push bucket %ld failed ret %d\n", bucket, ret);
wake_up:
  wake_up_reserve_cond(ca);
  return ret;
}

static void bch_allocator_thread(void *arg)
{
  struct cache *ca = arg;

  pthread_setname_np(pthread_self(), "bch allocator");
  CACHE_INFOLOG(CAT_ALLOC, "start bucket alloc thread %p\n", pthread_self());

  /*
   * when alloc thread is cond wait, she will unlock bucket_lock
   * and when alloc thread is running, she will hand bucket_lock
   */
  pthread_mutex_lock(&ca->set->bucket_lock);
  while (1) {
    /*
     * First, we pull buckets off of the unused and free_inc lists,
     * possibly issue discards to them, then we add the bucket to
     * the free list:
     * 如果后备free_inc不为空，fifo_pop(&ca->free_inc, bucket)一个
     * 后备bucket，调用allocator_wait(ca, bch_allocator_push(ca, bucket));
     * 加入ca->free中，这样保证分配函数有可用的bucket。然后唤醒由于
     *  wait alloc而等待的线程。若ca->free已满，则alloc_thread阻塞
     */
    while (!fifo_empty(&ca->free_inc)) {
      long bucket;
      fifo_pop(&ca->free_inc, bucket);
      CACHE_DEBUGLOG(CAT_ALLOC,"pop bucket %ld from free_inc \n",bucket);

      // TODO
      /* 对磁盘进行trim操作，比如使用blkdiscard命令时 */
      /*
      if (ca->discard) {
        mutex_unlock(&ca->set->bucket_lock);
        blkdev_issue_discard(ca->bdev,
                        bucket_to_sector(ca->set, bucket),
                        ca->sb.bucket_size, GFP_KERNEL, 0);
        mutex_lock(&ca->set->bucket_lock);
      }
      */
      // if push bucket sucess, alloc thread will goto continue until push failed,
      // which means that full, so alloc thread will goto cond wait
      allocator_wait(ca, bch_allocator_push(ca, bucket));
    }

    /*
     * We've run out of free buckets, we need to find some buckets
     * we can invalidate.
     * First: invalidate them in memory
     * Second: add them to the free_inc list:
     */
retry_invalidate:
    /*
     * gc_mark_valid: gc_mark_valid is for caceh_set, when gc start set gc_mark_valid =0
     *                when gc finish set gc_mark_valid = 1
     *                so gc_mark_valid is true, meas we can wake up gc, false, meas we will cond wait
     * invalidate_needs_gc is false mean there is no invalidate bucket taks running
     * so will call invalidate_buckets
     */
    allocator_wait(ca, ca->set->gc_mark_valid && !ca->invalidate_needs_gc);
    invalidate_buckets(ca);

    /*
     * Now, we write their new gens to disk so we can start writing
     * new stuff to them:
     */
    // when btree node split or gc (freeing) then will block prio, we should wait
    // until those node write complete then write prio
    allocator_wait(ca, !atomic_read(&ca->set->prio_blocked));
    if (CACHE_SYNC(&ca->set->sb)) {
      /*
       * This could deadlock if an allocation with a btree
       * node locked ever blocked - having the btree node
       * locked would block garbage collection, but here we're
       * waiting on garbage collection before we invalidate
       * and free anything.
       *
       * But this should be safe since the btree code always
       * uses btree_check_reserve() before allocating now, and
       * if it fails it blocks without btree nodes locked.
       */
      /*
       * when free_inc is not full, goto retry and cond wait for gc finish.
       * this meas that free_inc must be refill until full
       */
      if (!fifo_full(&ca->free_inc))
        goto retry_invalidate;
      bch_prio_write(ca);
    }
  }
}

/*
 * Allocation
 * 分配bucket，将cache disk的线性空间划分为若干个bucket，
 * 每个bucket的大小一致
 */

long bch_bucket_alloc(struct cache *ca, unsigned reserve, bool wait)
{
  struct bucket *b;
  long r;

  if (fifo_pop(&ca->free[RESERVE_NONE], r) ||
      fifo_pop(&ca->free[reserve], r)) {
    goto out;
  }

  if (!wait) {
    /* 如果不需要等待，直接返回了 */
    //trace_bcache_alloc_fail(ca, reserve);
    return -1;
  }

  do {
    /* 如果没有空闲可用，则当前线程进入等待，直到有可用的bucket */
    //prepare_to_wait(&ca->set->bucket_wait, &w,
    //		TASK_UNINTERRUPTIBLE);

    pthread_mutex_unlock(&ca->set->bucket_lock);
    pthread_mutex_lock(&ca->set->bucket_wait_mut);
    pthread_cond_wait(&ca->set->bucket_wait_cond, &ca->set->bucket_wait_mut);
    pthread_mutex_unlock(&ca->set->bucket_wait_mut);
    pthread_mutex_lock(&ca->set->bucket_lock);
  } while (!fifo_pop(&ca->free[RESERVE_NONE], r) &&
      !fifo_pop(&ca->free[reserve], r));

  //finish_wait(&ca->set->bucket_wait, &w);
out:
  //wake_up_process(ca->alloc_thread); /* kernel/sched/core.c, 唤醒指定的进程 */
  /*printf(" start wake_up_alloc_thread \n");*/
  if ( ca->alloc_thread )
    wake_up_alloc_thread(ca); /* kernel/sched/core.c, 唤醒指定的进程 */

  //trace_bcache_alloc(ca, reserve);

  //if (expensive_debug_checks(ca->set)) {
  //	size_t iter;
  //	long i;
  //	unsigned j;

  //	for (iter = 0; iter < prio_buckets(ca) * 2; iter++)
  //		;
  //		//BUG_ON(ca->prio_buckets[iter] == (uint64_t) r);

  //	for (j = 0; j < RESERVE_NR; j++)
  //		fifo_for_each(i, &ca->free[j], iter)
  //			;//BUG_ON(i == r);
  //	fifo_for_each(i, &ca->free_inc, iter)
  //		//BUG_ON(i == r);
  //}

  b = ca->buckets + r;

  BUG_ON(atomic_read(&b->pin) != 1);

  SET_GC_SECTORS_USED(b, ca->sb.bucket_size);

  if (reserve <= RESERVE_PRIO) {
    SET_GC_MARK(b, GC_MARK_METADATA);
    SET_GC_MOVE(b, 0);
    b->prio = BTREE_PRIO; /* 65536 */
  } else {
    SET_GC_MARK(b, GC_MARK_RECLAIMABLE);
    SET_GC_MOVE(b, 0);
    b->prio = INITIAL_PRIO;
  }

  if (ca->set->avail_nbuckets > 0) {
    ca->set->avail_nbuckets--;
    bch_update_bucket_in_use(ca->set, &ca->set->gc_stats);
  }

  CACHE_DEBUGLOG(CAT_ALLOC_BUCKET, "alloc bucket %p ( %ld GC_MOVE %d GC_MARK %d prio %d gc_sectors_used %lu pin %d) \n",
                 b, r, GC_MOVE(b), GC_MARK(b), b->prio, GC_SECTORS_USED(b), atomic_read(&b->pin));

  return r;
}

void __bch_bucket_free(struct cache *ca, struct bucket *b)
{
  SET_GC_MARK(b, 0);
  SET_GC_SECTORS_USED(b, 0);
  if (ca->set->avail_nbuckets < ca->set->nbuckets) {
    ca->set->avail_nbuckets++;
    bch_update_bucket_in_use(ca->set, &ca->set->gc_stats);
  }
}

void bch_bucket_free(struct cache_set *c, struct bkey *k)
{
  unsigned i;
  /* KEY_PTRS表示cache设备的个数 */
  for (i = 0; i < KEY_PTRS(k); i++){
    __bch_bucket_free(PTR_CACHE(c, k, i), PTR_BUCKET(c, k, i));
  }
}

int __bch_bucket_alloc_set(struct cache_set *c, unsigned reserve,
                          struct bkey *k, int n, bool wait)
{
  int i;
  //lockdep_assert_held(&c->bucket_lock);
  BUG_ON(!n || n > c->caches_loaded || n > 8);
  bkey_init(k);
  /* sort by free space/prio of oldest data in caches */
  for (i = 0; i < n; i++) {
    struct cache *ca = c->cache_by_alloc[i];
    long b = bch_bucket_alloc(ca, reserve, wait);

    if (b == -1) {
      goto err;
    }
    /*
     * #define PTR(gen, offset, dev)                             \
     *       ((((__u64) dev) << 51) | ((__u64) offset) << 8 | gen)
     *
     * (((__u64)ca->sb.nr_this_dev)<<51) |
     *   (((__u64)bucket_to_sector(c, b)) << 8 | ca->buckets[b].gen)
     */
    k->ptr[i] = PTR(ca->buckets[b].gen, bucket_to_sector(c, b),
        ca->sb.nr_this_dev);
    SET_KEY_PTRS(k, i + 1);
  }

  return 0;
err:
  bch_bucket_free(c, k);
  bkey_put(c, k);
  return -1;
}

int bch_bucket_alloc_set(struct cache_set *c, unsigned reserve,
                        struct bkey *k, int n, bool wait)
{
  int ret;
  pthread_mutex_lock(&c->bucket_lock);
  ret = __bch_bucket_alloc_set(c, reserve, k, n, wait);
  pthread_mutex_unlock(&c->bucket_lock);
  return ret;
}

/* Sector allocator */

struct open_bucket {
  struct list_head      list;
  unsigned              last_write_point;
  unsigned              sectors_free;
  BKEY_PADDED(key); /* union { struct bkey key; __u64 key_pad[8]; }; */
  bool wait;
};

/*
 * We keep multiple buckets open for writes, and try to segregate different
 * write streams for better cache utilization: first we look for a bucket where
 * the last write to it was sequential with the current write, and failing that
 * we look for a bucket that was last used by the same task.
 * 我们保持多个buckets打开来用作写，并试图将多个写入流给分开，以便更好地利用
 * cache：首先我们会查找最后一个写来作为当前写入的顺序，当找到的一个bucket是被
 * 同一个任务最后使用的，就失败。
 *
 * The ideas is if you've got multiple tasks pulling data into the cache at the
 * same time, you'll get better cache utilization if you try to segregate their
 * data and preserve locality.
 * 思路就是，如果你得到多个任务在同一时刻往cache里面写数据，可以试图将它们的数据
 * 分开并在本地预留，那么将会有更好的cache利用率。
 *
 * For example, say you've starting Firefox at the same time you're copying a
 * bunch of files. Firefox will likely end up being fairly hot and stay in the
 * cache awhile, but the data you copied might not be; if you wrote all that
 * data to the same buckets it'd get invalidated at the same time.
 * 比如说，你打开Firefox的同时又在拷贝数据。Firefox可能最终会变得很热（数据被
 * 频繁使用），并在cache中保留一段时间，但是你所拷贝的数据可能不会。如果你将所
 * 有的数据都写入相同的buckets当中，那么它们可能会同时失效。
 *
 * Both of those tasks will be doing fairly random IO so we can't rely on
 * detecting sequential IO to segregate their data, but going off of the task
 * should be a sane heuristic.
 * 这两个任务都会做相当多的随机IO，因此不能依赖检测顺序IO来将它们的数据分开。
 *
 * How to find best open bucket:
 * 1. Try to match start address is equal bucket's last address and sectors_free greater than alloc.
 * 2. Try to find sectors_free equal to alloc.
 * 3. Try to find sectors_free greater than alloc.
 * 4. Try to find sectors_free equal to zero.
 * 5. Try to find the smallest open bucket to invalid.
 *
 * Todo: How to use write_point to filter open buckets.
 */
static struct open_bucket *
pick_data_bucket(struct cache_set *c, const struct bkey *search,
                struct bkey *alloc, unsigned sectors, struct open_bucket **last)
{
  struct open_bucket *ret, *min_bkt = NULL, *eq_task = NULL, *gt_task = NULL, *zero_task = NULL;
  int i;

  if (*last){
    ret = *last;
    if (ret->sectors_free) {
      CACHE_ERRORLOG(CAT_ALLOC, "alloc for no empty open bucket(%p) sectors_free=%u\n",
                     ret, ret->sectors_free);
      assert("alloc for no empty open bucket" == 0);
    }
    goto found;
  }

  min_bkt = list_last_entry(&c->data_buckets, struct open_bucket, list);

  list_for_each_entry_reverse(ret, &c->data_buckets, list) {
    if (ret->wait){
      continue;
    }
    if (!bkey_cmp(&ret->key, search) && ret->sectors_free > sectors) {
      goto found;
    } else {
//      if (ret->last_write_point == write_point)
//        ret_task = ret;
      if (ret->sectors_free == sectors)
        eq_task = ret;
      else if (ret->sectors_free > sectors)
        gt_task = ret;
      else if (!ret->sectors_free)
        zero_task = ret;
      else if (ret->sectors_free < min_bkt->sectors_free){
        min_bkt = ret;
      }
    }
  }

  ret = eq_task?:(gt_task?: zero_task);
  if (ret) {
    goto found;
  }

  // must make sure the bucket not used by other thread
  if (min_bkt->wait)
    return NULL;
  ret = min_bkt;
  ret->sectors_free = 0;
  for (i = 0; i < KEY_PTRS(&ret->key); i++){
    atomic_dec(&PTR_BUCKET(c, &ret->key, i)->pin);
  }

found:
  /* 找到的bucket中没有可用的扇区？*/
  if (!ret->sectors_free && KEY_PTRS(alloc)) {
    ret->sectors_free = c->sb.bucket_size;
    bkey_copy(&ret->key, alloc);
    bkey_init(alloc);
    ret->wait = false;
  }
  if (!ret->sectors_free) {
    ret->wait = true;
    *last = ret;
    CACHE_DEBUGLOG(CAT_ALLOC, "last open_bucket: %p, sectors_free=%u, wait %d\n",
        *last, (*last)->sectors_free, (*last)->wait);
    ret = NULL;
  }
  return ret;
}

/*
 * Allocates some space in the cache to write to, and k to point to the newly
 * allocated space, and updates KEY_SIZE(k) and KEY_OFFSET(k) (to point to the
 * end of the newly allocated space).
 * 分配cache中的空间用作写（这里的cache是ssd吧？），k指向新分配的空间，并更新
 * KEY_SIZE(k)和KEY_OFFSET(k)（指向新分配的空间的结束位置）
 *
 * May allocate fewer sectors than @sectors, KEY_SIZE(k) indicates how many
 * sectors were actually allocated.
 * 分配的空间可能会少于sectors参数指定的值，KEY_SIZE(k)指示了分配了多少个扇区
 *
 * If s->writeback is true, will not fail.
 */
bool bch_alloc_sectors(struct cache_set *c, struct bkey *k, unsigned sectors,
                      unsigned write_point, unsigned write_prio, bool wait)
{
  struct open_bucket *b, *last_bkt = NULL;
  BKEY_PADDED(key) alloc;
  unsigned i;

  /*
   * We might have to allocate a new bucket, which we can't do with a
   * spinlock held. So if we have to allocate, we drop the lock, allocate
   * and then retry. KEY_PTRS() indicates whether alloc points to
   * allocated bucket(s).
   *
   * 有可能不得不得分配一个新的bucket，我们不能持有一个自旋锁来这么做。
   * 因此，如果必须得分配，要丢弃这个锁，分配然后再次重试。KEY_PTRS()指示
   * 了alloc指向已分配buckets的位置。
   */

  bkey_init(&alloc.key); /* __bch_bucket_alloc_set中已经初始化过了，这就不需要了吧？*/
  //spin_lock(&c->data_bucket_lock);
  pthread_spin_lock(&c->data_bucket_lock);

  while (!(b = pick_data_bucket(c, k, &alloc.key, sectors, &last_bkt))) {
    unsigned watermark = write_prio
      ? RESERVE_MOVINGGC
      : RESERVE_NONE;
    pthread_spin_unlock(&c->data_bucket_lock);

    // if alloc failed, realloc again with data_bucket_lock
    if (last_bkt == NULL) {
      pthread_spin_lock(&c->data_bucket_lock);
      continue;
    }

    // if bch_bucket_alloc_set return failed and last_bkt is not NULL
    // we must set wait to false
    if (bch_bucket_alloc_set(c, watermark, &alloc.key, 1, wait)) {
      last_bkt->wait = false;
      return false;
    }
    pthread_spin_lock(&c->data_bucket_lock);
    //spin_lock(&c->data_bucket_lock);
  }

  /*
   * If we had to allocate, we might race and not need to allocate the
   * second time we call find_data_bucket(). If we allocated a bucket but
   * didn't use it, drop the refcount bch_bucket_alloc_set() took:
   *
   * 如果分配了一个bucket但是没有使用它，则丢弃bch_bucket_alloc_set得到的
   * 引用计数
   */
  if (KEY_PTRS(&alloc.key))
    bkey_put(c, &alloc.key);

  for (i = 0; i < KEY_PTRS(&b->key); i++) {
    if (ptr_stale(c, &b->key, i)){
      CACHE_ERRORLOG(NULL, "ptr_stale error \n");
      EBUG_ON(ptr_stale(c, &b->key, i));
    }
  }

  /* Set up the pointer to the space we're allocating: */

  for (i = 0; i < KEY_PTRS(&b->key); i++)
    k->ptr[i] = b->key.ptr[i];

  if (sectors > b->sectors_free) {
    CACHE_ERRORLOG(NULL, "error: sectors %u sectors_free %u \n",
        sectors, b->sectors_free);
    assert(sectors <= b->sectors_free);
  }

  SET_KEY_OFFSET(k, KEY_OFFSET(k) + sectors);
  SET_KEY_SIZE(k, sectors);
  SET_KEY_PTRS(k, KEY_PTRS(&b->key));

  /*
   * Move b to the end of the lru, and keep track of what this bucket was
   * last used for:
   * 将b这个结点移动到data_buckets链表的尾部
   */
  list_move_tail(&b->list, &c->data_buckets);
  bkey_copy_key(&b->key, k);
  b->last_write_point = write_point;

  /* buckets中可用的sectors */
  b->sectors_free	-= sectors;

  for (i = 0; i < KEY_PTRS(&b->key); i++) {
    SET_PTR_OFFSET(&b->key, i, PTR_OFFSET(&b->key, i) + sectors);

    // TODO
    atomic_long_add(sectors,
        &PTR_CACHE(c, &b->key, i)->sectors_written);
  }

  /* XXX 这里的sectors不是应该是扇区数么，怎么能和block_size直接比较呢？*/
  if (b->sectors_free < c->sb.block_size)
    b->sectors_free = 0;

  /*
   * k takes refcounts on the buckets it points to until it's inserted
   * into the btree, but if we're done with this bucket we just transfer
   * get_data_bucket()'s refcount.
   * k拿到它指向的buckets的引用计数直到它被插入到btree当中
   */
  if (b->sectors_free)
    for (i = 0; i < KEY_PTRS(&b->key); i++)
      atomic_inc(&PTR_BUCKET(c, &b->key, i)->pin);

  //spin_unlock(&c->data_bucket_lock);
  pthread_spin_unlock(&c->data_bucket_lock);
  return true;
}

/* Init */
void bch_open_buckets_free(struct cache_set *c)
{
  struct open_bucket *b;

  while (!list_empty(&c->data_buckets)) {
    b = list_first_entry(&c->data_buckets,
        struct open_bucket, list);
    list_del(&b->list);
    T2Free(b);
  }
}

int bch_open_buckets_alloc(struct cache_set *c)
{
  int i;
  //spin_lock_init(&c->data_bucket_lock);
  pthread_spin_init(&c->data_bucket_lock, 0);
  for (i = 0; i < MAX_OPEN_BUCKETS; i++) {
    struct open_bucket *b = calloc(1, sizeof(*b));
    if (!b) {
      return -ENOMEM;
    }
    list_add(&b->list, &c->data_buckets);
  }

  return 0;
}

int bch_cache_allocator_start(struct cache *ca)
{
  int err;
  err = pthread_create(&ca->alloc_thread, NULL, (void *)bch_allocator_thread, (void *)ca);
  if (err != 0) {
    CACHE_ERRORLOG(CAT_ALLOC, "can't create thread:%s\n", strerror(err));
    return err;
  }
  return 0;
}
void bch_cache_allocator_stop(struct cache *ca){
  int err;
  void *res;
  CACHE_INFOLOG(CAT_ALLOC, "Try stop alloc allocator thread\n");
  err = pthread_cancel(ca->alloc_thread);
  cache_bug_on(err != 0, ca->set, "Cache allocator send stop failed: %s\n", strerror(err));
  err = pthread_join(ca->alloc_thread, &res);
  cache_bug_on(err != 0 || res != PTHREAD_CANCELED, ca->set,
      "Cache allocator wait stop failed: %s\n", strerror(err));
}
