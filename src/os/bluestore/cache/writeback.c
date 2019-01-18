// SPDX-License-Identifier: GPL-2.0
/*
 * background writeback - scan btree for dirty data and write it to the backing
 * device
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "util.h"
#include "atomic.h"
#include "writeback.h"

/* Rate limiting */

static void __update_writeback_rate(struct cached_dev *dc)
{
  struct cache_set *c = dc->c;
  /*uint64_t cache_sectors = c->nbuckets * c->sb.bucket_size -*/
  /*bcache_flash_devs_sectors_dirty(c);*/
  uint64_t cache_sectors = c->nbuckets * c->sb.bucket_size;
  uint64_t cache_dirty_target =
    div_u64(cache_sectors * dc->writeback_percent, 100);

  /*int64_t target = div64_u64(cache_dirty_target * bdev_sectors(dc->bdev),*/
  /*c->cached_dev_sectors);*/
  int64_t target = cache_dirty_target;

  /* PD controller */

  int64_t dirty = bcache_dev_sectors_dirty(dc);
  int64_t derivative = dirty - dc->sectors_dirty_last;
  int64_t proportional = dirty - target;
  int64_t change;

  dc->sectors_dirty_last = dirty;

  /* Scale to sectors per second */

  proportional *= dc->writeback_rate_update_seconds;
  proportional = div_s64(proportional, dc->writeback_rate_p_term_inverse);

  derivative = div_s64(derivative, dc->writeback_rate_update_seconds);

  derivative = ewma_add(dc->sectors_dirty_derivative, derivative,
      (dc->writeback_rate_d_term /
       dc->writeback_rate_update_seconds) ?: 1, 0);

  derivative *= dc->writeback_rate_d_term;
  derivative = div_s64(derivative, dc->writeback_rate_p_term_inverse);

  change = proportional + derivative;

  /* Don't increase writeback rate if the device isn't keeping up */

  if (change > 0 &&
      time_after64(cache_realtime_u64(),
        dc->writeback_rate.next + NSEC_PER_MSEC))
    change = 0;

  dc->writeback_rate.rate =
    clamp_t(int64_t, (int64_t) dc->writeback_rate.rate + change,
        1, NSEC_PER_MSEC);

  dc->writeback_rate_proportional = proportional;
  dc->writeback_rate_derivative = derivative;
  dc->writeback_rate_change = change;
  dc->writeback_rate_target = target;
}

static void __update_read_rate(struct cached_dev *dc){
  int iops = atomic_read(&dc->read_iops);
  dc->read_wait = iops / dc->safe_read * dc->pre_read_wait;
  if (dc->read_wait > 1000000){
    dc->read_wait = 1000000;
  }
  atomic_set(&dc->read_iops, 0);
}

/*static void update_writeback_rate(struct work_struct *work)*/
static void update_writeback_rate(void *arg)
{
  /*struct cached_dev *dc = container_of(to_delayed_work(work),*/
  /*struct cached_dev,*/
  /*writeback_rate_update);*/
  struct cached_dev *dc = arg;


  pthread_setname_np(pthread_self(), "wb rate update");
  while (!dc->writeback_should_stop) {
    //pthread_rwlock_rdlock(&dc->writeback_lock);
    if (atomic_read(&dc->has_dirty) &&
        dc->writeback_percent){
      __update_writeback_rate(dc);
      __update_read_rate(dc);
    }

    //pthread_rwlock_unlock(&dc->writeback_lock);

    /*schedule_delayed_work(&dc->writeback_rate_update,*/
    /*dc->writeback_rate_update_seconds * HZ);*/
    sleep(dc->writeback_rate_update_seconds);
  }
}

static unsigned writeback_delay(struct cached_dev *dc, unsigned sectors)
{
  /*if (test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags) ||*/
  /*!dc->writeback_percent)*/
  /*return 0;*/
  unsigned delay;
  if (!dc->writeback_percent)
    return 0;

  delay = bch_next_delay(&dc->writeback_rate, sectors);
  /*return delay + dc->read_wait;*/
  return delay;
}

struct dirty_item {
  struct ring_item *item;
  struct keybuf_key *keys[MAX_WRITEBACKS_IN_PASS];
  struct cached_dev *dc;
  int nk;
};

static void dirty_io_complete(struct keybuf_key *w, struct cached_dev *dc)
{
  if (KEY_DIRTY(&w->key)) {
    unsigned i;
    struct keylist keys;

    bch_keylist_init(&keys);

    bkey_copy(keys.top, &w->key);
    SET_KEY_DIRTY(keys.top, false);
    bch_keylist_push(&keys);

    for (i = 0; i < KEY_PTRS(&w->key); i++)
      atomic_inc(&PTR_BUCKET(dc->c, &w->key, i)->pin);

    // TODO why replace key???
    bch_btree_insert(dc->c, &keys, NULL, &w->key);
  }
}

static void write_completion(void *arg){
  struct dirty_item *d = (struct dirty_item *)arg;
  struct ring_item *item = d->item;
  struct cached_dev *dc = d->dc;
  struct keybuf_key *w;
  int i;

  for (i = 0; i < d->nk; i++){
    w = d->keys[i];
    dirty_io_complete(w, dc);
    bch_keybuf_del(&dc->writeback_keys, w);
  }

  free(item->data);
  free(item);
  free(d);
}

static void dirty_io_write(struct dirty_item *d){
  struct ring_item *item = d->item;
  struct cached_dev *dc = d->dc;
  int ret, i;

  dc->wb_status = WB_WRITING_DIRTY;
  item->io.offset = item->o_offset;
  item->io.len = item->o_len;
  item->io.pos = item->data;
  item->io.type = CACHE_IO_TYPE_WRITE;
  item->iou_completion_cb = write_completion;

  CACHE_DEBUGLOG(WRITEBACK, "Item(%p) o_offset=%lu, o_len=%lu, data=%p, io offset=%lu, len=%lu, pos=%p\n",
                 item, item->o_offset, item->o_len, item->data, item->io.offset, item->io.len, item->io.pos);
  ret = aio_enqueue(CACHE_THREAD_BACKEND, dc->c->cache[0]->handler, item);
  if (ret < 0) {
    for (i = 0; i < d->nk; i++)
      bch_keybuf_del(&dc->writeback_keys, d->keys[i]);
    assert( "dirty aio_enqueue read error  " == 0);
  }

}

static void read_completion(void *arg){
  struct dirty_item *d = (struct dirty_item *)arg;
  struct ring_item *item = d->item;

  if (!atomic_dec_return(&item->seq)){
    dirty_io_write(d);
  }
}

static void dirty_io_read(struct keybuf_key *w, struct dirty_item *d)
{
  int ret, i;
  struct cached_dev *dc = d->dc;
  struct ring_item *item = d->item;

  dc->wb_status = WB_READING_DIRTY;
  item->iou_completion_cb = read_completion;
  item->iou_arg = d;
  item->io.type=CACHE_IO_TYPE_READ;
  item->io.pos = (char *)item->data + ((KEY_START(&w->key) << 9) - item->o_offset);
  item->io.offset = PTR_OFFSET(&w->key, 0) << 9;
  item->io.len = KEY_SIZE(&w->key) << 9;
  item->type = ITEM_WRITEBACK;

  CACHE_DEBUGLOG(WRITEBACK, "Item(%p) o_offset=%lu, o_len=%lu, data=%p, io offset=%lu, len=%lu, pos=%p\n",
                 item, item->o_offset, item->o_len, item->data, item->io.offset, item->io.len, item->io.pos);
  pdump_bkey(WRITEBACK, __func__, &w->key);
  ret = aio_enqueue(CACHE_THREAD_CACHE, dc->c->cache[0]->handler, item);
  if (ret < 0) {
    for (i = 0; i < d->nk; i++)
      bch_keybuf_del(&dc->writeback_keys, d->keys[i]);
    assert( "dirty aio_enqueue read error  " == 0);
  }
}

static void read_dirty(struct cached_dev *dc)
{
  unsigned delay = 0;
  struct keybuf_key *next, *w;
  size_t size;
  int nk, i;
  void *data;
  struct dirty_item *d;
  struct ring_item *item;

  next = bch_keybuf_next(&dc->writeback_keys);

  while (!dc->writeback_should_stop && next) {
    size = 0;
    nk = 0;
    d = calloc(1, sizeof(struct dirty_item));
    if (!d){
      CACHE_ERRORLOG(WRITEBACK, "Memory error for dirty_item \n");
      assert("Memory error for dirty_item" == 0);
    }

    do {

      /*
       * Don't combine too many operations, even if they
       * are all small.
       */
      if (nk >= MAX_WRITEBACKS_IN_PASS)
        break;

      /*
       * If the current operation is very large, don't
       * further combine operations.
       */
      if (size >= MAX_WRITESIZE_IN_PASS)
        break;

      /*
       * Operations are only eligible to be combined
       * if they are contiguous.
       *
       * TODO: add a heuristic willing to fire a
       * certain amount of non-contiguous IO per pass,
       * so that we can benefit from backing device
       * command queueing.
       */
      if ((nk != 0) && bkey_cmp(&d->keys[nk-1]->key,
                                &START_KEY(&next->key)))
        break;

      size += KEY_SIZE(&next->key);
      d->keys[nk++] = next;
    } while ((next = bch_keybuf_next(&dc->writeback_keys)));

    d->dc = dc;
    d->nk = nk;

    CACHE_DEBUGLOG(WRITEBACK, "Try to writeback %d next(%p) sleep=%d\n", nk, next, delay);

    data = calloc(1, size << 9);
    if (!data){
      CACHE_ERRORLOG(WRITEBACK, "Memory error for data \n");
      assert("Memory error for data" == 0);
    }
    item = get_ring_item(data, KEY_START(&d->keys[0]->key) << 9, size << 9);
    atomic_set(&item->seq, nk);
    d->item = item;

    for (i = 0; i < nk; i++) {
      w = d->keys[i];
      pdump_bkey(WRITEBACK, __func__, &w->key);

      dc->last_read = KEY_OFFSET(&w->key);

      if (ptr_stale(dc->c, &w->key, 0)) {
        CACHE_ERRORLOG(NULL, "writeback key stale bucket gen = %d, ptr gen = %d\n", PTR_BUCKET(dc->c, &w->key, 0)->gen, PTR_GEN(&w->key, 0));
        dump_bkey("writeback stale key", &w->key);
        assert("writeback stale key" == 0);
      }
      /*BUG_ON(ptr_stale(dc->c, &w->key, 0));*/

      dirty_io_read(w, d);
    }

    delay = writeback_delay(dc, size);
    atomic_set(&dc->real_wb_delay, delay);
    usleep(delay);
  }

  /*if (0) {*/
  /*err_free:*/
  /*kfree(w->private);*/
  /*err:*/
  /*bch_keybuf_del(&dc->writeback_keys, w);*/
  /*}*/

  /*
   * Wait for outstanding writeback IOs to finish (and keybuf slots to be
   * freed) before refilling again
   */
  /*closure_sync(&cl);*/
}

/*
 * Scan for dirty data
 * 标记设备的sector为dirty
 */
void bcache_dev_sectors_dirty_add(struct cache_set *c, unsigned inode,
    uint64_t offset, int nr_sectors)
{
  struct cached_dev *dc = c->dc;
  unsigned stripe_offset, stripe, sectors_dirty;

  stripe = offset_to_stripe(dc, offset);
  stripe_offset = offset & (dc->stripe_size - 1);

  while (nr_sectors) {
    int s = min_t(unsigned, abs(nr_sectors),
        dc->stripe_size - stripe_offset);

    if (nr_sectors < 0)
      s = -s;

    if (stripe >= dc->nr_stripes)
      return;

    sectors_dirty = atomic_add_return(s,
        dc->stripe_sectors_dirty + stripe);
    if (sectors_dirty == dc->stripe_size)
      set_bit(stripe, dc->full_dirty_stripes);
    else
      clear_bit(stripe, dc->full_dirty_stripes);

    nr_sectors -= s;
    stripe_offset = 0;
    stripe++;
  }
}

static bool dirty_pred(struct keybuf *buf, struct bkey *k)
{
  /*struct cached_dev *dc = container_of(buf, struct cached_dev, writeback_keys);*/

  /*BUG_ON(KEY_INODE(k) != dc->disk.id);*/

  return KEY_DIRTY(k);
}

static void refill_full_stripes(struct cached_dev *dc)
{
  struct keybuf *buf = &dc->writeback_keys;
  unsigned start_stripe, stripe, next_stripe;
  bool wrapped = false;

  stripe = offset_to_stripe(dc, KEY_OFFSET(&buf->last_scanned));

  if (stripe >= dc->nr_stripes)
    stripe = 0;

  start_stripe = stripe;

  while (1) {
    stripe = find_next_bit(dc->disk.full_dirty_stripes,
        dc->disk.nr_stripes, stripe);

    if (stripe == dc->disk.nr_stripes)
      goto next;

    next_stripe = find_next_zero_bit(dc->full_dirty_stripes,
        dc->nr_stripes, stripe);

    buf->last_scanned = KEY(0,
        stripe * dc->stripe_size, 0);

    bch_refill_keybuf(dc->c, buf,
        &KEY(0,
          next_stripe * dc->stripe_size, 0),
        dirty_pred);

    if (array_freelist_empty(&buf->freelist))
      return;

    stripe = next_stripe;
next:
    if (wrapped && stripe > start_stripe)
      return;

    if (stripe == dc->disk.nr_stripes) {
      stripe = 0;
      wrapped = true;
    }
  }
}

/*
 * Returns true if we scanned the entire disk
 */
static bool refill_dirty(struct cached_dev *dc)
{
  struct keybuf *buf = &dc->writeback_keys;
  struct bkey start = KEY(0, 0, 0);
  struct bkey end = KEY(0, MAX_KEY_OFFSET, 0);
  struct bkey start_pos;

  /*
   * make sure keybuf pos is inside the range for this disk - at bringup
   * we might not be attached yet so this disk's inode nr isn't
   * initialized then
   */
  if (bkey_cmp(&buf->last_scanned, &start) < 0 ||
      bkey_cmp(&buf->last_scanned, &end) > 0)
    buf->last_scanned = start;

  if (dc->partial_stripes_expensive) {
    refill_full_stripes(dc);
    if (array_freelist_empty(&buf->freelist))
      return false;
  }

  start_pos = buf->last_scanned;
  bch_refill_keybuf(dc->c, buf, &end, dirty_pred);

  if (bkey_cmp(&buf->last_scanned, &end) < 0)
    return false;

  /*
   * If we get to the end start scanning again from the beginning, and
   * only scan up to where we initially started scanning from:
   */
  buf->last_scanned = start;
  dc->wb_status = WB_REFILL_DIRTY;
  bch_refill_keybuf(dc->c, buf, &start_pos, dirty_pred);

  return bkey_cmp(&buf->last_scanned, &start_pos) >= 0;
}

static bool refill_should_wait(struct cached_dev *dc)
{
  return !RB_EMPTY_ROOT(&dc->writeback_keys.keys);
}

/* writeback线程 */
static int bch_writeback_thread(void *arg)
{
  struct cached_dev *dc = arg;
  bool searched_full_index;

  CACHE_DEBUGLOG(WRITEBACK, "Thread start\n");
  pthread_setname_np(pthread_self(), "writeback");

  aio_thread_init(dc->c->cache[0]);
  bch_ratelimit_reset(&dc->writeback_rate);

  while (!dc->writeback_should_stop) {
    pthread_rwlock_wrlock(&dc->writeback_lock);

    /* 如果不为dirty或者writeback机制未运行时，该线程让出CPU控制权 */
    if (!atomic_read(&dc->has_dirty) || atomic_read(&dc->writeback_stop)
        || refill_should_wait(dc)) {
      dc->wb_status = WB_IDLE;
      struct timespec out = time_from_now(1, 0);
      pthread_rwlock_unlock(&dc->writeback_lock);
      pthread_mutex_lock(&dc->writeback_mut);
      pthread_cond_timedwait(&dc->writeback_cond, &dc->writeback_mut, &out);
      pthread_mutex_unlock(&dc->writeback_mut);

      continue;
    }

    searched_full_index = refill_dirty(dc);

    //show_list(&dc->writeback_keys);
    if (searched_full_index && RB_EMPTY_ROOT(&dc->writeback_keys.keys)) {
      atomic_set(&dc->has_dirty, 0);
      SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);
      pthread_rwlock_unlock(&dc->writeback_lock);
      /*bch_write_bdev_super(dc, NULL);*/
      goto sleep;
    }

    pthread_rwlock_unlock(&dc->writeback_lock);

    ///*up_write(&dc->writeback_lock);*/

    bch_ratelimit_reset(&dc->writeback_rate);
    read_dirty(dc);

    if (searched_full_index) {
sleep:
      CACHE_INFOLOG(WRITEBACK, "Writeback goto sleep \n");
      sleep(dc->writeback_delay);
    }
  }

  return 0;
}

/* Init */
#if 0

struct sectors_dirty_init {
  struct btree_op	op;
  unsigned	inode;
};
#endif

static int sectors_dirty_init_fn(struct btree_op *_op, struct btree *b,
    struct bkey *k)
{
  /*struct sectors_dirty_init *op = container_of(_op,*/
  /*struct sectors_dirty_init, op);*/
  /*if (KEY_INODE(k) > op->inode)*/
  /*return MAP_DONE;*/

  if (KEY_DIRTY(k))
    bcache_dev_sectors_dirty_add(b->c, KEY_INODE(k),
        KEY_START(k), KEY_SIZE(k));

  return MAP_CONTINUE;
}

void bch_sectors_dirty_init(struct cached_dev *dc)
{
  struct btree_op op;

  bch_btree_op_init(&op, -1, BTREE_OP_TRAVERSE);
  /*op.inode = d->id; [> 这里的inode就是bcache的从设备号 <]*/

  bch_btree_map_keys(&op, dc->c, &KEY(0, 0, 0),
      sectors_dirty_init_fn, 0);

  dc->sectors_dirty_last = bcache_dev_sectors_dirty(dc);
}

/* 初始化writeback */
void bch_cached_dev_writeback_init(struct cached_dev *dc)
{
  /*sema_init(&dc->in_flight, 64);*/
  /*init_rwsem(&dc->writeback_lock);*/
  pthread_rwlock_init(&dc->writeback_lock, NULL);
  bch_keybuf_init(&dc->writeback_keys);

  dc->sequential_cutoff           = 0;
  dc->writeback_metadata		= true;
  atomic_set(&dc->writeback_stop, 0);
  dc->writeback_percent		= 10;
  dc->writeback_delay		= 3;
  dc->writeback_rate.rate		= 1024;

  dc->writeback_rate_update_seconds = 5;
  dc->writeback_rate_d_term	= 30;
  dc->writeback_rate_p_term_inverse = 6000;

  atomic_set(&dc->read_iops, 0);
  dc->safe_read = 200;
  dc->read_wait = 200;
  dc->pre_read_wait = 200; /* us */

  /*INIT_DELAYED_WORK(&dc->writeback_rate_update, update_writeback_rate);*/
}

/*int bch_cached_dev_writeback_start(struct cached_dev *dc)*/
/*{*/
/*dc->writeback_write_wq = alloc_workqueue("bcache_writeback_wq",*/
/*WQ_MEM_RECLAIM, 0);*/
/*if (!dc->writeback_write_wq)*/
/*return -ENOMEM;*/

/*dc->writeback_thread = kthread_create(bch_writeback_thread, dc,*/
/*"bcache_writeback");*/
/*if (IS_ERR(dc->writeback_thread))*/
/*return PTR_ERR(dc->writeback_thread);*/

/*schedule_delayed_work(&dc->writeback_rate_update,*/
/*dc->writeback_rate_update_seconds * HZ);*/

/*bch_writeback_queue(dc);*/

/*return 0;*/
/*}*/

int bch_cached_dev_writeback_start(struct cached_dev *dc)
{
  int err;
  dc->writeback_should_stop = false;
  /*dc->rate_update_should_stop = false;*/
  err = pthread_create(&dc->writeback_thread, NULL, (void *)bch_writeback_thread, (void *)dc);
  if (err != 0)
  {
    printf("can't create writeback thread:%s\n", strerror(err));
    return err;
  }
  /*pthread_mutex_init(&dc->writeback_mut, NULL);*/

  err = pthread_create(&dc->writeback_rate_update_thread, NULL, (void *)update_writeback_rate, (void *)dc);
  if (err != 0)
  {
    printf("can't create writeback rate update thread:%s\n", strerror(err));
    return err;
  }

  return 0;
}

void bch_cached_dev_writeback_stop(struct cached_dev *dc){
  int err;
  CACHE_INFOLOG(WRITEBACK, "stop wirteback\n");
  dc->writeback_should_stop = true;
  if (dc->writeback_thread){
    err = pthread_join(dc->writeback_thread, NULL);
    cache_bug_on(err != 0, dc->c, "can't wait writeback thread:%s\n", strerror(err));
  }

  if (dc->writeback_rate_update_thread){
    err = pthread_join(dc->writeback_rate_update_thread, NULL);
    cache_bug_on(err != 0, dc->c, "can't wait writeback rage update thread:%s\n", strerror(err));
  }
}

uint64_t get_sectors_dirty(struct cached_dev *dc)
{
  return bcache_dev_sectors_dirty(dc);
}

void t2ce_set_flush_water_level(struct cache *ca, int percent)
{
  ca->set->dc->writeback_percent = percent;
}

