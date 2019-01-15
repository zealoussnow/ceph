// SPDX-License-Identifier: GPL-2.0
/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "request.h"
#include "list.h"

static bool moving_pred(struct keybuf *buf, struct bkey *k)
{
  struct cache_set *c = container_of(buf, struct cache_set,
      moving_gc_keys);
  unsigned i;

  for (i = 0; i < KEY_PTRS(k); i++) {
    if (ptr_available(c, k, i) &&
        GC_MOVE(PTR_BUCKET(c, k, i))) {
      if (PTR_BUCKET(c, k, i)->move_dirty_only && !KEY_DIRTY(k))
        return false;
      else
        return true;
    }
  }

  return false;
}

struct moving_item {
  struct ring_item *item;
  struct keybuf_key *w;
  struct cache_set *c;
};

static void free_moving_item(struct ring_item *item)
{
  if (item->data)
    free(item->data);
  free_ring_item(item);

}

static void write_completion(void *arg){
  struct ring_item *item = (struct ring_item *)arg;
  struct keybuf_key *w = (struct keybuf_key *)item->io_arg;
  struct cache * ca = (struct cache *)item->ca_handler;
  struct cache_set *c = ca->set;

  CACHE_DEBUGLOG(MOVINGGC, "Write completion key(%p) \n", &w->key);
  bch_data_insert_keys(c, item->insert_keys, &w->key);

  bch_keybuf_del(&c->moving_gc_keys, w);
  atomic_dec(&c->gc_seq);
  free_moving_item(item);
}

static void read_completion(void *arg){
  struct ring_item *item = (struct ring_item *)arg;
  /*struct moving_item *d = container_of(&item, struct moving_item, item);*/
  /*struct ring_item *item = d->item;*/
  struct keybuf_key *w = (struct keybuf_key *)item->io_arg;
  struct cache *ca = (struct cache *)item->ca_handler;
  struct cache_set *c = ca->set;
  uint64_t s_offset = PTR_OFFSET(&w->key, 0);
  int ret;
  int i;

  if (KEY_DIRTY(&w->key) || !ptr_stale(c, &w->key, 0)) {
    struct bkey *new_key = NULL;
    struct keylist *insert_keys = calloc(1, sizeof(struct keylist));
    if (insert_keys == NULL) {
      CACHE_ERRORLOG(NULL, "calloc insert_keys keylist failed \n");
      assert("calloc insert_keys keylist failed " == 0);
    }

    bch_keylist_init(insert_keys);

    new_key = insert_keys->top;
    bkey_init(new_key);

    bkey_copy_key(new_key, &w->key);
    SET_KEY_OFFSET(new_key, KEY_START(&w->key));

    // wirte moving gc to moving buckets
    if (!bch_alloc_sectors(c, new_key, KEY_SIZE(&w->key), 0, 1, 0)) {
      CACHE_ERRORLOG(MOVINGGC, "bch_alloc_sectors failed!\n");
      goto out;
    }

    if (KEY_DIRTY(&w->key)){
      SET_KEY_DIRTY(new_key, true);
      for (i = 0; i < KEY_PTRS(new_key); i++)
	SET_GC_MARK(PTR_BUCKET(c, new_key, i),
	    GC_MARK_DIRTY);
    }

    bch_keylist_push(insert_keys);
    item->io.offset = PTR_OFFSET(new_key, 0) << 9;
    item->io.type=CACHE_IO_TYPE_WRITE;
    item->iou_completion_cb = write_completion;
    item->insert_keys = insert_keys;
    item->iou_arg = item;
    item->type = ITEM_MOVINGGC;



    CACHE_DEBUGLOG(MOVINGGC, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx) cache move "
        "cache=%lu(0x%lx) to cache=%lu(0x%lx)) \n",
        item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len,
        s_offset, s_offset << 9, item->io.offset >> 9, item->io.offset);

    pdump_bkey(MOVINGGC, __func__, &w->key);
    ret = aio_enqueue(CACHE_THREAD_CACHE, c->cache[0]->handler, item);
    if (ret < 0) {
      assert( "dirty aio_enqueue read error  " == 0);
      goto out;
    }
  } else {
    goto out;
  }
  return;

out:
  bch_keybuf_del(&c->moving_gc_keys, w);
  atomic_dec(&c->gc_seq);
  free_moving_item(item);
  return;
}

static void begin_io_read(struct keybuf_key *w, struct cache_set *c)
{
  int ret;
  uint64_t len = KEY_SIZE(&w->key) << 9;
  void *data = malloc(len);
  uint64_t offset = KEY_START(&w->key) << 9;
  struct ring_item *item = get_ring_item(data, offset, len);
  /*struct moving_item *d = malloc(sizeof(struct moving_item));*/

  /*d->item = item;*/
  /*d->w = w;*/
  /*d->c = c;*/

  item->iou_completion_cb = read_completion;
  /*item->iou_arg = d;*/
  item->ca_handler = c->cache[0];
  item->iou_arg = item;
  item->io_arg = w;

  item->io.type=CACHE_IO_TYPE_READ;
  item->io.pos = item->data;
  item->io.offset = PTR_OFFSET(&w->key, 0) << 9;
  item->io.len = item->o_len;
  item->type = ITEM_AIO_READ;

  atomic_inc(&c->gc_seq);
  ret = aio_enqueue(CACHE_THREAD_CACHE, c->cache[0]->handler, item);
  if (ret < 0) {
    atomic_dec(&c->gc_seq);
    bch_keybuf_del(&c->moving_gc_keys, w);
    CACHE_ERRORLOG(MOVINGGC, "Movinggc read io error (offset %lu len %lu)\n",item->io.offset, item->io.len);
    assert( "dirty aio_enqueue read error  " == 0);
  }
}


static void read_moving(struct cache_set *c)
{
  struct keybuf_key       *w;

  while (!test_bit(CACHE_SET_STOPPING, &c->flags)) {
    /*
     * 填充moving_gc_keys
     * 循环调用bch_keybuf_next_rescan，每次从红黑树返回一个keybuf_key
     */
    w = bch_keybuf_next_rescan(c, &c->moving_gc_keys, &MAX_KEY, moving_pred);
    if (!w)
      break;

    if (ptr_stale(c, &w->key, 0)) {
      if (KEY_DIRTY(&w->key)) {
        CACHE_ERRORLOG(NULL, "moving dirty key stale bucket gen = %d, ptr gen = %d\n", PTR_BUCKET(c, &w->key, 0)->gen, PTR_GEN(&w->key, 0));
        dump_bkey("moving dirty stale key", &w->key);
        assert("moving dirty stale key" == 0);
      }
      bch_keybuf_del(&c->moving_gc_keys, w);
      continue;
    }

    begin_io_read(w, c);
    c->gc_stats.gc_moving_bkeys++;
    c->gc_stats.gc_moving_bkey_size += KEY_SIZE(&w->key);
  }
  /*KEY_SIZE*/
  CACHE_INFOLOG(MOVINGGC, "Movinggc submit bkeys %lu size %lu\n", c->gc_stats.gc_moving_bkeys, c->gc_stats.gc_moving_bkey_size);
}

static bool bucket_cmp(struct bucket *l, struct bucket *r)
{
  return GC_SECTORS_USED(l) < GC_SECTORS_USED(r);
}

static bool bucket_dirty_cmp(struct bucket *l, struct bucket *r)
{
  return l->dirty_keys < r->dirty_keys;
}

static unsigned bucket_heap_top(struct cache *ca)
{
  struct bucket *b;
  return (b = heap_peek(&ca->heap)) ? GC_SECTORS_USED(b) : 0;
}

static unsigned bucket_heap_top_keys(struct cache *ca)
{
  struct bucket *b;
  return (b = heap_peek(&ca->heap)) ? b->dirty_keys : 0;
}


bool dirty_filter(struct bucket *b, struct cache *ca)
{
  bool ret = GC_MARK(b) == GC_MARK_METADATA ||
            !GC_SECTORS_USED(b) ||
            !b->dirty_keys ||
            atomic_read(&b->pin);
  return ret;
}

bool used_filter(struct bucket *b, struct cache *ca)
{
  bool ret = GC_MARK(b) == GC_MARK_METADATA ||
             !GC_SECTORS_USED(b) ||
             GC_SECTORS_USED(b) == ca->sb.bucket_size ||
             atomic_read(&b->pin);
  return ret;
}

void bch_moving_gc(struct cache_set *c)
{
  struct cache *ca;
  struct bucket *b;
  unsigned i;

  pthread_mutex_lock(&c->bucket_lock);
  CACHE_DEBUGLOG(MOVINGGC, "Begin moving gc. \n");
  /*
   * movinggc主要目的是整理空洞，如果bucket 上面有数据被删除了，为了保持整个bucket的完整性，则将这类型的bucket
   * 的合法数据进行搬移，实际上效果并不好，后期可以考虑在一定条件下，只搬移dirty的数据，这样在wb来不及处理的时候，
   * 可以通过movinggc释放一部分的区间
   */
  bool busy = (c->gc_stats.in_use > c->dc->cutoff_gc_busy);
  bool (*bucket_filter)(struct bucket *, struct cache *) = busy? dirty_filter : used_filter;
  bool (*cmp)() = busy ? bucket_dirty_cmp: bucket_cmp;
  for_each_cache(ca, c, i) {
    unsigned sectors_to_move = 0;
    unsigned reserve_sectors = ca->sb.bucket_size *
      fifo_used(&ca->free[RESERVE_MOVINGGC]);
    if ( reserve_sectors == 0 ) {
      CACHE_INFOLOG(MOVINGGC, "reserve movinggc bucket not enough(%d)\n", fifo_used(&ca->free[RESERVE_MOVINGGC]));
      pthread_mutex_unlock(&c->bucket_lock);
      return ;
    }
    ca->heap.used = 0;
    // 遍历一次所有的bucket进行一次统计过滤，大约耗时300us
    // 1. 先找到所有复合条件的bucket
    for_each_bucket(b, ca) {
      if (bucket_filter(b, ca)) {
        continue;
      }
      if (!heap_full(&ca->heap)) {
        sectors_to_move += GC_SECTORS_USED(b);
        heap_add(&ca->heap, b, cmp);
      } else if (cmp(b, heap_peek(&ca->heap))) {
        sectors_to_move -= bucket_heap_top(ca);
        sectors_to_move += GC_SECTORS_USED(b);
        ca->heap.data[0] = b;
        heap_sift(&ca->heap, 0, cmp);
      }
    }
    // 2.再看下剩余的bucket是否够用
    while (sectors_to_move > reserve_sectors) {
      heap_pop(&ca->heap, b, cmp);
      sectors_to_move -= GC_SECTORS_USED(b);
    }
    // 3.确定哪些bucket要搬移之后，设置这些bucket为gc_move
    while (heap_pop(&ca->heap, b, cmp)) {
      SET_GC_MOVE(b, 1);
      b->move_dirty_only = busy;
      c->gc_stats.gc_moving_buckets++;
    }
    if (!c->gc_stats.gc_moving_buckets) {
      pthread_mutex_unlock(&c->bucket_lock);
      return 0;
    }
    CACHE_DEBUGLOG(MOVINGGC, "Movinggc busy %d moving_buckets %lu \n", busy, c->gc_stats.gc_moving_buckets);
  }
  pthread_mutex_unlock(&c->bucket_lock);
  c->moving_gc_keys.last_scanned = ZERO_KEY;
  read_moving(c);
}

void bch_moving_init_cache_set(struct cache_set *c)
{
  bch_keybuf_init(&c->moving_gc_keys);
  /*sema_init(&c->moving_in_flight, 64);*/
}
