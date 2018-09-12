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
  int ret;
  int i;

  if (KEY_DIRTY(&w->key) || !ptr_stale(c, &w->key, 0)) {
    struct bkey *new_key = NULL;
    struct keylist *insert_keys = calloc(1, sizeof(struct keylist));

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

    pdump_bkey(WRITEBACK, __func__, &w->key);
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
  uint64_t offset = PTR_OFFSET(&w->key, 0) << 9;
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
  item->io.offset = item->o_offset;
  item->io.len = item->o_len;
  item->type = ITEM_AIO_READ;

  atomic_inc(&c->gc_seq);
  ret = aio_enqueue(CACHE_THREAD_CACHE, c->cache[0]->handler, item);
  if (ret < 0) {
    atomic_dec(&c->gc_seq);
    bch_keybuf_del(&c->moving_gc_keys, w);
    assert( "dirty aio_enqueue read error  " == 0);
  }
}


static void read_moving(struct cache_set *c)
{
  struct keybuf_key       *w;

  CACHE_INFOLOG(MOVINGGC, "start moving gc\n");
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
  }
  CACHE_INFOLOG(MOVINGGC, "end of moving gc\n");
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

void calc_bucket_state(struct cache *ca, struct cache_set *c, struct bucket *b)
{
  if (GC_SECTORS_USED(b) == ca->sb.bucket_size)
    c->gc_stats.gc_full_buckets++;
  if (!GC_SECTORS_USED(b))
    c->gc_stats.gc_empty_buckets++;
}

/* 根据bucket的标志位做实际回收  */
void bch_moving_gc(struct cache_set *c)
{
  struct cache *ca;
  struct bucket *b;
  unsigned i;

  /*if (!c->copy_gc_enabled)*/
  /*return;*/

  pthread_mutex_lock(&c->bucket_lock);
  CACHE_DEBUGLOG(MOVINGGC, "Begin moving gc. \n");

  c->gc_stats.gc_moving_buckets = 0;
  c->gc_stats.gc_pin_buckets = 0;
  c->gc_stats.gc_empty_buckets = 0;
  c->gc_stats.gc_full_buckets = 0;

  if (c->gc_stats.in_use > c->dc->cutoff_gc_busy) {
    for_each_cache(ca, c, i) {
      unsigned keys_to_move = 0;
      unsigned reserve_keys = c->dc->max_gc_keys_onetime;

      ca->heap.used = 0;

      /* 遍历cached disk的bucket */
      for_each_bucket(b, ca) {
        /* 如果为元数据或数据占用量为bucket_size，则continue */

        calc_bucket_state(ca, c, b);
        if (GC_MARK(b) == GC_MARK_METADATA ||
            !GC_SECTORS_USED(b) ||
            !b->dirty_keys ||
            atomic_read(&b->pin))
          continue;

        if (!heap_full(&ca->heap)) {
          keys_to_move += b->dirty_keys;
          heap_add(&ca->heap, b, bucket_dirty_cmp);
        } else if (bucket_dirty_cmp(b, heap_peek(&ca->heap))) {
          keys_to_move -= bucket_heap_top_keys(ca);
          keys_to_move += b->dirty_keys;

          ca->heap.data[0] = b;
          heap_sift(&ca->heap, 0, bucket_dirty_cmp);
        }
      }

      while (keys_to_move > reserve_keys) {
        heap_pop(&ca->heap, b, bucket_cmp);
        keys_to_move -= b->dirty_keys;
      }
      /*
       * 统计哪些bucket可以通过移动来合并bucket的使用
       * 标记这些bucket为SET_GC_MOVE(b, 1);
       */
      CACHE_INFOLOG(MOVINGGC, "moving dirty gc heap size %d , heap used %d \n", ca->heap.size, ca->heap.used);

      while (heap_pop(&ca->heap, b, bucket_dirty_cmp)) {
        SET_GC_MOVE(b, 1);
        b->move_dirty_only = true;
        c->gc_stats.gc_moving_buckets++;
      }
      CACHE_INFOLOG(MOVINGGC, " need to gc dirty moving_buckets = %lu \n", c->gc_stats.gc_moving_buckets);
    }
  } else {
    for_each_cache(ca, c, i) {
      unsigned sectors_to_move = 0;
      unsigned reserve_sectors = ca->sb.bucket_size *
        fifo_used(&ca->free[RESERVE_MOVINGGC]);

      ca->heap.used = 0;

      /* 遍历cached disk的bucket */
      for_each_bucket(b, ca) {
        /* 如果为元数据或数据占用量为bucket_size，则continue */

        calc_bucket_state(ca, c, b);
        if (GC_MARK(b) == GC_MARK_METADATA ||
            !GC_SECTORS_USED(b) ||
            GC_SECTORS_USED(b) == ca->sb.bucket_size ||
            atomic_read(&b->pin))
          continue;

        if (!heap_full(&ca->heap)) {
          sectors_to_move += GC_SECTORS_USED(b);
          heap_add(&ca->heap, b, bucket_cmp);
        } else if (bucket_cmp(b, heap_peek(&ca->heap))) {
          sectors_to_move -= bucket_heap_top(ca);
          sectors_to_move += GC_SECTORS_USED(b);

          ca->heap.data[0] = b;
          heap_sift(&ca->heap, 0, bucket_cmp);
        }
      }

      while (sectors_to_move > reserve_sectors) {
        heap_pop(&ca->heap, b, bucket_cmp);
        sectors_to_move -= GC_SECTORS_USED(b);
      }

      /*
       * 统计哪些bucket可以通过移动来合并bucket的使用
       * 标记这些bucket为SET_GC_MOVE(b, 1);
       */
      CACHE_INFOLOG(MOVINGGC, "moving gc heap size %d , heap used %d \n", ca->heap.size, ca->heap.used);

      while (heap_pop(&ca->heap, b, bucket_cmp)) {
        SET_GC_MOVE(b, 1);
        b->move_dirty_only = false;
        c->gc_stats.gc_moving_buckets++;
      }
      CACHE_INFOLOG(MOVINGGC, " need to gc moving_buckets = %lu \n", c->gc_stats.gc_moving_buckets);
    }
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
