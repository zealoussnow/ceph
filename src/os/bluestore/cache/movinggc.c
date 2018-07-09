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

#if 0
struct moving_io {
  //struct closure		cl;
  struct keybuf_key	*w;
  struct data_insert_op	op;
  struct bbio		bio;
};
#endif

static bool moving_pred(struct keybuf *buf, struct bkey *k)
{
  struct cache_set *c = container_of(buf, struct cache_set,
      moving_gc_keys);
  unsigned i;

  for (i = 0; i < KEY_PTRS(k); i++)
    if (ptr_available(c, k, i) &&
        GC_MOVE(PTR_BUCKET(c, k, i)))
      return true;

  return false;
}

/* Moving GC - IO loop */

#if 0
static void moving_io_destructor()
{
  //struct moving_io *io = container_of(cl, struct moving_io, cl);
  //free(io);
}

static void write_moving_finish(struct closure *cl)
{
  struct moving_io *io = container_of(cl, struct moving_io, cl);
  struct bio *bio = &io->bio.bio;

  bio_free_pages(bio);

  if (io->op.replace_collision)
    trace_bcache_gc_copy_collision(&io->w->key);

  bch_keybuf_del(&io->op.c->moving_gc_keys, io->w);

  up(&io->op.c->moving_in_flight);

  closure_return_with_destructor(cl, moving_io_destructor);
}

static void read_moving_endio(struct bio *bio)
{
  struct bbio *b = container_of(bio, struct bbio, bio);
  struct moving_io *io = container_of(bio->bi_private,
      struct moving_io, cl);

  if (bio->bi_status)
    io->op.status = bio->bi_status;
  else if (!KEY_DIRTY(&b->key) &&
      ptr_stale(io->op.c, &b->key, 0)) {
    io->op.status = BLK_STS_IOERR;
  }

  bch_bbio_endio(io->op.c, bio, bio->bi_status, "reading data to move");
}

static void moving_init(struct moving_io *io)
{
  struct bio *bio = &io->bio.bio;

  bio_init(bio, bio->bi_inline_vecs,
      DIV_ROUND_UP(KEY_SIZE(&io->w->key), PAGE_SECTORS));
  bio_get(bio);
  bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

  bio->bi_iter.bi_size	= KEY_SIZE(&io->w->key) << 9;
  bio->bi_private		= &io->cl;
  bch_bio_map(bio, NULL);
}

static void write_moving(struct closure *cl)
{
  struct moving_io *io = container_of(cl, struct moving_io, cl);
  struct data_insert_op *op = &io->op;

  if (!op->status) {
    moving_init(io);

    io->bio.bio.bi_iter.bi_sector = KEY_START(&io->w->key);
    op->write_prio		= 1;
    op->bio			= &io->bio.bio;

    op->writeback		= KEY_DIRTY(&io->w->key);
    op->csum		= KEY_CSUM(&io->w->key);

    bkey_copy(&op->replace_key, &io->w->key);
    op->replace		= true;

    closure_call(&op->cl, bch_data_insert, NULL, cl);
  }

  continue_at(cl, write_moving_finish, op->wq);
}

static void read_moving_submit(struct closure *cl)
{
  struct moving_io *io = container_of(cl, struct moving_io, cl);
  struct bio *bio = &io->bio.bio;

  bch_submit_bbio(bio, io->op.c, &io->w->key, 0);

  continue_at(cl, write_moving, io->op.wq);
}
#endif

struct moving_item {
  struct ring_item *item;
  struct keybuf_key *w;
  struct cache_set *c;
};

static void *write_completion(void *arg){
  struct moving_item *d = (struct moving_item *)arg;
  struct ring_item *item = d->item;
  struct keybuf_key *w = d->w;
  struct cache_set *c = d->c;

  CACHE_DEBUGLOG(MOVINGGC, "Write completion key(%p) \n", &w->key);
  bch_keylist_push(item->insert_keys);
  bch_btree_insert(c, item->insert_keys, NULL, &w->key);
  bch_keylist_free(item->insert_keys);

  bch_keybuf_del(&c->moving_gc_keys, w);
  free(item->data);
  free(item);
  free(d);
}

static void *read_completion(void *arg){
  struct moving_item *d = (struct moving_item *)arg;
  struct ring_item *item = d->item;
  struct keybuf_key *w = d->w;
  struct cache_set *c = d->c;
  int ret;

  if (KEY_DIRTY(&w->key) || !ptr_stale(c, &w->key, 0)) {
    struct bkey *new_key = NULL;
    struct keylist *insert_keys = calloc(1, sizeof(struct keylist));

    bch_keylist_init(insert_keys);

    new_key = insert_keys->top;
    bkey_init(new_key);

    bkey_copy_key(new_key, &w->key);
    SET_KEY_OFFSET(new_key, KEY_START(&w->key));
    if (KEY_DIRTY(&w->key))
      SET_KEY_DIRTY(new_key, true);

    // wirte moving gc to moving buckets
    if (!bch_alloc_sectors(c, new_key, KEY_SIZE(&w->key), 0, 1, 1)) {
      CACHE_ERRORLOG(MOVINGGC, "bch_alloc_sectors failed!\n");
      bch_keybuf_del(&c->moving_gc_keys, w);
      assert("bch_alloc_sectors" == 0);
    }

    item->io.offset = PTR_OFFSET(new_key, 0) << 9;
    item->io.type=CACHE_IO_TYPE_WRITE;
    item->iou_completion_cb = write_completion;
    item->insert_keys = insert_keys;

    pdump_bkey(WRITEBACK, __func__, &w->key);
    ret = aio_enqueue(CACHE_THREAD_CACHE, c->cache[0]->handler, item);
    if (ret < 0) {
      bch_keybuf_del(&c->moving_gc_keys, w);
      assert( "dirty aio_enqueue read error  " == 0);
    }
  }
}

static void begin_io_read(struct keybuf_key *w, struct cache_set *c)
{
  int ret;
  uint64_t len = KEY_SIZE(&w->key) << 9;
  void *data = malloc(len);
  uint64_t offset = PTR_OFFSET(&w->key, 0) << 9;
  struct ring_item *item = get_ring_item(data, offset, len);
  struct moving_item *d = malloc(sizeof(struct moving_item));

  d->item = item;
  d->w = w;
  d->c = c;

  item->iou_completion_cb = read_completion;
  item->iou_arg = d;
  item->io.type=CACHE_IO_TYPE_READ;
  item->io.pos = item->data;
  item->io.offset = item->o_offset;
  item->io.len = item->o_len;

  ret = aio_enqueue(CACHE_THREAD_CACHE, c->cache[0]->handler, item);
  if (ret < 0) {
    bch_keybuf_del(&c->moving_gc_keys, w);
    assert( "dirty aio_enqueue read error  " == 0);
  }
}


static void read_moving(struct cache_set *c)
{
  struct keybuf_key       *w;
  char * data=NULL;
  off_t offset = 0;
  uint64_t len = 0;
  int j;

  while (!test_bit(CACHE_SET_STOPPING, &c->flags)) {
    /*
     * 填充moving_gc_keys
     * 循环调用bch_keybuf_next_rescan，每次从红黑树返回一个keybuf_key
     */
    w = bch_keybuf_next_rescan(c, &c->moving_gc_keys, &MAX_KEY, moving_pred);
    if (!w)
      break;

    if (ptr_stale(c, &w->key, 0)) {
      bch_keybuf_del(&c->moving_gc_keys, w);
      continue;
    }

    begin_io_read(w, c);
  }
}

static bool bucket_cmp(struct bucket *l, struct bucket *r)
{
  return GC_SECTORS_USED(l) < GC_SECTORS_USED(r);
}

static unsigned bucket_heap_top(struct cache *ca)
{
  struct bucket *b;
  return (b = heap_peek(&ca->heap)) ? GC_SECTORS_USED(b) : 0;
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

  for_each_cache(ca, c, i) {
    unsigned sectors_to_move = 0;
    unsigned reserve_sectors = ca->sb.bucket_size *
      fifo_used(&ca->free[RESERVE_MOVINGGC]);

    ca->heap.used = 0;

    /* 遍历cached disk的bucket */
    for_each_bucket(b, ca) {
      /* 如果为元数据或数据占用量为bucket_size，则continue */
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
    while (heap_pop(&ca->heap, b, bucket_cmp))
      SET_GC_MOVE(b, 1);
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
