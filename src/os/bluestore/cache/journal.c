// SPDX-License-Identifier: GPL-2.0
/*
 * bcache journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "rte_ring.h"

/*
 * Journal replay/recovery:
 *
 * This code is all driven from run_cache_set(); we first read the journal
 * entries, do some other stuff, then we mark all the keys in the journal
 * entries (same as garbage collection would), then we replay them - reinserting
 * them into the cache in precisely the same order as they appear in the
 * journal.
 *
 * We only journal keys that go in leaf nodes, which simplifies things quite a
 * bit.
 */

//static void journal_read_endio(struct bio *bio)
//{
//	struct closure *cl = bio->bi_private;
//	closure_put(cl);
//}
//
static int
journal_read_bucket(struct cache *ca, struct list_head *list, unsigned bucket_index)
{
  /*bucket_index = 2;*/
  struct journal_device *ja = &ca->journal;
  struct journal_replay *i;
  struct jset *j, *data = ca->set->journal.w[0].data;
  unsigned len, left, offset = 0;
  int ret = 0;
  /*printf(" ca->sb.d[%d] = %d. ca->set->bucket_bits = %d \n", bucket_index, ca->sb.d[bucket_index], ca->set->bucket_bits);*/
  /*printf("bucket_to_sector(ca->set, ca->sb.d[bucket_index] = %lu \n", bucket_to_sector(ca->set, ca->sb.d[bucket_index]));*/
  sector_t bucket = bucket_to_sector(ca->set, ca->sb.d[bucket_index]);
  /*unsigned long bucket = bucket_to_sector(ca->set, ca->sb.d[bucket_index]);*/
  //	//closure_init_stack(&cl);
  CACHE_INFOLOG(CAT_JOURNAL," read %lu(sb.d[%u]) bucket \n", ca->sb.d[bucket_index],
                                 bucket_index);
  while (offset < ca->sb.bucket_size) {
reread:	left = ca->sb.bucket_size - offset;
        len = min(left, PAGE_SECTORS << JSET_BITS);
        CACHE_DEBUGLOG(CAT_JOURNAL," left %u len %u offset %u \n",left, len, offset);
        off_t start = (bucket+offset) << 9;
        size_t lenght = len << 9;
        if ( sync_read( ca->fd, data, lenght, start ) == -1 ) {
          CACHE_ERRORLOG(CAT_JOURNAL," read bucket(index %u bucket %ld) error %s \n",
                                        bucket_index, ca->sb.d[bucket_index], strerror(errno));
          assert("read bucket got error"==0);
        }

        j = data;
        while (len) {
          struct list_head *where;
          size_t blocks, bytes = set_bytes(j);
          if (j->magic != jset_magic(&ca->sb)) {
            CACHE_DEBUGLOG(CAT_JOURNAL, "%u: bad magic \n", bucket_index);
            return ret;
          }
          if (bytes > left << 9 || bytes > PAGE_SIZE << JSET_BITS) {
            cache_bug(ca->set, "%u: too big, %zu bytes, offset %u \n",
                                        bucket_index, bytes, offset);
            return ret;
          }
          if (bytes > len << 9) {
            CACHE_INFOLOG(CAT_JOURNAL," bytes %zu > (len %u << 9), goto reread \n",
                                        bytes, len);
            goto reread;
          }
          if (j->csum != csum_set(j)) {
            cache_bug(ca->set, "%u: bad csum, %zu bytes, offset %u\n",
                                    bucket_index, bytes, offset);
            return ret;
          }
          blocks = set_blocks(j, block_bytes(ca->set));
          while (!list_empty(list)) {
            i = list_first_entry(list, struct journal_replay, list);
            if (i->j.seq >= j->last_seq)
              break;
            list_del(&i->list);
            free(i);
          }
          list_for_each_entry_reverse(i, list, list) {
            CACHE_DEBUGLOG(CAT_JOURNAL," j->seq %lu i->j.seq %lu i->j.last_seq %lu \n",
                                        j->seq, i->j.seq, i->j.last_seq);
            if (j->seq == i->j.seq) {
              goto next_set;
            }
            if (j->seq < i->j.last_seq) {
              goto next_set;
            }
            if (j->seq > i->j.seq) {
              where = &i->list;
              goto add;
            }
          }

          where = list;
add:
          i = T2Molloc(offsetof(struct journal_replay, j) + bytes);
          if (!i) {
            return -ENOMEM;
          }
          memcpy(&i->j, j, bytes);
          list_add(&i->list, where);
          ret = 1;
          ja->seq[bucket_index] = j->seq;
          CACHE_INFOLOG(CAT_JOURNAL, "new jset(seq=%lu) ja->seq[%u] %lu\n", j->seq, bucket_index, ja->seq[bucket_index]);
next_set:
          offset        += blocks * ca->sb.block_size;
          len           -= blocks * ca->sb.block_size;
          j = (struct jset *)(((char *) j) + blocks * block_bytes(ca));
        }
  }

  return ret;
}

int bch_journal_read(struct cache_set *c, struct list_head *list)
{
#define read_bucket(b)                                  \
  ({                                                    \
   int ret = journal_read_bucket(ca, list, b);          \
   __set_bit(b, bitmap);                                \
   if (ret < 0)	                                        \
     return ret;                                        \
   ret;                                                 \
   })

  struct cache *ca;
  unsigned iter;

  for_each_cache(ca, c, iter) {
    struct journal_device *ja = &ca->journal;
    /* SB_JOURNAL_BUCKETS: 256U，即占用32个字节，4个unsigned long  */
    DECLARE_BITMAP(bitmap, SB_JOURNAL_BUCKETS);
    unsigned i, l, r, m;
    uint64_t seq;

    bitmap_zero(bitmap, SB_JOURNAL_BUCKETS);
    CACHE_INFOLOG("CAT_JOURNAL", "read %u journal buckets\n", ca->sb.njournal_buckets);
    /*
    * http://book.huihoo.com/data-structures-and-algorithms-with-object-oriented-design-patterns-in-c++/html/page214.html
    *
    * Read journal buckets ordered by golden ratio hash to quickly
    * find a sequence of buckets with valid journal entries
    * 按黄金比率散列顺序读取journal，快速查找一系列有效的journal
    * 条目的buckets
    */
    for (i = 0; i < ca->sb.njournal_buckets; i++) {
      l = (i * 2654435769U) % ca->sb.njournal_buckets;
      if (test_bit(l, bitmap)) {
        break;
      }
      // 1. 如果调用read_bucket 返回 > 0, 则会goto bsearch
      if (read_bucket(l))
        goto bsearch;
    }

    /*
     * If that fails, check all the buckets we haven't checked
     * already
     */
    CACHE_INFOLOG(CAT_JOURNAL,"falling back to linear search \n");

    for (l = find_first_zero_bit(bitmap, ca->sb.njournal_buckets);
        l < ca->sb.njournal_buckets;
        l = find_next_zero_bit(bitmap, ca->sb.njournal_buckets, l + 1)) {
      if (read_bucket(l))
        goto bsearch;
    }

    /* no journal entries on this device? */
    if (l == ca->sb.njournal_buckets) {
      CACHE_WARNLOG(CAT_JOURNAL,"no journal entries on this device, continue\n");
      continue;
    }
bsearch:
    BUG_ON(list_empty(list));

    /* Binary search */
    m = l;
    r = find_next_bit(bitmap, ca->sb.njournal_buckets, l + 1);
    CACHE_INFOLOG(CAT_JOURNAL, "starting binary search, l=%u, r=%u\n",l,r);

    while (l + 1 < r) {
      seq = list_entry(list->prev, struct journal_replay,
          list)->j.seq;

      m = (l + r) >> 1;
      read_bucket(m);

      if (seq != list_entry(list->prev, struct journal_replay,
            list)->j.seq)
        l = m;
      else
        r = m;
    }

    /*
     * Read buckets in reverse order until we stop finding more
     * journal entries
     */
    /*printf(" journal.c FUN %s: finishing up: m=%u njournal_buckets=%u\n",__func__, m, ca->sb.njournal_buckets);*/
    l = m;

    while (1) {
      if (!l--)
        l = ca->sb.njournal_buckets - 1;

      if (l == m)
        break;

      if (test_bit(l, bitmap))
        continue;

      if (!read_bucket(l))
        break;
    }

    seq = 0;

    CACHE_INFOLOG(CAT_JOURNAL,"before(update cur_idx %u last_idx %u discard_idx %u\n",
                ja->cur_idx,ja->last_idx,ja->discard_idx);
    for (i = 0; i < ca->sb.njournal_buckets; i++)
      if (ja->seq[i] > seq) {
        seq = ja->seq[i];
        /*
         * When journal_reclaim() goes to allocate for
         * the first time, it'll use the bucket after
         * ja->cur_idx
         */
        ja->cur_idx = i;
        ja->last_idx = ja->discard_idx = (i + 1) %
        ca->sb.njournal_buckets;

      }
      CACHE_INFOLOG(CAT_JOURNAL,"after(update cur_idx %u last_idx %u discard_idx %u\n",
                ja->cur_idx,ja->last_idx,ja->discard_idx);
    }

  if (!list_empty(list))
    c->journal.seq = list_entry(list->prev,
        struct journal_replay,
        list)->j.seq;
  CACHE_INFOLOG(CAT_JOURNAL,"now new journal seq %lu \n", c->journal.seq);
  return 0;
#undef read_bucket
}

void bch_journal_mark(struct cache_set *c, struct list_head *list)
{
  /*printf(" journal.c FUN %s: journal mark from read journal_replay list \n", __func__);*/
  atomic_t p = { 0 };
  struct bkey *k;
  struct journal_replay *i;
  struct journal *j = &c->journal;
  uint64_t last = j->seq;

  /*
   * journal.pin should never fill up - we never write a journal
   * entry when it would fill up. But if for some reason it does, we
   * iterate over the list in reverse order so that we can just skip that
   * refcount instead of bugging.
   * journal.pin应该永远填不满 - 当它将要满的时候，我们从不写journal条目
   * 但是如果有些理由要这么做，我们逆序迭代list，因此我们可以忽略引用计数
   * 来代替debuging。
   */

  list_for_each_entry_reverse(i, list, list) {
    cache_bug_on(last-- != i->j.seq, c, "Journal seq lost\n");
    i->pin = NULL;

    cache_bug_on(fifo_free(&j->pin) <= 1, c, "Journal pin full\n");
    fifo_push_front(&j->pin, p);
    i->pin = &fifo_front(&j->pin);
    atomic_set(i->pin, 1);

    for (k = i->j.start;
        k < bset_bkey_last(&i->j);
        k = bkey_next(k))
      if (!__bch_extent_invalid(c, k)) {
        unsigned j;

        for (j = 0; j < KEY_PTRS(k); j++)
          if (ptr_available(c, k, j))
            atomic_inc(&PTR_BUCKET(c, k, j)->pin);

        /*printf(" journal.c FUN %s: journal mark initial_mark_key \n", __func__);*/
        bch_initial_mark_key(c, 0, k);
      }
  }
}

///* 下次打开时对未处理的btree insert做重新提交操作 */
int bch_journal_replay(struct cache_set *s, struct list_head *list)
{
  int ret = 0, keys = 0, entries = 0;
  struct bkey *k;
  struct journal_replay *i;
  struct journal_replay *last =
    list_entry(list->prev, struct journal_replay, list);

  uint64_t start = last->j.last_seq, end = last->j.seq, n = start;
  struct keylist keylist;
  CACHE_INFOLOG(CAT_JOURNAL,"journal replay start %lu end %lu\n",
                start, end);
  list_for_each_entry(i, list, list) {
    cache_bug_on(!i->pin || atomic_read(i->pin) != 1, s, "journal replay pin error\n");

    cache_bug_on(n != i->j.seq, s,
        "bcache: journal entries %llu-%llu missing! (replaying %llu-%llu)\n",
        n, i->j.seq - 1, start, end);
    /*printf("<<fun %s, btree_level=%d,keys=%d\n", __func__, i->j.btree_level, i->j.keys);*/
    /*printf(" journal.c FUN %s: jset.btree_level=%d,jset.keys=%d\n",__func__,i->j.btree_level,i->j.keys);*/
    CACHE_INFOLOG(CAT_JOURNAL,"jset seq=%d keys=%d \n", i->j.seq, i->j.keys);
    for (k = i->j.start;
        k < bset_bkey_last(&i->j);
        k = bkey_next(k)) {
      /*trace_bcache_journal_replay_key(k);*/
      /*printf(" journal.c FUN %s: Reply Bkey size=%d,PTR_OFFSET=%d\n",__func__,KEY_SIZE(k),PTR_OFFSET(k,0));*/
      bch_keylist_init_single(&keylist, k);

      /*printf(" journal.c FUN %s: Start insert single keylist nkeys=%d,journal_replay.pin=%d\n",__func__,bch_keylist_nkeys(&keylist),i->pin);*/
      pdump_level_bkey(CACHE_INFOLOG, CAT_JOURNAL, "", k);
      ret = bch_btree_insert(s, &keylist, i->pin, NULL);
      if (ret)
        goto err;

      BUG_ON(!bch_keylist_empty(&keylist));
      keys++;
      /*cond_resched();*/
    }

    if (i->pin)
      atomic_dec(i->pin);
    n = i->j.seq + 1;
    entries++;
  }

  CACHE_INFOLOG(CAT_JOURNAL, "journal replay done, %i keys in %i entries, seq %llu \n",
      keys, entries, end);
err:
  while (!list_empty(list)) {
    i = list_first_entry(list, struct journal_replay, list);
    list_del(&i->list);
    /*kfree(i);*/
    free(i);
  }

  return ret;
}

///* Journalling */
//
static void btree_flush_write(struct cache_set *c)
{
  /*
   * Try to find the btree node with that references the oldest journal
   * entry, best is our current candidate and is locked if non NULL:
   */
  struct btree *b, *best;
  unsigned i;
retry:
  best = NULL;

  for_each_cached_btree(b, c, i) {
    if (btree_current_write(b)->journal) {
      if (!best) {
        best = b;
      } else if (journal_pin_cmp(c, btree_current_write(best)->journal,
        btree_current_write(b)->journal)) {
        best = b;
      }
    }
  }
  b = best;
  if (b) {
    pthread_mutex_lock(&b->write_lock);
    if (!btree_current_write(b)->journal) {
      pthread_mutex_unlock(&b->write_lock);
      /* We raced */
      goto retry;
    }
    __bch_btree_node_write(b);
    pthread_mutex_unlock(&b->write_lock);
  }
}

#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)
//
//static void journal_discard_endio(struct bio *bio)
//{
//	struct journal_device *ja =
//		container_of(bio, struct journal_device, discard_bio);
//	struct cache *ca = container_of(ja, struct cache, journal);
//
//	atomic_set(&ja->discard_in_flight, DISCARD_DONE);
//
//	closure_wake_up(&ca->set->journal.wait);
//	closure_put(&ca->set->cl);
//}
//
//static void journal_discard_work(struct work_struct *work)
//{
//	struct journal_device *ja =
//		container_of(work, struct journal_device, discard_work);
//
//	submit_bio(&ja->discard_bio);
//}
//
static void do_journal_discard(struct cache *ca)
{
  struct journal_device *ja = &ca->journal;
  /*struct bio *bio = &ja->discard_bio;*/
  /*printf(" journal.c FUN %s: ca->discard=%d,ja->discard_idx=%d,ja->last_idx=%d\n",__func__,ca->discard,ja->discard_idx,ja->last_idx );*/
  if (!ca->discard) {
    ja->discard_idx = ja->last_idx;
    return;
  }

  /*switch (atomic_read(&ja->discard_in_flight)) {*/
  /*case DISCARD_IN_FLIGHT:*/
  /*return;*/

  /*case DISCARD_DONE:*/
  /*ja->discard_idx = (ja->discard_idx + 1) %*/
  /*ca->sb.njournal_buckets;*/

  /*atomic_set(&ja->discard_in_flight, DISCARD_READY);*/
  /*fallthrough */

  /*case DISCARD_READY:*/
  /*if (ja->discard_idx == ja->last_idx)*/
  /*return;*/

  /*atomic_set(&ja->discard_in_flight, DISCARD_IN_FLIGHT);*/

  /*bio_init(bio, bio->bi_inline_vecs, 1);*/
  /*bio_set_op_attrs(bio, REQ_OP_DISCARD, 0);*/
  /*bio->bi_iter.bi_sector	= bucket_to_sector(ca->set,*/
  /*ca->sb.d[ja->discard_idx]);*/
  /*bio_set_dev(bio, ca->bdev);*/
  /*bio->bi_iter.bi_size	= bucket_bytes(ca);*/
  /*bio->bi_end_io		= journal_discard_endio;*/

  /*closure_get(&ca->set->cl);*/
  /*INIT_WORK(&ja->discard_work, journal_discard_work);*/
  /*schedule_work(&ja->discard_work);*/
  /*}*/
}

static void journal_reclaim(struct cache_set *c)
{
  struct bkey *k = &c->journal.key;
  struct cache *ca;
  uint64_t last_seq;
  unsigned iter, n = 0;
  atomic_t p;

  /*printf(" journal.c <%s>: Reclaim: before update pin(pop front 0)/last_seq fifo_used=%d,last_seq=%d\n",__func__, fifo_used(&c->journal.pin),last_seq);*/
  while (!atomic_read(&fifo_front(&c->journal.pin)))
    fifo_pop(&c->journal.pin, p);

  /*#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)*/
  last_seq = last_seq(&c->journal);
  /*printf(" journal.c <%s>: Reclaim: after update pin(pop front 0)/last_seq fifo_used=%d,last_seq=%d\n",__func__, fifo_used(&c->journal.pin),last_seq);*/

  /* Update last_idx */

  for_each_cache(ca, c, iter) {
    struct journal_device *ja = &ca->journal;
    /*printf(" journal.c <%s>: befor(update last_idx) last_idx=%d,cur_idx=%d\n",__func__, ja->last_idx,ja->cur_idx);*/
    while (ja->last_idx != ja->cur_idx &&
        ja->seq[ja->last_idx] < last_seq)
      ja->last_idx = (ja->last_idx + 1) %
        ca->sb.njournal_buckets;
    /*printf(" journal.c FUN %s: after(update last_idx)  last_idx=%d,cur_idx=%d\n",__func__, ja->last_idx,ja->cur_idx);*/
  }

  for_each_cache(ca, c, iter)
    do_journal_discard(ca);

  if (c->journal.blocks_free)
    goto out;

  /*
   * Allocate:
   * XXX: Sort by free journal space
   */

  for_each_cache(ca, c, iter) {
    struct journal_device *ja = &ca->journal;
    /*printf(" ja->cur_idx = %d \n", ja->cur_idx);*/
    unsigned next = (ja->cur_idx + 1) % ca->sb.njournal_buckets;
    /*printf(" next = %d \n", next);*/

    /*printf(">> function %s,cur_idx=%d,discard_idx=%d,next=%d \n", __func__,ja->cur_idx,ja->discard_idx,next);*/
    /*printf(" journal.c FUN %s: befor(update cur_idx): cur_idx=%d,next(new)=%d,discard_idx=%d\n",__func__, ja->cur_idx,next,ja->discard_idx);*/
    /* No space available on this device */
    if (next == ja->discard_idx)
      continue;

    ja->cur_idx = next;
    /*printf(" ca->sb.d[ja->cur_idx] = %d \n", ca->sb.d[ja->cur_idx]);*/
    k->ptr[n++] = PTR(0,
        bucket_to_sector(c, ca->sb.d[ja->cur_idx]),
        ca->sb.nr_this_dev);
    /*printf(" journal.c FUN %s: after(update cur_idx): cur_idx=%d,next=%d,discard_idx=%d\n",__func__, ja->cur_idx,next,ja->discard_idx);*/
    /*printf(" journal.c FUN %s: journal new bucket nr=%d\n",__func__, ca->sb.d[ja->cur_idx]);*/
  }

  bkey_init(k);
  SET_KEY_PTRS(k, n);
  if (n)
    c->journal.blocks_free = c->sb.bucket_size >> c->block_bits;
  /*printf(" journal.c FUN %s: journal new blocks_free=%d\n",__func__, c->journal.blocks_free);*/
  return ;
out:
  /*printf(" journal.c FUN %s: journal bucket blocks_free=%d, no need update cur_idx\n",__func__, c->journal.blocks_free);*/
  return;
  /*if (!journal_full(&c->journal))*/
  /*__closure_wake_up(&c->journal.wait);*/
}
//
void bch_journal_next(struct journal *j)
{
  atomic_t p = { 1 };

  j->cur = (j->cur == j->w)
    ? &j->w[1]
    : &j->w[0];

  /*
   * The fifo_push() needs to happen at the same time as j->seq is
   * incremented for last_seq() to be calculated correctly
   */
  /*printf(" journal.c <%s>: Journal Next before update pin(push 1)/seq fifo_used=%d,jset->seq=%d\n",__func__,fifo_used(&j->pin),j->cur->data->seq);*/
  BUG_ON(!fifo_push(&j->pin, p));
  atomic_set(&fifo_back(&j->pin), 1);
  j->cur->data->seq	= ++j->seq;
  j->cur->dirty		= false;
  j->cur->need_write	= false;
  j->cur->data->keys	= 0;
  /*printf(" journal.c <%s>: Journal Next after update pin(push 1)/seq fifo_used=%d,jset->seq=%d\n",__func__,fifo_used(&j->pin),j->cur->data->seq);*/

  if (fifo_full(&j->pin)){
    printf(" journal.c <%s>: Journal Next fifo is full fifo_used=%ld\n",__func__,fifo_used(&j->pin));
  }
}

static void journal_write_unlocked(struct cache_set *c)
{
  struct cache *ca;
  struct journal_write *w = c->journal.cur;
  struct bkey *k = &c->journal.key;
  unsigned i, sectors = set_blocks(w->data, block_bytes(c)) *
    c->sb.block_size;
  CACHE_DEBUGLOG(CAT_JOURNAL," journal write \n");
  if (!w->need_write) {
    CACHE_ERRORLOG(CAT_JOURNAL,"need write %d in here\n", w->need_write);
    assert("need write false" == 0 );
#if 0
    closure_return_with_destructor(cl, journal_write_unlock);
    return;
#endif
  } else if (journal_full(&c->journal)) {
    CACHE_ERRORLOG(CAT_JOURNAL,"journal should not be full in here\n");
    assert("journal should not be full in here" == 0);
#if 0
    journal_reclaim(c);
    spin_unlock(&c->journal.lock);
    btree_flush_write(c);
    continue_at(cl, journal_write, system_wq);
    return;
#endif
  }

  c->journal.blocks_free -= set_blocks(w->data, block_bytes(c));

  w->data->btree_level = c->root->level;

  bkey_copy(&w->data->btree_root, &c->root->key);
  bkey_copy(&w->data->uuid_bucket, &c->uuid_bucket);

  for_each_cache(ca, c, i) {
    w->data->prio_bucket[ca->sb.nr_this_dev] = ca->prio_buckets[0];
  }

  w->data->magic		= jset_magic(&c->sb);
  w->data->version	= BCACHE_JSET_VERSION;
  w->data->last_seq	= last_seq(&c->journal);
  w->data->csum		= csum_set(w->data);
  for (i = 0; i < KEY_PTRS(k); i++) {
    ca = PTR_CACHE(c, k, i);
    atomic_long_add(sectors, &ca->meta_sectors_written);
    // 1. start = PTR_OFFSET;
    /*off_t start = PTR_OFFSET(k, i) << 9;*/
    off_t start = PTR_OFFSET_to_bytes(k, i);
    size_t len = sectors << 9;
    if ( sync_write( ca->fd, w->data, len, start) == -1) {
      CACHE_ERRORLOG(CAT_JOURNAL, "write journal(fd %d data %p start %lu len %lu) got error: %s\n",
                                          ca->fd, w->data, start, len, strerror(errno));
      assert("write journal got error" == 0);
    }
    SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + sectors);
    ca->journal.seq[ca->journal.cur_idx] = w->data->seq;
  }
  atomic_dec_bug(&fifo_back(&c->journal.pin));
  bch_journal_next(&c->journal);
  journal_reclaim(c);

  /*spin_unlock(&c->journal.lock);*/
  pthread_spin_unlock(&c->journal.lock);
  //	continue_at(cl, journal_write_done, NULL);
}
//
//static void journal_write(struct closure *cl)
//{
//	struct cache_set *c = container_of(cl, struct cache_set, journal.io);
//
//	spin_lock(&c->journal.lock);
//	journal_write_unlocked(cl);
//}
//
static void journal_try_write(struct cache_set *c)
{
  struct journal_write *w = c->journal.cur;

  w->need_write = true;
  journal_write_unlocked(c);
  /*if (!c->journal.io_in_flight) {*/
  /*c->journal.io_in_flight = 1;*/
  /*journal_write_unlocked(c);*/
  /*closure_call(cl, journal_write_unlocked, NULL, &c->cl);*/
  /*} else {*/
  /*pthread_spin_unlock(&c->journal.lock);*/
  /*spin_unlock(&c->journal.lock);*/
  /*}*/
}

struct journal_write *
journal_wait_for_write(struct cache_set *c, unsigned nkeys)
{
  size_t sectors;

  /*pthread_spin_lock( &c->journal.lock);*/
  while (1) {
    if (fifo_free(&c->journal.pin) <= 1) {
      dump_journal_pin("fifo full", &c->journal.pin);
      goto flush;
    }
    struct journal_write *w = c->journal.cur;
    sectors = __set_blocks(w->data, w->data->keys + nkeys,
        block_bytes(c)) * c->sb.block_size;
    if (sectors <= min_t(size_t, c->journal.blocks_free * c->sb.block_size,
          PAGE_SECTORS << JSET_BITS)) {
      return w;
    }
    if (!journal_full(&c->journal)) {
      /*
       1. block_free不为0
       2. pip也还够用
         所以这种场景是插入的数据空间太大了，导致blocks_free剩余的空间
         不够，所以需要先将现在的jset数据刷到磁盘，之后会进行journal_reclam
         和journal_next，来保证本次的journal有足够的空间，所以这种场景下，我们
         需要保证必须有bkeys需要写入，否则断言
      */
      /*
       * XXX: If we were inserting so many keys that they
       * won't fit in an _empty_ journal write, we'll
       * deadlock. For now, handle this in
       * bch_keylist_realloc() - but something to think about.
       */
      if ( !w->data->keys) {
        CACHE_ERRORLOG(CAT_JOURNAL," journal write jset keys is NULL( block_free %u full? %d\n",
                c->journal.blocks_free, fifo_free(&(c->journal.pin)));
        BUG_ON(!w->data->keys);
      }
      CACHE_DEBUGLOG(CAT_JOURNAL,"journal not full,but blocks_free %u is not \
                                enough for sectors %u, try to flush cur write\n",
                                c->journal.blocks_free, sectors);
      journal_try_write(c);
    } else {
flush:
      dump_journal("journal full", &c->journal);
      dump_journal_pin("journal full",&c->journal.pin);
      // 先刷入，释放pin
      journal_reclaim(c);
      pthread_spin_unlock(&c->journal.lock);

      btree_flush_write(c);
      // 后将其释放的pin记性回收
      /*
      * btree_flush_write 采用同步刷，这里不用解锁
      */
      //pthread_spin_unlock(&c->journal.lock);
    }
    /*spin_lock(&c->journal.lock);*/
    pthread_spin_lock(&c->journal.lock);
  }
}

static void journal_write_batch(struct cache_set *c)
{
  struct journal *j = &c->journal;
  struct journal_write *w = NULL;
  struct ring_items *items = j->items;
  struct ring_item *item = NULL;
  int i = 0;
  uint32_t new_lat = 0;
  struct bkey *insert;
  int ret;

  if (items->count) {
    struct ring_items *insert_items = ring_items_alloc(items->count);
    insert_items->insert_keys = calloc(1, sizeof(struct keylist));
    if (insert_items->insert_keys == NULL) {
      CACHE_ERRORLOG(NULL, "calloc insert items insert_keys keylist failed\n");
      assert("calloc insert items insert_keys keylist failed" == 0);
    }
    bch_keylist_init(insert_items->insert_keys);

    j->last_journal_count = items->count;
    new_lat = j->last_journal_count / j->last_journal_lat;
    j->last_journal_lat = clamp_t(uint32_t, new_lat,
        1, 10);

    for(i = 0; i< items->count; i++){
      item = items->items[i];

      for(insert = item->insert_keys->keys; insert != item->insert_keys->top; insert = bkey_next(insert)){
        bch_keylist_insert(insert_items->insert_keys, insert, c);
      }

      if (ring_items_add(insert_items, item) != 0) {
        CACHE_ERRORLOG(CAT_JOURNAL, "add item to insert_items error, items count %u\n", insert_items->count);
        assert("error add item" == 0);
      }
    }
    ring_items_reset(items);
    j->journal_batch_dirty = false;

    w = journal_wait_for_write(c, bch_keylist_nkeys(insert_items->insert_keys));

    memcpy(bset_bkey_last(w->data), insert_items->insert_keys->keys, bch_keylist_bytes(insert_items->insert_keys));
    w->data->keys += bch_keylist_nkeys(insert_items->insert_keys);
    insert_items->journal_ref = &fifo_back(&c->journal.pin);
    atomic_inc(insert_items->journal_ref);
    journal_try_write(c);

    while (rte_ring_enqueue(c->journal_ring, insert_items)) {
      pthread_yield();
    }
    pthread_cond_broadcast(&c->journal_ring_cond);

  } else {
    pthread_spin_unlock(&c->journal.lock);
  }
}

static void journal_write_work(evutil_socket_t fd, short events, void *arg)
{
  struct cache_set *c = arg;

  pthread_spin_lock( &c->journal.lock);
  journal_write_batch(c);
}

/*
 * Entry point to the journalling code - bio_insert() and btree_invalidate()
 * pass bch_journal() a list of keys to be journalled, and then
 * bch_journal() hands those same keys off to btree_insert_async()
 * 向btree添加时，调用该函数建立journal
 */
atomic_t *bch_prep_journal(struct ring_item *item)
{
  /*struct journal_write *w = NULL;*/
  struct keylist *keys = item->insert_keys;
  struct cache *ca = item->ca_handler;
  struct cache_set *c = ca->set;
  struct journal *j = &c->journal;
  atomic_t *ret;

  pthread_spin_lock( &c->journal.lock);
  if ((j->items->nkeys + bch_keylist_nkeys(item->insert_keys)) * sizeof(uint64_t) > (block_bytes(c) - sizeof(struct jset))) {
    journal_write_batch(c);
    pthread_spin_lock( &c->journal.lock);
  }

  if (ring_items_add(j->items, item) != 0) {
    CACHE_ERRORLOG(CAT_JOURNAL, "add item to items error, items count %u\n", j->items->count);
    assert("error add item" == 0);
  }

  j->items->nkeys += bch_keylist_nkeys(item->insert_keys);

  if (!j->journal_batch_dirty) {
    j->journal_batch_dirty = true;
    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec = 0;
    tv.tv_usec = j->last_journal_lat * USEC_PER_MSEC;
    delayed_work_add(&c->journal.ev_journal_write, &tv);
    pthread_spin_unlock(&c->journal.lock);
  } else {
    pthread_spin_unlock(&c->journal.lock);
  }

  /*dump_pin("journal write done", ret, c);*/

  return ret;
}

atomic_t *bch_journal(struct cache_set *c, struct keylist *keys)
{
  struct journal_write *w = NULL;
  atomic_t *ret;

  CACHE_DEBUGLOG(CAT_JOURNAL,"journal cache sync %d \n",CACHE_SYNC(&c->sb));
  if (!CACHE_SYNC(&c->sb)) {
    CACHE_WARNLOG(CAT_JOURNAL,"not sync, do not allowed journal\n");
    return NULL;
  }

  pthread_spin_lock( &c->journal.lock);
  w = journal_wait_for_write(c, bch_keylist_nkeys(keys));

  memcpy(bset_bkey_last(w->data), keys->keys, bch_keylist_bytes(keys));
  w->data->keys += bch_keylist_nkeys(keys);
  ret = &fifo_back(&c->journal.pin);
  atomic_inc(ret);
  journal_try_write(c);

  dump_pin("journal write done", ret, c);
  return ret;
}

void bch_journal_meta(struct cache_set *c)
{
  struct keylist keys;
  atomic_t *ref;
  bch_keylist_init(&keys);

  ref = bch_journal(c, &keys);
  if (ref)
    atomic_dec_bug(ref);
  dump_pin("journal meta", ref, c);
}

/*void bch_journal_free(struct cache_set *c)*/
/*{*/
/*free_pages((unsigned long) c->journal.w[1].data, JSET_BITS);*/
/*free_pages((unsigned long) c->journal.w[0].data, JSET_BITS);*/
/*free_fifo(&c->journal.pin);*/
/*}*/

int bch_journal_alloc(struct cache_set *c)
{
  struct journal *j = &c->journal;

  pthread_spin_init(&j->lock, 0);
  /*INIT_DELAYED_WORK(&j->work, journal_write_work);*/

  c->journal_delay_ms = 100;

  j->w[0].c = c;
  j->w[1].c = c;

  delayed_work_assign(&j->ev_journal_write, c->ev_base, journal_write_work, (void*)c, 0);

  j->items = ring_items_alloc((block_bytes(c) - sizeof(struct jset))/sizeof(uint64_t) + 1);
  if ( j->items == NULL) {
    CACHE_ERRORLOG(NULL, "alloc ring items faild \n");
    assert("alloc ring items faild " == 0);
  }
  j->last_journal_lat = 1;
  j->last_journal_count = 0;
  j->journal_batch_dirty = false;


  if (!(init_fifo(&j->pin, JOURNAL_PIN)) ||
      posix_memalign(&j->w[0].data, MEMALIGN, PAGE_SIZE << JSET_BITS ) ||
      posix_memalign(&j->w[1].data, MEMALIGN, PAGE_SIZE << JSET_BITS ))
    return -ENOMEM;
  dump_journal_pin("journal alloc init", &j->pin);
  return 0;
}

int bch_dump_journal_replay(struct cache_set *s, struct list_head *list)
{
  int keys = 0, entries = 0;
  struct bkey *k;
  struct journal_replay *i;
  struct journal_replay *last =
    list_entry(list->prev, struct journal_replay, list);

  uint64_t start = last->j.last_seq, end = last->j.seq;
  CACHE_INFOLOG(CAT_JOURNAL,"start %lu end %lu\n",
                start, end);
  list_for_each_entry(i, list, list) {
    CACHE_INFOLOG(CAT_JOURNAL,"jset seq=%d keys=%d \n", i->j.seq, i->j.keys);
    for (k = i->j.start;
        k < bset_bkey_last(&i->j);
        k = bkey_next(k)) {
      pdump_level_bkey(CACHE_INFOLOG, CAT_JOURNAL, "", k);
      keys++;
    }
    entries++;
  }

  CACHE_INFOLOG(CAT_JOURNAL, "Dump done, %i keys in %i entries, seq %llu \n",
      keys, entries, end);
}
