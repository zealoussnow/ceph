/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_JOURNAL_H
#define _BCACHE_JOURNAL_H

/*
 * THE JOURNAL:
 *
 * The journal is treated as a circular buffer of buckets - a journal entry
 * never spans two buckets. This means (not implemented yet) we can resize the
 * journal at runtime, and will be needed for bcache on raw flash support.
 * 可以将journal视为一个有多个bucket组成的环形队列 - 一个journal条目永远不会跨越
 * 两个bucket。这意味着（还未实现），我们可以在运行时resize。
 *
 * Journal entries contain a list of keys, ordered by the time they were
 * inserted; thus journal replay just has to reinsert the keys.
 * Journal条目包含由多个key组成的列表，按照它们被插入的时间来排序；因此journal
 * 重放时仅仅要重新插入key。
 *
 * We also keep some things in the journal header that are logically part of the
 * superblock - all the things that are frequently updated. This is for future
 * bcache on raw flash support; the superblock (which will become another
 * journal) can't be moved or wear leveled, so it contains just enough
 * information to find the main journal, and the superblock only has to be
 * rewritten when we want to move/wear level the main journal.
 * 我们也保留一些东西在journal的header中，并且它是超级块的逻辑部分 - 所有这些都
 * 频繁更新。这些是为了在未来支持裸flash设备上的bcache；超级块（可能会称为另外
 * 的journal）不能被移动或者wear leveled，因此它仅仅包含了足够的信息来查找主
 * journal，并且superblock只必须重写当我们想移动/wear level主journal。
 *
 * Currently, we don't journal BTREE_REPLACE operations - this will hopefully be
 * fixed eventually. This isn't a bug - BTREE_REPLACE is used for insertions
 * from cache misses, which don't have to be journaled, and for writeback and
 * moving gc we work around it by flushing the btree to disk before updating the
 * gc information. But it is a potential issue with incremental garbage
 * collection, and it's fragile.
 * 目前，我们不记录BTREE_REPLACE操作 - 这将有希望最终得到修复。这个不是bug -
 * BTREE_REPLACE是用来在cache不命中时插入，此时不必记录日志，对于writeback和moving
 * gc，我们在更新gc信息钱，通过flush btree到磁盘上来绕过。但是递增垃圾回收器是
 * 一个潜在的问题，而且还很脆弱。
 *
 * OPEN JOURNAL ENTRIES:
 *
 * Each journal entry contains, in the header, the sequence number of the last
 * journal entry still open - i.e. that has keys that haven't been flushed to
 * disk in the btree.
 * 每个journal条目的header中，包含了最后的journal仍然打开的序列号 - 即btree中还有未
 * flush到磁盘的keys。
 *
 * We track this by maintaining a refcount for every open journal entry, in a
 * fifo; each entry in the fifo corresponds to a particular journal
 * entry/sequence number. When the refcount at the tail of the fifo goes to
 * zero, we pop it off - thus, the size of the fifo tells us the number of open
 * journal entries
 * 我们通过为每个打开的journal条目维持一个引用计数来跟踪，在一个fifo中；fifo中
 * 的每个条目对应于特定的jounral条目/序列号。当fifo中尾部的引用计数为0时，将它
 * 弹出 - 因此，fifo的大小告诉我们打开的journal条目数。
 *
 * We take a refcount on a journal entry when we add some keys to a journal
 * entry that we're going to insert (held by struct btree_op), and then when we
 * insert those keys into the btree the btree write we're setting up takes a
 * copy of that refcount (held by struct btree_write). That refcount is dropped
 * when the btree write completes.
 * 当我们向将要插入的journal条目中（被btree_op结构体持有）添加一些keys时，且当
 * 我们插入这些key到btree中时，我们要拿到引用计数的一个副本（被btree_write结构
 * 体持有）。当btree写完成的时候引用计数被丢弃。
 *
 * A struct btree_write can only hold a refcount on a single journal entry, but
 * might contain keys for many journal entries - we handle this by making sure
 * it always has a refcount on the _oldest_ journal entry of all the journal
 * entries it has keys for.
 * 一个btree_write结构体只能在单个journal条目中持有一个引用计数，但是可能会为多
 * 个journal条目包含keys - 我们通过确保它始终在其所有的journal条目中最旧的条目
 * 中拥有一个引用计数。
 *
 * JOURNAL RECLAIM:
 * JOURNAL回收：
 *
 * As mentioned previously, our fifo of refcounts tells us the number of open
 * journal entries; from that and the current journal sequence number we compute
 * last_seq - the oldest journal entry we still need. We write last_seq in each
 * journal entry, and we also have to keep track of where it exists on disk so
 * we don't overwrite it when we loop around the journal.
 * 如前所述，fifo的引用计数告诉了我们打开的journal条目个数；从这个和当前journal
 * 序列号我们计算last_seq - 最旧的journal条目我们仍人需要。我们写入last_seq到每
 * 个journal条目，而且我们还必须跟踪磁盘上存在的位置，所以当我们绕过journal时，
 * 不会覆盖它。
 *
 * To do that we track, for each journal bucket, the sequence number of the
 * newest journal entry it contains - if we don't need that journal entry we
 * don't need anything in that bucket anymore. From that we track the last
 * journal bucket we still need; all this is tracked in struct journal_device
 * and updated by journal_reclaim().
 * 为此，我们跟踪每个journal bucket所包含的最新的journal条目序列号 - 如果我们不
 * 需要journal条目，那么我们就不需要bucket中的任何东西了。从那我们跟踪仍然需要的
* journal bucket；所有这些都在结构体journal_device中，并由journal_reclaim()更新。
 *
 * JOURNAL FILLING UP:
 * JOURNAL填满：
 *
 * There are two ways the journal could fill up; either we could run out of
 * space to write to, or we could have too many open journal entries and run out
 * of room in the fifo of refcounts. Since those refcounts are decremented
 * without any locking we can't safely resize that fifo, so we handle it the
 * same way.
 * Journal满的两种方式：写的空间被用尽了，或者有太多打开的journal条目且用尽了
 * fifo中的引用计数。
 *
 * If the journal fills up, we start flushing dirty btree nodes until we can
 * allocate space for a journal write again - preferentially flushing btree
 * nodes that are pinning the oldest journal entries first.
 * 如果journal满了，就开始刷脏的btree节点，直到可以再次为写日志而分配空间 - 优
 * 先刷journal条目中最早的btree节点。
 */

#include "util.h"
#include "list.h"

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
  struct list_head      list;
  atomic_t              *pin;
  struct jset           j;
};

/*
 * We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
  struct jset           *data;
#define JSET_BITS       3
  struct cache_set      *c;
  bool                  dirty;
  bool                  need_write;
};

/* Embedded in struct cache_set */
struct journal {
  struct event                  ev_journal_write;
  pthread_spinlock_t            lock;
  int                           io_in_flight;
  unsigned                      blocks_free;
  uint64_t                      seq;
  DECLARE_FIFO(atomic_t, pin); /* struct { size_t front, back, size, mask; atomic_t *data; } pin; */
  BKEY_PADDED(key);
  struct journal_write	w[2], *cur;
  struct ring_items *items;
  uint32_t journal_batch_lat;
  uint32_t journal_batch_count;
};

/*
 * Embedded in struct cache. First three fields refer to the array of journal
 * buckets, in cache_sb.
 */
struct journal_device {
  /*
   * For each journal bucket, contains the max sequence number of the
   * journal writes it contains - so we know when a bucket can be reused.
   */
  uint64_t              seq[SB_JOURNAL_BUCKETS];
  /* Journal bucket we're currently writing to */
  unsigned              cur_idx;
  /* Last journal bucket that still contains an open journal entry */
  unsigned              last_idx;
  /* Next journal bucket to be discarded */
  unsigned              discard_idx;

#define DISCARD_READY	        0
#define DISCARD_IN_FLIGHT       1
#define DISCARD_DONE            2
  /* 1 - discard in flight, -1 - discard completed */
  atomic_t              discard_in_flight;

  //struct work_struct	discard_work;
  //struct bio          discard_bio;
  //struct bio_vec      discard_bv;

  /* Bio for journal reads/writes to this device */
};

#define journal_pin_cmp(c, l, r)                                        \
  (fifo_idx(&(c)->journal.pin, (l)) > fifo_idx(&(c)->journal.pin, (r)))

#define JOURNAL_PIN     20000

#define journal_full(j)                                                 \
        (!(j)->blocks_free || fifo_free(&(j)->pin) <= 1)

struct cache_set;
struct btree_op;
struct keylist;

atomic_t *bch_journal(struct cache_set *, struct keylist *);
void bch_journal_next(struct journal *);
void bch_journal_meta(struct cache_set *);
int bch_journal_alloc(struct cache_set *);
int bch_journal_read(struct cache_set *c, struct list_head *list);
void bch_journal_mark(struct cache_set *c, struct list_head *list);
int bch_journal_replay(struct cache_set *s, struct list_head *list);

#define dump_pin(pre, p,c)        \
  if (p==NULL) {\
    CACHE_DEBUGLOG(CAT_JOURNAL,"%s dump pin is NULL \n", pre);       \
  } else {      \
    CACHE_DEBUGLOG(CAT_JOURNAL,"%s dump pin %p(value %d idx %d)\n", \
            pre, p, *p, fifo_idx(&(c)->journal.pin,(p)));\
  };

#define dump_journal_pin(prefix,p)                                            \
  if (p==NULL) {                                                              \
    CACHE_DEBUGLOG(CAT_JOURNAL,"%s dump journal pin is NULL \n", prefix);     \
  } else {                                                                    \
    CACHE_DEBUGLOG(CAT_JOURNAL,"%s dump journal pin (size %lu used %lu free %lu full? %d front %d back %d)\n",\
        prefix, (*p).size, fifo_used(p), fifo_free(p),                        \
        fifo_full(p), fifo_front(p), fifo_back(p));                           \
  };

#define dump_journal(p,j)                                 \
  CACHE_DEBUGLOG(CAT_JOURNAL,"%s dump journal seq %lu block_free %u last_seq %lu cur journal write %p(dirty %d need_write %d)\n", \
        p, (*j).seq, (*j).blocks_free, last_seq(j), (*j).cur, (*j).cur->dirty, (*j).cur->need_write);\

#define dump_journal_device(p, j)       \
  CACHE_DEBUGLOG(CAT_JOURNAL,"%s dump journal device(cur_idx %u last_idx %u discard_idx %u discard_in_flight %d)\n",  \
      p, (*j).cur_idx, (*j).last_idx, (*j).discard_idx, (*j).discard_in_flight);


#endif /* _BCACHE_JOURNAL_H */
