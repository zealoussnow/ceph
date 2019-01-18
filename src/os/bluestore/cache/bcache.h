/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_H
#define _BCACHE_H

/*
 * SOME HIGH LEVEL CODE DOCUMENTATION:
 *
 * Bcache mostly works with cache sets, cache devices, and backing devices.
 *
 * Support for multiple cache devices hasn't quite been finished off yet, but
 * it's about 95% plumbed through. A cache set and its cache devices is sort of
 * like a md raid array and its component devices. Most of the code doesn't care
 * about individual cache devices, the main abstraction is the cache set.
 *
 * Multiple cache devices is intended to give us the ability to mirror dirty
 * cached data and metadata, without mirroring clean cached data.
 *
 * Backing devices are different, in that they have a lifetime independent of a
 * cache set. When you register a newly formatted backing device it'll come up
 * in passthrough mode, and then you can attach and detach a backing device from
 * a cache set at runtime - while it's mounted and in use. Detaching implicitly
 * invalidates any cached data for that backing device.
 *
 * A cache set can have multiple (many) backing devices attached to it.
 *
 * There's also flash only volumes - this is the reason for the distinction
 * between struct cached_dev and struct bcache_device. A flash only volume
 * works much like a bcache device that has a backing device, except the
 * "cached" data is always dirty. The end result is that we get thin
 * provisioning with very little additional code.
 *
 * Flash only volumes work but they're not production ready because the moving
 * garbage collector needs more work. More on that later.
 *
 * BUCKETS/ALLOCATION:
 *
 * Bcache is primarily designed for caching, which means that in normal
 * operation all of our available space will be allocated. Thus, we need an
 * efficient way of deleting things from the cache so we can write new things to
 * it.
 *
 * To do this, we first divide the cache device up into buckets. A bucket is the
 * unit of allocation; they're typically around 1 mb - anywhere from 128k to 2M+
 * works efficiently.
 *
 * Each bucket has a 16 bit priority, and an 8 bit generation associated with
 * it. The gens and priorities for all the buckets are stored contiguously and
 * packed on disk (in a linked list of buckets - aside from the superblock, all
 * of bcache's metadata is stored in buckets).
 *
 * The priority is used to implement an LRU. We reset a bucket's priority when
 * we allocate it or on cache it, and every so often we decrement the priority
 * of each bucket. It could be used to implement something more sophisticated,
 * if anyone ever gets around to it.
 *
 * The generation is used for invalidating buckets. Each pointer also has an 8
 * bit generation embedded in it; for a pointer to be considered valid, its gen
 * must match the gen of the bucket it points into.  Thus, to reuse a bucket all
 * we have to do is increment its gen (and write its new gen to disk; we batch
 * this up).
 *
 * Bcache is entirely COW - we never write twice to a bucket, even buckets that
 * contain metadata (including btree nodes).
 *
 * THE BTREE:
 *
 * Bcache is in large part design around the btree.
 *
 * At a high level, the btree is just an index of key -> ptr tuples.
 *
 * Keys represent extents, and thus have a size field. Keys also have a variable
 * number of pointers attached to them (potentially zero, which is handy for
 * invalidating the cache).
 *
 * The key itself is an inode:offset pair. The inode number corresponds to a
 * backing device or a flash only volume. The offset is the ending offset of the
 * extent within the inode - not the starting offset; this makes lookups
 * slightly more convenient.
 *
 * Pointers contain the cache device id, the offset on that device, and an 8 bit
 * generation number. More on the gen later.
 *
 * Index lookups are not fully abstracted - cache lookups in particular are
 * still somewhat mixed in with the btree code, but things are headed in that
 * direction.
 *
 * Updates are fairly well abstracted, though. There are two different ways of
 * updating the btree; insert and replace.
 *
 * BTREE_INSERT will just take a list of keys and insert them into the btree -
 * overwriting (possibly only partially) any extents they overlap with. This is
 * used to update the index after a write.
 *
 * BTREE_REPLACE is really cmpxchg(); it inserts a key into the btree iff it is
 * overwriting a key that matches another given key. This is used for inserting
 * data into the cache after a cache miss, and for background writeback, and for
 * the moving garbage collector.
 *
 * There is no "delete" operation; deleting things from the index is
 * accomplished by either by invalidating pointers (by incrementing a bucket's
 * gen) or by inserting a key with 0 pointers - which will overwrite anything
 * previously present at that location in the index.
 *
 * This means that there are always stale/invalid keys in the btree. They're
 * filtered out by the code that iterates through a btree node, and removed when
 * a btree node is rewritten.
 *
 * BTREE NODES:
 *
 * Our unit of allocation is a bucket, and we we can't arbitrarily allocate and
 * free smaller than a bucket - so, that's how big our btree nodes are.
 *
 * (If buckets are really big we'll only use part of the bucket for a btree node
 * - no less than 1/4th - but a bucket still contains no more than a single
 * btree node. I'd actually like to change this, but for now we rely on the
 * bucket's gen for deleting btree nodes when we rewrite/split a node.)
 *
 * Anyways, btree nodes are big - big enough to be inefficient with a textbook
 * btree implementation.
 * 不管怎样，btree节点非常大 - 大到足以使效率低下。
 *
 * The way this is solved is that btree nodes are internally log structured; we
 * can append new keys to an existing btree node without rewriting it. This
 * means each set of keys we write is sorted, but the node is not.
 *
 * We maintain this log structure in memory - keeping 1Mb of keys sorted would
 * be expensive, and we have to distinguish between the keys we have written and
 * the keys we haven't. So to do a lookup in a btree node, we have to search
 * each sorted set. But we do merge written sets together lazily, so the cost of
 * these extra searches is quite low (normally most of the keys in a btree node
 * will be in one big set, and then there'll be one or two sets that are much
 * smaller).
 *
 * This log structure makes bcache's btree more of a hybrid between a
 * conventional btree and a compacting data structure, with some of the
 * advantages of both.
 *
 * GARBAGE COLLECTION:
 *
 * We can't just invalidate any bucket - it might contain dirty data or
 * metadata. If it once contained dirty data, other writes might overwrite it
 * later, leaving no valid pointers into that bucket in the index.
 *
 * Thus, the primary purpose of garbage collection is to find buckets to reuse.
 * It also counts how much valid data it each bucket currently contains, so that
 * allocation can reuse buckets sooner when they've been mostly overwritten.
 *
 * It also does some things that are really internal to the btree
 * implementation. If a btree node contains pointers that are stale by more than
 * some threshold, it rewrites the btree node to avoid the bucket's generation
 * wrapping around. It also merges adjacent btree nodes if they're empty enough.
 *
 * THE JOURNAL:
 *
 * Bcache's journal is not necessary for consistency; we always strictly
 * order metadata writes so that the btree and everything else is consistent on
 * disk in the event of an unclean shutdown, and in fact bcache had writeback
 * caching (with recovery from unclean shutdown) before journalling was
 * implemented.
 *
 * Rather, the journal is purely a performance optimization; we can't complete a
 * write until we've updated the index on disk, otherwise the cache would be
 * inconsistent in the event of an unclean shutdown. This means that without the
 * journal, on random write workloads we constantly have to update all the leaf
 * nodes in the btree, and those writes will be mostly empty (appending at most
 * a few keys each) - highly inefficient in terms of amount of metadata writes,
 * and it puts more strain on the various btree resorting/compacting code.
 *
 * The journal is just a log of keys we've inserted; on startup we just reinsert
 * all the keys in the open journal entries. That means that when we're updating
 * a node in the btree, we can wait until a 4k block of keys fills up before
 * writing them out.
 *
 * For simplicity, we only journal updates to leaf nodes; updates to parent
 * nodes are rare enough (since our leaf nodes are huge) that it wasn't worth
 * the complexity to deal with journalling them (in particular, journal replay)
 * - updates to non leaf nodes just happen synchronously (see btree_split()).
 */

#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <limits.h>
#include <pthread.h>

#include "bcache_types.h"
#include "delayed_work.h"
#include "bset.h"
#include "util.h"
#include "journal.h"
#include "atomic.h"
#include "aio.h"
#include "log.h"
#include "rbtree.h"
#include "rbtree_augmented.h"

struct bucket {
  atomic_t      pin;

  uint16_t      prio;

  uint8_t       gen;
  uint8_t       last_gc; /* Most out of date gen in the btree */
  uint16_t      gc_mark; /* Bitfield used by GC. See below for field */
  uint16_t      dirty_keys; /* dirty keys in bucket */
  bool          move_dirty_only; /* dirty keys in bucket */
};

/*
 * I'd use bitfields for these, but I don't trust the compiler not to screw me
 * as multiple threads touch struct bucket without locking
 */

BITMASK(GC_MARK,                struct bucket, gc_mark, 0, 2);
#define GC_MARK_INIT            0
#define GC_MARK_RECLAIMABLE     1
#define GC_MARK_DIRTY           2
#define GC_MARK_METADATA        3
#define GC_SECTORS_USED_SIZE    13
#define MAX_GC_SECTORS_USED     (~(~0ULL << GC_SECTORS_USED_SIZE)) /* 8191 */
BITMASK(GC_SECTORS_USED, struct bucket, gc_mark, 2, GC_SECTORS_USED_SIZE);
BITMASK(GC_MOVE, struct bucket, gc_mark, 15, 1);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

// used for gc
#define UPDATE_GC_SIZE_WM_SECONDS 5
#define WAKE_UP_GC_SIZE_WM  1073741824 // 1GB
#define WAKE_UP_GC_WM 80

struct search;
struct btree;
struct keybuf;

//struct keybuf_key {
//      //struct rb_node                node; /* include/linux/rbtree.h */
//      BKEY_PADDED(key);
//      void                    *private;
//};

//struct keybuf {
//      struct bkey             last_scanned;
//      //spinlock_t            lock;
//
//      /*
//       * Beginning and end of range in rb tree - so that we can skip taking
//       * lock and checking the rb tree when we need to check for overlapping
//       * keys.
//       */
//      struct bkey             start;
//      struct bkey             end;
//
//      //struct rb_root                keys;
//
//#define KEYBUF_NR             500
//      DECLARE_ARRAY_ALLOCATOR(struct keybuf_key, freelist, KEYBUF_NR);
//};

struct keybuf_key {
  struct rb_node          node;
  BKEY_PADDED(key);
  bool                    private;
};

struct keybuf {
  struct bkey             last_scanned;
  pthread_spinlock_t      lock;
  struct bkey             start;
  struct bkey             end;

  struct rb_root          keys;

#define KEYBUF_NR               500
  DECLARE_ARRAY_ALLOCATOR(struct keybuf_key, freelist, KEYBUF_NR);
};

struct bcache_device {
  struct cache_set      *c;
  unsigned              id;
#define BCACHEDEVNAME_SIZE      12
  char                  name[BCACHEDEVNAME_SIZE];

  //struct gendisk              *disk;

  unsigned long         flags;
#define BCACHE_DEV_CLOSING      0
#define BCACHE_DEV_DETACHING    1
#define BCACHE_DEV_UNLINK_DONE  2

  unsigned              nr_stripes;
  unsigned              stripe_size;
  atomic_t              *stripe_sectors_dirty;
  unsigned long         *full_dirty_stripes;

  unsigned long         sectors_dirty_last;
  long                  sectors_dirty_derivative;
  //struct bio_set              *bio_split;
  //int (*cache_miss)(struct btree *, struct search *,
  //              struct bio *, unsigned);
  //int (*ioctl) (struct bcache_device *, fmode_t, unsigned, unsigned long);
};

struct io {
  /* Used to track sequential IO so it can be skipped */
  struct hlist_node     hash;
  struct list_head      lru;

  unsigned long         jiffies;
  uint64_t                sequential;
  sector_t              last;
};

struct current_thread {
  pthread_t               thread_id;

  struct list_head        list;
  unsigned int            sequential_io;
  unsigned int            sequential_io_avg;
};

struct cached_dev {
  // 从bcache_device中合并
  struct cache_set      *c;
  unsigned              nr_stripes;
  unsigned              stripe_size;
  atomic_t              *stripe_sectors_dirty;
  unsigned long         *full_dirty_stripes;
  unsigned long         sectors_dirty_last;
  long                  sectors_dirty_derivative;
  unsigned              data_csum:1;

  struct list_head      list;    /* 链表的表头，链表节点就是cached_dev */
  struct bcache_device  disk;
  //struct block_device *bdev;

  /* 管理super block io */
  struct cache_sb               sb;

  /* Refcount on the cache set. Always nonzero when we're caching. */
  atomic_t              count;
  //struct work_struct  detach;

  /*
  * Device might not be running if it's dirty and the cache set hasn't
  * showed up yet.
  */
  atomic_t              running; /* 表明主设备的状态 */

  /*
  * Writes take a shared lock from start to finish; scanning for dirty
  * data to refill the rb tree requires an exclusive lock.
  */
  //struct rw_semaphore writeback_lock;
  pthread_rwlock_t writeback_lock;

  /*
  * Nonzero, and writeback has a refcount (d->count), iff there is dirty
  * data in the cache. Protected by writeback_lock; must have an
  * shared lock to set and exclusive lock to clear.
  */
  struct bch_ratelimit  writeback_rate;
  atomic_t              read_iops;
  unsigned              safe_read;
  unsigned              read_wait;
  unsigned              pre_read_wait;
  //struct delayed_work writeback_rate_update;

  // control writeback cutoffs
  int                   cutoff_writeback;
  int                   cutoff_writeback_sync;
  int                   iobypass_water_level;

  unsigned              read_water_level;
  unsigned              cutoff_gc_busy;
  unsigned              max_gc_keys_onetime;

  /*
  * Internal to the writeback code, so read_dirty() can keep track of
  * where it's at.
  */
  sector_t              last_read;

  /* Limit number of writeback bios in flight */
  //struct semaphore    in_flight;
  //struct task_struct  *writeback_thread;
  //struct workqueue_struct     *writeback_write_wq;

  pthread_t               writeback_thread;
  pthread_mutex_t         writeback_mut;
  pthread_cond_t          writeback_cond;
  bool                    writeback_should_stop;
  atomic_t                has_dirty;

  pthread_t               writeback_rate_update_thread;

  struct keybuf         writeback_keys;

  /* For tracking sequential IO */
#define RECENT_IO_BITS  7
#define RECENT_IO       (1 << RECENT_IO_BITS)
  struct io             io[RECENT_IO]; /* 记录顺序读写信息？*/
  struct hlist_head     io_hash[RECENT_IO + 1];
  struct list_head      io_lru;
  struct list_head      io_thread;
  pthread_spinlock_t    io_lock;
  //spinlock_t          io_lock;

  //struct cache_accounting     accounting;

  /* The rest of this all shows up in sysfs */
  unsigned              sequential_cutoff;
  unsigned              readahead;

  unsigned              verify:1;
  unsigned              bypass_torture_test:1;

  unsigned              partial_stripes_expensive:1;
  unsigned              writeback_metadata:1;
  atomic_t              writeback_stop;
  unsigned char         writeback_percent;
  unsigned              writeback_delay;
  atomic_t              real_wb_delay;

  uint64_t              writeback_rate_target;
  int64_t                       writeback_rate_proportional;
  int64_t                       writeback_rate_derivative;
  int64_t                       writeback_rate_change;

  unsigned              writeback_rate_update_seconds;
  unsigned              writeback_rate_d_term;
  unsigned              writeback_rate_p_term_inverse;
  unsigned              wb_status;
};

enum alloc_reserve {
  RESERVE_BTREE,
  RESERVE_PRIO,
  RESERVE_MOVINGGC,
  RESERVE_NONE,
  RESERVE_NR,
};


typedef void (*logger_callback_fn)(void *cd, int serial, struct timespec start, struct timespec end);

struct cache {
  char uuid_str[40];
  logger_callback_fn logger_cb;
  void               *bluestore_cd;
  struct aio_handler  * handler;
  int                  fd;
  int                  hdd_fd;
  const char *bdev_path;
  struct cache_set      *set;
  struct cache_sb               sb;
  //struct bio          sb_bio;
  //struct bio_vec              sb_bv[1];

  //struct kobject              kobj;
  //struct block_device *bdev;

  //struct task_struct  *alloc_thread;

  pthread_t               alloc_thread;
  pthread_mutex_t         alloc_mut;
  pthread_cond_t          alloc_cond;
  struct prio_set               *disk_buckets;

  /*
  * When allocating new buckets, prio_write() gets first dibs - since we
  * may not be allocate at all without writing priorities and gens.
  * prio_buckets[] contains the last buckets we wrote priorities to (so
  * gc can mark them as metadata), prio_next[] contains the buckets
  * allocated for the next prio write.
  */
  uint64_t              *prio_buckets;
  uint64_t              *prio_last_buckets;

  /*
  * free: Buckets that are ready to be used
  *
  * free_inc: Incoming buckets - these are buckets that currently have
  * cached data in them, and we can't reuse them until after we write
  * their new gen to disk. After prio_write() finishes writing the new
  * gens/prios, they'll be moved to the free list (and possibly discarded
  * in the process)
  */
  DECLARE_FIFO(long, free)[RESERVE_NR];
  DECLARE_FIFO(long, free_inc);

  size_t                        fifo_last_bucket;

  /* Allocation stuff: */
  struct bucket         *buckets;

  /* struct { size_t size, used; struct bucket * *data; } heap; */
  DECLARE_HEAP(struct bucket *, heap);

  /*
  * If nonzero, we know we aren't going to find any buckets to invalidate
  * until a gc finishes - otherwise we could pointlessly burn a ton of
  * cpu
  */
  unsigned              invalidate_needs_gc;

  bool                  discard; /* Get rid of? */

  struct journal_device journal;

  /* The rest of this all shows up in sysfs */
#define IO_ERROR_SHIFT          20
  atomic_t              io_errors;
  atomic_t              io_count;

  atomic_long_t         meta_sectors_written;
  atomic_long_t         btree_sectors_written;
  atomic_long_t         sectors_written;
  uint64_t btree_nodes;
  uint64_t btree_nbkeys;
  uint64_t total_size;
  uint64_t dirty_size;
  uint64_t btree_bad_nbeys;
  uint64_t btree_dirty_nbkeys;
  uint64_t btree_null_nbkeys;
  uint64_t zero_keysize_nbkeys;
  bool dump_btree_detail;
  struct event ev_update_gc_wm;
  uint64_t wake_up_gc_size_wm;
  bool need_wakeup_gc;
};

enum gc_running_status {
  GC_IDLE = 0,
  GC_START,
  GC_RUNNING,
  GC_READ_MOVING,
  GC_INVALID,
};

enum wb_running_status {
  WB_IDLE = 0,
  WB_REFILL_DIRTY,
  WB_READING_DIRTY,
  WB_WRITING_DIRTY,
};

struct gc_stat {
  size_t                nodes;
  size_t                key_bytes;

  size_t                nkeys;
  uint64_t              data;   /* sectors */
  unsigned              in_use; /* percent */
  // all bucket include pin+avail+unavail
  uint64_t              gc_all_buckets;

  // avail = init + reclaimable
  uint64_t              gc_avail_buckets;
  uint64_t              gc_init_buckets;
  uint64_t              gc_reclaimable_buckets;
  // unavail = dirty + meta
  uint64_t              gc_unavail_buckets;
  uint64_t              gc_dirty_buckets;
  uint64_t              gc_meta_buckets;
  // meta = uuids + writeback_dirty + journal +prio
  uint64_t              gc_uuids_buckets;
  uint64_t              gc_writeback_dirty_buckets;
  uint64_t              gc_journal_buckets;
  uint64_t              gc_prio_buckets;

  // moving is need to read and write to new
  uint64_t              gc_moving_buckets;
  uint64_t              gc_moving_bkeys;
  uint64_t              gc_moving_bkey_size;
  uint64_t              gc_pin_buckets;
  uint64_t              gc_empty_buckets;
  uint64_t              gc_full_buckets;

  unsigned              status;
};

/*
 * Flag bits, for how the cache set is shutting down, and what phase it's at:
 *
 * CACHE_SET_UNREGISTERING means we're not just shutting down, we're detaching
 * all the backing devices first (their cached data gets invalidated, and they
 * won't automatically reattach).
 *
 * CACHE_SET_STOPPING always gets set first when we're closing down a cache set;
 * we'll continue to run normally for awhile with CACHE_SET_STOPPING set (i.e.
 * flushing dirty data).
 *
 * CACHE_SET_RUNNING means all cache devices have been registered and journal
 * replay is complete.
 */
#define CACHE_SET_UNREGISTERING         0
#define CACHE_SET_STOPPING              1
#define CACHE_SET_RUNNING               2

struct cache_set {
  int                     fd;
  int                     hdd_fd;

  logger_callback_fn logger_cb;
  void               *bluestore_cd;
  struct event_base     *ev_base;

  bool wakeup_gc_immeditally;

  struct list_head      list;
  //struct kobject              kobj;
  //struct kobject              internal;
  //struct dentry               *debug;
  //struct cache_accounting accounting;

  unsigned long         flags;

  struct cache_sb               sb;

  struct cache          *cache[MAX_CACHES_PER_SET]; /* MAX_CACHES_PER_SET: 8 */
  struct cache          *cache_by_alloc[MAX_CACHES_PER_SET];
  int                   caches_loaded;

  struct bcache_device  **devices;
  struct list_head      cached_devs;
  uint64_t              cached_dev_sectors;
  struct cached_dev       *dc;

  pthread_mutex_t         bucket_lock;

  /* log2(bucket_size), in sectors */
  unsigned short                bucket_bits;

  /* log2(block_size), in sectors */
  unsigned short                block_bits;

  /*
  * Default number of pages for a new btree node - may be less than a
  * full bucket
  */
  unsigned              btree_pages;

  /*
  * Lists of struct btrees; lru is the list for structs that have memory
  * allocated for actual btree node, freed is for structs that do not.
  *
  * We never free a struct btree, except on shutdown - we just put it on
  * the btree_cache_freed list and reuse it later. This simplifies the
  * code, and it doesn't cost us much memory as the memory usage is
  * dominated by buffers that hold the actual btree node data and those
  * can be freed - and the number of struct btrees allocated is
  * effectively bounded.
  *
  * btree_cache_freeable effectively is a small cache - we use it because
  * high order page allocations can be rather expensive, and it's quite
  * common to delete and allocate btree nodes in quick succession. It
  * should never grow past ~2-3 nodes in practice.
  */
  struct list_head      btree_cache;
  struct list_head      btree_cache_freeable;
  struct list_head      btree_cache_freed;

  /* Number of elements in btree_cache + btree_cache_freeable lists */
  unsigned              btree_cache_used;

  /*
  * If we need to allocate memory for a new btree node and that
  * allocation fails, we can cannibalize another node in the btree cache
  * to satisfy the allocation - lock to guarantee only one thread does
  * this at a time:
  */
  //wait_queue_head_t   btree_cache_wait;
  pthread_mutex_t         btree_cache_wait_mut;
  pthread_cond_t          btree_cache_wait_cond;
  //struct task_struct  *btree_cache_alloc_lock;
  pthread_t               btree_cache_alloc_lock;

  /*
  * When we free a btree node, we increment the gen of the bucket the
  * node is in - but we can't rewrite the prios and gens until we
  * finished whatever it is we were doing, otherwise after a crash the
  * btree node would be freed but for say a split, we might not have the
  * pointers to the new nodes inserted into the btree yet.
  *
  * This is a refcount that blocks prio_write() until the new keys are
  * written.
  */
  atomic_t              prio_blocked;
  //wait_queue_head_t   bucket_wait;
  pthread_mutex_t         bucket_wait_mut;
  pthread_cond_t          bucket_wait_cond;

  pthread_mutex_t         journal_ring_mut;
  pthread_cond_t          journal_ring_cond;
  struct rte_ring         *journal_ring;

  /*
  * For any bio we don't skip we subtract the number of sectors from
  * rescale; when it hits 0 we rescale all the bucket priorities.
  */
  atomic_t              rescale;
  /*
  * When we invalidate buckets, we use both the priority and the amount
  * of good data to determine which buckets to reuse first - to weight
  * those together consistently we keep track of the smallest nonzero
  * priority of any bucket.
  */
  uint16_t              min_prio;

  /*
  * max(gen - last_gc) for all buckets. When it gets too big we have to gc
  * to keep gens from wrapping around.
  */
  uint8_t                       need_gc;
  struct gc_stat                gc_stats;
  size_t                        nbuckets;
  size_t                        avail_nbuckets;

  //struct task_struct  *gc_thread;
  /* Where in the btree gc currently is */
  struct bkey           gc_done;

  /*
  * The allocation code needs gc_mark in struct bucket to be correct, but
  * it's not while a gc is in progress. Protected by bucket_lock.
  */
  int                   gc_mark_valid;

  /* Counts how many sectors bio_insert has added to the cache */
  atomic_t              sectors_to_gc;
  //wait_queue_head_t   gc_wait;
  pthread_t             gc_thread;
  pthread_mutex_t       gc_wait_mut;
  pthread_cond_t        gc_wait_cond;
  atomic_t              gc_stop;
  atomic_t              gc_thread_stop;
  atomic_t              gc_moving_stop;

  atomic_t              cached_hits;
  //struct list_head    moving_gc_keys;
  //struct bkey             gc_last_scanned;
  struct keybuf           moving_gc_keys;
  atomic_t              gc_seq;
  /* Number of moving GC bios in flight */
  //struct semaphore    moving_in_flight;

  //struct workqueue_struct     *moving_gc_wq;

  struct btree          *root;

#ifdef CONFIG_BCACHE_DEBUG
  struct btree          *verify_data;
  struct bset           *verify_ondisk;
  //struct mutex                verify_lock;
  pthread_mutex_t               verify_lock;
#endif

  unsigned              nr_uuids;
  struct uuid_entry     *uuids;
  BKEY_PADDED(uuid_bucket);
  //struct semaphore    uuid_write_mutex;

  /*
  * A btree node on disk could have too many bsets for an iterator to fit
  * on the stack - have to dynamically allocate them
  */
  //mempool_t           *fill_iter;

  struct bset_sort_state        sort;

  /* List of buckets we're currently writing data to */
  struct list_head      data_buckets;
  //spinlock_t          data_bucket_lock;
  pthread_spinlock_t      data_bucket_lock;

  struct journal                journal;

#define CONGESTED_MAX           1024
  unsigned              congested_last_us;
  atomic_t              congested;

  /* The rest of this all shows up in sysfs */
  unsigned              congested_read_threshold_us;
  unsigned              congested_write_threshold_us;

  struct time_stats     btree_gc_time;
  struct time_stats     btree_split_time;
  struct time_stats     btree_read_time;

  //atomic_long_t               cache_read_races;
  //atomic_long_t               writeback_keys_done;
  //atomic_long_t               writeback_keys_failed;

  enum                  {
    ON_ERROR_UNREGISTER,
    ON_ERROR_PANIC,
  }                     on_error;
  unsigned              error_limit;
  unsigned              error_decay;

  unsigned short                journal_delay_ms;
  bool                  expensive_debug_checks;
  unsigned              verify:1;
  unsigned              key_merging_disabled:1;
  unsigned              gc_always_rewrite:1;
  unsigned              shrinker_disabled:1;
  unsigned              copy_gc_enabled:1;

#define BUCKET_HASH_BITS        12
        struct hlist_head       bucket_hash[1 << BUCKET_HASH_BITS]; /* 4096 */
};

struct bbio {
  unsigned              submit_time_us;
  union {
    struct bkey key;
    uint64_t    _pad[3];
    /*
     * We only need pad = 3 here because we only ever carry around a
     * single pointer - i.e. the pointer we're doing io to/from.
     */
  };
  //struct bio          bio;
};

#define BTREE_PRIO              USHRT_MAX
#define INITIAL_PRIO            32768U
#define BTREE_MAX_PAGES         (256 * 1024 / PAGE_SIZE)

#define btree_bytes(c)          ((c)->btree_pages * PAGE_SIZE)
#define btree_blocks(b)                                                 \
        ((unsigned) (KEY_SIZE(&b->key) >> (b)->c->block_bits))

#define btree_default_blocks(c)                                         \
        ((unsigned) ((PAGE_SECTORS * (c)->btree_pages) >> (c)->block_bits))

#define bucket_pages(c)         ((c)->sb.bucket_size / PAGE_SECTORS)
#define bucket_bytes(c)         ((c)->sb.bucket_size << 9)
#define block_bytes(c)          ((c)->sb.block_size << 9)


#define prios_per_bucket(c)                             \
        ((bucket_bytes(c) - sizeof(struct prio_set)) /  \
         sizeof(struct bucket_disk))
#define prio_buckets(c)                                 \
        DIV_ROUND_UP((size_t) (c)->sb.nbuckets, prios_per_bucket(c))

static inline size_t sector_to_bucket(struct cache_set *c, sector_t s)
{
  return s >> c->bucket_bits;
}

#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error)
{
  return (void *) error;
}

static inline long PTR_ERR(__force const void *ptr)
{
  return (long) ptr;
}

static inline bool IS_ERR(__force const void *ptr)
{
  return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(__force const void *ptr)
{
  return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

/* 将bucket的个数转换为多少个扇区数 */
static inline sector_t bucket_to_sector(struct cache_set *c, size_t b)
{
  return ((sector_t) b) << c->bucket_bits;
}

static inline sector_t bucket_remainder(struct cache_set *c, sector_t s)
{
  return s & (c->sb.bucket_size - 1);
}

static inline struct cache *PTR_CACHE(struct cache_set *c,
                                      const struct bkey *k,
                                      unsigned ptr)
{
  return c->cache[PTR_DEV(k, ptr)];
}

static inline size_t PTR_BUCKET_NR(struct cache_set *c,
                                   const struct bkey *k,
                                   unsigned ptr)
{
  return sector_to_bucket(c, PTR_OFFSET(k, ptr));
}

static inline struct bucket *PTR_BUCKET(struct cache_set *c,
                                        const struct bkey *k,
                                        unsigned ptr)
{
  return PTR_CACHE(c, k, ptr)->buckets + PTR_BUCKET_NR(c, k, ptr);
}

static inline uint8_t gen_after(uint8_t a, uint8_t b)
{
  uint8_t r = a - b;
  return r > 128U ? 0 : r;
}

static inline uint8_t ptr_stale(struct cache_set *c, const struct bkey *k,
                                unsigned i)
{
  return gen_after(PTR_BUCKET(c, k, i)->gen, PTR_GEN(k, i));
}

static inline bool ptr_available(struct cache_set *c, const struct bkey *k,
                                 unsigned i)
{
  return (PTR_DEV(k, i) < MAX_CACHES_PER_SET) && PTR_CACHE(c, k, i);
}

/* Btree key macros */

/*
 * This is used for various on disk data structures - cache_sb, prio_set, bset,
 * jset: The checksum is _always_ the first 8 bytes of these structs
 */
#define csum_set(i)                                                     \
        bch_crc64(((char *) (i)) + sizeof(uint64_t),                    \
                  ((char *) bset_bkey_last(i)) -                        \
                  (((char *) (i)) + sizeof(uint64_t)))

/* Error handling macros */

#define warn_dump_stack(cat, ...)                                       \
do {                                                                    \
     CACHE_WARNLOG(cat, __VA_ARGS__);                                   \
     dump_stack();                                                      \
} while (0)

#define warn_dump_stack_on(cond, cat, ...)                              \
do {                                                                    \
     if (cond) {                                                        \
       warn_dump_stack(cat, ...)                                        \
     }                                                                  \
} while (0)


/*
 * we can add some bkey info when bkey bug happend
 */
#define bkey_bug(bkey, ...)                                             \
do {                                                                    \
        CACHE_ERRORLOG(NULL, __VA_ARGS__);                              \
        dump_stack();                                                   \
        assert("bkey_bug" == 0);                                        \
} while (0)

/*
 * we add some btree info when btree bug happend
 */
#define btree_bug(btree, ...)                                           \
do {                                                                    \
        CACHE_ERRORLOG(NULL, __VA_ARGS__);                              \
        dump_stack();                                                   \
        assert("btree_bug" == 0);                                       \
} while (0)

/*
 * we add same cache info when cache module bug happend
 */
#define cache_bug(cache_set, ...)                                       \
do {                                                                    \
        CACHE_ERRORLOG(NULL, __VA_ARGS__);                              \
        dump_stack();                                                   \
        assert("cache_bug" == 0);                                       \
} while (0)

#define btree_bug_on(cond, btree, ...)                                  \
do {                                                                    \
        if (cond)                                                       \
                btree_bug(b, __VA_ARGS__);                              \
} while (0)

#define cache_bug_on(cond, cache_set, ...)                              \
do {                                                                    \
        if (cond)                                                       \
                cache_bug(c, __VA_ARGS__);                              \
} while (0)

/* Looping macros */

#define for_each_cache(ca, cs, iter)                                    \
        for (iter = 0; ca = cs->cache[iter], iter < (cs)->sb.nr_in_set; iter++)

#define for_each_bucket(b, ca)                                          \
        for (b = (ca)->buckets + (ca)->sb.first_bucket;                 \
             b < (ca)->buckets + (ca)->sb.nbuckets; b++)

static inline void cached_dev_put(struct cached_dev *dc)
{
#if 0
        if (atomic_dec_and_test(&dc->count))
                schedule_work(&dc->detach);
#endif
}

static inline bool cached_dev_get(struct cached_dev *dc)
{
        /*
         * atomic_inc_not_zero(v): include/linux/atomic.h
         * 当v不为0时加1
         */
        //if (!atomic_inc_not_zero(&dc->count))
        //      return false;

        /* Paired with the mb in cached_dev_attach */
        //smp_mb__after_atomic();
        return true;
}

/*
 * bucket_gc_gen() returns the difference between the bucket's current gen and
 * the oldest gen of any pointer into that bucket in the btree (last_gc).
 */

static inline uint8_t bucket_gc_gen(struct bucket *b)
{
  return b->gen - b->last_gc;
}

#define BUCKET_GC_GEN_MAX       96U

static inline void wake_up_gc(struct cache_set *c)
{
  pthread_cond_signal(&c->gc_wait_cond);
}

static inline void wake_up_alloc_thread(struct cache *ca)
{
  pthread_cond_signal(&ca->alloc_cond);
}

static inline void wake_up_allocators(struct cache_set *c)
{
  struct cache *ca;
  unsigned i;

  for_each_cache(ca, c, i)
    wake_up_alloc_thread(ca);
}

/* Forward declarations */

//void bch_count_io_errors(struct cache *, blk_status_t, const char *);
//void bch_bbio_count_io_errors(struct cache_set *, struct bio *,
//                            blk_status_t, const char *);
//void bch_bbio_endio(struct cache_set *, struct bio *, blk_status_t,
//              const char *);
//void bch_bbio_free(struct bio *, struct cache_set *);
//struct bio *bch_bbio_alloc(struct cache_set *);

int sync_write( int fd, void *buf, size_t lenght, off_t offset);
int sync_read( int fd, void *buf, size_t lenght, off_t offset);
//void __bch_submit_bbio(struct bio *, struct cache_set *);
//void bch_submit_bbio(struct bio *, struct cache_set *, struct bkey *, unsigned);

uint8_t bch_inc_gen(struct cache *, struct bucket *);
//void bch_rescale_priorities(struct cache_set *, int);

bool bch_can_invalidate_bucket(struct cache *, struct bucket *);
void __bch_invalidate_one_bucket(struct cache *, struct bucket *);

void __bch_bucket_free(struct cache *, struct bucket *);
void bch_bucket_free(struct cache_set *, struct bkey *);

long bch_bucket_alloc(struct cache *, unsigned, bool);
int __bch_bucket_alloc_set(struct cache_set *, unsigned,
                           struct bkey *, int, bool);
int bch_bucket_alloc_set(struct cache_set *, unsigned,
                         struct bkey *, int, bool);
bool bch_alloc_sectors(struct cache_set *, struct bkey *, unsigned,
                       unsigned, unsigned, bool);

__printf(2, 3)
bool bch_cache_set_error(struct cache_set *, const char *, ...);

void bch_prio_write(struct cache *);

//extern struct workqueue_struct *bcache_wq;
extern const char * const bch_cache_modes[];
//extern struct mutex bch_register_lock;
extern pthread_mutex_t bch_register_lock;
extern struct list_head bch_cache_sets;

//extern struct kobj_type bch_cached_dev_ktype;
//extern struct kobj_type bch_flash_dev_ktype;
//extern struct kobj_type bch_cache_set_ktype;
//extern struct kobj_type bch_cache_set_internal_ktype;
//extern struct kobj_type bch_cache_ktype;

//void bch_cached_dev_release(struct kobject *);
//void bch_flash_dev_release(struct kobject *);
//void bch_cache_set_release(struct kobject *);
//void bch_cache_release(struct kobject *);

int bch_uuid_write(struct cache_set *);
void bcache_write_super(struct cache_set *);

//int bch_flash_dev_create(struct cache_set *c, uint64_t size);

//int bch_cached_dev_attach(struct cached_dev *, struct cache_set *);
//void bch_cached_dev_detach(struct cached_dev *);
void bch_cached_dev_run(struct cached_dev *);
//void bcache_device_stop(struct bcache_device *);

//void bch_cache_set_unregister(struct cache_set *);
void bch_cache_set_stop(struct cache_set *);
int bch_keylist_realloc(struct keylist *, unsigned, struct cache_set *);
int bch_keylist_insert(struct keylist *, struct bkey *, struct cache_set *);

struct cache_set *bch_cache_set_alloc(struct cache_sb *);
void bch_btree_cache_free(struct cache_set *);
int bch_btree_cache_alloc(struct cache_set *);
void bch_moving_init_cache_set(struct cache_set *);
int bch_open_buckets_alloc(struct cache_set *);
void bch_open_buckets_free(struct cache_set *);

int bch_cache_allocator_start(struct cache *ca);
void dump_stack();
void set_gc_mode(struct cached_dev *dc, int val);
void set_read_water_level(struct cached_dev *dc, int val);
void set_cached_hits(struct cache *ca, int val);

#endif /* _BCACHE_H */
