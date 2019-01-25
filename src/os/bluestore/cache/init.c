

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libaio.h>
#include <uuid/uuid.h>
#include <blkid/blkid.h>

#include <limits.h>

#include "bcache.h"
#include "btree.h"
#include "atomic.h"
#include "request.h"
#include <math.h>
#include "writeback.h"
#include "delayed_work.h"

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>




#include "aio.h"
#include "extents.h"
#include "log.h"
#include "libcache.h"

#define BUFFER_SIZE 4096
#define IO_LOG_LINE 100

/*struct cache_set bch_cache_sets;*/
T2_LIST_HEAD(bch_cache_sets);
/*struct mutex bch_register_lock;*/
pthread_mutex_t bch_register_lock;

enum prio_io_op {
  REQ_OP_READ,
  REQ_OP_WRITE,
  REQ_OP_INVALID,
};

#define CUTOFF_CACHE_ADD 95
uint64_t
getblocks(int fd)
{
  uint64_t ret;
  struct stat statbuf;
  if (fstat(fd, &statbuf)) {
    CACHE_ERRORLOG(NULL, "ioctl fd %d got error\n", fd);
    assert("ioctl fd got error" == 0);
  }
#define BLKGETSIZE _IO(0x12,96) /* return device size /512 (long *arg) */
  ret = statbuf.st_size / 512;
  if (S_ISBLK(statbuf.st_mode))
    if (ioctl(fd, BLKGETSIZE, &ret)) {
      CACHE_ERRORLOG(NULL, "ioctl fd %d got error\n", fd);
      assert("ioctl fd got error" == 0);
  }
  CACHE_INFOLOG(NULL,"get fd %d blocks %u \n", fd, ret);

  return ret;
}

/*struct cache *g_cache;*/
/*
 *  prio_io即可处理写，也可以处理写，根据op来定义
 */
static void
prio_io(struct cache *ca, uint64_t bucket, int op,
		    unsigned long op_flags)
{
  off_t start = (bucket * ca->sb.bucket_size) << 9;
  size_t len = bucket_bytes(ca);

  // 数据：数据在ca->disk_buckets
  if ( op == REQ_OP_WRITE ) {
    CACHE_DEBUGLOG(CAT_WRITE,"prio io write fd %d start 0x%x len %x (bucket %u)\n",
                                ca->fd, start, len, bucket);
    if ( sync_write(ca->fd, ca->disk_buckets, len, start) == -1){
      CACHE_ERRORLOG(CAT_WRITE, "prio io write error: %s\n", strerror(errno));
      assert("prio io write error" == 0);
    }
  }
  if ( op == REQ_OP_READ ) {
    CACHE_DEBUGLOG(CAT_WRITE,"prio io read fd %d start 0x%x len %x (bucket %u)\n",
                                ca->fd, start, len, bucket);
    if ( sync_read(ca->fd, ca->disk_buckets, len, start ) == -1 ) {
      CACHE_ERRORLOG(CAT_WRITE, "prio io read error: %s\n", strerror(errno));
      assert("prio io read error" == 0);
    }
  }

  // 这部分IO有必要进行异步写入吗？后期可以好好考虑下
  // 如果被设计成异步的形式，则需要有一个写完成回调
}

static void prio_read(struct cache *ca, uint64_t bucket)
{
  CACHE_INFOLOG(NULL,"prio read bucket %lu \n", bucket);
  struct prio_set *p = ca->disk_buckets;
  struct bucket_disk *d = p->data + prios_per_bucket(ca), *end = d;
  struct bucket *b;
  unsigned bucket_nr = 0;
  for (b = ca->buckets;b < ca->buckets + ca->sb.nbuckets; b++, d++) {
    if (d == end) {
      ca->prio_buckets[bucket_nr] = bucket;
      ca->prio_last_buckets[bucket_nr] = bucket;
      bucket_nr++;
      prio_io(ca, bucket, REQ_OP_READ, 0);
      if (p->csum != bch_crc64(&p->magic, bucket_bytes(ca) - 8)) {
        cache_bug(ca->set ,"check csum error \n");
      }
      if (p->magic != pset_magic(&ca->sb)) {
        cache_bug(ca->set, "check prio_set magic error \n");
      }
      bucket = p->next_bucket;
      d = p->data;
    }
    b->prio = d->prio;
    b->gen = b->last_gc = d->gen;
  }
}


void
bch_prio_write(struct cache *ca)
{
  int i;
  struct bucket *b;
  ca->disk_buckets->seq++;

  atomic_long_add(ca->sb.bucket_size * prio_buckets(ca),
      &ca->meta_sectors_written);
  CACHE_DEBUGLOG(CAT_WRITE, "prio write(prio_buckets(ca) %lu meta_sectors_written %ld \n",
        prio_buckets(ca), ca->meta_sectors_written);
  /*
   * #define prio_buckets(c)                                         \
   *	DIV_ROUND_UP((size_t) (c)->sb.nbuckets, prios_per_bucket(c))
   */
  for (i = prio_buckets(ca) - 1; i >= 0; --i) {
    long bucket;
    struct prio_set *p = ca->disk_buckets;
    /* 第一个bucket_disk数据和最后一个bucket_disk数据 */
    struct bucket_disk *d = p->data;
    struct bucket_disk *end = d + prios_per_bucket(ca);

    /*
     * #define prios_per_bucket(c)                             \
     *         ((bucket_bytes(c) - sizeof(struct prio_set)) /  \
     *         sizeof(struct bucket_disk))
     */
    for (b = ca->buckets + i * prios_per_bucket(ca);
        b < ca->buckets + ca->sb.nbuckets && d < end;
        b++, d++) {
      d->prio = b->prio;
      d->gen = b->gen;
    }
    p->next_bucket	= ca->prio_buckets[i + 1];
    p->magic	= pset_magic(&ca->sb);
    p->csum		= bch_crc64(&p->magic, bucket_bytes(ca) - 8);
    bucket = bch_bucket_alloc(ca, RESERVE_PRIO, true);
    /*printf(" main.c FUN %s: alloc bucket nr=%d\n",__func__, bucket);*/
    BUG_ON(bucket == -1);
    pthread_mutex_unlock(&ca->set->bucket_lock);
    prio_io(ca, bucket, REQ_OP_WRITE, 0);
    pthread_mutex_lock(&ca->set->bucket_lock);
    ca->prio_buckets[i] = bucket;
    atomic_dec_bug(&ca->buckets[bucket].pin);
  }
  pthread_mutex_unlock(&ca->set->bucket_lock);
  bch_journal_meta(ca->set);
  pthread_mutex_lock(&ca->set->bucket_lock);

  /*
   * Don't want the old priorities to get garbage collected until after we
   * finish writing the new ones, and they're journalled
   */
  for (i = 0; i < prio_buckets(ca); i++) {
    if (ca->prio_last_buckets[i]) {
      __bch_bucket_free(ca, &ca->buckets[ca->prio_last_buckets[i]]);
    }
    ca->prio_last_buckets[i] = ca->prio_buckets[i];
  }
}


/* Superblock */
static const char *read_super(struct cache_sb *sb, struct cache_sb *s)
{
  const char *err;
  unsigned i;
  sb->offset		= s->offset;
  sb->version		= s->version;

  memcpy(sb->magic,	s->magic, 16);
  memcpy(sb->uuid,	s->uuid, 16);
  memcpy(sb->set_uuid,	s->set_uuid, 16);
  memcpy(sb->label,	s->label, SB_LABEL_SIZE);

  sb->flags		= s->flags;
  sb->seq			= s->seq;
  sb->last_mount		= s->last_mount;
  sb->first_bucket	= s->first_bucket;
  sb->keys		= s->keys;

  /* #define SB_JOURNAL_BUCKETS      256U */
  for (i = 0; i < SB_JOURNAL_BUCKETS; i++) {
    sb->d[i] = s->d[i]; /* d is journal buckets */
  }

  CACHE_INFOLOG(NULL, "read sb version %llu, flags %llu, seq %llu, journal size %u\n",
  sb->version, sb->flags, sb->seq, sb->keys);

  err = "Not a bcache superblock";
  if (sb->offset != SB_SECTOR) {
    goto err;
  }

  err = "Magic number not matched";
  if (memcmp(sb->magic, bcache_magic, 16)) {
    goto err;
  }

  err = "Too many journal buckets";
  if (sb->keys > SB_JOURNAL_BUCKETS) {
    goto err;
  }
  err = "Bad checksum";
  if (s->csum != csum_set(s)) {
    CACHE_ERRORLOG(NULL, "super csum check error read csum %lu  now csum %lu \n", s->csum, csum_set(s));
    goto err;
  }

  err = "Bad UUID";
  if (bch_is_zero(sb->uuid, 16)) {
    CACHE_ERRORLOG(NULL, "super check uuid is zero \n");
    goto err;
  }
  sb->block_size	= s->block_size;
  /*err = "Superblock block size smaller than device block size";*/
  /*if (sb->block_size << 9 < bdev_logical_block_size(bdev))*/
  /*goto err;*/
  switch (sb->version) {
    /*case BCACHE_SB_VERSION_BDEV:*/
      /*sb->data_offset	= BDEV_DATA_START_DEFAULT;*/
      /*break;*/
      /*case BCACHE_SB_VERSION_BDEV_WITH_OFFSET:*/
      /*sb->data_offset	= le64_to_cpu(s->data_offset);*/

      /*err = "Bad data offset";*/
      /*if (sb->data_offset < BDEV_DATA_START_DEFAULT)*/
      /*goto err;*/

      /*break;*/
    case BCACHE_SB_VERSION_CDEV:
    case BCACHE_SB_VERSION_CDEV_WITH_UUID:
      /* nbuckets: 磁盘可用的buckets总数，总的扇区数/bucket_size */
      sb->nbuckets	= s->nbuckets;
      sb->bucket_size	= s->bucket_size; /* 默认为1024 */
      sb->nr_in_set	= s->nr_in_set;

      /*
      * TODO nr_this_dev应该是为了支持同一个cache set有多个cache设备
      * 的情况，目前来说，一个cache set只有一个cache设备和多个backing
      * 设置，所以nr_this_dev为0，bcache-super-show中列出的dev.cache.pos
      * 就是nr_this_dev这个值
      */
      sb->nr_this_dev	= s->nr_this_dev;

      err = "Too many buckets";
      if (sb->nbuckets > LONG_MAX) {
        goto err;
      }

      err = "Not enough buckets";
      if (sb->nbuckets < 1 << 7) {
        goto err;
      }

      err = "Bad block/bucket size";
      if (!is_power_of_2(sb->block_size) ||
                sb->block_size > PAGE_SECTORS ||
                !is_power_of_2(sb->bucket_size) ||
                sb->bucket_size < PAGE_SECTORS) {
        goto err;
      }
     err = "Bad set UUID";
     if (bch_is_zero(sb->set_uuid, 16)) {
         goto err;
     }
      err = "Bad cache device number in set";
      if (!sb->nr_in_set ||
                sb->nr_in_set <= sb->nr_this_dev ||
                sb->nr_in_set > MAX_CACHES_PER_SET) {
        goto err;
      }
      err = "Journal buckets not sequential";
      for (i = 0; i < sb->keys; i++) {
        if (sb->d[i] != sb->first_bucket + i) {
          goto err;
        }
      }

      err = "Too many journal buckets";
      if (sb->first_bucket + sb->keys > sb->nbuckets) {
        goto err;
      }

      err = "Invalid superblock: first bucket comes before end of super";
      if (sb->first_bucket * sb->bucket_size < 16) {
        goto err;
      }
      break;
    default:
      err = "Unsupported superblock version";
      goto err;
  }

  time_t now;
  time(&now);
  sb->last_mount = now;
  err = NULL;

  return err;
err:
  CACHE_ERRORLOG(NULL, "read super error: %s\n", err);
  return err;
}

#define alloc_bucket_pages(buf, c)			\
	posix_memalign(&buf, MEMALIGN, bucket_pages(c)*PAGE_SIZE)

void
bch_cache_set_unregister(struct cache_set *c)
{
  set_bit(CACHE_SET_UNREGISTERING, &c->flags);
  /*bch_cache_set_stop(c);*/
}


static int
cache_alloc(struct cache *ca)
{
  size_t free;
  struct bucket *b;

  // 比如nbucket=20480，那么向上靠近它的就是2**15=32768(2**14=16386)
  free = roundup_pow_of_two(ca->sb.nbuckets) >> 10;
  /*printf(" main.c FUN %s: nbuckets=%d,free=%d,prio_buckets(ca)=%d,bucket_pages(ca)=%d\n",__func__, ca->sb.nbuckets,free,prio_buckets(ca),bucket_pages(ca));*/
  // 1. 一个bucket是1024个扇区，一个页是4096，即8个扇区,因此，一个bucket是128页
  // 2. 一个bucket的字节数是：1024*512b
  if (!init_fifo(&ca->free[RESERVE_BTREE], 8) ||
        !init_fifo_exact(&ca->free[RESERVE_PRIO], prio_buckets(ca)) ||
        !init_fifo(&ca->free[RESERVE_MOVINGGC], free) ||
        !init_fifo(&ca->free[RESERVE_NONE], free) ||
        !init_fifo(&ca->free_inc,	free << 2) ||
        !init_heap(&ca->heap,	free << 3) ||
        !(ca->buckets	= T2Molloc(sizeof(struct bucket) *
        ca->sb.nbuckets)) ||
        !(ca->prio_buckets	= T2Molloc(sizeof(uint64_t) * prio_buckets(ca) * 2)) ||
        alloc_bucket_pages(ca->disk_buckets, ca)) {
    return -ENOMEM;
  }
  /*printf(" init  &ca->free[RESERVE_PRIO].size=%d\n", fifo_free(&ca->free[RESERVE_PRIO]));*/
  // prio_buckets(ca)算出prio io需要的bucket个数，记录下最后一个bucket
  // 1. prios_per_bucket(c)先算出每个bucket能放下多少prio，即放下多少个bucket_disk
  // 2. 然后再拿全部的bucket去向上取整，看下全部的bucket的bucket_disk需要多少个prio bucket
  // 每个bucket，能够放下174749个bucket_disk
  ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);

  for_each_bucket(b, ca) {
    atomic_set(&b->pin, 0);
  }
  return 0;
}

struct cache_set *
bch_cache_set_alloc(struct cache_sb *sb)
{
  struct cache_set *c = T2Molloc(sizeof(struct cache_set));
  if (!c) {
    return NULL;
  }

  memcpy(c->sb.set_uuid, sb->set_uuid, 16);
  c->sb.block_size	= sb->block_size; /* 一个扇区 */
  c->sb.bucket_size	= sb->bucket_size; /* 1024 */
  c->sb.nr_in_set		= sb->nr_in_set;
  c->sb.last_mount	= sb->last_mount;
  c->bucket_bits		= ilog2(sb->bucket_size); /* log2(1024) = 10 */
  c->block_bits		= ilog2(sb->block_size);  /* log2(1)    = 0 */
  /*c->nr_uuids		= bucket_bytes(c) / sizeof(struct uuid_entry); [> 4096 <]*/

  c->btree_pages		= bucket_pages(c); /* 1024/8 = 128 */
  // tmp close limit, now btree node can using full bucket(512k)
  /*
  if (c->btree_pages > BTREE_MAX_PAGES) {
    c->btree_pages = max_t(int, c->btree_pages / 4,
                BTREE_MAX_PAGES);
  }
  */
  CACHE_INFOLOG(NULL, "block_size %u(sectors) bits=%u \n", c->sb.block_size, c->block_bits);
  CACHE_INFOLOG(NULL, "bucket_size %u(sectors) bits=%u \n", c->sb.bucket_size, c->bucket_bits);
  CACHE_INFOLOG(NULL, "nr_in_set %u \n", c->sb.nr_in_set);
  CACHE_INFOLOG(NULL, "btree_pages %u \n", c->btree_pages);

  pthread_mutex_init(&c->bucket_lock, NULL);
  pthread_spin_init(&c->btree_gc_time.lock,0);
  pthread_spin_init(&c->btree_split_time.lock,0);
  pthread_spin_init(&c->btree_read_time.lock,0);

  INIT_LIST_HEAD(&c->list);
  INIT_LIST_HEAD(&c->cached_devs);
  INIT_LIST_HEAD(&c->btree_cache);
  INIT_LIST_HEAD(&c->btree_cache_freeable);
  INIT_LIST_HEAD(&c->btree_cache_freed);
  INIT_LIST_HEAD(&c->data_buckets);

  c->ev_base = bch_delayed_work_init();
  cache_bug_on((c->ev_base == NULL), c, "delayed work init failed");
  /* XXX devices是一个二级指针 */
  // bch_btree_cache_alloc(c) btree 节点链表freeable、freed
  // 此处遗留
  // 1. fill_iter
  // 2. journal
  // 3. bset_sort_state
  // 4. moving_gc_wq
  /*if (!(c->devices = T2Molloc(c->nr_uuids * sizeof(void *))) ||*/
                        /*alloc_bucket_pages(c->uuids, c) ||*/
    if( bch_journal_alloc(c) ||
                        bch_btree_cache_alloc(c) ||
                        bch_open_buckets_alloc(c) ||
          bch_bset_sort_state_init(&c->sort, ilog2(c->btree_pages))) {
    goto err;
  }

  c->congested_read_threshold_us	= 2000;
  c->congested_write_threshold_us	= 20000;
  c->error_limit	= 8 << IO_ERROR_SHIFT;  /* IO_ERROR_SHIFT=20, 8MB */
  c->expensive_debug_checks = false;
  atomic_set(&c->cached_hits, 1);

  return c;
err:
  bch_cache_set_unregister(c);
  return NULL;
}

static void
__write_super(struct cache *c)
{
  struct cache_sb *sb = NULL;
  off_t start = SB_START;
  size_t len = SB_SIZE;
  int err;
  c->sb.csum = csum_set(&c->sb);
  err = posix_memalign(&sb, MEMALIGN, SB_SIZE);
  if (err){
   CACHE_ERRORLOG(CAT_WRITE,"mem alloc failed\n");
   assert(err == 0);
  }
  memcpy(sb, &c->sb, sizeof(struct cache_sb));

  CACHE_INFOLOG(CAT_WRITE,"write super fd %d start 0x%x len %d\n",
                        c->fd, start, len);
  if (sync_write(c->fd, sb, len, start) == -1) {
    CACHE_ERRORLOG(CAT_WRITE,"write super error :%s\n", strerror(errno));
    assert("write super error" == 0);
  }
}


void bcache_write_super(struct cache_set *c)
{
  struct cache *ca;
  unsigned i;

  c->sb.seq++;

  for_each_cache(ca, c, i) {
    ca->sb.version		= BCACHE_SB_VERSION_CDEV_WITH_UUID;
    ca->sb.seq		= c->sb.seq;
    ca->sb.last_mount	= c->sb.last_mount;

    SET_CACHE_SYNC(&ca->sb, CACHE_SYNC(&c->sb));
    CACHE_INFOLOG(NULL, "write super version %lu seq %lu  last_mount %u sync %d \n",
        ca->sb.version, ca->sb.seq, ca->sb.last_mount, CACHE_SYNC(&c->sb));
    __write_super(ca);
  }
}



static void uuid_io(struct cache_set *c, int op, unsigned long op_flags, struct bkey *k)
{
  return;
  struct uuid_entry *u;
  char buf[80];
  off_t start = PTR_OFFSET(k, 0) << 9; // bucket_number * bucket_size
  size_t len = KEY_SIZE(k) << 9;

  CACHE_DEBUGLOG(NULL,"uuid io op %d ( fd %d start %lu len %lu \n",
                        op, c->fd, start, len);
  if ( op == REQ_OP_WRITE ) {
    if ( sync_write(c->fd, c->uuids, len , start) == -1 ) {
      CACHE_ERRORLOG(CAT_WRITE,"write uuid error: %s \n", strerror(errno));
      assert("write uuid error" == 0);
    }
  }
  if ( op == REQ_OP_READ ) {
    if ( sync_read(c->fd, c->uuids, len , start) == -1 ) {
      CACHE_ERRORLOG(CAT_WRITE,"read uuid error: %s\n", strerror(errno));
      assert("read uuid error" == 0);
    }
  }
  bch_extent_to_text(buf, sizeof(buf), k);

  CACHE_DEBUGLOG(NULL, "%s UUIDs at %s (nr_uuids %u) \n",
        op == REQ_OP_WRITE ? "wrote" : "read", buf, c->nr_uuids);
  for (u = c->uuids; u < c->uuids + c->nr_uuids; u++) {
    if (!bch_is_zero(u->uuid, 16)) {
      CACHE_INFOLOG(NULL, "uuid io Slot %zi: %pU: %s: 1st: %u last: %u inv: %u \n",
                                 u - c->uuids, u->uuid, u->label,
                                 u->first_reg, u->last_reg, u->invalidated);
    }
  }
}

static char *uuid_read(struct cache_set *c, struct jset *j)
{
  struct bkey *k = &j->uuid_bucket;
  if (__bch_btree_ptr_invalid(c, k)) {
    return "bad uuid pointer";
  }
  bkey_copy(&c->uuid_bucket, k);
  uuid_io(c, REQ_OP_READ, 0, k);
  if (j->version < BCACHE_JSET_VERSION_UUIDv1) {
    struct uuid_entry_v0	*u0 = (void *) c->uuids;
    struct uuid_entry	*u1 = (void *) c->uuids;
    int i;

    /*
     *  Since the new uuid entry is bigger than the old, we have to
     *  convert starting at the highest memory address and work down
     *  in order to do it in place
     */
    for (i = c->nr_uuids - 1; i >= 0; --i) {
      memcpy(u1[i].uuid,	u0[i].uuid, 16);
      memcpy(u1[i].label,	u0[i].label, 32);

      u1[i].first_reg		= u0[i].first_reg;
      u1[i].last_reg		= u0[i].last_reg;
      u1[i].invalidated	= u0[i].invalidated;

      u1[i].flags	= 0;
      u1[i].sectors	= 0;
    }
  }
  return NULL;
}


static int __uuid_write(struct cache_set *c)
{
  BKEY_PADDED(key) k;

  CACHE_DEBUGLOG(NULL, "write uuid internal\n");
  if (bch_bucket_alloc_set(c, RESERVE_BTREE, &k.key, 1, true))
    return 1;

  SET_KEY_SIZE(&k.key, c->sb.bucket_size);
  uuid_io(c, REQ_OP_WRITE, 0, &k.key);
  bkey_copy(&c->uuid_bucket, &k.key);
  bkey_put(c, &k.key);
  return 0;
}

int bch_uuid_write(struct cache_set *c)
{
  CACHE_DEBUGLOG(NULL, "write uuid\n");
  int ret = __uuid_write(c);
  if (!ret) {
    bch_journal_meta(c);
  }
  return ret;
}

static void
run_cache_set(struct cache_set *c)
{
  const char *err = "cannot allocate memory";
  /*struct cached_dev *dc, *t;*/
  struct cache *ca;
  unsigned i;
  for_each_cache(ca, c, i) {
    c->nbuckets += ca->sb.nbuckets;
  }
  set_gc_sectors(c);
  if (CACHE_SYNC(&c->sb)) {
    CACHE_INFOLOG(NULL,"have sync run cache set from super \n");
    T2_LIST_HEAD(journal);
    struct bkey *k;
    struct jset *j;

    err = "cannot allocate memory for journal";
    CACHE_INFOLOG(NULL,"journal read \n");
    if (bch_journal_read(c, &journal)) {
      goto err;
    }
    bch_dump_journal_replay(c, &journal);
    err = "no journal entries found";
    if (list_empty(&journal)) {
      goto err;
    }

    j = &list_entry(journal.prev, struct journal_replay, list)->j;
    err = "IO error reading priorities";
    for_each_cache(ca, c, i) {
      prio_read(ca, j->prio_bucket[ca->sb.nr_this_dev]);
    }
    /*
     * If prio_read() fails it'll call cache_set_error and we'll
     * tear everything down right away, but if we perhaps checked
     * sooner we could avoid journal replay.
     */
    k = &j->btree_root;
    err = "bad btree root";
    if (__bch_btree_ptr_invalid(c, k)) {
      CACHE_ERRORLOG(NULL, "root bkey is invalid\n");
      goto err;
    }
    err = "error reading btree root";
    c->root = bch_btree_node_get(c, NULL, k, j->btree_level, true, NULL);
    if (IS_ERR_OR_NULL(c->root)) {
      goto err;
    }
    /* 将节点从链表中移除，并重新初始化该节点的next和prev指针 */
    list_del_init(&c->root->list);
    rw_unlock(true, c->root);
    /*err = uuid_read(c, j);*/
    /*if (err) {*/
      /*goto err;*/
    /*}*/
    err = "error in recovery";
    if (bch_btree_check(c)) {
      goto err;
    }
    bch_journal_mark(c, &journal);
    bch_initial_gc_finish(c);
    CACHE_DEBUGLOG(NULL, "btree_check() done");

    /*
     * bcache_journal_next() can't happen sooner, or
     * btree_gc_finish() will give spurious errors about last_gc >
     * gc_gen - this is a hack but oh well.
     */
    bch_journal_next(&c->journal);
    err = "error starting allocator thread";
    for_each_cache(ca, c, i) {
      if (bch_cache_allocator_start(ca)) {
        goto err;
      }
    }

    /*
     * First place it's safe to allocate: btree_check() and
     * btree_gc_finish() have to run before we have buckets to
     * allocate, and bch_bucket_alloc_set() might cause a journal
     * entry to be written so bcache_journal_next() has to be called
     * first.
     *
     * If the uuids were in the old format we have to rewrite them
     * before the next journal entry is written:
     */
    /*printf(" j->verison = %d \n", j->version);*/
    /*CACHE_INFOLOG(NULL, "j->verison  %u BCACHE_JSET_VERSION_UUID %d \n",*/
                        /*j->version, BCACHE_JSET_VERSION_UUID);*/
    /*if (j->version < BCACHE_JSET_VERSION_UUID) {*/
      /*__uuid_write(c);*/
    /*}*/

    bch_journal_replay(c, &journal);
  } else {
    CACHE_INFOLOG(NULL,"not have sync run cache set from init \n");
    for_each_cache(ca, c, i) {
      unsigned j;
      ca->sb.keys = clamp_t(int, ca->sb.nbuckets >> 7, 2, SB_JOURNAL_BUCKETS);
      CACHE_INFOLOG(NULL,"journal keys %u first_bucket %u  \n",
                ca->sb.keys, ca->sb.first_bucket);
      for (j = 0; j < ca->sb.keys; j++) {
        ca->sb.d[j] = ca->sb.first_bucket + j;
        CACHE_DEBUGLOG(NULL,"ca->sb.d[%u] %lu \n",j,ca->sb.d[j]);
      }
    }
    bch_initial_gc_finish(c);
    err = "error starting allocator thread";
    /* 启动cache分配线程 */
    for_each_cache(ca, c, i) {
      if (bch_cache_allocator_start(ca)) {
        goto err;
      }
    }
    pthread_mutex_lock(&c->bucket_lock);
    for_each_cache(ca, c, i) {
      bch_prio_write(ca);
    }
    pthread_mutex_unlock(&c->bucket_lock);
    /*err = "cannot allocate new UUID bucket";*/
    /*if (__uuid_write(c)) {*/
      /*goto err;*/
    /*}*/
    err = "cannot allocate new btree root";
    /* 分配btree的根节点 */
    CACHE_DEBUGLOG(NULL,"alloc btree root node\n");
    c->root = __bch_btree_node_alloc(c, NULL, 0, true, NULL);
    if (IS_ERR_OR_NULL(c->root)) {
      goto err;
    }
    pthread_mutex_lock(&c->root->write_lock);
    bkey_copy_key(&c->root->key, &MAX_KEY);
    bch_btree_node_write(c->root);
    pthread_mutex_unlock(&c->root->write_lock);
    bch_btree_set_root(c->root);
    rw_unlock(true, c->root);
    /*
     * We don't want to write the first journal entry until
     * everything is set up - fortunately journal entries won't be
     * written until the SET_CACHE_SYNC() here:
     *
     * 我们不想写第一个journal条目，直到所有都设置好了 - 幸运地是，
     * journal条目不会被写入直到在这使用SET_CACHE_SYNC
     */
    SET_CACHE_SYNC(&c->sb, true);
    bch_journal_next(&c->journal);
    bch_journal_meta(c);
  }

  /*err = "error starting gc thread";*/
  /*if (bch_gc_thread_start(c))*/
    /*goto err;*/

  time_t now;
  time(&now);
  c->sb.last_mount = now;
  // 测试临时想关闭
  bcache_write_super(c);
  set_bit(CACHE_SET_RUNNING, &c->flags);

  return;
err:
  cache_bug(c, err);
}

static int cached_dev_init(struct cached_dev *dc)
{
  size_t n;
  struct io *io;

  dc->stripe_size = 1 << 31;
  dc->nr_stripes = DIV_ROUND_UP_ULL(getblocks(dc->c->hdd_fd) - BDEV_DATA_START_DEFAULT, dc->stripe_size);

  n = dc->nr_stripes * sizeof(atomic_t);
  dc->stripe_sectors_dirty = T2Molloc(n);
  if (!dc->stripe_sectors_dirty) {
    return -ENOMEM;
  }

  n = BITS_TO_LONGS(dc->nr_stripes) * sizeof(unsigned long);
  dc->full_dirty_stripes = T2Molloc(n);
  if (!dc->full_dirty_stripes) {
    return -ENOMEM;
  }

  SET_BDEV_CACHE_MODE(&dc->sb, CACHE_MODE_WRITEBACK);
  INIT_LIST_HEAD(&dc->io_thread);
  INIT_LIST_HEAD(&dc->io_lru);
  pthread_spin_init(&dc->io_lock, 0);

  for (io = dc->io; io < dc->io + RECENT_IO; io++) {
    list_add(&io->lru, &dc->io_lru);
    hlist_add_head(&io->hash, dc->io_hash + RECENT_IO);
  }

  /*if (BDEV_STATE(&dc->c->sb) == BDEV_STATE_DIRTY) {*/
        /*bch_sectors_dirty_init(dc);*/
        /*atomic_set(&dc->has_dirty, 1);*/
        /*atomic_inc(&dc->count);*/
  /*}*/
  /*bch_sectors_dirty_init(dc);*/
  /*atomic_set(&dc->has_dirty, 1);*/
  /*atomic_inc(&dc->count);*/

  bch_cached_dev_writeback_init(dc);
  return 0;
}

static const char *register_cache_set(struct cache *ca)
{
  char buf[12];
  const char *err = "cannot allocate memory";
  struct cache_set *c;

  c = bch_cache_set_alloc(&ca->sb);
  if (!c) {
    return err;
  }

  list_add(&c->list, &bch_cache_sets);

  sprintf(buf, "cache%i", ca->sb.nr_this_dev);

  CACHE_INFOLOG(NULL,"register cache seq %llu, cache set seq %llu \n",ca->sb.seq, c->sb.seq);
  if (ca->sb.seq > c->sb.seq) {
    c->sb.version		= ca->sb.version;
    memcpy(c->sb.set_uuid, ca->sb.set_uuid, 16);
    c->sb.flags             = ca->sb.flags;
    c->sb.seq		= ca->sb.seq;
    CACHE_DEBUGLOG(NULL, "cache set version = %llu", c->sb.version);
  }

  ca->set = c;
  ca->set->cache[ca->sb.nr_this_dev] = ca;
  c->cache_by_alloc[c->caches_loaded++] = ca;
  ca->set->fd = ca->fd;
  ca->set->hdd_fd = ca->hdd_fd;
  ca->set->logger_cb = ca->logger_cb;
  ca->set->bluestore_cd = ca->bluestore_cd;

  c->dc = calloc(1, sizeof(struct cached_dev));
  if ( c->dc == NULL ) {
    CACHE_ERRORLOG(NULL, " calloc cache device failed \n" );
    assert("calloc cache device failed " == 0);
  }

  memcpy(&c->dc->sb, &c->sb, sizeof(struct cache_sb));
  c->dc->c = c;
  cached_dev_init(c->dc);
  CACHE_DEBUGLOG(NULL, "cache_set caches_loaded=%d super nr_in_set=%u\n",__func__,c->caches_loaded,c->sb.nr_in_set);
  if (c->caches_loaded == c->sb.nr_in_set) {
    run_cache_set(c);
  }

  return NULL;
}


static int _register_cache(struct cache_sb *sb, struct cache *ca)
{
  const char *err = NULL;
  int ret = 0;

  memcpy(&ca->sb, sb, sizeof(struct cache_sb));
  /*if (blk_queue_discard(bdev_get_queue(ca->bdev)))*/
          /*ca->discard = CACHE_DISCARD(&ca->sb);*/
  ret = cache_alloc(ca);
  if (ret != 0) {
    if (ret == -ENOMEM)
            err = "cache_alloc(): -ENOMEM";
    else
            err = "cache_alloc(): unknown error";
    goto err;
  }
  pthread_mutex_lock(&bch_register_lock);
  err = register_cache_set(ca);
  pthread_mutex_unlock(&bch_register_lock);

  cache_rte_ring_init();
  cache_rte_dequeue_init(ca);

  if (err) {
    ret = -ENODEV;
    goto err;
  }

  CACHE_INFOLOG(NULL, "registere cache device success ret(%d) \n",ret);
  return ret;
err:
  if (err) {
    CACHE_ERRORLOG(NULL,"registere cache device error: %s, ret(%d) \n",err, ret);
  }

  return ret;
}


void
data_insert_test(struct cache * c)
{
  printf(" fuc: %s \n", __func__);
  struct keylist          insert_keys;
  struct bkey *k;
  bch_keylist_init(&insert_keys);
  k=insert_keys.top;
  bkey_init(k);
  SET_KEY_INODE(k, 0);
  SET_KEY_OFFSET(k, 500);
  bch_alloc_sectors(c->set, k, 10, 0,0,1);
}

int
bch_insert_keys_batch(struct cache_set *c_set,
                struct keylist *insert_keys, struct bkey *replace_key, atomic_t *journal_ref)
{
  int ret;

  ret = bch_btree_insert(c_set, insert_keys, journal_ref, replace_key);

  if (ret != 0) {
    CACHE_ERRORLOG(CAT_BTREE,"insert keylist error ret %d\n", ret);
    /*
     * for test, we assert every io should be sucessfull
     * insert to btree, however, one io error should not
     * make crash progress
     */
    assert("bch btree insert error"==0);
  }

  if (journal_ref) {
    atomic_dec_bug(journal_ref);
  }
  bch_keylist_free(insert_keys);
  T2Free(insert_keys);

  return ret;
}


int
bch_data_insert_keys(struct cache_set *c_set,
                struct keylist *insert_keys, struct bkey *replace_key)
{
  atomic_t *journal_ref = NULL;
  int ret;

  struct timespec start = cache_clock_now();
  if ( !bch_keylist_nkeys(insert_keys)) {
    CACHE_ERRORLOG(NULL, "no bkeys insert\n");
    assert(bch_keylist_nkeys(insert_keys) != 0);
  }
  if (!replace_key){
    journal_ref = bch_journal(c_set, insert_keys);
    cache_bug_on(!journal_ref, c_set, "write journal error\n");
  }
  c_set->logger_cb(c_set->bluestore_cd, l_bluestore_cachedevice_t2cache_journal_write, start, cache_clock_now());

  ret = bch_btree_insert(c_set, insert_keys, journal_ref, replace_key);

  if (ret != 0) {
    CACHE_ERRORLOG(CAT_BTREE,"insert keylist error ret %d\n", ret);
    /*
     * for test, we assert every io should be sucessfull
     * insert to btree, however, one io error should not
     * make crash progress
    */
    assert("bch btree insert error"==0);
  }
  if (journal_ref) {
    atomic_dec_bug(journal_ref);
  }
  bch_keylist_free(insert_keys);

  return ret;
}

int cache_lookup_fn(struct btree_op *op, struct btree *b, struct bkey *k)
{
  uint64_t start;

  struct search *s = container_of(op, struct search, op);
  if (s) {
    start = s->offset;
  } else {
    return MAP_DONE;
  }

  if (bkey_cmp(k, &KEY(0, start, 0)) <= 0) {
    return MAP_CONTINUE;
  }
  /*if (KEY_INODE(k) != 1 || KEY_START(k) > start) {*/
	  /*printf(TEXT_RED"CACHE MISS, btree node(level: %d, offset: %lu) bkey offset: %lu, size: %lu, KEY_START: %lu, PTR_OFFSET: %#lx\n"TEXT_NORMAL,*/
		  /*b->level, KEY_OFFSET(&b->key),*/
		  /*KEY_OFFSET(k), KEY_SIZE(k), KEY_START(k),*/
		  /*PTR_OFFSET(k, 0) << 9);*/

	  /*uint64_t miss_sector = KEY_INODE(k) == 1*/
		  /*? min_t(uint64_t, INT_MAX, KEY_START(k) - start)*/
		  /*: INT_MAX;*/

	  /*cache_miss(b, s->offset, miss_sector, s);*/
	  /*return MAP_DONE;*/
  /*}*/
  printf(TEXT_CYAN"CACHE HIT, btree node(level: %d, offset: %lu) bkey offset: %lu, start: %lu, size: %lu, PTR_OFFSET: %#lx, KEY_START(k): %lu\n"TEXT_NORMAL,
      b->level, KEY_OFFSET(&b->key),
      KEY_OFFSET(k), start, KEY_SIZE(k),
      PTR_OFFSET(k, 0) << 9, KEY_START(k));

  if (!KEY_SIZE(k)) {
    return MAP_CONTINUE;
  }
  int io_sectors_left = (s->left % 512) ? (s->left / 512 + 1) : (s->left / 512);
  int n = min_t(uint64_t, KEY_OFFSET(k) - start, io_sectors_left);
  printf("need read %d sectors\n", n);
  /*char *data = s->data;*/
  struct bkey *io_bkey = k;
  sync_read(b->c->fd, s->pos, 512 * n, PTR_OFFSET(io_bkey, 0) << 9);
  s->offset += n;
  s->pos   += (n * 512);
  s->left   -= (n * 512);
  return MAP_DONE;

}

int cache_sync_read(struct cache *ca, void *data, uint64_t off, uint64_t len)
{
  int ret = 0;
  struct search s;

  memset(&s, 0, sizeof(struct search));
  bch_btree_op_init(&s.op, -1, BTREE_OP_READ);
  s.data = data;
  s.pos = data;
  s.offset = (off>>9);
  s.bi_sector = (off >> 9);
  s.length = len;
  s.left = len;

  while ( s.left > 0 ) {
    bch_btree_map_keys(&s.op, ca->set, &KEY(0, s.offset, 0), cache_lookup_fn, MAP_END_KEY);
  }
  ret = s.length;
  return ret;
}

int cache_sync_write(struct cache *ca, void * data, uint64_t off, uint64_t len)
{
  int ret = 0;
  struct keylist insert_keys;
  uint64_t left = len >> 9;
  char * pos = data;
  /*bch_writeback_add(ca->set->dc);*/

  bch_keylist_init(&insert_keys);
  do {
    struct bkey *k=NULL;
    /*struct cache_set *c = T2Molloc(sizeof(struct cache_set));*/
    k = insert_keys.top;

    bkey_init(k);
    SET_KEY_INODE(k, 0);
    SET_KEY_OFFSET(k, (off>>9));
    SET_KEY_DIRTY(k, true);
    bch_alloc_sectors(ca->set, k, len>>9, 0, 0, 1);
    /*printf( " main.c <%s>: after alloc sectors KEY_OFFSET=%lu,KEY_SIZE=%lu\n", __func__,KEY_OFFSET(k),KEY_SIZE(k));*/
    left -= KEY_SIZE(k);
    /*printf( " main.c <%s>: left=%lu \n", __func__,left);*/
    /*printf( " main.c <%s>: Write Data SSD fd=%d,start=0x%x,len=%d\n", __func__,ca->fd,(PTR_OFFSET(k,0)<<9),(KEY_SIZE(k)<<9));*/
    sync_write(ca->fd, pos, KEY_SIZE(k)<<9, PTR_OFFSET(k, 0)<<9);
    pos += KEY_SIZE(k) << 9;
    off = off + (KEY_SIZE(k) << 9);
    bch_keylist_push(&insert_keys);
  } while(left > 0);

  bch_data_insert_keys(ca->set, &insert_keys, NULL);

  return ret;
}

int
traverse_btree_keys_fn(struct btree_op * op, struct btree *b)
{
  CACHE_DEBUGLOG("traverse", ">>>>>> Entry Btree Node(level=%d,offset=%lu,size=%lu) <<<<<<<\n",
                        b->level, KEY_OFFSET(&b->key), KEY_SIZE(&b->key));
  CACHE_DUMPLOG(NULL, ">>>>>> Entry Btree Node(level=%d,offset=%lu,size=%lu) <<<<<<<\n",
                        b->level, KEY_OFFSET(&b->key), KEY_SIZE(&b->key));
  struct bkey *k = NULL;
  struct btree_iter iter;
  for_each_key(&b->keys, k, &iter) {
    CACHE_DEBUGLOG("traverse", "node(level=%d,of=%lu) bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,dirty=%u) \n",
                        b->level, KEY_OFFSET(&b->key), KEY_OFFSET(k) - KEY_SIZE(k),
                        KEY_OFFSET(k), KEY_SIZE(k), PTR_OFFSET(k,0), KEY_PTRS(k), KEY_DIRTY(k));
    CACHE_DUMPLOG(NULL, "node(level=%d,of=%lu) bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,dirty=%u) \n",
                        b->level, KEY_OFFSET(&b->key), KEY_OFFSET(k) - KEY_SIZE(k),
                        KEY_OFFSET(k), KEY_SIZE(k), PTR_OFFSET(k,0), KEY_PTRS(k), KEY_DIRTY(k));
  }

  return MAP_CONTINUE;
}

void
traverse_btree(struct cache * c)
{
  struct btree_op op;
  bch_btree_op_init(&op, 0, BTREE_OP_TRAVERSE);
  bch_btree_map_nodes(&op,c->set,NULL,traverse_btree_keys_fn);
}

int dump_btree_kes_fn(struct btree_op *op, struct btree *b)
{
  struct bkey *k = NULL;
  struct btree_iter iter;
  for_each_key(&b->keys, k, &iter) {
    if (b->level == 0) {
      b->c->cache[0]->btree_nbkeys++;
      b->c->cache[0]->total_size += (KEY_SIZE(k) << 9);
      if (bch_ptr_bad(&b->keys, k)) {
        b->c->cache[0]->btree_bad_nbeys++;
        if (!bkey_cmp(k, &ZERO_KEY))
          b->c->cache[0]->btree_null_nbkeys++;
        if (!KEY_SIZE(k))
          b->c->cache[0]->zero_keysize_nbkeys++;
      }
      else {
        if (KEY_DIRTY(k)) {
          b->c->cache[0]->btree_dirty_nbkeys++;
          b->c->cache[0]->dirty_size += (KEY_SIZE(k) << 9);
        }
      }
    }
    else if (b->level == 1)
      b->c->cache[0]->btree_nodes++;
  }

  return MAP_CONTINUE;
}

void dump_btree_info(struct cache *c)
{
  struct btree_op op;
  bch_btree_op_init(&op, 0, BTREE_OP_TRAVERSE);
  bch_btree_map_nodes(&op, c->set, NULL, dump_btree_kes_fn);
}

int get_t2ce_meta(struct cache_context *ctx, struct t2ce_meta *meta)
{
  struct cache *ca = ctx->cache;
  ca->btree_nodes  =  0;
  ca->btree_nbkeys =  0;
  ca->total_size   = 0;
  ca->dirty_size   = 0;
  ca->btree_bad_nbeys = 0;
  ca->btree_dirty_nbkeys = 0;
  ca->btree_null_nbkeys = 0;
  ca->zero_keysize_nbkeys = 0;

  if (meta) {
    dump_btree_info(ca);
    meta->btree_nodes  = ca->btree_nodes;
    meta->btree_nbkeys = ca->btree_nbkeys;
    meta->total_size   = ca->total_size;
    meta->dirty_size   = ca->dirty_size;
    meta->btree_bad_nbeys = ca->btree_bad_nbeys;
    meta->btree_dirty_nbkeys = ca->btree_dirty_nbkeys;
    meta->btree_null_nbkeys  = ca->btree_null_nbkeys;
    meta->zero_keysize_nbkeys = ca->zero_keysize_nbkeys;
    meta->cached_hits       = atomic_read(&ca->set->cached_hits);
    meta->cache_mode        = get_cache_mode(BDEV_CACHE_MODE(&ca->set->dc->sb));
  } else {
    traverse_btree(ca);
  }

  return 0;
}

void set_writeback_cutoff(struct cached_dev *dc, int val)
{
  dc->cutoff_writeback = val;
}

void set_writeback_sync_cutoff(struct cached_dev *dc, int val)
{
  dc->cutoff_writeback_sync = val;
}

void set_read_water_level(struct cached_dev *dc, int val)
{
  dc->read_water_level = val;
}

void set_gc_mode(struct cached_dev *dc, int val)
{
  if (val == GC_MODE_READ_PRIO)
    dc->cutoff_gc_busy = CUTOFF_WRITEBACK_SYNC;
  else if (val == GC_MODE_WRITE_PRIO)
    dc->cutoff_gc_busy = (CUTOFF_WRITEBACK * 3) / 4;

}

void set_cached_hits(struct cache *ca, int val)
{
  atomic_set(&ca->set->cached_hits, val);
}

void set_max_gc_keys_onetime(struct cached_dev *dc, int val)
{
  dc->max_gc_keys_onetime = val;
}

void t2ce_set_iobypass_water_level(struct cached_dev *dc, int val)
{
  dc->iobypass_water_level = val;
  set_read_water_level(dc, dc->iobypass_water_level/2);
}

static void set_writeback_cutoffs(struct cached_dev *dc)
{
  dc->cutoff_writeback      = CUTOFF_WRITEBACK;
  dc->cutoff_writeback_sync = CUTOFF_WRITEBACK_SYNC;
  dc->iobypass_water_level      = CUTOFF_CACHE_ADD;
}

static void bch_gc_conf_init(struct cached_dev *dc)
{
  dc->read_water_level = CUTOFF_WRITEBACK / 2;
  /*dc->cutoff_gc_busy = 100;*/
  dc->cutoff_gc_busy = 80;
  dc->max_gc_keys_onetime = 512;
}

static void update_gc_size_wm(evutil_socket_t fd, short events, void *arg)
{
  struct cache *ca = (struct cache *)arg;
  struct gc_stat gs;;
  bch_update_bucket_in_use(ca->set, &gs);

  CACHE_DEBUGLOG(NULL, "update_gc_size_wm, gc.in_use: %u, gc_size_wm: %lu(M)\n",
                       gs.in_use, ca->wake_up_gc_size_wm/1024/1024);
  if (gs.status == GC_IDLE && (gs.in_use >= WAKE_UP_GC_WM ||
        ca->wake_up_gc_size_wm >= WAKE_UP_GC_SIZE_WM)) {
    // 不能通过invalidate_needs_gc来控制唤醒gc之后立马工作
    /*ca->invalidate_needs_gc = true;*/
    /*wake_up_gc(ca->set);*/
    CACHE_DEBUGLOG(NULL, "will wake up gc now...\n");
  }
  ca->wake_up_gc_size_wm = 0;
}

int
init(struct cache * ca)
{
  int fd = ca->fd;
  const char *err = "cannot allocate memory";
  struct cache_sb *sb;
  int rc;

  rc = posix_memalign(&sb, MEMALIGN, SB_SIZE);
  if (rc){
    CACHE_ERRORLOG(NULL, "memalign error!\n");
    assert(rc != 0);
  }

  rc = pread(fd, sb, SB_SIZE, SB_START);
  if (rc != SB_SIZE) {
   CACHE_ERRORLOG(NULL, "Couldn't read cache device: %s, size %d, SB_SIZE %d, SB_START %d, buf %p, fd %d\n",
       strerror(errno), sizeof(struct cache_sb), SB_SIZE, SB_START, sb, fd);
   assert("Couldn't read cache device super" == 0);
  }
  err = read_super(&ca->sb, sb);
  if (err) {
    CACHE_ERRORLOG(NULL, "read super error\n");
    assert("read super error" == 0);
  }

  // check super uuid with fsid
  char uuid[40] = {0};
  uuid_unparse(ca->sb.uuid, uuid);
  if (memcmp(ca->uuid_str,uuid,37)) {
    CACHE_ERRORLOG(NULL, "cache dev uuid %s mismatch with fsid %s \n", uuid, ca->uuid_str);
    assert(" uuid mismatch" == 0);
  }

  if (_register_cache(sb, ca) != 0) {
    CACHE_ERRORLOG(NULL, "register cache error\n");
    assert("register cache error" == 0);
  }
  pthread_cond_signal(&ca->alloc_cond);

  ca->handler = aio_init((void *)ca);


  bch_cached_dev_writeback_start(ca->set->dc);
  bch_sectors_dirty_init(ca->set->dc);
  /*atomic_set(&ca->set->dc->has_dirty, 1);*/
  /*atomic_inc(&ca->set->dc->count);*/

  bch_moving_init_cache_set(ca->set);
  bch_gc_thread_start(ca->set);
  set_writeback_cutoffs(ca->set->dc);
  bch_gc_conf_init(ca->set->dc);

  /*
   * 暂时先关闭这个逻辑
   */
  /*struct timeval tv;*/
  /*evutil_timerclear(&tv);*/
  /*tv.tv_sec = UPDATE_GC_SIZE_WM_SECONDS;*/
  /*delayed_work_assign(&ca->ev_update_gc_wm, ca->set->ev_base, update_gc_size_wm, (void*)ca, EV_PERSIST);*/
  /*delayed_work_add(&ca->ev_update_gc_wm, &tv);*/

  free(sb);

  return 0;
}

int destroy(struct cache * ca){
  if (!ca)
    return ;
  bch_gc_thread_stop(ca->set);
  bch_cached_dev_writeback_stop(ca->set->dc);
  aio_destroy((void *)ca);
  rte_dequeue_ring_destroy();
  bch_delayed_work_stop(ca->set);
  bch_cache_allocator_stop(ca);
  // Todo: close log
}

struct bkey *
get_init_bkey(struct keylist *keylist, uint64_t offset, struct cache *ca)
{
  struct bkey *k = NULL;

  if (bch_keylist_realloc(keylist, 3, ca->set)) {
    CACHE_ERRORLOG(NULL, "keylist realloc nomem\n");
    assert("keylist realloc no memory" == 0);
  }

  k = keylist->top;
  assert(k != NULL);

  if ( k ) {
    bkey_init(k);
    SET_KEY_INODE(k, 0);
    SET_KEY_OFFSET(k, (offset>>9));
  }

  return k;
}

int item_write_next(struct ring_item *item, bool dirty)
{
  int ret = 0;
  struct cache *ca = item->ca_handler;
  struct bkey *k = NULL;
  k = get_init_bkey(item->insert_keys, (item->o_offset + item->io.len), ca);
  if ( !k ) {
    CACHE_ERRORLOG(NULL, "keylist is not enough, need realloc \n");
    assert ( "keylist is not enough, need realloc" == 0);
  }

  if ( dirty ) {
    SET_KEY_DIRTY(k, true);
  }

  item->io.pos = (char *)item->io.pos + item->io.len;
  uint64_t left = item->o_len - ((char *)item->io.pos - (char *)item->data);
  ret = bch_alloc_sectors(ca->set, k,(left >> 9), 0, 0, 1);
  if ( ret < 0 ) {
    CACHE_ERRORLOG(NULL, "alloc bucket/sectors failed\n");
    assert("alloc bucket/sectors failed" == 0);
  }

  item->io.offset = (PTR_OFFSET(k, 0) << 9);
  item->io.len = (KEY_SIZE(k)<<9);

  bch_keylist_push(item->insert_keys);

  return ret;
}

// 对于写来说，不管ssd还是hdd，都是要把所有的io写完才能
// 返回，唯一需要注意的就是writethrough策略
// 对于writethrough策略，先发给hdd进行写入，hdd写完成
// 再发给ssd进行写（需要改变item->io，已经enquene到ssd的线程池即可
void aio_write_completion(void *cb)
{
  struct ring_item *item = cb;
  struct cache *ca = item->ca_handler;
  int ret = 0;

  if ( ! item->io.success ) {
    CACHE_ERRORLOG(NULL, "Aio completion, io not Sucessfull %d \n", item->io.success);
    assert(" Aio completion, io not Sucessfull " == 0);
  }

  if (((char *)item->data + item->o_len ) == ((char *)item->io.pos + item->io.len )) {
    CACHE_DEBUGLOG(CAT_AIO_WRITE,"AIO IO(start=%lu(0x%lx),len=%lu(0x%lx)) Completion success=%d\n",
                item->o_offset/512, item->o_offset, item->o_len/512,
                item->o_len, item->io.success);
    struct timespec insert_start = cache_clock_now();
    switch (item->strategy) {
      case CACHE_MODE_WRITEAROUND:
        CACHE_DEBUGLOG(CAT_AIO_WRITE,"writearound completion start insert keys \n");
        /*if ( bch_keylist_nkeys(item->insert_keys) != 2) {*/
          /*CACHE_ERRORLOG(NULL, " writeaound error, nkeys = %d \n",*/
                                /*bch_keylist_nkeys(item->insert_keys));*/
          /*assert(bch_keylist_nkeys(item->insert_keys) == 2);*/
        /*}*/
        ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_libaio_write_lat, item->aio_start, insert_start);
        /*ret = bch_data_insert_keys(ca->set, item->insert_keys, NULL);*/
        break;
      case CACHE_MODE_WRITETHROUGH:
        // write through 写完hhd之后，开始写ssd
        // 如果是write through写ssd完成，则插入btree
        if ( !item->write_through_done) {
          CACHE_DEBUGLOG(CAT_AIO_WRITE,"writethrough completion start write to cache device \n");
          // 将io_u重制到初始化状态
          item->write_through_done = true;
          item->io.pos = item->data;
          item->io.offset = item->o_offset;
          item->io.len = 0;
          // write through的bkey不需要设置dirty=true
          if (!item_write_next(item, false)) {
            CACHE_ERRORLOG(NULL,"writethough write left io failed\n");
            assert("writethough write left io failed" == 0);
          }
          if ( item->o_len != item->io.len ) {
            CACHE_ERRORLOG(NULL,"writethrough got len error o_len %lu, io.len %lu\n",
                item->o_len, item->io.len);
            assert(item->o_len == item->io.len);
          }
          ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
          if ( ret < 0) {
            CACHE_ERRORLOG(NULL,"writethough aio enqueue failed\n");
            assert("writethough aio enqueue failed" == 0);
          }
          return ;
        } else {
          CACHE_DEBUGLOG(CAT_AIO_WRITE,"writethrough completion start insert keys \n");
          if (bch_keylist_nkeys(item->insert_keys) != 3) {
            CACHE_ERRORLOG(NULL, "writethrough insert error nkeys %d\n",
                        bch_keylist_nkeys(item->insert_keys));
            assert(bch_keylist_nkeys(item->insert_keys) == 3);
          }
          ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_libaio_write_lat, item->aio_start, insert_start);
          ret = bch_data_insert_keys(ca->set, item->insert_keys, NULL);
          break;
        }
      case CACHE_MODE_WRITEBACK:
        CACHE_DEBUGLOG(CAT_AIO_WRITE,"writeback completion start insert keys \n");
        /*if (bch_keylist_nkeys(item->insert_keys) != 3) {*/
          /*CACHE_ERRORLOG(NULL, " nkeys %d error \n", bch_keylist_nkeys(item->insert_keys));*/
          /*assert("nkeys error" == 0);*/
        /*}*/
        /*assert(bch_keylist_nkeys(item->insert_keys) == 3);*/
        ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_libaio_write_lat, item->aio_start, insert_start);
        /*ret = bch_data_insert_keys(ca->set, item->insert_keys, NULL);*/
        ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_insert_keys, insert_start, cache_clock_now());
        bch_writeback_add(ca->set->dc);
        break;
      default:
        CACHE_ERRORLOG(NULL,"Unsupported io strategy(%d)\n",item->strategy);
        assert(" Unsupported io strategy " == 0);
    }
    /*
     * when error got
     * choice 1. do not call io_completion_cb
     * choice 2. call io_completion_cb and return error code
     *    to bluestore
     * choice 2 is most suitable,but for testing, we choose choice 1
     */
    pthread_rwlock_unlock(&ca->set->dc->writeback_lock);

    if ( ret!=0 ) {
      // choice 1
      CACHE_ERRORLOG(NULL,"Insert btree error %d\n", ret);
      assert("Insert btree error"==0);
    } else if( item->io_completion_cb ) {
      // choice 2
      // item->io_completion_cb(item->io_arg, ret);
      ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_write_lat, item->start, cache_clock_now());
      item->io_completion_cb(item->io_arg);
    } else {
      CACHE_WARNLOG(NULL, "No io_completion_cb for IO(star=%lu(0x%lx),len=%lu(0x%lx))\n",
                item->o_offset/512, item->o_offset, item->o_len/512,item->o_len);
    }
    SAFE_FREE_DEC(item, free_ring_item);
  } else {
    CACHE_ERRORLOG(CAT_AIO_WRITE,"AIO split to multiple. IO(start=%lu(0x%lx),len=%lu(0x%lx)) Completion success=%d\n",
                   item->o_offset/512, item->o_offset, item->o_len/512,
                   item->o_len, item->io.success);
    assert( "IO Split" == 0);
    assert( item != NULL);
    assert( item->insert_keys != NULL);
    if (!item_write_next(item, true)) {
      CACHE_ERRORLOG(NULL,"write left io failed\n");
      assert("write left io failed" == 0);
    }
    // re enqueue
    ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
    if (ret < 0) {
      CACHE_ERRORLOG(NULL,"write left io aio enqueue io failed\n");
      assert("write left io aio enqueue io failed" == 0);
    }
  }
}

int cache_invalidate_region(struct cache *ca, uint64_t offset, uint64_t len)
{
  CACHE_DEBUGLOG(NULL,"Invalidate region(start=%lu/0x%lx,len=%lu,0x%lx) \n",
                        offset/512,offset,len/512,len);
  int ret = 0;
  struct keylist *insert_keys = NULL;
  uint64_t sectors = (len >> 9);

  assert(sectors != 0);
  if (sectors > MAX_KEY_SIZE) {
    CACHE_WARNLOG(NULL, "big size sectors %lu, max %u\n", sectors, MAX_KEY_SIZE);
  }
  insert_keys = calloc(1, sizeof(*insert_keys));
  if ( !insert_keys ) {
    CACHE_ERRORLOG(NULL, "calloc insert_keys no mem\n");
    assert("calloc insert_keys no mem" == 0);
    goto err;
  }
  bch_keylist_init(insert_keys);

  do {
    struct bkey *k = NULL;
    uint64_t key_size = 0;

    k = get_init_bkey(insert_keys, offset, ca);
    key_size = sectors > MAX_KEY_SIZE ? MAX_KEY_SIZE : sectors;

    SET_KEY_OFFSET(k, KEY_OFFSET(k) + key_size);
    SET_KEY_SIZE(k, key_size);
    bch_keylist_push(insert_keys);

    sectors -= key_size;
    offset += (key_size << 9);
  } while (sectors > 0);

  ret = bch_data_insert_keys(ca->set, insert_keys, NULL);
  if ( ret != 0 ) {
    CACHE_DEBUGLOG(NULL,"Invalidate region(start=%lu/0x%lx,len=%lu,0x%lx) ERROR.\n",
                        offset/512,offset,len/512,len);
    assert("Invaliedate region error"==0);
  }

  ca->wake_up_gc_size_wm += len;
  ret = 0;

  free(insert_keys);
err:
  return ret;
}

int
_prep_writearound(struct ring_item * item)
{
  int ret = 0;
  struct cache *ca = (struct cache *) item->ca_handler;
  struct keylist *insert_keys = NULL;
  struct bkey *k = NULL;

  insert_keys = calloc(1, sizeof(*insert_keys));
  if ( !insert_keys ) {
    goto err;
  }
  bch_keylist_init(insert_keys);
  k = get_init_bkey(insert_keys, item->o_offset, ca);
  if ( !k ) {
    goto free_keylist;
  }

  SET_KEY_OFFSET(k, KEY_OFFSET(k) + (item->o_len >> 9));
  SET_KEY_SIZE(k, (item->o_len >> 9));

  item->io.pos = item->data;
  item->io.offset = item->o_offset;
  item->io.len = (KEY_SIZE(k)<<9);
  item->iou_arg = item;
  item->iou_completion_cb = aio_write_completion;
  item->type = ITEM_AIO_WRITE;
  CACHE_DEBUGLOG(CAT_WRITE, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx)) \n",
      item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  bch_keylist_push(insert_keys);
  item->insert_keys = insert_keys;

  return ret;
free_keylist:
  free(insert_keys);
err:
  return -1;
}

int
do_write_writearound(struct ring_item * item)
{
  struct cache *ca = (struct cache *) item->ca_handler;

  if(_prep_writearound(item) < 0){
    assert( " prep writearound error  " == 0);
  }

  if (aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item) < 0){
    assert( "writearound aio_enqueue error  " == 0);
  }

  return 0;
}

int
cache_aio_writearound_batch(struct cache *ca, struct ring_items * items)
{
  int i;
  struct ring_item * item;
  for (i = 0; i < items->count; i++){
    item = items->items[i];
    item->ca_handler = ca;
    item->io.type=CACHE_IO_TYPE_WRITE;
    item->start = cache_clock_now();

    if (_prep_writearound(item) < 0) {
      assert( " prep writearound error  " == 0);
    }
  }
  if (aio_enqueue_batch(CACHE_THREAD_BACKEND, ca->handler, items) < 0) {
    CACHE_ERRORLOG(NULL,"writearound aio_enqueue error == 0");
    assert( "writearound aio_enqueue error  " == 0);
  }
  return 0;
}

int _prep_writeback(struct ring_item * item){
  struct keylist *insert_keys = NULL;
  struct bkey *k = NULL;
  struct cache *ca = (struct cache *) item->ca_handler;
  int ret = 0;
  unsigned i;

  insert_keys = calloc(1, sizeof(*insert_keys));
  if ( !insert_keys ) {
    goto err;
  }
  bch_keylist_init(insert_keys);

  k = get_init_bkey(insert_keys, item->o_offset, ca);
  if ( !k ) {
    goto free_keylist;
  }

  struct timespec start = cache_clock_now();
  ret = bch_alloc_sectors(ca->set, k, (item->o_len >> 9), 0, 0, 1);
  ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_alloc_sectors, start, cache_clock_now());

  SET_KEY_DIRTY(k, true);
  for (i = 0; i < KEY_PTRS(k); i++)
    SET_GC_MARK(PTR_BUCKET(ca->set, k, i),
	        GC_MARK_DIRTY);
  // dump_bkey("aio_en", k);
  item->io.pos = item->data;
  item->io.offset = (PTR_OFFSET(k, 0) << 9);
  item->io.len = (KEY_SIZE(k)<<9);
  item->iou_arg = item;
  item->iou_completion_cb = aio_write_completion;
  item->type = ITEM_AIO_WRITE;
  CACHE_DEBUGLOG(CAT_WRITE, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx)) "
      "write cache=%lu(0x%lx)\n",
      item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len,
      item->io.offset >> 9, item->io.offset);

  bch_keylist_push(insert_keys);
  if (bch_keylist_nkeys(insert_keys) != 3) {
    CACHE_ERRORLOG(NULL, " nkeys %d error \n", bch_keylist_nkeys(insert_keys));
    assert("nkeys error" == 0);
  }
  item->insert_keys = insert_keys;

  return ret;
free_keylist:
  free(insert_keys);
err:
  return -1;
}

int
do_write_writeback(struct ring_item * item)
{
  struct cache *ca = (struct cache *) item->ca_handler;

  if (_prep_writeback(item) < 0) {
    assert( " prep_writeback error  " == 0);
  }

  if (aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item) < 0) {
    assert( " writeback aio_enqueue error  " == 0);
  }
  return 0;
}

int
cache_aio_writeback_batch(struct cache *ca, struct ring_items * items)
{
  int i;
  struct ring_item * item;

  for (i = 0; i < items->count; i++){
    item = items->items[i];
    item->ca_handler = ca;
    item->strategy = CACHE_MODE_WRITEBACK;
    item->io.type=CACHE_IO_TYPE_WRITE;
    item->start = cache_clock_now();
    if (atomic_sub_return((item->o_len >> 9), &ca->set->sectors_to_gc) < 0) {
      CACHE_WARNLOG(CAT_WRITE, "wakeup gc \n");
      wake_up_gc(ca->set);
    }
    if (_prep_writeback(item) < 0) {
      CACHE_ERRORLOG(CAT_WRITE, "prep writeback error \n");
      assert("prep_writeback error" == 0);
    }
  }

  if (aio_enqueue_batch(CACHE_THREAD_CACHE, ca->handler, items) < 0) {
    CACHE_ERRORLOG(CAT_WRITE, "aio_enqueue_batch error \n");
    assert("writeback aio_enqueue error" == 0);
  }
  return 0;
}

int
_prep_writethrough(struct ring_item * item)
{
  struct keylist *insert_keys = NULL;

  insert_keys = calloc(1, sizeof(*insert_keys));
  if ( !insert_keys ) {
    goto err;
  }
  bch_keylist_init(insert_keys);

  item->io.pos = item->data;
  item->io.offset = item->o_offset;
  item->io.len = item->o_len;
  item->iou_arg = item;
  item->iou_completion_cb = aio_write_completion;
  item->insert_keys = insert_keys;
  item->type = ITEM_AIO_WRITE;
  CACHE_DEBUGLOG(CAT_WRITE, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx)) \n",
      item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  return 0;
err:
  return -1;
}

int
do_write_writethrough(struct ring_item * item)
{
  struct cache *ca = (struct cache *) item->ca_handler;

  if (_prep_writethrough(item) < 0) {
    assert( " prep writethrough error  " == 0);
  }

  if (aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item) < 0) {
    assert( " writethrough aio_enqueue error  " == 0);
  }
  return 0;
}

int
cache_aio_writethrough_batch(struct cache *ca, struct ring_items * items)
{
  int i;
  struct ring_item * item;
  for (i = 0; i < items->count; i++){
    item = items->items[i];
    item->ca_handler = ca;
    item->io.type=CACHE_IO_TYPE_WRITE;
    item->start = cache_clock_now();
    if (atomic_sub_return((item->o_len >> 9), &ca->set->sectors_to_gc) < 0)
       wake_up_gc(ca->set);
    if (_prep_writethrough(item) < 0) {
      assert( " prep_writeback error  " == 0);
    }
  }

  if (aio_enqueue_batch(CACHE_THREAD_BACKEND, ca->handler, items) < 0) {
    assert( "writeback aio_enqueue error  " == 0);
  }
  return 0;
}

static void add_sequential(struct current_thread *t)
{
  ewma_add(t->sequential_io_avg,
           t->sequential_io, 8, 0);

  t->sequential_io = 0;
}

#define GOLDEN_RATIO_64 0x61C8864680B583EBull
static inline int hash_64(uint64_t val, unsigned int bits)
{
  return val * GOLDEN_RATIO_64 >> (64 - bits);
}

static struct hlist_head *iohash(struct cached_dev *dc, uint64_t k)
{
  return &dc->io_hash[hash_64(k, RECENT_IO_BITS)];
}

static bool check_should_bypass(struct cached_dev *dc, struct ring_item *item)
{
  struct cache_set *c = dc->c;
  unsigned mode = BDEV_CACHE_MODE(&dc->sb);
  unsigned sectors;
  struct io *i;

  struct current_thread *task = NULL;

  if (c->gc_stats.in_use > dc->iobypass_water_level)
    goto skip;

  if (mode == CACHE_MODE_NONE || mode == CACHE_MODE_WRITEAROUND)
    goto skip;

  if ((item->o_offset >> 9) & (c->sb.block_size -1) ||
      (item->o_len >> 9) & (c->sb.block_size -1)) {
    CACHE_ERRORLOG(CAT_WRITE, "got unaligned io(o_offset 0x%lx len 0x%lx\n",
        item->o_offset, item->o_len);
    assert("skipping unaligned io" == 0);
    goto skip;
  }

  if (bypass_torture_test(dc)) {
    int i = 0;
    get_random_bytes(&i, sizeof(int));
    if ((i & 3) == 3)
      goto skip;
    else
      goto rescale;
  }

  list_for_each_entry(task, &dc->io_thread, list) {
    if (task->thread_id == pthread_self())
      goto out;
  }

  task = calloc(1, sizeof(*task));
  if ( task == NULL ) {
    CACHE_ERRORLOG(NULL, "calloc thread task faild \n");
    assert("calloc thread task faild " == 0);
  }
  task->thread_id = pthread_self();
  pthread_spin_lock(&dc->io_lock);
  list_add_tail(&task->list, &dc->io_thread);
  pthread_spin_unlock(&dc->io_lock);

out:
  pthread_spin_lock(&dc->io_lock);

  hlist_for_each_entry(i, iohash(dc, (item->o_offset >> 9)), hash) {
    if (i->last == (item->o_offset >> 9) &&
        time_before64((uint64_t)time(NULL), i->jiffies))
      goto found;
  }

  i = list_first_entry(&dc->io_lru, struct io, lru);
  add_sequential(task);
  i->sequential = 0;

found:
  if (i->sequential + item->o_len > i->sequential)
    i->sequential   += item->o_len;

  i->last                 = (item->o_offset >> 9) + (item->o_len >> 9);
  i->jiffies              = time(NULL) + 5;
  task->sequential_io     = i->sequential;

  hlist_del(&i->hash);
  hlist_add_head(&i->hash, iohash(dc, i->last));
  list_move_tail(&i->lru, &dc->io_lru);

  pthread_spin_unlock(&dc->io_lock);


  sectors = max(task->sequential_io,
      task->sequential_io_avg) >> 9;

  if (dc->sequential_cutoff &&
      sectors >= dc->sequential_cutoff >> 9) {
    goto skip;
  }
rescale:
  bch_rescale_priorities(c, item->o_len >> 9);
  return false;
skip:
  // 此处需要统计下bypass的io数据量（其他wb的数据量也要统计下）
  return true;
}

static bool should_writeback(struct cached_dev *dc, unsigned int cache_mode, bool would_skip)
{
  unsigned in_use = dc->c->gc_stats.in_use;

  if (cache_mode != CACHE_MODE_WRITEBACK || in_use > dc->cutoff_writeback_sync)
    return false;

  if (would_skip)
    return false;

  return in_use <= dc->cutoff_writeback;
}

int get_cache_strategy(struct cache *ca, struct ring_item *item)
{
  struct cached_dev *dc = ca->set->dc;
  unsigned int mode = BDEV_CACHE_MODE(&dc->sb);
  struct bkey start = KEY(0, item->o_offset >> 9, 0);
  struct bkey end = KEY(0, (item->o_offset >> 9) + (item->o_len >> 9), 0);

  bool bypass = false;
  bool writeback = true;

  // 判断io是否可以绕过cache，
  // 条件：
  // 1. cache盘的使用量达到阈值iobypass_water_level
  // 2. cache模式是none或者around
  // 3. io在同一个线程内的一段时间内是否连续
  bypass = check_should_bypass(dc, item);

  bch_keybuf_check_overlapping(&dc->c->moving_gc_keys, &start, &end);

  pthread_rwlock_rdlock(&dc->writeback_lock);

  // 如果与正在回刷的bkey有重叠部分，需要使用writeback模式
  if (bch_keybuf_check_overlapping(&dc->writeback_keys, &start, &end)) {
    bypass = false;
    writeback = true;
  }

  // 如果cache使用量没超过回刷的水位线并且模式是writeback模式的情况，返回true
  /*if (should_writeback(dc, mode, bypass)) {*/
    /*bypass = false;*/
    /*writeback = true;*/
  /*}*/

  if (bypass) {
    return CACHE_MODE_WRITEAROUND;
  } else if (writeback) {
    return CACHE_MODE_WRITEBACK;
  } else {
    /*return CACHE_MODE_WRITETHROUGH;*/
    return CACHE_MODE_WRITEAROUND;
  }
}

int cache_aio_write(struct cache*ca, void *data, uint64_t offset, uint64_t len, void *cb, void *cb_arg)
{
  CACHE_DEBUGLOG(CAT_WRITE,"IO(start=%lu(0x%lx),len=%lu(%lx)) \n", offset/512, offset, len/512, len);
  struct ring_item *item = NULL;
  int ret=0;

  item = get_ring_item(data, offset, len);
  if ( !item ) {
    goto err;
  }
  item->io_completion_cb = cb;
  item->io_arg = cb_arg;
  item->start = cache_clock_now();
  item->type = ITEM_AIO_WRITE;

  item->strategy = get_cache_strategy(ca, item);
  /**********   策略相关的代码 ******************/
  // 进行一些列判断，最终得到本次io的写入策略
  // 1. should bypass
  // 2. should writeback
  /***********************************************/

  //item->strategy = CACHE_MODE_WRITEBACK;
  /*insert_keys = calloc(1, sizeof(*insert_keys));*/
  if (item->strategy != CACHE_MODE_WRITEAROUND) {
    if (atomic_sub_return((item->o_len >> 9), &ca->set->sectors_to_gc) < 0)
      wake_up_gc(ca->set);
  }

  item->io.type=CACHE_IO_TYPE_WRITE;
  item->ca_handler = ca;
  switch (item->strategy) {
    case CACHE_MODE_WRITEBACK:
      ret = do_write_writeback(item);
      if (ret < 0) {
        goto free_item;
      }
      break;
    case CACHE_MODE_WRITETHROUGH:
      ret = do_write_writethrough(item);
      if (ret < 0) {
        goto free_item;
      }
      break;
    case CACHE_MODE_WRITEAROUND:
      ret = do_write_writearound(item);
      if (ret < 0) {
        goto free_item;
      }
      break;
    default:
      assert(" Unsupported io stragegy " == 0);
  }
  return 0;
free_item:
  free(item);
err:
  return -1;
}

void
aio_write_test(struct cache *ca)
{
  printf(" ******** aio_write_test ****** \n");
  void *data = NULL;
  uint64_t len = 512*1025;
  uint64_t offset = 8192;

  int ret = posix_memalign((void **)&data, MEMALIGN, len);
  if (ret != 0) {
    CACHE_ERRORLOG(NULL, "alloc align memory failed");
    assert(ret == 0);
  }
  memset(data, 'b', len);
  cache_aio_write(ca, data, offset, len, NULL, NULL);
  cache_aio_write(ca, data, offset + len + 512*10, 512*10, NULL, NULL);
}


int
set_item_io(struct ring_item *item, const struct bkey *k) {
  uint64_t cache_end = KEY_OFFSET(k) << 9;
  uint64_t cache_offset = (KEY_OFFSET(k) - KEY_SIZE(k)) << 9;
  uint64_t read_offset = item->o_offset;
  uint64_t read_len = item->o_len;
  void *read_data = item->data;
  uint64_t read_end = read_offset + read_len;
  int ret = 0;

  if (cache_offset < read_offset) {
    item->io.offset = (PTR_OFFSET(k, 0) << 9) + read_offset - cache_offset;
    item->io.len = read_len;
    item->io.pos = read_data;
  } else {
    item->io.offset = PTR_OFFSET(k, 0) << 9;
    item->io.len = read_len - (cache_offset - read_offset);
    item->io.pos = (char *)read_data + (cache_offset - read_offset);
  }

  if (cache_end < read_end) {
    item->io.len -= (read_end - cache_end);
  } else {
    // hit the end
    ret = 1;
  }

  return ret;
}

int _write_cache_miss(struct ring_item *item)
{
  int ret = 0;
  struct cache *ca = item->ca_handler;

  if (item->io.type != CACHE_IO_TYPE_READ ) {
    CACHE_ERRORLOG(NULL, "not read io got(type %d) \n", item->io.type);
    assert(item->io.type == CACHE_IO_TYPE_READ);
  }
  item->io.type=CACHE_IO_TYPE_WRITE;
  item->start = item->aio_start = cache_clock_now();


  // 读热点数据需要写入到缓存中，如需replace_key，需要在writeback回调中修改
  // 1. when write readed data, we should also check_overlapping with gc and wb
  // 2. we should handle writeback_lock read lock when write complete it
  // will unlock, if not it will cause wb thread write lock hung
  if (atomic_sub_return((item->o_len >> 9), &ca->set->sectors_to_gc) < 0)
    wake_up_gc(ca->set);

  if (_prep_writeback(item) < 0) {
    CACHE_ERRORLOG(NULL,"prep cache miss error %d\n", ret);
    assert( " prep_cache_miss error  " == 0);
  }

  if (bch_keylist_nkeys(item->insert_keys) != 3) {
    CACHE_ERRORLOG(NULL, " nkeys %d error \n", bch_keylist_nkeys(item->insert_keys));
    assert("nkeys error" == 0);
  }
  ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
  if (ret < 0) {
    CACHE_ERRORLOG(NULL,"write hits sync error %d\n", ret);
    assert("Write hits sync error" == 0);
  }

  return ret;
}

void
aio_read_completion(struct ring_item *item)
{
  struct cache *ca = item->ca_handler;
  CACHE_DEBUGLOG(CAT_READ, "free item(%p) IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  if (item->io.type != CACHE_IO_TYPE_READ ) {
    CACHE_ERRORLOG(NULL, "aio read completion got not read io got(type %d) \n", item->io.type);
    assert(item->io.type == CACHE_IO_TYPE_READ);
  }

  if (item->need_write_cache) {
    item->strategy = get_cache_strategy(ca, item);
    CACHE_DEBUGLOG(NULL," stratege = %d  io type %d \n",
                        item->strategy, item->io.type);
    if (item->strategy == CACHE_MODE_WRITEBACK) {
      _write_cache_miss(item);
      return;
    } else {
      CACHE_DEBUGLOG(NULL,"cache should not hits by strategy \n");
      pthread_rwlock_unlock(&ca->set->dc->writeback_lock);
    }
  }

  ca->set->logger_cb(ca->set->bluestore_cd, l_bluestore_cachedevice_t2cache_read_lat, item->start, cache_clock_now());
  // call callback function
  if (item->io_completion_cb) {
    item->io_completion_cb(item->io_arg);
  }

  // TODO: Let the user decide whether to write to the cache.
  // write data to cache
  // TODO: we should not direct write readed data into caceh when using
  // caceh_aio_write interface, that will cause data error
  // 1. we should consider of user desire or business
  // 2. take care of when read complete, need sync write, no async, this
  //    will drop perf downk

  SAFE_FREE_DEC(item, free_ring_item);
}

static struct bkey * bkey_cut_invalid(struct bkey *k, uint64_t start, uint64_t len){
  uint64_t end = len + start;
  // discard left of start
  if (KEY_START(k) < start){
    SET_PTR_OFFSET(k, 0, PTR_OFFSET(k, 0) + (start - KEY_START(k)));
    SET_KEY_SIZE(k, KEY_SIZE(k) - (start - KEY_START(k)));
  }
  // discard right of end
  if (KEY_OFFSET(k) > end){
    SET_KEY_SIZE(k, KEY_SIZE(k) - (KEY_OFFSET(k) - end));
    SET_KEY_OFFSET(k, end);
  }
  return k;
}

int bkey_contain(struct bkey *large, struct bkey *small){
  return KEY_OFFSET(large) >= KEY_OFFSET(small) &&
    KEY_START(large) <= KEY_START(small);
}


int _do_read_cache(struct ring_item *item){
  struct cache *ca = item->ca_handler;
  // second loop bkeys
  struct bkey *new_bkey = item->read_new_keys->keys;
  // first loop bkeys
  struct bkey *old_bkey = item->read_keys->keys;
  BKEY_PADDED(key) _bkey;
  struct bkey *tmp = &_bkey.key;
  struct keylist *caches = NULL;
  struct keylist *backends = NULL;
  int io_num = 0;
  int ret;
  char buf[BUFFER_SIZE]={0};
  char* next = buf;


  caches = calloc(1, sizeof(struct keylist));
  if ( caches == NULL ) {
    CACHE_ERRORLOG(NULL, "alloc keylist failed \n");
    assert("calloc thread task failed" == 0);
  }
  backends = calloc(1, sizeof(struct keylist));
  if ( backends == NULL ) {
    CACHE_ERRORLOG(NULL, "alloc keylist failed \n");
    assert("calloc thread task failed" == 0);
  }

  bch_keylist_init(caches);
  bch_keylist_init(backends);

  CACHE_DEBUGLOG(CAT_READ, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);
  SAFE_FREE_INC(item);

  for (; old_bkey != item->read_keys->top; old_bkey = bkey_next(old_bkey)){
    // skip useless bkey
    if (item->need_read_backend && !KEY_DIRTY(old_bkey)){
      continue;
    }

    // move new_bkey when rbky is behind
    while (new_bkey){
      if (new_bkey == item->read_new_keys->top){
        new_bkey = NULL;
        break;
      }
      else if (KEY_OFFSET(new_bkey) <= KEY_START(old_bkey))
        new_bkey = bkey_next(new_bkey);
      else
        break;
    }

    if (new_bkey && bkey_contain(new_bkey, old_bkey)) {
      // cache find and read cache
      //top = caches->top;
      bkey_copy(tmp, new_bkey);
      bkey_cut_invalid(tmp, KEY_START(old_bkey), KEY_SIZE(old_bkey));
      bch_keylist_add(caches, tmp);
    } else {
      // cache not found and read backend
      CACHE_WARNLOG(CAT_READ, "Cache not found and push io to backend\n");
      bch_keylist_add(backends, old_bkey);
    }
    io_num ++;
  }

  if (!io_num){
    CACHE_ERRORLOG(CAT_READ, "IO not found!\n");
    assert(io_num);
  }

  atomic_set(&item->seq, io_num);
  bch_keylist_free(item->read_keys);
  T2Free(item->read_keys);
  item->read_keys = backends;
  bch_keylist_free(item->read_new_keys);
  T2Free(item->read_new_keys);
  item->read_new_keys = caches;

  for (new_bkey = caches->keys; new_bkey != caches->top; new_bkey = bkey_next(new_bkey)){
    set_item_io(item, new_bkey);

    // note: log not large than IO_LOG_LINE
    ENABLE_DEBUG_LOG
    ret = sprintf(next, "cache=%lu(0x%lx)-%lu(%lx),",
        item->io.offset >> 9, item->io.offset, item->io.len >> 9, item->io.len);
    cache_bug_on(ret > IO_LOG_LINE, ca->set, "pre io log large than IO_LOG_LINE");
    cache_bug_on(next > buf + BUFFER_SIZE - 1, ca->set, "buf not enough for log");
    next += ret;
    // check buffer space for next log
    if (next > buf + BUFFER_SIZE - IO_LOG_LINE){
      CACHE_DEBUGLOG(CAT_READ, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx) from %s) \n",
          item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len, buf);
      next = buf;
    }
    END_LOG

    ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
    if (ret < 0) {
      CACHE_ERRORLOG(CAT_READ, "read cache aio_enqueue error  \n");
      assert("read cache aio_enqueue error  " == 0);
    }
  }
  CACHE_DEBUGLOG(CAT_READ, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx) from cache %s) \n",
      item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len, buf);

  for (new_bkey = backends->keys; new_bkey != backends->top; new_bkey = bkey_next(new_bkey)){
    item->io.len = KEY_SIZE(new_bkey) << 9;
    item->io.offset = KEY_START(new_bkey) << 9;
    item->io.pos = (char *)item->data + ((KEY_START(new_bkey) << 9) - item->o_offset);
    ret = aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item);
    if (ret < 0) {
      CACHE_ERRORLOG(CAT_READ, "read cache aio_enqueue error  \n");
      assert("read cache aio_enqueue error  " == 0);
    }
  }
  SAFE_FREE_DEC(item, free_ring_item);
  return 0;
}

int
read_cache_lookup_fn(struct btree_op * op, struct btree *b,
						 struct bkey *key)
{
  struct search *s = container_of(op, struct search, op);
  struct ring_item *item = s->item;
  uint64_t offset = item->o_offset >> 9;
  uint64_t end = offset + (item->o_len >> 9);

  // bkey is before of data
   if (KEY_OFFSET(key)  <= offset) {
     return MAP_CONTINUE;
   }
   // bkey is after of data
   else if (KEY_START(key) >= end) {
     _do_read_cache(item);
     return MAP_DONE;
   }
   // bkey in data
   else if (KEY_SIZE(key) && KEY_PTRS(key)) {
     BKEY_PADDED(key) tmp;
     bkey_copy(&tmp, key);
     bkey_cut_invalid(&tmp.key, item->o_offset >> 9, item->o_len >> 9);
     bch_keylist_add(item->read_new_keys, &tmp.key);
     PTR_BUCKET(b->c, key, 0)->prio = INITIAL_PRIO;
   }
   return MAP_CONTINUE;
}

void aio_fix_stale_cache_completion(void *cb)
{
  struct ring_item *item = cb;
  CACHE_DEBUGLOG(CAT_WRITE, "item(%p) req=%d IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, atomic_read(&item->seq), item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  if (item->io.type != CACHE_IO_TYPE_READ ) {
    CACHE_ERRORLOG(NULL, "aio read cache completion got not read io got(type %d) \n", item->io.type);
    assert(item->io.type == CACHE_IO_TYPE_READ);
  }
  if (!atomic_dec_return(&item->seq)) {
    aio_read_completion(item);
  }
}

int _read_check_bkey(struct ring_item *item){
  struct bkey *iter;
  struct cache *ca = item->ca_handler;
  int seq = 0;
  int ret;
  struct keylist *backends = NULL;


  backends = calloc(1, sizeof(struct keylist));
  if ( backends == NULL ) {
    CACHE_ERRORLOG(NULL, "alloc keylist failed \n");
    assert("calloc thread task failed" == 0);
  }
  bch_keylist_init(backends);

  SAFE_FREE_INC(item);
  for (iter = item->read_new_keys->keys; iter!= item->read_new_keys->top; iter = bkey_next(iter)){
    if(ptr_stale(ca->set, iter, 0)){
      CACHE_WARNLOG(CAT_READ, "aio read cache completion but key stable \n");
      bch_keylist_add(backends, iter);
      seq ++;
    }
  }

  atomic_set(&item->seq, seq);
  item->iou_completion_cb = aio_fix_stale_cache_completion;
  for (iter = backends->keys; iter != backends->top; iter = bkey_next(iter)){
    item->io.len = KEY_SIZE(iter) << 9;
    item->io.offset = KEY_START(iter) << 9;
    item->io.pos = (char *)item->data + ((KEY_START(iter) << 9) - item->o_offset);
    ret = aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item);
    if (ret < 0) {
      CACHE_ERRORLOG(CAT_READ, "read cache aio_enqueue error  \n");
      assert("read cache aio_enqueue error  " == 0);
    }
  }

  bch_keylist_free(backends);
  T2Free(backends);
  SAFE_FREE_DEC(item, free_ring_item);
  return seq;
}

void aio_read_cache_completion(void *cb)
{
  struct ring_item *item = cb;
  CACHE_DEBUGLOG(CAT_WRITE, "item(%p) req=%d IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, atomic_read(&item->seq), item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  if (item->io.type != CACHE_IO_TYPE_READ ) {
    CACHE_ERRORLOG(NULL, "aio read cache completion got not read io got(type %d) \n", item->io.type);
    assert(item->io.type == CACHE_IO_TYPE_READ);
  }
  if (!atomic_dec_return(&item->seq)) {
    if(!_read_check_bkey(item)){
      aio_read_completion(item);
    }
  }
}

void aio_read_cache(struct ring_item *item){
  struct cache *ca = item->ca_handler;
  struct search s;
  CACHE_DEBUGLOG(CAT_READ, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  if (item->io.type != CACHE_IO_TYPE_READ ) {
    assert(item->io.type == CACHE_IO_TYPE_READ);
  }

  item->read_new_keys = calloc(1, sizeof(struct keylist));
  if (!item->read_new_keys){
    CACHE_ERRORLOG(CAT_READ, "Calloc memory for read_new_keys error\n");
    assert(item->read_new_keys);
  }
  bch_keylist_init(item->read_new_keys);
  item->iou_completion_cb = aio_read_cache_completion;
  atomic_set(&item->seq, -1);
  s.item = item;
  bch_btree_op_init(&s.op, -1, BTREE_OP_READ);
  /*printf("<%s>: find btree node offset=%lu, len=%lu ------------------\n",*/
                        /*__func__, item->o_offset, item->o_len );*/
  bch_btree_map_keys(&s.op, ca->set, &KEY(0,(s.item->o_offset >> 9),0),
                     read_cache_lookup_fn, MAP_END_KEY);

}

void
aio_read_backend_completion(void *cb)
{
  struct ring_item *item = cb;
  CACHE_DEBUGLOG(CAT_READ, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);
  if (item->need_read_cache)
    aio_read_cache(item);
  else{
    aio_read_completion(item);
  }
}


void
aio_read_backend(struct ring_item *item)
{
  int ret = 0;
  struct cache *ca = item->ca_handler;

  CACHE_DEBUGLOG(CAT_READ, "item(%p) IO(start=%lu(0x%lx),len=%lu(%lx))\n",
                 item, item->o_offset/512, item->o_offset, item->o_len/512, item->o_len);

  item->io.offset = item->o_offset;
  item->io.pos = item->data;
  item->io.len = item->o_len;
  item->iou_completion_cb = aio_read_backend_completion;

  CACHE_DEBUGLOG(CAT_READ, "aio_enqueue backend (start=%lu, len=%lu)\n",
                 item->o_offset >> 9, item->o_len >> 9);
  // read hdd first
  ret = aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item);
  if (ret < 0) {
    assert( "test aio_enqueue error  " == 0);
  }
}

static bool cache_read_hits(struct ring_item *item)
{
  // TODO 判断是否需要缓存
  struct cache *ca = item->ca_handler;

  return atomic_read(&ca->set->cached_hits);
}

int
read_is_all_cache_fn(struct btree_op * op, struct btree *b,
                         struct bkey *key)
{
  struct search *s = container_of(op, struct search, op);
  struct ring_item *item = s->item;
  uint64_t cache_start = (KEY_OFFSET(key) - KEY_SIZE(key)) << 9;
  uint64_t cache_end = KEY_OFFSET(key) << 9;

  CACHE_DEBUGLOG(CAT_READ,"iter bkey(start=%lu,of=%lu,len=%lu)\n",
      (KEY_OFFSET(key) - KEY_SIZE(key)),KEY_OFFSET(key),KEY_SIZE(key));
  CACHE_DEBUGLOG(CAT_READ,"iter search(start=%lu,of=%lu,len=%lu)\n",
                 (item->o_offset >> 9),((item->o_offset + item->o_len) >> 9),((item->o_len) >> 9));

  // bkey is before of data
  if (cache_end <= item->o_offset) {
    return MAP_CONTINUE;
  }
  // bkey is after of data
  // item->io.offset is last hit bkey's end
  else if (cache_start >= item->o_offset + item->o_len) {
    // hdd
    CACHE_DEBUGLOG(CAT_READ,"Read: not all data in cache, goto read backend \n");
    if (cache_read_hits(item))
      item->need_write_cache = true;
    item->need_read_backend = true;
    return MAP_DONE;
  }
  // bkey in data
  else if (KEY_SIZE(key) && KEY_PTRS(key)) {
    BKEY_PADDED(key) tmp;
    if (KEY_DIRTY(key)){
      item->need_read_cache = true;
    }
    //pos
    bkey_copy(&tmp.key, key);
    bkey_cut_invalid(&tmp.key, item->o_offset >> 9, item->o_len >> 9);
    bch_keylist_add(item->read_keys, &tmp.key);

    // get bkey available length

    item->io.len += KEY_SIZE(&tmp.key) << 9;
    if (item->io.len == item->o_len) {
      // all in ssd
      CACHE_DEBUGLOG(CAT_READ,"Read: all data in cache\n");
      item->need_read_backend = false;
      return MAP_DONE;
    }

    // TODO: collect the bkey for read cache.
  }
  return MAP_CONTINUE;
}


int
cache_aio_read(struct cache*ca, void *data, uint64_t offset, uint64_t len,
                   io_completion_fn io_completion, void *io_arg)
{
  CACHE_DEBUGLOG(CAT_READ, "cache_aio_read IO(start=%lu(0x%lx),len=%lu(%lx)) \n", offset/512, offset, len/512, len);
  struct ring_item *item;
  struct search s;
  int ret = 0;

  item = get_ring_item(data, offset, len);
  item->io.offset = offset;
  item->io.len = 0;
  item->io.type = CACHE_IO_TYPE_READ;
  item->io_completion_cb = io_completion;
  item->io_arg = io_arg;
  item->iou_arg = item;
  item->ca_handler = ca;
  item->need_write_cache = false;
  item->need_read_backend = false;
  item->need_read_cache = false;
  item->start = cache_clock_now();
  item->read_keys = calloc(1, sizeof(struct keylist));
  if (item->read_keys == NULL) {
    CACHE_ERRORLOG(NULL, "calloc read_keys failed \n");
    assert("calloc read_keys failed" == 0);
  }
  item->type = ITEM_AIO_READ;
  bch_keylist_init(item->read_keys);
  bch_rescale_priorities(ca->set, len >> 9);

  atomic_add(1 + (len >> 8) / 2, &ca->set->dc->read_iops);
  s.item = item;
  bch_btree_op_init(&s.op, -1, BTREE_OP_READ);
  bch_btree_map_keys(&s.op, ca->set, &KEY(0,(s.item->o_offset >> 9),0),
                        read_is_all_cache_fn, MAP_END_KEY);

  CACHE_DEBUGLOG(CAT_READ, "calloc item(%p) IO(start=%lu(0x%lx),len=%lu(%lx)) %s %s\n",
                 item, offset/512, offset, len/512, len,
                 item->need_read_backend ? "need_backend": "",
                 item->need_read_cache? "need_cache": "");

  if (item->need_read_backend)
    aio_read_backend(item);
  else
    aio_read_cache(item);

  return ret;
}

// cache super block
int write_sb(const char *dev, unsigned block_size, unsigned bucket_size,
    bool writeback, bool discard, bool wipe_bcache,
    unsigned cache_replacement_policy,
    uint64_t data_offset, bool bdev, const char *uuid_str)
{
  int ret = 0;
  int fd;
  char set_uuid_str[40], zeroes[SB_START] = {0};
  struct cache_sb sb;
  blkid_probe pr;

  if ((fd = open(dev, O_RDWR|O_EXCL)) == -1) {
    CACHE_ERRORLOG(NULL, "Can't open dev %s: %s\n", dev, strerror(errno));
    assert("open cache device failed" == 0);
  }
  if (pread(fd, &sb, sizeof(sb), SB_START) != sizeof(sb)) {
    CACHE_ERRORLOG(NULL, "pread dev %s: %s\n", dev, strerror(errno));
    assert("pread cache device super block failed" == 0);
  }
  if (!memcmp(sb.magic, bcache_magic, 16) && !wipe_bcache) {
    CACHE_ERRORLOG(NULL, "Already a bcache device on %s, "
        "overwrite with --wipe-bcache\n", dev);
    assert("cache device super block magic need overwrite with --wipe-bcache"==0);
  }

  if (!(pr = blkid_new_probe())) {
    CACHE_ERRORLOG(NULL, "cache device blkid new probe failed\n");
    assert("cache device blkid new probe failed"==0);
  }
  if (blkid_probe_set_device(pr, fd, 0, 0)) {
    CACHE_ERRORLOG(NULL, "cache device blkid probe set device failed\n");
    assert("cache device blkid probe set device failed" == 0);
  }
  /* enable ptable probing; superblock probing is enabled by default */
  if (blkid_probe_enable_partitions(pr, true)) {
    CACHE_ERRORLOG(NULL, "cache device blkid probe enable partitions failed\n");
    assert("cache device blkid probe enable partitions failed" == 0);
  }
  if (!blkid_do_probe(pr)) {
    /* XXX wipefs doesn't know how to remove partition tables */
    CACHE_ERRORLOG(NULL, "Device %s already has a non-bcache superblock, "
        "remove it using wipefs and wipefs -a\n", dev);
    assert("cache device already has a non-bcache superblock, need wipsfs -a" == 0);
  }
  memset(&sb, 0, sizeof(struct cache_sb));
  sb.offset	= SB_SECTOR;
  sb.version	= bdev
    ? BCACHE_SB_VERSION_BDEV
    : BCACHE_SB_VERSION_CDEV;
  memcpy(sb.magic, bcache_magic, 16);

  /*memcpy(sb.set_uuid, set_uuid, sizeof(sb.set_uuid));*/
  sb.bucket_size	= bucket_size;
  sb.block_size	= block_size;

  uuid_parse(uuid_str, &sb.uuid);
  uuid_parse(uuid_str, &sb.set_uuid);
  uuid_unparse(sb.set_uuid, set_uuid_str);

  if (SB_IS_BDEV(&sb)) {
    SET_BDEV_CACHE_MODE(
        &sb, writeback ? CACHE_MODE_WRITEBACK : CACHE_MODE_WRITETHROUGH);
    if (data_offset != BDEV_DATA_START_DEFAULT) {
      sb.version = BCACHE_SB_VERSION_BDEV_WITH_OFFSET;
      sb.data_offset = data_offset;
    }
    CACHE_INFOLOG(NULL, "\nUUID:			%s\n"
                        "Set UUID:		%s\n"
                        "version:		%u\n"
                        "block_size:		%u\n"
                        "data_offset:		%ju\n",
                        uuid_str, set_uuid_str,
                        (unsigned) sb.version,
                        sb.block_size,
                        data_offset);
  } else {
    sb.nbuckets		= getblocks(fd) / sb.bucket_size;
    sb.nr_in_set		= 1;
    sb.first_bucket		= (23 / sb.bucket_size) + 1;
    if (sb.nbuckets < 1 << 7) {
      CACHE_ERRORLOG(NULL, "not have enough buckets: %ju, need %u\n",
                                sb.nbuckets, 1 << 7);
      assert("not have enough buckets"==0);
    }
    SET_CACHE_DISCARD(&sb, discard);
    SET_CACHE_REPLACEMENT(&sb, cache_replacement_policy);
    CACHE_INFOLOG(NULL, "\nUUID:			%s\n"
                        "Set UUID:		%s\n"
                        "version:		%u\n"
                        "nbuckets:		%ju\n"
                        "block_size:		%u\n"
                        "bucket_size:		%u\n"
                        "nr_in_set:		%u\n"
                        "nr_this_dev:		%u\n"
                        "first_bucket:		%u\n",
                        uuid_str, set_uuid_str,
                        (unsigned) sb.version,
                        sb.nbuckets,
                        sb.block_size,
                        sb.bucket_size,
                        sb.nr_in_set,
                        sb.nr_this_dev,
                        sb.first_bucket);
  }
  sb.csum = csum_set(&sb);
  /* Zero start of disk */
  if (pwrite(fd, zeroes, SB_START, 0) != SB_START) {
    CACHE_ERRORLOG(NULL, "write zeroes super from SB_START %u error \n", SB_START);
    assert("write zeroes super from SB_START got error" == 0);
  }
  /* Write superblock */
  if (pwrite(fd, &sb, sizeof(sb), SB_START) != sizeof(sb)) {
    CACHE_ERRORLOG(NULL, "write super from SB_START %u error \n", SB_START);
    assert("write super from SB_START got error" == 0);
  }

  if (fsync(fd) < 0) {
    CACHE_ERRORLOG(NULL, "sync superblock data failed");
    ret = -errno;
  }
  close(fd);

  return ret;
}

void t2ce_set_iobypass_size(struct cache *ca, int sequential_cutoff)
{
  ca->set->dc->sequential_cutoff = sequential_cutoff << 10;
}

