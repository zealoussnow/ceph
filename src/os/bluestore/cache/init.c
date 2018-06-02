

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#define __USE_GNU 1 
#include <fcntl.h>
#include <libaio.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <blkid/blkid.h>

#include <limits.h>

#include "bcache.h"
#include "btree.h"
#include "atomic.h"
#include "request.h"
#include <math.h>
#include "writeback.h"

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>




#include "aio.h"
#include "log.h"

/*struct cache_set bch_cache_sets;*/
LIST_HEAD(bch_cache_sets);
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
    perror("stat error\n");
    exit(EXIT_FAILURE);
  }
#define BLKGETSIZE _IO(0x12,96) /* return device size /512 (long *arg) */
  ret = statbuf.st_size / 512;
  if (S_ISBLK(statbuf.st_mode))
    if (ioctl(fd, BLKGETSIZE, &ret)) {
      perror("ioctl error");
      exit(EXIT_FAILURE);
  }
  CACHE_DEBUGLOG(NULL,"getblocks %u \n", ret);
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
    CACHE_DEBUGLOG(CAT_WRITE,"Prio io write fd %d start 0x%x len %x (bucket %u) \n", 
                                ca->fd, start, len, bucket);
    if ( sync_write(ca->fd, ca->disk_buckets, len, start) == -1){
      CACHE_ERRORLOG(CAT_WRITE, "Prio io write error \n");
      exit(1);
    }
  }
  if ( op == REQ_OP_READ ) {
    CACHE_DEBUGLOG(CAT_WRITE,"Prio io read fd %d start 0x%x len %x (bucket %u) \n", 
                                ca->fd, start, len, bucket);
    if ( sync_read(ca->fd, ca->disk_buckets, len, start ) == -1 ) {
      CACHE_ERRORLOG(CAT_WRITE, "Prio io read error \n");
      exit(1);
    }
  }

  // 这部分IO有必要进行异步写入吗？后期可以好好考虑下
  // 如果被设计成异步的形式，则需要有一个写完成回调

  /*closure_init_stack(cl);*/

  /*bio->bi_iter.bi_sector	= bucket * ca->sb.bucket_size;*/
  /*bio_set_dev(bio, ca->bdev);*/
  /*bio->bi_iter.bi_size	= bucket_bytes(ca);*/

  /*bio->bi_end_io	= prio_endio;*/
  /*bio->bi_private = ca;*/

  /* 设置IO属性，被弃用，以后不要使用了 */
  /*bio_set_op_attrs(bio, op, REQ_SYNC|REQ_META|op_flags);*/

  /*bch_bio_map(bio, ca->disk_buckets);*/

  /*closure_bio_submit(bio, &ca->prio);*/
  /*closure_sync(cl);*/
}

static void prio_read(struct cache *ca, uint64_t bucket)
{
  CACHE_INFOLOG(NULL,"prio read \n");
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
        CACHE_ERRORLOG(CAT_READ,"check csum error \n");
      }
      if (p->magic != pset_magic(&ca->sb)) {
        CACHE_ERRORLOG(CAT_READ,"check prio_set magic error \n");
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
  struct closure cl;
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
  
  if (memcmp(sb->magic, bcache_magic, 16)) {
    goto err;
  }
  
  err = "Too many journal buckets";
  if (sb->keys > SB_JOURNAL_BUCKETS) {
    goto err;
  }
  /*err = "Bad checksum";*/
  /*if (s->csum != csum_set(s))*/
  /*goto err;*/
  /*err = "Bad UUID";*/
  /*if (bch_is_zero(sb->uuid, 16))*/
  /*goto err;*/
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
      /*err = "Invalid superblock: device too small";*/
      /*if (get_capacity(bdev->bd_disk) < sb->bucket_size * sb->nbuckets)*/
      /*goto err;*/
      err = "Bad UUID";
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

#define alloc_bucket_pages(c)			\
	((void *) T2Molloc(bucket_pages(c)*PAGE_SIZE))

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
        !(ca->disk_buckets	= alloc_bucket_pages(ca))) {
    return -ENOMEM;
  }
  /*printf(" init  &ca->free[RESERVE_PRIO].size=%d\n", fifo_free(&ca->free[RESERVE_PRIO]));*/
  // prio_buckets(ca)算出prio io需要的bucket个数，记录下最后一个bucket
  // 1. prios_per_bucket(c)先算出每个bucket能放下多少prio，即放下多少个bucket_disk
  // 2. 然后再拿全部的bucket去向上取整，看下全部的bucket的bucket_disk需要多少个prio bucket
  // 每个bucket，能够放下174749个bucket_disk
  ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);
  
  for_each_bucket(b, ca)
  atomic_set(&b->pin, 0);
  return 0;
}

struct cache_set *
bch_cache_set_alloc(struct cache_sb *sb)
{
  int iter_size;
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
  c->nr_uuids		= bucket_bytes(c) / sizeof(struct uuid_entry); /* 4096 */
  
  c->btree_pages		= bucket_pages(c); /* 1024/8 = 128 */
  if (c->btree_pages > BTREE_MAX_PAGES) {
    c->btree_pages = max_t(int, c->btree_pages / 4,
                BTREE_MAX_PAGES);
  }
  CACHE_INFOLOG(NULL, "block_size %u(sectors) bits=%u \n", c->sb.block_size, c->block_bits);
  CACHE_INFOLOG(NULL, "bucket_size %u(sectors) bits=%u \n", c->sb.bucket_size, c->bucket_bits);
  CACHE_INFOLOG(NULL, "nr_in_set %u \n", c->sb.nr_in_set);
  CACHE_INFOLOG(NULL, "btree_pages %u \n", c->btree_pages);
  
  /*sema_init(&c->sb_write_mutex, 1);*/
  pthread_mutex_init(&c->bucket_lock, NULL);
  /*init_waitqueue_head(&c->btree_cache_wait);*/
  /*init_waitqueue_head(&c->bucket_wait);*/
  /*init_waitqueue_head(&c->gc_wait);*/
  /*sema_init(&c->uuid_write_mutex, 1);*/
  
  /*spin_lock_init(&c->btree_gc_time.lock);*/
  /*spin_lock_init(&c->btree_split_time.lock);*/
  /*spin_lock_init(&c->btree_read_time.lock);*/
  pthread_spin_init(&c->btree_gc_time.lock,0);
  pthread_spin_init(&c->btree_split_time.lock,0);
  pthread_spin_init(&c->btree_read_time.lock,0);
  /*bch_moving_init_cache_set(c);*/

  INIT_LIST_HEAD(&c->list);
  INIT_LIST_HEAD(&c->cached_devs);
  INIT_LIST_HEAD(&c->btree_cache);
  INIT_LIST_HEAD(&c->btree_cache_freeable);
  INIT_LIST_HEAD(&c->btree_cache_freed);
  INIT_LIST_HEAD(&c->data_buckets);
  /*c->search = mempool_create_slab_pool(32, bch_search_cache);*/
  /*if (!c->search)*/
  /*goto err;*/
  iter_size = (sb->bucket_size / sb->block_size + 1) *
        sizeof(struct btree_iter_set);

  /* XXX devices是一个二级指针 */
  // bch_btree_cache_alloc(c) btree 节点链表freeable、freed
  // 此处遗留
  // 1. fill_iter
  // 2. journal
  // 3. bset_sort_state
  // 4. moving_gc_wq
  if (!(c->devices = T2Molloc(c->nr_uuids * sizeof(void *))) ||
                        !(c->uuids = alloc_bucket_pages(c)) ||
                        bch_journal_alloc(c) ||
                        bch_btree_cache_alloc(c) ||
                        bch_open_buckets_alloc(c) ||
          bch_bset_sort_state_init(&c->sort, ilog2(c->btree_pages))) {
    goto err;
  }
  
  c->congested_read_threshold_us	= 2000;
  c->congested_write_threshold_us	= 20000;
  c->error_limit	= 8 << IO_ERROR_SHIFT;  /* IO_ERROR_SHIFT=20, 8MB */
  
  return c;
err:
  bch_cache_set_unregister(c);
  return NULL;
}

static void 
__write_super(struct cache *c)
{
  struct cache_sb *sb = &c->sb;
  unsigned i;
  off_t start = SB_START;
  size_t len = SB_SIZE;
  sb->csum = csum_set(sb);
  /* 提交bio给块设备层 block/blk-core.c */
  /*submit_bio(bio);*/
  /*printf(" main.c FUN %s: Write super fd=%d,start=0x%x,len=%d\n",__func__,c->fd,start,len);*/
  CACHE_INFOLOG(CAT_WRITE,"write super fd %d start 0x%x len %d\n",
                        c->fd, start, len);
  if (sync_write(c->fd, sb, len, start) == -1) {
    CACHE_ERRORLOG(CAT_WRITE,"write super error \n");
    exit(1);
  }
}


void 
bcache_write_super(struct cache_set *c)
{
  /*struct closure *cl = &c->sb_write;*/
  struct cache *ca;
  unsigned i;

  /*down(&c->sb_write_mutex);*/
  /*closure_init(cl, &c->cl);*/

  c->sb.seq++;

  for_each_cache(ca, c, i) {
    /*struct bio *bio = &ca->sb_bio;*/

    ca->sb.version		= BCACHE_SB_VERSION_CDEV_WITH_UUID;
    ca->sb.seq		= c->sb.seq;
    ca->sb.last_mount	= c->sb.last_mount;

    SET_CACHE_SYNC(&ca->sb, CACHE_SYNC(&c->sb));
    CACHE_INFOLOG(NULL, "write super version %lu seq %lu  last_mount %u sync %d \n",
        ca->sb.version, ca->sb.seq, ca->sb.last_mount, CACHE_SYNC(&c->sb));
    __write_super(ca);
  }
  /*bcache_write_super_unlock*/
  /*closure_return_with_destructor(cl, bcache_write_super_unlock);*/
}



static void 
uuid_io(struct cache_set *c, int op, unsigned long op_flags,
		    struct bkey *k, struct closure *parent)
{
  struct uuid_entry *u;
  unsigned i;
  char buf[80];
  off_t start = PTR_OFFSET(k, 0) << 9; // bucket_number * bucket_size
  size_t len = KEY_SIZE(k) << 9;
  // buf = c->uuids
  if ( op == REQ_OP_WRITE ) {
    if ( sync_write(c->fd, c->uuids, len , start) == -1 ) {
      CACHE_ERRORLOG(CAT_WRITE,"write uuid error \n");
      exit(-1);
    }
  }
  if ( op == REQ_OP_READ ) {
    /*printf(" main.c FUN %s: Read fd=%d,start=0x%x,len=%d\n",__func__,c->fd,start,len);*/
    if ( sync_read(c->fd, c->uuids, len , start) == -1 ) {
      CACHE_ERRORLOG(CAT_WRITE,"read uuid error \n");
      exit(-1);
    }
  }
  //BUG_ON(!parent);
  /*down(&c->uuid_write_mutex);*/
  /*closure_init(cl, parent);*/
  bch_extent_to_text(buf, sizeof(buf), k);
  /*pr_debug("%s UUIDs at %s", op == REQ_OP_WRITE ? "wrote" : "read", buf);*/
  /*printf("%s UUIDs at %s \n", op == REQ_OP_WRITE ? "wrote" : "read", buf);*/
  /*printf(" c->nr_uuids = %d \n", c->nr_uuids);*/
  for (u = c->uuids; u < c->uuids + c->nr_uuids; u++) {
    if (!bch_is_zero(u->uuid, 16)) {
      CACHE_INFOLOG(NULL, "uuid io Slot %zi: %pU: %s: 1st: %u last: %u inv: %u \n",
                                 u - c->uuids, u->uuid, u->label,
                                 u->first_reg, u->last_reg, u->invalidated);
    }
  }
  /*closure_return_with_destructor(cl, uuid_io_unlock);*/
}

static char *uuid_read(struct cache_set *c, struct jset *j)//, struct closure *cl)
{
  struct bkey *k = &j->uuid_bucket;
  if (__bch_btree_ptr_invalid(c, k)) {
    return "bad uuid pointer";
  }
  bkey_copy(&c->uuid_bucket, k);
  uuid_io(c, REQ_OP_READ, 0, k, NULL);
  if (j->version < BCACHE_JSET_VERSION_UUIDv1) {
    struct uuid_entry_v0	*u0 = (void *) c->uuids;
    struct uuid_entry	*u1 = (void *) c->uuids;
    int i;

    /*closure_sync(cl);*/
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
  struct closure cl;
  
  CACHE_DEBUGLOG(NULL, "write uuid internal\n"); 
  /*lockdep_assert_held(&bch_register_lock);*/
  if (bch_bucket_alloc_set(c, RESERVE_BTREE, &k.key, 1, true))
    return 1;
  
  SET_KEY_SIZE(&k.key, c->sb.bucket_size);
  uuid_io(c, REQ_OP_WRITE, 0, &k.key, &cl);
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

static bool 
can_attach_cache(struct cache *ca, struct cache_set *c)
{
  return ca->sb.block_size == c->sb.block_size &&
            ca->sb.bucket_size == c->sb.bucket_size &&
                    ca->sb.nr_in_set == c->sb.nr_in_set;
}


static void 
run_cache_set(struct cache_set *c)
{
  const char *err = "cannot allocate memory";
  /*struct cached_dev *dc, *t;*/
  struct cache *ca;
  struct closure cl;
  unsigned i;
  for_each_cache(ca, c, i) {
    c->nbuckets += ca->sb.nbuckets;
  }
  set_gc_sectors(c);
  if (CACHE_SYNC(&c->sb)) {
    CACHE_INFOLOG(NULL,"have sync run cache set from super \n");
    LIST_HEAD(journal);
    struct bkey *k;
    struct jset *j;
    unsigned iter;
    for_each_cache(ca, c, iter) {
      struct journal_device *ja = &ca->journal;
      /*memset(ja->seq, 0, ca->sb.njournal_buckets * sizeof(uint64_t));*/
    }
    err = "cannot allocate memory for journal";
    CACHE_INFOLOG(NULL,"journal read \n");
    if (bch_journal_read(c, &journal)) {
      goto err;
    }
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
    /*pthread_rwlock_unlock(&c->root->lock);*/
    err = uuid_read(c, j);//, &cl);
    if (err) {
      goto err;
    }
    err = "error in recovery";
    if (bch_btree_check(c)) {
      goto err;
    }
    bch_journal_mark(c, &journal);
    bch_initial_gc_finish(c);
    /*pr_debug("btree_check() done");*/
    /*printf("btree_check() done \n");*/

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
    if (j->version < BCACHE_JSET_VERSION_UUID) {
            __uuid_write(c);
    }

    bch_journal_replay(c, &journal);
  } else {
    CACHE_INFOLOG(NULL,"not have sync run cache set from init \n");
    for_each_cache(ca, c, i) {
      unsigned j;
      ca->sb.keys = clamp_t(int, ca->sb.nbuckets >> 7, 2, SB_JOURNAL_BUCKETS);
      for (j = 0; j < ca->sb.keys; j++) {
        ca->sb.d[j] = ca->sb.first_bucket + j;
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
    err = "cannot allocate new UUID bucket";
    if (__uuid_write(c)) {
      goto err;
    }
    /*err = "cannot allocate new btree root";*/
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

  /*closure_sync(&cl);*/
  time_t now;
  time(&now);
  c->sb.last_mount = now;
  // 测试临时想关闭
  bcache_write_super(c);
  set_bit(CACHE_SET_RUNNING, &c->flags);

  return;
err:
  CACHE_ERRORLOG(NULL, "run cache error\n");
  assert(" run cache error" == 0);
  /*bch_cache_set_error(c, "%s", err);*/
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

  for (io = dc->io; io < dc->io + RECENT_IO; io++) {
    list_add(&io->lru, &dc->io_lru);
    hlist_add_head(&io->hash, dc->io_hash + RECENT_IO);
  }
  dc->sequential_cutoff = 4 << 20;

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
found:
  sprintf(buf, "cache%i", ca->sb.nr_this_dev);
  
  CACHE_INFOLOG(NULL,"register cache seq %llu, cache set seq %llu \n",ca->sb.seq, c->sb.seq);
  if (ca->sb.seq > c->sb.seq) {
    c->sb.version		= ca->sb.version;
    memcpy(c->sb.set_uuid, ca->sb.set_uuid, 16);
    c->sb.flags             = ca->sb.flags;
    c->sb.seq		= ca->sb.seq;
    /*pr_debug("set version = %llu", c->sb.version);*/
    CACHE_DEBUGLOG(NULL, "cache set version = %llu", c->sb.version);
  }

  ca->set = c;
  ca->set->cache[ca->sb.nr_this_dev] = ca;
  c->cache_by_alloc[c->caches_loaded++] = ca;
  ca->set->fd = ca->fd;
  ca->set->hdd_fd = ca->hdd_fd;

  c->dc = calloc(1, sizeof(struct cached_dev));
  memcpy(&c->dc->sb, &c->sb, sizeof(struct cache_sb));
  c->dc->c = c;
  cached_dev_init(c->dc);
  CACHE_DEBUGLOG(NULL, "cache_set caches_loaded=%d super nr_in_set=%u\n",__func__,c->caches_loaded,c->sb.nr_in_set);
  if (c->caches_loaded == c->sb.nr_in_set) {
    run_cache_set(c);
  }

  return NULL;
err:
  bch_cache_set_unregister(c);
  return err;
}


static int _register_cache(struct cache_sb *sb, struct cache *ca)
{
  /*char name[BDEVNAME_SIZE];*/
  const char *err = NULL; /* must be set for any error case */
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
  SET_KEY_INODE(k, 1);
  SET_KEY_OFFSET(k, 500);
  bch_alloc_sectors(c->set, k, 10, 0,0,1);
  printf(" KEY_SIZE(k) = %d \n", KEY_SIZE(k));
}


int 
bch_data_insert_keys(struct cache_set *c_set,
                struct keylist *insert_keys)
{
  atomic_t *journal_ref = NULL;
  struct bkey *replace_key = NULL;
  int ret;

  journal_ref = bch_journal(c_set, insert_keys);
  if (!journal_ref) {
    return ;
  }

  ret = bch_btree_insert(c_set, insert_keys, NULL, replace_key);

  if (ret != 0) {
    CACHE_ERRORLOG(CAT_BTREE,"Keylist Insert error ret=%d\n", ret);
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
  unsigned ptr;
  struct bkey *bio_key;


  struct search *s = container_of(op, struct search, op);
  if (s) {
    start = s->offset;
  } else {
    return MAP_DONE;
  }

  if (bkey_cmp(k, &KEY(1, start, 0)) <= 0) {
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
  struct btree_op op;
  /*uint64_t bi_sector = (off >> 9);*/

  memset(&s, 0, sizeof(struct search));
  bch_btree_op_init(&s.op, -1);
  s.data = data;
  s.pos = data;
  s.offset = (off>>9);
  s.bi_sector = (off >> 9);
  s.length = len;
  s.left = len;

  while ( s.left > 0 ) {
    bch_btree_map_keys(&s.op, ca->set, &KEY(1, s.offset, 0), cache_lookup_fn, MAP_END_KEY);
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
    unsigned i;
    struct bkey *k=NULL;
    /*struct cache_set *c = T2Molloc(sizeof(struct cache_set));*/
    k = insert_keys.top;

    bkey_init(k);
    SET_KEY_INODE(k, 1);
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

  bch_data_insert_keys(ca->set, &insert_keys);

  return ret;
}

int 
traverse_btree_keys_fn(struct btree_op * op, struct btree *b)
{
  CACHE_DEBUGLOG("traverse", ">>>>>> Entry Btree Node(level=%d,offset=%lu,size=%lu) <<<<<<<\n", 
                        b->level, KEY_OFFSET(&b->key), KEY_SIZE(&b->key));
  struct bkey *k, *p = NULL;
  struct btree_iter iter;
  for_each_key(&b->keys, k, &iter) {
    CACHE_DEBUGLOG("traverse", "node(level=%d,of=%lu) bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,diryt=%u) \n",
                        b->level, KEY_OFFSET(&b->key), KEY_OFFSET(k) - KEY_SIZE(k),
                        KEY_OFFSET(k), KEY_SIZE(k), PTR_OFFSET(k,0), KEY_PTRS(k), KEY_DIRTY(k));
  }

  return MAP_CONTINUE;
}

void 
traverse_btree(struct cache * c)
{
  struct btree_insert_op op;
  bch_btree_op_init(&op.op, 0);
  bch_btree_map_nodes(&op.op,c->set,NULL,traverse_btree_keys_fn);
}

int 
init(struct cache * ca)
{
  int fd = ca->fd;
  const char *err = "cannot allocate memory";
  struct cache_sb sb;

  if (pread(fd, &sb, sizeof(struct cache_sb), SB_START) != sizeof(struct cache_sb)) {
   CACHE_ERRORLOG(NULL, "Couldn't read cache device\n");
   exit(2);
  }
  err = read_super(&ca->sb, &sb);
  if (err) {
    goto err_close;
  }

  if (_register_cache(&sb, ca) != 0) {
    goto err_close;
  }
  pthread_cond_signal(&ca->alloc_cond);

  
  /*bch_cached_dev_writeback_start(ca->set->dc);*/
  /*bch_sectors_dirty_init(ca->set->dc);*/
  /*atomic_set(&ca->set->dc->has_dirty, 1);*/
  /*atomic_inc(&ca->set->dc->count);*/

  bch_moving_init_cache_set(ca->set);
  /*bch_gc_thread_start(ca->set);*/

  ca->handler = aio_init((void *)ca);

  return 0;

err_close:
  CACHE_ERRORLOG(NULL, "cache module init error \n");
  return -1;
}

static int bch_keylist_realloc(struct keylist *l, unsigned u64s,
                               struct cache_set *c)
{
        size_t oldsize = bch_keylist_nkeys(l);
        size_t newsize = oldsize + u64s;

        /*
         * The journalling code doesn't handle the case where the keys to insert
         * is bigger than an empty write: If we just return -ENOMEM here,
         * bio_insert() and bio_invalidate() will insert the keys created so far
         * and finish the rest when the keylist is empty.
         */
        if (newsize * sizeof(uint64_t) > block_bytes(c) - sizeof(struct jset))
                return -ENOMEM;

        return __bch_keylist_realloc(l, u64s);
}

struct bkey *
get_init_bkey(struct keylist *keylist, uint64_t offset, struct cache *ca)
{
  struct bkey *k = NULL;

  if (bch_keylist_realloc(keylist, 3, ca->set)) {
    assert("no memory" == 0);
  }

  k = keylist->top;

  if ( k ) {
    bkey_init(k);
    SET_KEY_INODE(k, 1);
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
    goto free_keylist;
    assert ( " keylist is not enough, need realloc " == 0);
  }

  if ( dirty ) {
    SET_KEY_DIRTY(k, true);
  }

  uint64_t left = item->o_len - item->io.len;
  ret = bch_alloc_sectors(ca->set, k,(left >> 9), 0, 0, 1);
  if ( ret < 0 ) {
    assert(" alloc sectors faild " == 0);
  }
  item->io.pos = item->io.pos + item->io.len;
  item->io.offset = (PTR_OFFSET(k, 0) << 9);
  item->io.len = (KEY_SIZE(k)<<9);

  bch_keylist_push(item->insert_keys);

  return ret;
free_keylist:
  free(item->insert_keys);
  return -1;
}

// 对于写来说，不管ssd还是hdd，都是要把所有的io写完才能
// 返回，唯一需要注意的就是writethrough策略
// 对于writethrough策略，先发给hdd进行写入，hdd写完成
// 再发给ssd进行写（需要改变item->io，已经enquene到ssd的线程池即可
void *
aio_write_completion(void *cb)
{
  struct ring_item *item = cb;
  struct cache *ca = item->ca_handler;
  int ret = 0;

  if ( ! item->io.success ) {
    assert(" Aio completion, io not Sucessfull " == 0);
  }

  if (( item->data + item->o_len ) == ( item->io.pos + item->io.len )) {
    /*printf("<%s> AIO IO(start=%lu(0x%lx),len=%lu(0x%lx)) Completion success=%d\n", */
                /*__func__, item->o_offset/512, item->o_offset, item->o_len/512,*/
                /*item->o_len, item->io.success);*/
    CACHE_DEBUGLOG(CAT_AIO_WRITE,"AIO IO(start=%lu(0x%lx),len=%lu(0x%lx)) Completion success=%d\n", 
                item->o_offset/512, item->o_offset, item->o_len/512,
                item->o_len, item->io.success);
    switch (item->strategy) {
      case CACHE_MODE_WRITEAROUND:
        ret = bch_data_insert_keys(ca->set, item->insert_keys);
        break;
      case CACHE_MODE_WRITETHROUGH:
        // write through 写完hhd之后，开始写ssd
        // 如果是write through写ssd完成，则插入btree
        if ( !item->write_through_done) {
          // 将io_u重制到初始化状态
          item->write_through_done = true;
          item->io.pos = item->data;
          item->io.offset = item->o_offset;
          item->io.len = 0;
          // write through的bkey不需要设置dirty=true
          if (!item_write_next(item, false)) {
            assert(" item init failed " == 0);
          }
          ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
          if ( ret < 0) {
              assert(" test aio enqueue faild " == 0);
          }
          return ;
        } else {
          ret = bch_data_insert_keys(ca->set, item->insert_keys);
          break;
        }
      case CACHE_MODE_WRITEBACK:
        ret = bch_data_insert_keys(ca->set, item->insert_keys);
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
    if ( ret!=0 ) {
      // choice 1
      CACHE_ERRORLOG(NULL,"Insert btree error %d\n", ret);
      assert("Insert btree error"==0);
    } else if( item->io_completion_cb ) {
      // choice 2
      // item->io_completion_cb(item->io_arg, ret); 
      item->io_completion_cb(item->io_arg); 
    } else {
      /*printf("<%s>: No io_completion_cb for IO(star=%lu(0x%lx),len=%lu(0x%lx))\n",*/
                /*__func__, item->o_offset/512, item->o_offset, item->o_len/512,item->o_len);*/
      CACHE_WARNLOG(NULL, "No io_completion_cb for IO(star=%lu(0x%lx),len=%lu(0x%lx))\n",
                item->o_offset/512, item->o_offset, item->o_len/512,item->o_len);

    }
    free(item->insert_keys);
    free(item);
  } else {
    /*printf(" ********** write rest io *********88 \n");*/
    item_write_next(item, true);
    // re enqueue
    ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
    if (ret < 0) {
      assert(" test aio enqueue faild " == 0);
    }
  }
}

int cache_invalidate_region(struct cache *ca, uint64_t offset, uint64_t len)
{
  /*printf("<%s>: Invalidate region(start=%lu/0x%lx,len=%lu,0x%lx) \n",*/
                        /*__func__, offset/512,offset,len/512,len);*/

  CACHE_DEBUGLOG(NULL,"Invalidate region(start=%lu/0x%lx,len=%lu,0x%lx) \n",
                        offset/512,offset,len/512,len);
  int ret = 0;
  struct keylist *insert_keys = NULL;
  struct bkey *k = NULL;

  insert_keys = calloc(1, sizeof(*insert_keys));
  if ( !insert_keys ) {
    goto err;
  }
  bch_keylist_init(insert_keys);

  k = get_init_bkey(insert_keys, offset, ca);
  if ( !k ) {
    ret = -1;
    goto free_keylist;
  }

  SET_KEY_OFFSET(k, KEY_OFFSET(k) + (len >> 9));
  SET_KEY_SIZE(k, (len >> 9));
  bch_keylist_push(insert_keys);

  ret = bch_data_insert_keys(ca->set, insert_keys);
  if ( ret !=0 ) {
    CACHE_DEBUGLOG(NULL,"Invalidate region(start=%lu/0x%lx,len=%lu,0x%lx) ERROR.\n",
                        offset/512,offset,len/512,len);
    assert("Invaliedate region error"==0);
  }

  ret = 0;

free_keylist:
  free(insert_keys);
err:
  return ret;
}

int
do_write_writearound(struct ring_item * item)
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
  /*k = insert_keys->top;*/
  /*bkey_init(k);*/
  /*SET_KEY_INODE(k, 1);*/
  /*SET_KEY_OFFSET(k, (item->o_offset>>9));*/
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

  bch_keylist_push(insert_keys);
  item->insert_keys = insert_keys;

  ret = aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item);

  if (ret < 0) {
    assert( "test aio_enqueue error  " == 0);
  }

  return ret;
free_keylist:
  free(insert_keys);
err:
  return -1;
}

int 
do_write_writeback(struct ring_item * item)
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
    /*assert(" keylist is not enough, need realloc " == 0);*/
  }

  ret = bch_alloc_sectors(ca->set, k, (item->o_len >> 9), 0, 0, 1);

  SET_KEY_DIRTY(k, true);
  item->io.pos = item->data;
  item->io.offset = (PTR_OFFSET(k, 0) << 9);
  item->io.len = (KEY_SIZE(k)<<9);
  item->iou_arg = item;
  item->iou_completion_cb = aio_write_completion;

  bch_keylist_push(insert_keys);
  item->insert_keys = insert_keys;

  ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);

  if (ret < 0) {
    assert( "test aio_enqueue error  " == 0);
  }

  return ret;
free_keylist:
  free(insert_keys);
err:
  return -1;
}

int 
do_write_writethrough(struct ring_item * item)
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

  item->io.pos = item->data;
  item->io.offset = item->o_offset;
  item->io.len = item->o_len;
  item->iou_arg = item;
  item->iou_completion_cb = aio_write_completion;
  item->insert_keys = insert_keys;

  ret = aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item);

  if (ret < 0) {
    assert( "test aio_enqueue error  " == 0);
  }

  return ret;
err:
  return -1;
}

static void add_sequential(struct current_thread *t)
{
  ewma_add(t->sequential_io_avg,
           t->sequential_io, 8, 0);
  
  t->sequential_io = 0;
}

#define GOLDEN_RATIO_64 0x61C8864680B583EBull
static inline hash_64(uint64_t val, unsigned int bits)
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

  if (c->gc_stats.in_use > CUTOFF_CACHE_ADD)
    goto skip;

  if (mode == CACHE_MODE_NONE || mode == CACHE_MODE_WRITEAROUND)
    goto skip;

  if ((item->o_offset >> 9) & (c->sb.block_size -1) ||
      (item->o_len >> 9) & (c->sb.block_size -1)) {
    printf("skipping unaligned io\n");
    goto skip;
  }

  if (bypass_torture_test(dc))
    if ((get_random_int() & 3) == 3)
      goto skip;

  list_for_each_entry(task, &dc->io_thread, list) {
    /*printf("task->thread_id = %ld\n", task->thread_id);*/
    if (task->thread_id == pthread_self())
      goto out;
  }

  task = malloc(sizeof(struct current_thread));
  task->thread_id = pthread_self();
  list_add_tail(&task->list, &dc->io_thread);

out:
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


  sectors = max(task->sequential_io,
      task->sequential_io_avg) >> 9;

  if (dc->sequential_cutoff &&
      sectors >= dc->sequential_cutoff >> 9) {
    goto skip;
  }
  return false;
skip:
  return true;
}

int get_cache_strategy(struct cached_dev *dc, struct ring_item *item)
{
  unsigned int mode = BDEV_CACHE_MODE(&dc->sb);
  struct bkey start = KEY(1, item->o_offset >> 9, 0);
  struct bkey end = KEY(1, (item->o_offset >> 9) + (item->o_len >> 9), 0);

  bch_keybuf_check_overlapping(&dc->c->moving_gc_keys, &start, &end);

  if (bch_keybuf_check_overlapping(&dc->writeback_keys, &start, &end))
    return CACHE_MODE_WRITEBACK;

  if (check_should_bypass(dc, item))
    return CACHE_MODE_WRITEAROUND;

  return mode;
}

int cache_aio_write(struct cache*ca, void *data, uint64_t offset, uint64_t len, void *cb, void *cb_arg)
{
  CACHE_DEBUGLOG("write","IO(start=%lu(0x%lx),len=%lu(%lx)) \n", offset/512, offset, len/512, len);
  struct ring_item *item = NULL;
  int ret=0;
  struct cached_dev *dc = ca->set->dc;

  item = get_ring_item(data, offset, len);
  if ( !item ) {
    goto err;
  }
  item->io_completion_cb = cb;
  item->io_arg = cb_arg;

  /*item->strategy = get_cache_strategy(dc, item);*/
  /**********   策略相关的代码 ******************/
  // 进行一些列判断，最终得到本次io的写入策略
  // 1. should bypass
  // 2. should writeback
  /***********************************************/

  item->strategy = CACHE_MODE_WRITEBACK;
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

  posix_memalign((void **)&data, 512, len);
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
    item->io.pos = read_data + (cache_offset - read_offset);
  }
  
  if (cache_end < read_end) {
    item->io.len -= (read_end - cache_end);
  } else {
    // hit the end
    ret = 1;
  }

  return ret;
}

void 
aio_read_completion(struct ring_item *item)
{
  struct cache *ca = item->ca_handler;
  /*printf("<%s>: All read complete. \n", __func__);*/

  // call callback function
  if (item->io_completion_cb) {
    item->io_completion_cb(item->io_arg);
  }

  // TODO: Let the user decide whether to write to the cache.
  // write data to cache
  if (atomic_read(&item->need_write_cache)) {
    // 这里需要有一个回调来确认读出来的数据正确的写入到SSD,暂时设置成NULL
    cache_aio_write(ca, item->data, item->o_offset, item->o_len, NULL, NULL);
  }
  free(item);
}

void 
read_cache_look_done(struct ring_item *item) {
  /*printf("<%s>: MAP_DONE \n", __func__);*/
  // set a tag for read aio push complete.
  atomic_dec(&item->seq);
  /*printf("<%s>: All data complete. seq=%d \n",*/
              /*__func__, atomic_read(&item->seq));*/
  if (atomic_read(&item->seq) == 0 ) {
    aio_read_completion(item);
  }
}

int 
read_cache_lookup_fn(struct btree_op * op, struct btree *b,
						 struct bkey *key)
{
  struct search *s = container_of(op, struct search, op);
  struct ring_item *item = s->item;
  struct cache *ca = item->ca_handler;
  int io_ret, is_end;
  uint64_t offset = item->o_offset >> 9;
  uint64_t end = offset + (item->o_len >> 9);
  
  /*printf("<%s>: btree node(level=%d,offset=%lu) bkey offset=%lu,size=%lu,dirty=%lu\n",*/
      /*__func__,b->level,KEY_OFFSET(&b->key),KEY_OFFSET(key),KEY_SIZE(key),KEY_DIRTY(key));*/
  // bkey is before of data
   if (KEY_OFFSET(key)  < offset) {
     return MAP_CONTINUE;
   }
   // bkey is after of data
   else if (KEY_OFFSET(key) - KEY_SIZE(key) > end) {
     read_cache_look_done(item);
     return MAP_DONE;
   }
   // todo: set a flag to switch read DIRTY
   // if full in cache, wo need to read undirty
   // if not full in cache, wo not need to read undirty
   else if (KEY_SIZE(key) && KEY_PTRS(key)) { // bkey in data*/
     /*printf("<%s>: find bkey offset=%lu,size=%lu \n",*/
         /*__func__,KEY_OFFSET(key),KEY_SIZE(key));*/
     is_end = set_item_io(item, key);
     atomic_inc(&item->seq);
     // read ssd
     /*printf("<%s>: aio_enqueue cache \n", __func__);*/
     io_ret = aio_enqueue(CACHE_THREAD_CACHE, ca->handler, item);
     if (io_ret < 0) {
       assert( "test aio_enqueue error  " == 0);
     }
     if (is_end) {
       read_cache_look_done(item);
       return MAP_DONE;
     }
   }
   return MAP_CONTINUE;
}

void aio_read_cache_completion(void *cb)
{
  struct ring_item *item = cb;
  struct cache *ca = item->ca_handler;
  atomic_dec(&item->seq);
  if (atomic_read(&item->seq)) {
    /*printf("<%s>: Wait for (%d) cache complete. \n",*/
                        /*__func__, atomic_read(&item->seq));*/
  } else {
    /*printf("<%s>: All cache complete. \n", __func__);*/
    aio_read_completion(cb);
  }
}

void 
aio_read_backend_completion(void *cb)
{
  struct ring_item *item = cb;
  struct cache *ca = item->ca_handler;
  struct search s;
  
  item->iou_completion_cb = aio_read_cache_completion;
  atomic_set(&item->seq, 1);
  s.item = item;
  bch_btree_op_init(&s.op, -1);
  /*printf("<%s>: find btree node offset=%lu, len=%lu ------------------\n",*/
                        /*__func__, item->o_offset, item->o_len );*/
  bch_btree_map_keys(&s.op, ca->set, &KEY(1,(s.item->o_offset >> 9),0),
                        read_cache_lookup_fn, MAP_END_KEY);
}


void 
cache_aio_read_backend(struct ring_item *item)
{
  int ret = 0;
  struct cache *ca = item->ca_handler;

  item->io.offset = item->o_offset;
  item->io.pos = item->data;
  item->io.len = item->o_len;
  item->iou_completion_cb = aio_read_backend_completion;

  /*printf("<%s>: aio_enqueue backend \n", __func__);*/
  // read hdd first
  ret = aio_enqueue(CACHE_THREAD_BACKEND, ca->handler, item);
  if (ret < 0) {
    assert( "test aio_enqueue error  " == 0);
  }
}

int 
read_is_all_cache_fn(struct btree_op * op, struct btree *b,
                         struct bkey *key)
{
  struct search *s = container_of(op, struct search, op);
  struct ring_item *item = s->item;
  uint64_t cache_start = (KEY_OFFSET(key) - KEY_SIZE(key)) << 9;
  uint64_t cache_end = KEY_OFFSET(key) << 9;
  uint64_t cache_len = KEY_SIZE(key) << 9;

  CACHE_DEBUGLOG(CAT_READ,"iter bkey(start=%lu,of=%lu,len=%lu)\n",
      (KEY_OFFSET(key) - KEY_SIZE(key)),KEY_OFFSET(key),KEY_SIZE(key));
  // bkey is before of data
  if (cache_end < item->o_offset) {
    return MAP_CONTINUE;
  }
  // bkey is after of data
  // item->io.offset is last hit bkey's end
  else if (cache_start > item->io.offset) {
    // hdd
    CACHE_DEBUGLOG(CAT_READ,"Read: not all data in cache, goto read backend \n");
    atomic_inc(&item->need_write_cache);
    cache_aio_read_backend(item);
    return MAP_DONE;
  }
  // bkey in data
  else if (KEY_SIZE(key) && KEY_PTRS(key)) {
    //pos
    int is_dirty = KEY_DIRTY(key);
    item->io.offset += cache_len - (item->io.offset - cache_start);
    if (item->io.offset >= item->o_offset + item->o_len) {
      // all in ssd
      CACHE_DEBUGLOG(CAT_READ,"Read: all data in cache\n");
      aio_read_backend_completion(item);
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
  CACHE_DEBUGLOG(NULL,"cache_aio_read IO(start=%lu(0x%lx),len=%lu(%lx)) \n", offset/512, offset, len/512, len);
  struct ring_item *item;
  struct search s;
  int ret = 0;

  item = calloc(1, sizeof(*item));
  item->o_len = len;
  item->o_offset = offset;
  item->data = data;
  item->io.offset = offset;
  item->io.type = CACHE_IO_TYPE_READ;
  item->io_completion_cb = io_completion;
  item->io_arg = io_arg;
  item->iou_arg = item;
  item->ca_handler = ca;
  atomic_set(&item->need_write_cache, 0);
  
  s.item = item;
  bch_btree_op_init(&s.op, -1);
  bch_btree_map_keys(&s.op, ca->set, &KEY(1,(s.item->o_offset >> 9),0),
                        read_is_all_cache_fn, MAP_END_KEY);
  return ret;
}

// cache super block
int write_sb(const char *dev, unsigned block_size, unsigned bucket_size,
    bool writeback, bool discard, bool wipe_bcache,
    unsigned cache_replacement_policy,
    uint64_t data_offset, bool bdev)
{
  int ret = 0;
  int fd;
  char uuid_str[40], set_uuid_str[40], zeroes[SB_START] = {0};
  struct cache_sb sb;
  blkid_probe pr;
  uuid_t set_uuid;
  uuid_generate(set_uuid);

  if ((fd = open(dev, O_RDWR|O_EXCL)) == -1) {
    CACHE_ERRORLOG(NULL, "Can't open dev %s: %s\n", dev, strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (pread(fd, &sb, sizeof(sb), SB_START) != sizeof(sb)) {
    CACHE_ERRORLOG(NULL, "pread dev %s: %s\n", dev, strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (!memcmp(sb.magic, bcache_magic, 16) && !wipe_bcache) {
    CACHE_ERRORLOG(NULL, "Already a bcache device on %s, "
        "overwrite with --wipe-bcache\n", dev);
    exit(EXIT_FAILURE);
  }

  if (!(pr = blkid_new_probe())) {
    exit(EXIT_FAILURE);
  }
  if (blkid_probe_set_device(pr, fd, 0, 0)) {
    exit(EXIT_FAILURE);
  }
  /* enable ptable probing; superblock probing is enabled by default */
  if (blkid_probe_enable_partitions(pr, true)) {
    exit(EXIT_FAILURE);
  }
  if (!blkid_do_probe(pr)) {
    /* XXX wipefs doesn't know how to remove partition tables */
    CACHE_ERRORLOG(NULL, "Device %s already has a non-bcache superblock, "
        "remove it using wipefs and wipefs -a\n", dev);
    exit(EXIT_FAILURE);
  }
  memset(&sb, 0, sizeof(struct cache_sb));
  sb.offset	= SB_SECTOR;
  sb.version	= bdev
    ? BCACHE_SB_VERSION_BDEV
    : BCACHE_SB_VERSION_CDEV;
  memcpy(sb.magic, bcache_magic, 16);
  uuid_generate(sb.uuid);
  memcpy(sb.set_uuid, set_uuid, sizeof(sb.set_uuid));
  sb.bucket_size	= bucket_size;
  sb.block_size	= block_size;
  uuid_unparse(sb.uuid, uuid_str);
  uuid_unparse(sb.set_uuid, set_uuid_str);
  if (SB_IS_BDEV(&sb)) {
    SET_BDEV_CACHE_MODE(
        &sb, writeback ? CACHE_MODE_WRITEBACK : CACHE_MODE_WRITETHROUGH);
    if (data_offset != BDEV_DATA_START_DEFAULT) {
      sb.version = BCACHE_SB_VERSION_BDEV_WITH_OFFSET;
      sb.data_offset = data_offset;
    }
    CACHE_INFOLOG(NULL, "UUID:			%s\n"
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
      fprintf(stderr, "Not enough buckets: %ju, need %u\n",
          sb.nbuckets, 1 << 7);
      exit(EXIT_FAILURE);
    }
    SET_CACHE_DISCARD(&sb, discard);
    SET_CACHE_REPLACEMENT(&sb, cache_replacement_policy);
    CACHE_INFOLOG(NULL, "UUID:			%s\n"
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
    perror("write error\n");
    exit(EXIT_FAILURE);
  }
  /* Write superblock */
  if (pwrite(fd, &sb, sizeof(sb), SB_START) != sizeof(sb)) {
    perror("write error\n");
    exit(EXIT_FAILURE);
  }

  return 0;
}

