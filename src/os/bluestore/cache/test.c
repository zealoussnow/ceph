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






void
read_complete_cb(void *arg){
  printf("<%s>: I got the data!\n",__func__);
  printf(" read result =%s \n", arg);
}

void 
aio_read_test(struct cache *ca)
{
  int i;
  uint64_t len = 512*64;
  uint64_t offset[3] = {512*100, 512 * 1039, 512 * 1080};
  void *data = NULL;

  posix_memalign(&data, 512, len);
  for (i = 0; i < 3; ++i) {
    cache_aio_read(ca, data, offset[i], len, read_complete_cb, NULL);
    sleep(3);
  }
  cache_aio_read(ca, data, 512 * 1039, 512*2, read_complete_cb, NULL);
  sleep(1);
  for (i = 0; i < 3; ++i) {
    cache_aio_read(ca, data, offset[i], len, read_complete_cb, NULL);
    sleep(1);
  }
}


void do_write_split_test(struct cache *ca)
{
  void *data = NULL;
  void *read_data = NULL;
  uint64_t len = 512;
  uint64_t offset = 8192;

  posix_memalign((void **)&data, 512, len);
  posix_memalign((void **)&read_data, 512, len);
  memset(data, 'b', len);
  memset(read_data, '0', len);

  /*cache_aio_write(ca, data, offset, len, NULL, NULL);*/
  /*sleep(1);*/
  /*cache_aio_write(ca, data, offset + 2*len, len, NULL, NULL);*/
  // write 512
  int i = 0;
  for (i; i<10; i++ ) {
    cache_aio_write(ca, data, offset+2*i, len, NULL, NULL);
    offset=offset+2*len;
  }
  printf(" ----- \n");
  sleep(10);
  traverse_btree(ca);
  /*sleep(4);*/
  // read 512
  /*cache_aio_read(ca, read_data, offset, len, read_complete_cb, NULL);*/
  // wait writeback
  /*sleep(4);*/
  /*traverse_btree(ca);*/
  // print read result
  /*printf(" read result =%s \n", read_data);*/
}

void do_writeback_test(struct cache *ca)
{
  printf(" ********* start writeback test *********** \n");
  void *data = NULL;
  void *read_data = NULL;
  uint64_t len = 512;
  uint64_t offset = 8192;

  posix_memalign((void **)&data, 512, len);
  posix_memalign((void **)&read_data, 512, len);
  memset(data, 'b', len);
  memset(read_data, '0', len);

  sleep(1);
  // write 512
  int i = 1;
  for ( i = 1; i<1000; i++ ) {
    cache_aio_write(ca, data, offset+1024*i, len*1024, NULL, NULL);
  }
  /*sleep(10);*/
  traverse_btree(ca);
  sleep(2);
  // read 512
  cache_aio_read(ca, read_data, offset + 1024 * 2, len, read_complete_cb, NULL);
  // wait writeback
  /*sleep(4);*/
  printf(" read result =%s \n", read_data);
  for ( i = 1000; i<2000; i++ ) {
    cache_aio_write(ca, data, offset+1024*i, len*1024, NULL, NULL);
  }

  traverse_btree(ca);
  // print read result
  /*printf(" read result =%s \n", read_data);*/
}

void write_complate(void *arg){
  atomic_t *seq = (atomic_t *)arg;
  atomic_dec(seq);
}

void do_writeback_batch_test(struct cache *ca)
{
  printf(" ********* start writeback test *********** \n");
  void *data = NULL;
  void *read_data = NULL;
  uint64_t len = 512;
  uint64_t offset = 8192;
  atomic_t seq;

  aio_thread_init(ca);
  struct ring_items *items = ring_items_alloc(1024);
  struct ring_item *item;

  posix_memalign((void **)&data, 512, len);
  posix_memalign((void **)&read_data, 512, len);
  memset(data, 'b', len);
  memset(read_data, '0', len);
  atomic_set(&seq, 1);

  sleep(1);
  // write 512
  int i, j;
  for (j = 0; j < 100; j++){
    for ( i = 1; i<100; i++ ) {
      //cache_aio_write(ca, data, offset+1024*i, len*1024, NULL, NULL);
      item = get_ring_item(data, offset+1024*i, len);
      item->strategy = get_cache_strategy(ca, item);
      item->io_completion_cb = write_complate;
      item->io_arg = &seq;
      ring_items_add(items, item);
      atomic_inc(&seq);
      usleep(1);
    }
    cache_aio_writeback_batch(ca, items);
    ring_items_reset(items);
  }
  ring_items_free(items);

  atomic_dec(&seq);
  if (!atomic_read(&seq)){
    sleep(1);
  }
  printf("write success\n");
}

void *start_do_writeback_batch(void *arg){
  struct cache *ca = arg;
  do_writeback_batch_test(ca);
}


void do_invalidate_region_test(struct cache *ca)
{
  printf(" ********* start invalidate_region test *********** \n");
  void *data = NULL;
  uint64_t len = 512*1024;
  uint64_t offset = 8192;

  posix_memalign((void **)&data, 512, len);
  memset(data, 'b', len);

  sleep(1);
  // write 16-24
  cache_aio_write(ca, data, 512*16, 512*8, NULL, NULL);
  sleep(4);
  traverse_btree(ca);
  // write 24-32
  cache_aio_write(ca, data, 512*24, 512*8, NULL, NULL);
  sleep(4);
  // merge  16-32
  traverse_btree(ca);
  // now invalidate 16-8
  cache_invalidate_region(ca,512*16, 512*8);
  sleep(2);
  // got 2 bkey: 1、16-8(ptr=0)  2、24-32 
  traverse_btree(ca);
}


void do_write_big_test(struct cache *ca)
{
  printf(" ********* write big test ********** \n");
  void *data = NULL;
  uint64_t len = 512*1024;
  uint64_t offset = 8192;
  uint64_t invalidate_offset = 0;
  
  posix_memalign((void **)&data, 512, len);
  memset(data, 'b', len);

  int num = 0;

  for (num; num < 10; num++) {
    cache_aio_write(ca, data, offset, len, NULL, NULL);
    if ( invalidate_offset ) {
        cache_invalidate_region(ca, invalidate_offset, len);
        /*sleep(1);*/
        /*traverse_btree(ca);*/
    }
    invalidate_offset = offset;
    sleep(2);
    traverse_btree(ca);
    offset=offset+len;
  }
  printf(" ********* done write big test ********** \n");
}

void 
bch_data_insert_start(struct cache *ca, struct keylist *insert_keys)
{
  int i, j;
  int keynum = 10;
  int keynum2 = 10;
  uint64_t start = 0;
  uint64_t start2 = 1000;
  char * data=NULL;
  uint64_t len = 2*512;
  uint64_t len2 = 4*512;
  struct keylist insert_keys2;
  bch_keylist_init(&insert_keys2);
  for (i = 0; i < keynum; i++) {
    struct bkey *k = NULL;
    /*k = insert_keys->top;*/
    k = get_init_bkey(insert_keys, start, ca);
    // 写入的数据按扇区对齐后的大小来分配bucket的资源,但是写入的数据依然按实际的长度
    // 比如：bio.bi_size是实际的数据长度，但是对bio分配bucket资源的时候，给的bi_size>>9
    // 之后变成扇区数进行分配，并不会改变bi_size原有的大小
    int sectors = ( len % 512 ) ? ( len / 512 + 1 ) : ( len / 512 );
    data=T2Molloc(sizeof(char)*len);
    memset(data,'x',sizeof(char)*len);
    int ret = bch_alloc_sectors(ca->set, k, sectors, 0, 0, 1);
    SET_KEY_DIRTY(k, true);
    for (j = 0; j < KEY_PTRS(k); j++)
      SET_GC_MARK(PTR_BUCKET(ca->set, k, j), GC_MARK_DIRTY);
    printf( " main.c FUN %s: after alloc sectors KEY_OFFSET=%d,KEY_SIZE=%d\n", __func__,KEY_OFFSET(k),KEY_SIZE(k));
    for (j = 0; j < KEY_PTRS(k); j++) {
      off_t ssd_off = PTR_OFFSET(k, j) << 9;
      printf( " main.c FUN %s: Write Data SSD fd=%d,start=0x%x,len=%d\n", __func__,ca->fd,ssd_off,len);
      sync_write(ca->fd, data, len, ssd_off);
    }
    free(data);
    start=start+2*sectors;
    /*start=start+2*sectors;*/
    /*len=2*len;*/
    /*start = start + 1;*/
    bch_keylist_push(insert_keys);
  }
  printf( " \n");
  printf( " main.c FUN %s: >>>>>>>>>>>  Start Insert keylist <<<<<<<<<<<<<<<<\n", __func__);
  bch_data_insert_keys(ca->set, insert_keys, NULL);
  printf( " main.c FUN %s: >>>>>>>>>>>  End Insert keylist <<<<<<<<<<<<<<<<\n", __func__);
  printf(" \n");
  return;

  for (i = 0; i < keynum2; i++) {
    struct bkey *k = NULL;
    k = insert_keys2.top;
    bkey_init(k);
    SET_KEY_INODE(k, 1);
    SET_KEY_OFFSET(k, start2);
    SET_KEY_DIRTY(k, true);
    int sectors = (len2 % 512)? ( len2 / 512 + 1) : ( len2 / 512);
    data = T2Molloc(sizeof(char)*len2);
    memset(data,'j',sizeof(char)*len2);
    int ret = bch_alloc_sectors(ca->set, k, sectors, 0, 0, 1);
    for (j = 0; j < KEY_PTRS(k); j++) {
      off_t ssd_off = PTR_OFFSET(k, j) << 9;
      /*printf( " main.c FUN %s: Write Data SSD fd=%d,start=0x%x,len=%d\n", __func__,ca->fd,ssd_off,len);*/
      sync_write(ca->fd, data, len2, ssd_off);
    }
    free(data);
    start2=start2+2*sectors;
    bch_keylist_push(&insert_keys2);
  }
  printf(" \n");
  printf( " main.c FUN %s: >>>>>>>>>>>  Start Insert keylist <<<<<<<<<<<<<<<<\n", __func__);
  bch_data_insert_keys(ca->set, &insert_keys2, NULL);
  printf( " main.c FUN %s: >>>>>>>>>>>  End Insert keylist <<<<<<<<<<<<<<<<\n", __func__);
  return ;

err:
  printf("can not alloc sectors!\n");
}


void * bch_data_insert(struct cache *ca)
{
  struct keylist *insert_keys;
  insert_keys = calloc(1, sizeof(*insert_keys));
  bch_keylist_init(insert_keys);
  bch_data_insert_start(ca, insert_keys);
}

static unsigned 
inorder_next(unsigned j, unsigned size)
{
  if (j * 2 + 1 < size) {
    j = j * 2 + 1;
    while (j * 2 < size) {
      j *= 2;
    }
  } else {
    j >>= ffz(j) + 1; /* arch/x86/include/asm/bitops.h, find first zero bit */
  }

  return j;
}


void inorder_test()
{
  unsigned j ;
  unsigned size = 7;

  //     1
  //   2   3
  // 4  5 6 7
  for (j = inorder_next(0, size); j; j = inorder_next(j, size)) {
    CACHE_DEBUGLOG(NULL, "inorder trave j %u \n", j);
  }
}

struct test_bkeys {
  struct btree_op	op;
  int pos;
  struct bkey bkeys[100];
};

copy_fn(struct btree_op * op, struct btree *b)
{
  struct test_bkeys *tt = container_of(op, struct test_bkeys, op);
  struct btree_iter iter;
  struct bkey *k, *p = NULL;
  printf("             %s \n", __func__);
  for_each_key(&b->keys, k, &iter) {
    if (KEY_SIZE(k)) {
      bkey_copy(&tt->bkeys[tt->pos], k);
      /*printf("node(level=%d,of=%lu) bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,diryt=%u) \n",*/
                        /*b->level, KEY_OFFSET(&b->key), KEY_OFFSET(k) - KEY_SIZE(k),*/
                        /*KEY_OFFSET(k), KEY_SIZE(k), PTR_OFFSET(k,0), KEY_PTRS(k), KEY_DIRTY(k));*/
      p = &tt->bkeys[tt->pos];
      printf("node(level=%d,of=%lu) bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,diryt=%u) \n",
                        b->level, KEY_OFFSET(&b->key), KEY_OFFSET(p) - KEY_SIZE(p),
                        KEY_OFFSET(p), KEY_SIZE(p), PTR_OFFSET(p,0), KEY_PTRS(p), KEY_DIRTY(p));
      tt->pos++;
    }
  }
}
do_bkey_replace_test(struct cache *ca)
{
  /*traverse_btree(ca);*/
  printf(" ********* %s ********** \n", __func__);
  void *data = NULL;
  uint64_t len = 512*10;
  uint64_t offset = 20*512;
  uint64_t invalidate_offset = 0;

  posix_memalign((void **)&data, 512, len);
  memset(data, 'b', len);
  cache_aio_write(ca, data, offset, len, NULL, NULL);
  sleep(2);
  traverse_btree(ca);

  printf("\n ------- copy big bkey ------------\n");
  struct test_bkeys *op;
  op = calloc(1, sizeof(struct test_bkeys));
  bch_btree_map_nodes(&op->op,ca->set,NULL,copy_fn);
  int i = 0;
  struct bkey *p= NULL;
  for(i; i<op->pos; i++) {
    p = &op->bkeys[i];
    printf("pos %d : bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,diryt=%u) \n",
                        i, KEY_OFFSET(p) - KEY_SIZE(p),
                        KEY_OFFSET(p), KEY_SIZE(p), PTR_OFFSET(p,0), KEY_PTRS(p), KEY_DIRTY(p));
  }
  printf(" ------- copy big bkey end------------\n");
  printf(" \n---------- change middle bkey -----------\n");
  cache_aio_write(ca, data, offset+0*512, 512*2, NULL, NULL);
  cache_aio_write(ca, data, offset+4*512, 512*2, NULL, NULL);
  cache_aio_write(ca, data, offset+7*512, 512*3, NULL, NULL);
  sleep(2);
  traverse_btree(ca);
  printf(" ---------- change middle bkey end-----------\n");

  printf("\n ---------- now insert origin big bkey and replace bkey -------\n");
  struct keylist *insert_keys = NULL;
  struct bkey *replace_key = NULL;
  insert_keys = calloc(1, sizeof(*insert_keys));
  replace_key = calloc(1, sizeof(*replace_key));
  bkey_copy(replace_key, p);
  SET_KEY_DIRTY(p,false);
  bch_keylist_init(insert_keys);
  bkey_copy(insert_keys->keys, p);
  bch_keylist_push(insert_keys);
  atomic_t *journal_ref = NULL;
  journal_ref = bch_journal(ca->set, insert_keys);
  printf("replace_key -------  bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,diryt=%u) \n",
                KEY_OFFSET(replace_key) - KEY_SIZE(replace_key),
                KEY_OFFSET(replace_key), KEY_SIZE(replace_key), 
                PTR_OFFSET(replace_key,0), KEY_PTRS(replace_key), KEY_DIRTY(replace_key));
  struct bkey *ii = insert_keys->keys;
  printf("insert_bkey -------  bkey(start=%lu,off=%lu,size=%lu,ptr_offset=%lu,ptrs=%lu,diryt=%u) \n",
                KEY_OFFSET(ii) - KEY_SIZE(ii),KEY_OFFSET(ii), KEY_SIZE(ii), 
                PTR_OFFSET(ii,0), KEY_PTRS(ii), KEY_DIRTY(ii));

  bch_btree_insert(ca->set, insert_keys, journal_ref, replace_key);
  sleep(1);
  traverse_btree(ca);
  printf(" ---------- insert origin big bkey and replace bkey end-------\n");
  
 
  printf(" ********* done write big test ********** \n");

}

void *log_fn(void *cd, int serial, struct timespec start, struct timespec end){

}

int main()
{
  struct cache *ca = T2Molloc(sizeof(struct cache));
  /*const char *cache_dev = "/dev/sdc";*/
  /*const char *hdd_dev = "/dev/sdd";*/
  /*ca->bdev_path="/etc/ceph/bdev.conf.in";*/
  const char *log_path = "/var/log/ceph";
  const char *whoami = "0";

  log_init(log_path, whoami);

  // 1. write_sb
  write_sb(cache_dev,1,1024,0,0,1,0,16,false);

  int fd = open(cache_dev, O_RDWR | O_DIRECT);
  ca->fd = fd;

  /*int hdd_fd = open(hdd_dev, O_RDWR);*/
  /*ca->hdd_fd = hdd_fd;*/

  init(ca);
  aio_thread_init(ca);
  ca->set->logger_cb = log_fn;

  /*do_write_split_test(ca);*/

  /*bch_data_insert(ca);*/
  /*do_writeback_test(ca);*/
  //do_writeback_batch_test(ca);
  //pthread_t pp,tt;
  //pthread_create(&pp, NULL, start_do_writeback_batch, ca);
  //pthread_create(&tt, NULL, start_do_writeback_batch, ca);

  /*do_invalidate_region_test(ca);*/

  /*do_write_big_test(ca);*/

  /*inorder_test();*/
  /*sleep(5);*/
  /*traverse_btree(ca);*/

  //do_bkey_replace_test(ca);
  while(1) {
    sleep(5);
  }

  return 0;
}
