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
  for (i; i<1000; i++ ) {
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
  for ( i; i<1000; i++ ) {
    cache_aio_write(ca, data, offset+1024*i, len*1024, NULL, NULL);
  }
  /*printf(" ----- \n");*/
  /*sleep(10);*/
  /*traverse_btree(ca);*/
  /*sleep(4);*/
  // read 512
  /*cache_aio_read(ca, read_data, offset, len, read_complete_cb, NULL);*/
  // wait writeback
  /*sleep(4);*/
  /*traverse_btree(ca);*/
  // print read result
  /*printf(" read result =%s \n", read_data);*/
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
  int keynum = 150;
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
    SET_KEY_DIRTY(k, true);
    int sectors = ( len % 512 ) ? ( len / 512 + 1 ) : ( len / 512 );
    data=T2Molloc(sizeof(char)*len);
    memset(data,'x',sizeof(char)*len);
    int ret = bch_alloc_sectors(ca->set, k, sectors, 0, 0, 1);
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
  bch_data_insert_keys(ca->set, insert_keys);
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
  bch_data_insert_keys(ca->set, &insert_keys2);
  printf( " main.c FUN %s: >>>>>>>>>>>  End Insert keylist <<<<<<<<<<<<<<<<\n", __func__);
  return ;

err:
  printf("can not alloc sectors!\n");
}


void * bch_data_insert(struct cache *ca)
{
  struct keylist insert_keys;
  bch_keylist_init(&insert_keys);
  bch_data_insert_start(ca, &insert_keys);
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


int main()
{
  struct cache *ca = T2Molloc(sizeof(struct cache));
  /*const char *cache_dev = "/dev/sdc";*/
  /*ca->bdev_path="/etc/ceph/bdev.conf.in";*/
  const char *log_path = "/var/log/ceph";
  const char *whoami = "0";

  log_init(log_path, whoami);

  // 1. write_sb
  write_sb(cache_dev,1,1024,0,0,1,0,16,false);

  int fd = open(cache_dev, O_RDWR);
  ca->fd = fd;

  init(ca);

  /*do_write_split_test(ca);*/

  /*bch_data_insert(ca);*/
  /*do_writeback_test(ca);*/

  /*do_invalidate_region_test(ca);*/

  /*do_write_big_test(ca);*/

  /*inorder_test();*/
  /*sleep(5);*/
  /*traverse_btree(ca);*/

  while(1) {
    sleep(5);
  }

  return 0;
}
