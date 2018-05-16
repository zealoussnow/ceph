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
  cache_aio_write(ca, data, offset, len, NULL, NULL);
  sleep(4);
  traverse_btree(ca);
  // read 512
  cache_aio_read(ca, read_data, offset, len, read_complete_cb, NULL);
  // wait writeback
  sleep(4);
  traverse_btree(ca);
  // print read result
  printf(" read result =%s \n", read_data);
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


int main()
{
  struct cache *ca = T2Molloc(sizeof(struct cache));
  int fd = open("/dev/sdc", O_RDWR );
  ca->fd = fd;
  init(ca);
  ca->handler = aio_init((void *)ca);

  /*do_writeback_test(ca);*/

  /*do_invalidate_region_test(ca);*/

  do_write_big_test(ca);

  while(1) {
    sleep(5);
  }

  return 0;
}
