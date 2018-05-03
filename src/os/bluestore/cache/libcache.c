
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <libaio.h>

#include "libcache.h"
/*#include "cache.h"*/
#include "bcache.h"


int t2store_cache_write_cache_sb(const char *dev, unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev)
{
  int ret = 0;
  ret = write_sb(dev, block_size, bucket_size,
                         writeback, discard, wipe_bcache,
                         cache_replacement_policy,
                         data_offset,bdev);
  printf(" ************** <%s> write sb done *************** \n",__func__);
  return ret;
}



int T2Store_Cache_register_cache(struct cache_context *ctx)
{
  int ret = 0;
  /*printf(" <%s> \n", __func__);*/
  /*ctx->cache = malloc*/
  ctx->cache = malloc(sizeof(struct cache));
  memset(ctx->cache, 0, sizeof(struct cache));
  ((struct cache *)ctx->cache)->fd=ctx->fd_cache;
  ((struct cache *)ctx->cache)->hdd_fd=ctx->fd_direct;
  printf(" libcache.c <%s> fd_cache = %d \n", __func__, ctx->fd_cache);
  ret = init(ctx->cache);
  if (ret < 0 )
  {
        ctx->registered=false;
        return -1;
  }
  ctx->registered=true;
  printf("    after init cache = %p, set=%p ctx->registered=%d\n", ctx->cache, ((struct cache *)ctx->cache)->set, ctx->registered);
  return ret;
}

int T2Store_Cache_sync_read(struct cache_context *ctx, void *bl, uint64_t off, uint64_t len)
{
  int ret = 0;
  printf("\n libcache.c <%s>: Sync read ------------------ \n",__func__);
  ret = cache_sync_read(ctx->cache, bl, off, len);
  return ret;

}

int T2Store_Cache_sync_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len)
{
  int ret = 0;
  printf(" libcache.c <%s> start write fd_cache=%d,fd_direct=%d \n", __func__, ctx->fd_cache,ctx->fd_direct);
  /*printf(" libcache.c <%s>: Start write \n",__func__);*/
  printf("   sync_write cache = %p \n", ctx->cache);
  printf("   sync_write cache = %p, set=%p \n", ctx->cache, ((struct cache *)ctx->cache)->set);
  ret = cache_sync_write(ctx->cache, bl, off, len);
  /*printf(" libcache.c <%s>: print \n",__func__);*/

  return ret;
}

CEPH_CACHE_API int T2Store_Cache_aio_read(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg)
{
    int ret = 0;
    ret = cache_aio_read(ctx->cache, bl, off, len, cb, cb_arg);
    return ret;
}

CEPH_CACHE_API int T2Store_Cache_aio_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg)
{
    int ret = 0;
    ret = cache_aio_write(ctx->cache, bl, off, len, cb, cb_arg);
    return ret;
}

int T2Store_Cache_aio_submit(struct cache_context *ctx, io_context_t io_ctx, long nr, struct iocb **iocb)
{
  int ret=0;
  printf(" init.c <%s>  fd=%d\n", __func__,(*iocb)->aio_fildes);
  ret = cache_aio_write(ctx->cache, io_ctx, nr, iocb);

  return ret;
}

