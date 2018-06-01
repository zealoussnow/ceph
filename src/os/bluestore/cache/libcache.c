
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <libaio.h>

#include "libcache.h"
/*#include "cache.h"*/
#include "bcache.h"


int t2store_cache_write_cache_sb(const char *log_path, const char *whoami, const char *dev, 
                     unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev)
{
  int ret = 0;
  log_init(log_path, whoami);
  CACHE_INFOLOG(NULL, "write %s super block \n",dev);
  ret = write_sb(dev, block_size, bucket_size,
                         writeback, discard, wipe_bcache,
                         cache_replacement_policy,
                         data_offset,bdev);
  CACHE_INFOLOG(NULL, "write %s super block done \n",dev);
  return ret;
}



int t2store_cache_register_cache(struct cache_context *ctx)
{
  int ret = 0;
  log_init(ctx->log_path, ctx->whoami);

  ctx->cache = malloc(sizeof(struct cache));
  memset(ctx->cache, 0, sizeof(struct cache));
  ((struct cache *)ctx->cache)->fd=ctx->fd_cache;
  ((struct cache *)ctx->cache)->hdd_fd=ctx->fd_direct;
  ((struct cache *)ctx->cache)->bdev_path = ctx->bdev_path;

  ret = init(ctx->cache);
  if (ret < 0 ) {
    ctx->registered=false;
    return -1;
  }

  ctx->registered=true;
  CACHE_INFOLOG(NULL, "After init: cache(%p), set(%p), registerd(%d) ret(%d)\n", ctx->cache, ((struct cache *)ctx->cache)->set, ctx->registered,ret);

  return ret;
}

CEPH_CACHE_API int t2store_cache_aio_read(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg)
{
  int ret = 0;
  ret = cache_aio_read(ctx->cache, bl, off, len, cb, cb_arg);
  return ret;
}

CEPH_CACHE_API int t2store_cache_aio_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg)
{
  int ret = 0;
  ret = cache_aio_write(ctx->cache, bl, off, len, cb, cb_arg);
  return ret;
}

int t2store_cache_invalidate_region(struct cache_context * ctx, uint64_t off, uint64_t len)
{
  int ret = 0;
  ret = cache_invalidate_region(ctx->cache, off, len);
  return ret;
}
