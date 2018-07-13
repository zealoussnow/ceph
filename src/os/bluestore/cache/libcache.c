#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  ((struct cache *)ctx->cache)->set->logger_cb = ctx->logger_cb;
  ((struct cache *)ctx->cache)->set->bluestore_cd = ctx->bluestore_cd;

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

struct ring_items * t2store_cache_aio_items_alloc(int max_buffer){
  return ring_items_alloc(max_buffer);
}

struct ring_item * t2store_cache_aio_get_item(void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg){
  struct ring_item * item = get_ring_item(bl, off, len);
  item->io_arg = cb_arg;
  item->io_completion_cb = cb;
}

int t2store_cache_aio_items_add(struct ring_items *items, struct ring_item * item){
  return ring_items_add(items, item);
}

void t2store_cache_aio_items_free(struct ring_items* items){
  ring_items_free(items);
}

int t2store_cache_ring_items_get_size(struct ring_items* items)
{
  return ring_items_count(items);
}

void t2store_cache_aio_items_reset(struct ring_items* items)
{
  ring_items_reset(items);
}

int t2store_cache_aio_writethrough_batch(struct cache_context * ctx, struct ring_items* items){
  if (items->count){
    return cache_aio_writethrough_batch(ctx->cache, items);
  }
  return 0;
}

int t2store_cache_aio_writeback_batch(struct cache_context * ctx, struct ring_items* items){
  if (items->count){
    return cache_aio_writeback_batch(ctx->cache, items);
  }
  return 0;
}

int t2store_cache_aio_writearound_batch(struct cache_context * ctx, struct ring_items* items){
  if (items->count){
    return cache_aio_writearound_batch(ctx->cache, items);
  }
  return 0;
}


int t2store_cache_aio_thread_init(struct cache_context * ctx){
  return aio_thread_init(ctx->cache);
}


int t2store_cache_aio_get_cache_strategy(struct cache_context * ctx, struct ring_item *item){
  // TODO: tmp return wirteback mode
  item->strategy = get_cache_strategy(ctx->cache, item);
  //item->strategy = CACHE_MODE_WRITEBACK;
  return item->strategy;
}

int t2store_handle_conf_change(struct cache_context *ctx, struct update_conf *u_conf)
{
  assert(u_conf != NULL);
  if (!strcmp(u_conf->opt_name, "t2store_gc_stop")) {
    set_gc_stop(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2store_writeback_stop")) {
    set_writeback_stop(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2store_cache_mode")) {
    set_writeback_stop(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2store_writeback_percent")) {
    set_writeback_stop(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2store_writeback_rate_update_seconds")) {
    set_writeback_stop(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2store_sequential_cutoff")) {
    set_writeback_stop(ctx->cache, atoi(u_conf->val));
  }

  return 0;
}
