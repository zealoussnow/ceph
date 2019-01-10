#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libaio.h>

#include "btree.h"
#include "init.h"
#include "libcache.h"
#include "log.h"
#include "bcache.h"
#include "writeback.h"

int t2store_cache_write_cache_sb(struct cache_context *ctx, const char *dev,
                     unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev, const char *uuid_str)
{
  int ret = 0;
  log_init(ctx);
  CACHE_INFOLOG(NULL, "write %s super block \n",dev);
  ret = write_sb(dev, block_size, bucket_size,
                         writeback, discard, wipe_bcache,
                         cache_replacement_policy,
                         data_offset,bdev, uuid_str);
  CACHE_INFOLOG(NULL, "write %s super block done \n",dev);
  return ret;
}



int t2store_cache_register_cache(struct cache_context *ctx)
{
  int ret = 0;
  log_init(ctx);

  ctx->cache = malloc(sizeof(struct cache));
  memset(ctx->cache, 0, sizeof(struct cache));
  ((struct cache *)ctx->cache)->fd=ctx->fd_cache;
  ((struct cache *)ctx->cache)->hdd_fd=ctx->fd_direct;
  memcpy(((struct cache *)ctx->cache)->uuid_str, ctx->uuid_str, 40);

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

void t2store_cache_destroy_cache(struct cache_context *ctx){
  destroy(ctx->cache);
  ctx->registered=false;
  free(ctx->cache);
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

  return item;
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
  struct cache *ca = (struct cache *)ctx->cache;

  if (!strcmp(u_conf->opt_name, "t2ce_flush_water_level")) {
    t2ce_set_flush_water_level(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2ce_iobypass_size_kb")) {
    t2ce_set_iobypass_size(ctx->cache, atoi(u_conf->val));
  }

  if (!strcmp(u_conf->opt_name, "t2ce_iobypass_water_level")) {
    t2ce_set_iobypass_water_level(ca->set->dc, atoi(u_conf->val));
  }

  return 0;
}

static const char *get_wb_running_state(int state)
{
  switch (state) {
  case WB_IDLE:
    return "wb_idle";
  case WB_REFILL_DIRTY:
    return "wb_refill_dirty";
  case WB_READING_DIRTY:
    return "wb_reading_dirty";
  case WB_WRITING_DIRTY:
    return "wb_writing_dirty";
  default:
    return "unknown";
  }
}

static void get_wb_status(struct cached_dev *dc, struct wb_status *s)
{
  s->wb_running_state  = get_wb_running_state(dc->wb_status);
  s->writeback_stop    = atomic_read(&dc->writeback_stop);
  /*s->has_dirty         = atomic_read(&dc->has_dirty);*/
  s->writeback_rate    = dc->writeback_rate.rate;
  s->dirty_sectors     = get_sectors_dirty(dc);
  s->writeback_percent = dc->writeback_percent;
  s->writeback_delay   = dc->writeback_delay;
  s->real_wb_delay     = atomic_read(&dc->real_wb_delay);
  s->writeback_rate_d_term = dc->writeback_rate_d_term;
  s->writeback_rate_p_term_inverse = dc->writeback_rate_p_term_inverse;
  s->writeback_rate_update_seconds = dc->writeback_rate_update_seconds;
  s->cutoff_writeback      = dc->cutoff_writeback;
  s->cutoff_writeback_sync = dc->cutoff_writeback_sync;
  s->cutoff_cache_add      = dc->cutoff_cache_add;
}

static const char *get_gc_running_state(int state)
{
  switch (state) {
  case GC_IDLE:
    return "gc_idle";
  case GC_START:
    return "gc_start";
  case GC_RUNNING:
    return "gc_running";
  case GC_READ_MOVING:
    return "gc_read_moving";
  case GC_INVALID:
    return "gc_invalid";
  default:
    return "unknown";
  }
}

static void get_gc_status(struct cache_set *c, struct gc_status *s)
{
  // gc status
  s->gc_mark_in_use    = (c->nbuckets - c->avail_nbuckets) * 100.0 / c->nbuckets;
  s->in_use    = c->gc_stats.in_use;
  s->sectors_to_gc     = atomic_read(&c->sectors_to_gc);
  s->gc_running_state  = get_gc_running_state(c->gc_stats.status);
  s->invalidate_needs_gc = c->cache[0]->invalidate_needs_gc;
  s->cutoff_gc = c->dc->cutoff_gc;
  s->cutoff_gc_busy = c->dc->cutoff_gc_busy;
  s->max_gc_keys_onetime = c->dc->max_gc_keys_onetime;

  // all bucket include pin+avail+unavail
  s->gc_all_buckets    = c->gc_stats.gc_all_buckets;
  s->gc_pin_buckets    = c->gc_stats.gc_pin_buckets;
  s->gc_avail_buckets    = c->gc_stats.gc_avail_buckets;
  s->gc_unavail_buckets    = c->gc_stats.gc_unavail_buckets;

  // avail = init + reclaimable
  s->gc_init_buckets    = c->gc_stats.gc_init_buckets;
  s->gc_reclaimable_buckets    = c->gc_stats.gc_reclaimable_buckets;

  // unavail = dirty + meta
  s->gc_meta_buckets    = c->gc_stats.gc_meta_buckets;
  s->gc_dirty_buckets    = c->gc_stats.gc_dirty_buckets;

  // meta = uuids + writeback_dirty + journal + others(btree nodes)
  s->gc_uuids_buckets    = c->gc_stats.gc_uuids_buckets;
  s->gc_writeback_dirty_buckets    = c->gc_stats.gc_writeback_dirty_buckets;
  s->gc_journal_buckets    = c->gc_stats.gc_journal_buckets;
  s->gc_prio_buckets    = c->gc_stats.gc_prio_buckets;

  // moving
  s->gc_moving_stop    = atomic_read(&c->gc_moving_stop);
  s->gc_moving_buckets = c->gc_stats.gc_moving_buckets;
  s->gc_empty_buckets = c->gc_stats.gc_empty_buckets;
  s->gc_full_buckets = c->gc_stats.gc_full_buckets;

  CACHE_DEBUGLOG(NULL, "gc_running_state: %s, invalidate_needs_gc: %u\n",
      get_gc_running_state(c->gc_stats.status), c->cache[0]->invalidate_needs_gc);
}


void get_t2ce_conf(struct cache *ca, struct t2ce_conf *conf)
{
  conf->iobypass_size = ca->set->dc->sequential_cutoff;
  conf->flush_water_level = ca->set->dc->writeback_percent;
  conf->iobypass_water_level = ca->set->dc->cutoff_writeback;
}

int t2store_admin_socket_dump_api(struct cache_context *ctx, const char*cmd, void *value) 
{
  struct cache *ca = (struct cache *)ctx->cache;

  if (!strcmp(cmd, "t2ce_dump_meta")) {
    struct t2ce_meta *meta = (struct t2ce_meta *)value;
    get_t2ce_meta(ctx, meta);
  } else if (!strcmp(cmd, "t2ce_dump_meta_detail")) {
    get_t2ce_meta(ctx, NULL);
  } else if (!strcmp(cmd, "t2ce_dump_wb")) {
    struct wb_status *ws = (struct wb_status *)value;
    get_wb_status(ca->set->dc, ws);
  } else if (!strcmp(cmd, "t2ce_dump_config")) {
    struct t2ce_conf *conf = (struct t2ce_conf *)value;
    get_t2ce_conf(ca, conf);
  } else if (!strcmp(cmd, "t2ce_dump_gc")) {
    struct gc_status *gs = (struct gc_status *)value;
    get_gc_status(ca->set, gs);
  } else {
    return -1;
  }
  return 0;
}
int t2store_admin_socket_set_api(struct cache_context *ctx, const char*cmd, void *value)
{
  if (!strcmp(cmd, "t2ce_set_gc_moving_skip")) {
    int *v = (int *)value;
    set_gc_moving_stop(ctx->cache, *v);
  } else if (!strcmp(cmd, "t2ce_set_wb_stop")) {
    int *v = (int *)value;
    set_writeback_stop(ctx->cache, *v);
  } else if (!strcmp(cmd, "t2ce_set_gc_stop")) {
    int *v = (int *)value;
    set_gc_pause(ctx->cache, *v);
  } else if (!strcmp(cmd, "t2ce_set_cache_mode")) {
    char *v = (char *)value;
    set_cache_mode(ctx->cache, v);
  } else if (!strcmp(cmd, "t2ce_set_cached_hits")) {
    int *v = (int *)value;
    set_cached_hits(ctx->cache, *v);
  } else if (!strcmp(cmd, "t2ce_wb_rate_update_seconds")) {
    int *v = (int *)value;
    set_writeback_rate_update_seconds(ctx->cache, *v);
  } else if (!strcmp(cmd, "t2ce_log_reload")) {
    return log_reload();
  } else if (!strcmp(cmd, "t2ce_set_log_level")) {
    char *v = (char *)value;
    return t2ce_set_log_level(v);
  } else if (!strcmp(cmd, "t2ce_wakeup_gc")) {
    CACHE_INFOLOG(NULL, "force wakeup gc immeditally\n");
    struct cache *ca  = (struct cache *)ctx->cache;
    set_gc_pause(ca, false);
    ca->invalidate_needs_gc = true;
    wake_up_gc(ca->set);
  } else if (!strcmp(cmd, "t2ce_set_expensive_checks")) {
    int *v = (int *)value;
    set_cache_expensive_debug_checks(ctx->cache, *v);
  } else {
    CACHE_INFOLOG(NULL, "cmd %s set error \n", cmd);
    return -1;
  }

  return 0;
}


