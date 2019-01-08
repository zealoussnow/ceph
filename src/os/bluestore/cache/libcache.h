#ifndef _CEPH_LIBCACHE_H
#define _CEPH_LIBCACHE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __GNUC__ >= 4
  #define CEPH_CACHE_API  __attribute__ ((visibility ("default")))
#else
  #define CEPH_CACHE_API
#endif

enum {
  l_cachedevice_first = 888888,
  l_bluestore_cachedevice_aio_write_lat,
  l_bluestore_cachedevice_aio_read_lat,
  l_bluestore_cachedevice_flush_lat,
  l_bluestore_cachedevice_write_queue_lat,
  l_bluestore_cachedevice_t2cache_write_lat,
  l_bluestore_cachedevice_t2cache_read_lat,
  l_bluestore_cachedevice_t2cache_libaio_write_lat,
  l_bluestore_cachedevice_t2cache_libaio_read_lat,
  l_bluestore_cachedevice_t2cache_alloc_sectors,
  l_bluestore_cachedevice_t2cache_insert_keys,
  l_bluestore_cachedevice_t2cache_journal_write,
  l_cachedevice_last
};

struct cache_context {
  void * cache;
  void * bluestore_cd;
  int fd_cache;
  int fd_direct;
  bool registered;
  void *logger_cb;
  const char *whoami;
  const char *log_file;
  bool log_crash_on_nospc;
  char uuid_str[40];
};

enum cache_write_strategy {
  CACHE_MODE_WRITETHROUGH = 0,
  CACHE_MODE_WRITEBACK,
  CACHE_MODE_WRITEAROUND,
  CACHE_MODE_NONE,
};

enum cache_gc_strategy {
  GC_MODE_READ_PRIO = 0,
  GC_MODE_WRITE_PRIO,
  GC_MODE_INVALID,
};

struct update_conf
{
  const char *opt_name;
  const char *val;
};

struct wb_status
{
  int sequential_cutoff;
  int writeback_percent;
  int writeback_delay;
  int real_wb_delay;
  int writeback_rate;
  uint64_t dirty_sectors;
  unsigned writeback_rate_d_term;
  unsigned writeback_rate_p_term_inverse;
  int writeback_rate_update_seconds;
  int cutoff_writeback;
  int cutoff_writeback_sync;
  int cutoff_cache_add;
  int has_dirty;
  int writeback_stop;
  int cached_hits;
  const char *wb_running_state;
  const char *cache_mode;
};

struct gc_status
{
  // gc status
  double gc_mark_in_use;
  int sectors_to_gc;
  const char *gc_running_state;
  unsigned  invalidate_needs_gc;
  unsigned cutoff_gc;
  unsigned cutoff_gc_busy;
  unsigned max_gc_keys_onetime;

  // all bucket include pin+avail+unavail
  uint64_t gc_all_buckets;
  uint64_t gc_avail_buckets;
  uint64_t gc_unavail_buckets;

  // avail = init + reclaimable
  uint64_t gc_init_buckets;
  uint64_t gc_reclaimable_buckets;

  // unavail = dirty + meta
  uint64_t gc_dirty_buckets;
  uint64_t gc_meta_buckets;

  // meta = uuids + writeback_dirty + journal + prio+others(btree nodes)
  uint64_t gc_uuids_buckets;
  uint64_t gc_writeback_dirty_buckets;
  uint64_t gc_journal_buckets;
  uint64_t gc_prio_buckets;

  // moving
  int gc_moving_stop;
  uint64_t gc_moving_buckets;
  uint64_t gc_pin_buckets;
  uint64_t gc_empty_buckets;
  uint64_t gc_full_buckets;
};

struct btree_info
{
  uint64_t btree_nodes;
  uint64_t btree_nbkeys;
  uint64_t total_size;
  uint64_t dirty_size;
  uint64_t btree_bad_nbeys;
  uint64_t btree_dirty_nbkeys;
  uint64_t btree_null_nbkeys;
  uint64_t zero_keysize_nbkeys;
};

struct ring_items;
struct ring_item;


CEPH_CACHE_API int t2store_cache_write_cache_sb(struct cache_context *ctx, const char *dev,
                     unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev, const char *uuid_str);
CEPH_CACHE_API int t2store_cache_register_cache(struct cache_context *ctx);
CEPH_CACHE_API void t2store_cache_destroy_cache(struct cache_context *ctx);
CEPH_CACHE_API int t2store_cache_aio_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_aio_read(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_invalidate_region(struct cache_context * ctx, uint64_t off, uint64_t len);

CEPH_CACHE_API struct ring_items * t2store_cache_aio_items_alloc(int max_buffer);
CEPH_CACHE_API struct ring_item * t2store_cache_aio_get_item(void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_aio_items_add(struct ring_items *items, struct ring_item * item);
CEPH_CACHE_API void t2store_cache_aio_items_free(struct ring_items* items);
CEPH_CACHE_API void t2store_cache_aio_items_reset(struct ring_items* items);
CEPH_CACHE_API int t2store_cache_ring_items_get_size(struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_writeback_batch(struct cache_context * ctx, struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_writethrough_batch(struct cache_context * ctx, struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_writearound_batch(struct cache_context * ctx, struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_thread_init(struct cache_context * ctx);
CEPH_CACHE_API int t2store_cache_aio_get_cache_strategy(struct cache_context * ctx, struct ring_item *item);
CEPH_CACHE_API int t2store_handle_conf_change(struct cache_context *ctx, struct update_conf *u_conf);
CEPH_CACHE_API int t2store_wb_status(struct cache_context *ctx, struct wb_status *s);
CEPH_CACHE_API int t2store_gc_status(struct cache_context *ctx, struct gc_status *s);
CEPH_CACHE_API int t2store_btree_info(struct cache_context *ctx, struct btree_info *bi);
CEPH_CACHE_API int t2store_reload_zlog_config();
CEPH_CACHE_API int t2store_set_log_level(const char *level);
CEPH_CACHE_API void t2store_set_gc_pause(struct cache_context *ctx, int pause);
CEPH_CACHE_API void t2store_wakeup_gc(struct cache_context *ctx);
CEPH_CACHE_API void t2store_expensive_debug_checks(struct cache_context *ctx, bool state);

#ifdef __cplusplus
}
#endif

#endif
