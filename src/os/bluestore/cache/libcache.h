#ifndef _CEPH_LIBCACHE_H
#define _CEPH_LIBCACHE_H

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
  l_bluestore_cachedevice_read_lat,
  l_bluestore_cachedevice_flush_lat,
  l_cachedevice_aio_write_lat,
  l_cachedevice_aio_read_lat,
  l_cachedevice_alloc_sectors,
  l_cachedevice_insert_keys,
  l_cachedevice_last
};

struct cache_context {
        void * cache;
        int fd_cache;
        int fd_direct;
        int fd_buffered;
        bool registered;
        const char *bdev_path;
        void *logger_cb;
        const char *whoami;
        const char *log_path;
};

enum cache_write_strategy {
  CACHE_MODE_WRITETHROUGH = 0,
  CACHE_MODE_WRITEBACK,
  CACHE_MODE_WRITEAROUND,
  CACHE_MODE_NONE,
};

struct ring_items;
struct ring_item;


CEPH_CACHE_API int t2store_cache_write_cache_sb(const char *log_path, const char *whoami, const char *dev, 
                     unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev);
CEPH_CACHE_API int t2store_cache_register_cache(struct cache_context *ctx);
CEPH_CACHE_API int t2store_cache_aio_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_aio_read(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_invalidate_region(struct cache_context * ctx, uint64_t off, uint64_t len);

CEPH_CACHE_API struct ring_items * t2store_cache_aio_items_alloc(int max_buffer);
CEPH_CACHE_API struct ring_item * t2store_cache_aio_get_item(void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_aio_items_add(struct ring_items *items, struct ring_item * item);
CEPH_CACHE_API void t2store_cache_aio_items_free(struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_items_reset(struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_writeback_batch(struct cache_context * ctx, struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_writethrough_batch(struct cache_context * ctx, struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_writearound_batch(struct cache_context * ctx, struct ring_items* items);
CEPH_CACHE_API int t2store_cache_aio_thread_init(struct cache_context * ctx);
CEPH_CACHE_API int t2store_cache_aio_get_cache_strategy(struct cache_context * ctx, struct ring_item *item);

#ifdef __cplusplus
}
#endif

#endif
