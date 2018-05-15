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

struct cache_context {
        void * cache;
        int fd_cache;
        int fd_direct;
        int fd_buffered;
        bool registered;
};



CEPH_CACHE_API int t2store_cache_write_cache_sb(const char *dev, unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev);


CEPH_CACHE_API int T2Store_Cache_register_cache(struct cache_context *ctx);

  //r = T2Store_Cache_sync_write(&cache_ctx, bl, off, len);
CEPH_CACHE_API int T2Store_Cache_sync_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len);
CEPH_CACHE_API int T2Store_Cache_aio_submit(struct cache_context *ctx, io_context_t io_ctx, long nr, struct iocb **iocb);
CEPH_CACHE_API int T2Store_Cache_sync_read(struct cache_context *ctx, void *bl, uint64_t off, uint64_t len);

CEPH_CACHE_API int T2Store_Cache_aio_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int T2Store_Cache_aio_read(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);

CEPH_CACHE_API int t2store_cache_invalidate_region(struct cache_context * ctx, uint64_t off, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif
