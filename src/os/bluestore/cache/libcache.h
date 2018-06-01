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
        const char *bdev_path;
        const char *whoami;
        const char *log_path;
};



CEPH_CACHE_API int t2store_cache_write_cache_sb(const char *log_path, const char *whoami, const char *dev, 
                     unsigned block_size, unsigned bucket_size,
                     bool writeback, bool discard, bool wipe_bcache,
                     unsigned cache_replacement_policy,
                     uint64_t data_offset, bool bdev);
CEPH_CACHE_API int t2store_cache_register_cache(struct cache_context *ctx);
CEPH_CACHE_API int t2store_cache_aio_write(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_aio_read(struct cache_context * ctx, void *bl, uint64_t off, uint64_t len, void *cb, void *cb_arg);
CEPH_CACHE_API int t2store_cache_invalidate_region(struct cache_context * ctx, uint64_t off, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif
