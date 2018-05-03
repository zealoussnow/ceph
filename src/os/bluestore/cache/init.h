#ifndef _CEPH_CACHE_H
#define _CEPH_CACHE_H

int init(struct cache * ca);
int cache_sync_write(struct cache *ca, void * data, uint64_t off, uint64_t len);
int cache_sync_read(struct cache *ca, void * data, uint64_t off, uint64_t len);

int cache_aio_write(struct cache*ca, void *data, uint64_t offset, uint64_t len, void *cb, void *cb_arg);
int write_sb(const char *dev, unsigned block_size, unsigned bucket_size,
    bool writeback, bool discard, bool wipe_bcache,
    unsigned cache_replacement_policy,
    uint64_t data_offset, bool bdev);

#endif


