#ifndef _CEPH_CACHE_H
#define _CEPH_CACHE_H

int init(struct cache * ca);
int cache_sync_write(struct cache *ca, void * data, uint64_t off, uint64_t len);
int cache_sync_read(struct cache *ca, void * data, uint64_t off, uint64_t len);

int cache_aio_write(struct cache*ca, void *data, uint64_t offset, uint64_t len, void *cb, void *cb_arg);
int cache_aio_writeback_batch(struct cache *ca, struct ring_items * items);
int cache_aio_writethrough_batch(struct cache *ca, struct ring_items * items);
int cache_aio_writearound_batch(struct cache *ca, struct ring_items * items);
int write_sb(const char *dev, unsigned block_size, unsigned bucket_size,
    bool writeback, bool discard, bool wipe_bcache,
    unsigned cache_replacement_policy,
    uint64_t data_offset, bool bdev, const char *uuid_str);
int cache_aio_read(struct cache*ca, void *data, uint64_t offset, uint64_t len,
                   void (*io_completion)(void *), void *io_arg);

int cache_invalidate_region(struct cache *ca, uint64_t offset, uint64_t len);

int get_cache_strategy(struct cache *ca, struct ring_item *item);

void set_writeback_cutoff(struct cached_dev *dc, int val);
void set_writeback_sync_cutoff(struct cached_dev *dc, int val);
void t2ce_set_iobypass_water_level(struct cached_dev *dc, int val);
void set_max_gc_keys_onetime(struct cached_dev *dc, int val);
void t2ce_set_iobypass_size(struct cache *ca, int sequential_cutoff);

#endif


