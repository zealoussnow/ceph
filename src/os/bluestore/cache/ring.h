#ifndef _RING_H
#define _RING_H

#include "bset.h"
#include <time.h>
#include <pthread.h>
typedef void (*io_completion_fn)(void *ctx);
struct io_u {
    void *pos;
    uint64_t offset;
    uint64_t len;
    bool success;
    uint16_t type;
};

struct io_sync_write {
  pthread_mutex_t         sync_io_mutex;
  pthread_cond_t         sync_io_cond;
};
struct ring_item {
    bool write_through_done;
    void *ca_handler;
    uint8_t strategy;
    void * data;
    uint64_t o_offset;
    uint64_t o_len;
    atomic_t seq;
    atomic_t need_write_cache;
    struct io_u io;
    void *io_arg;
    io_completion_fn io_completion_cb;
    void *iou_arg;
    io_completion_fn iou_completion_cb;
    struct keylist *insert_keys;
    struct io_sync_write *sync_io;
};


struct ring_item *get_ring_item(void *data, uint64_t offset, uint64_t len);


#endif

