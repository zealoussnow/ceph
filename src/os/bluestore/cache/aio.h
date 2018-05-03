#ifndef _AIO_H
#define _AIO_H

#include "ring.h"

struct aio_handler;
//struct aio_data {
    //void *buf;
    //uint64_t offset;
    //uint64_t len;
    //uint64_t done_offset;
//};

enum cache_io_type {
    CACHE_IO_TYPE_INVALID = 0,
    CACHE_IO_TYPE_READ,
    CACHE_IO_TYPE_WRITE,
    CACHE_IO_TYPE_FLUSH,
};

enum cache_thread_type {
    CACHE_THREAD_INVALID = 0,
    CACHE_THREAD_CACHE,
    CACHE_THREAD_BACKEND,
};

enum cache_write_strategy {
    CACHE_WRITE_STRATEGY_INVALID = 0,
    CACHE_WRITE_STRATEGY_WRITE_BACK,
    CACHE_WRITE_STRATEGY_WRITE_THROUGH,
    CACHE_WRITE_STRATEGY_WRITE_AROUND,
};

void *aio_init(void * ca);

int aio_enqueue(uint16_t type, struct aio_handler *h, struct ring_item *item);
#endif /* _AIO_H */

