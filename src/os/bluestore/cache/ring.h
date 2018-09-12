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

enum ITEM_TYPE
{
  ITEM_AIO_READ=1,
  ITEM_AIO_WRITE,
  ITEM_WRITEBACK,
  ITEM_MOVINGGC
};

struct ring_item {
  bool write_through_done;
  void *ca_handler;
  uint8_t strategy;
  void *data;
  uint64_t o_offset;
  uint64_t o_len;
  atomic_t seq;
  atomic_t gc;
  bool need_write_cache;
  bool need_read_backend;
  bool need_read_cache;
  struct io_u io;
  void *io_arg;
  io_completion_fn io_completion_cb;
  void *iou_arg;
  io_completion_fn iou_completion_cb;
  struct keylist *insert_keys;
  struct keylist *read_keys;
  struct keylist *read_new_keys;
  struct io_sync_write *sync_io;
  struct timespec start;
  struct timespec aio_start;
  enum ITEM_TYPE type;
};

struct ring_items {
  struct ring_item **items;
  unsigned count;
  unsigned buf_size;
  unsigned nkeys;
  struct keylist *insert_keys;
  atomic_t *journal_ref;
};

struct ring_items *ring_items_alloc(int max_buffer);

int ring_items_add(struct ring_items *items, struct ring_item *item);

void ring_items_free(struct ring_items *items);
void ring_items_reset(struct ring_items *items);
int ring_items_count(struct ring_items *items);

struct ring_item *get_ring_item(void *data, uint64_t offset, uint64_t len);
void free_ring_item(struct ring_item *item);


#endif

