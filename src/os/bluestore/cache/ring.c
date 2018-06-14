
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ring.h"

#define BUFFER_EXTEND_SIZE 16

struct ring_item *
get_ring_item(void *data, uint64_t offset, uint64_t len)
{
  struct ring_item *item = NULL;
  item = calloc(1, sizeof(*item));
  if (item) {
    item->data = data;
    item->o_offset = offset;
    item->o_len = len;
  }
  return item;
}


struct ring_items *
ring_items_alloc(){
  struct ring_items* items = calloc(1, sizeof(struct ring_items));
  if (!items){
    return NULL;
  }
  items->count = 0;
  items->buf_size = BUFFER_EXTEND_SIZE;
  items->items = calloc(BUFFER_EXTEND_SIZE, sizeof(struct ring_items *));
  if (!items->items){
    free(items);
    return NULL;
  }
  return items;
}

int
ring_items_add(struct ring_items *items, struct ring_item *item){
  unsigned new_buf_size;
  if (items->count == items->buf_size){
    new_buf_size = items->buf_size + BUFFER_EXTEND_SIZE;
    items->items = realloc(items->items, new_buf_size * sizeof(struct ring_items *));
    if (!items->items){
      assert("Count realloc memory!");
    }
    items->buf_size = new_buf_size;
  }
  items->items[items->count] = item;
  items->count ++;
  return 0;
}

void
ring_items_free(struct ring_items *items){
  free(items->items);
  free(items);
}

int
ring_items_reset(struct ring_items *items){
  free(items->items);
  items->count = 0;
  items->buf_size = BUFFER_EXTEND_SIZE;
  items->items = calloc(BUFFER_EXTEND_SIZE, sizeof(struct ring_items *));
  if (!items->items){
    return -1;
  }
  return 0;
}