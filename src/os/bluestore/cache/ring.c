
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ring.h"

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
  SAFE_FREE_INIT(item);
  SAFE_FREE_INC(item);
  return item;
}

void free_ring_item(struct ring_item *item)
{
  if (item->read_new_keys){
    bch_keylist_free(item->read_new_keys);
    T2Free(item->read_new_keys);
  }

  if (item->insert_keys){
    bch_keylist_free(item->insert_keys);
    T2Free(item->insert_keys);
  }

  if (item->read_keys){
    bch_keylist_free(item->read_keys);
    T2Free(item->read_keys);
  }

  T2Free(item);
}


struct ring_items *
ring_items_alloc(int max_buffer){
  struct ring_items* items = calloc(1, sizeof(struct ring_items));
  if (!items){
    return NULL;
  }
  items->count = 0;
  items->buf_size = max_buffer;
  items->items = calloc(max_buffer, sizeof(struct ring_item *));
  if (!items->items){
    free(items);
    return NULL;
  }
  return items;
}

int
ring_items_add(struct ring_items *items, struct ring_item *item){
  if (items->count == items->buf_size){
    return -1;
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

void ring_items_reset(struct ring_items *items)
{
  if (items != NULL) {
    items->count =0;
    items->nkeys =0;
  }
}

int ring_items_count(struct ring_items *items)
{
  if ( items != NULL) {
    return items->count;
  } else {
    return 0;
  }
}
