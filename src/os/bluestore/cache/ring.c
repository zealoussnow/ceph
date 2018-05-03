
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
  return item;
}
