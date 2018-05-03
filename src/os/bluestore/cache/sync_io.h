#ifndef _SYNC_IO_H
#define _SYNC_IO_H

#include <stdint.h>
#include <stdbool.h>

int cache_sync_io(int type, void *data, uint64_t offset, uint64_t len);


#endif

