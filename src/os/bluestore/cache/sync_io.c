

#include "sync_io.h"
#include "ring.h"
#include "aio.h"


void io_wait(struct ring_item *item)
{
  pthread_mutex_lock(&item->sync_io->sync_io_mutex);
  pthread_cond_wait(&item->sync_io->sync_io_cond,
                     &item->sync_io->sync_io_mutex);
  pthread_mutex_unlock(&item->sync_io->sync_io_mutex);
}

void sync_io_completion(void *cb)
{
  struct ring_item *item = cb;
  pthread_mutex_lock(&item->sync_io->sync_io_mutex);
  pthread_cond_signal(&item->sync_io->sync_io_cond);
  pthread_mutex_unlock(&item->sync_io->sync_io_mutex);
}


int cache_sync_io(int type, void *data, uint64_t offset, uint64_t len)
{
  struct ring_item *it = NULL;
  int ret = 0;
  it = get_ring_item(data, offset, len);
  if ( !it ) {
    ret = -1;
    goto out;
  }
  it->io.type = type;
  it->io.pos = it->data;
  it->io.offset = it->o_offset;
  it->io.len = it->o_len;
  it->iou_arg = it;
  it->iou_completion_cb = sync_io_completion;
  it->sync_io = calloc(1, sizeof(*it->sync_io));
  void *handler = aio_init(NULL);
  if ( !handler ) {
    ret = -1;
    goto out;
  }
  ret = aio_enqueue(CACHE_THREAD_CACHE, handler, it);
  if ( ret < 0) {
    ret = -1;
    goto out;
  }
  io_wait(it);
  if ( !it->io.success ) {
    ret = -1;
    goto out;
  }
out:
  free(it->sync_io);
  free(it);
  return ret;
}
