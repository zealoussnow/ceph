#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <libaio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <sys/eventfd.h>
#include "aio.h"
#include "kfifo.h"
#include "list.h"
#include "log.h"
#include "bcache.h"
#include "conf.h"


//#include <rte_lcore.h>

/*struct aio_handler;*/
struct thread_data;

struct aio_handler *g_handler = NULL;
#define LIBAIO_NR_EVENTS 4096
#define LIBAIO_EVENTS_PER_GET 32


struct thread_info {
  pthread_mutex_t wait_mutex;
  pthread_cond_t wait_cond;
  struct thread_data *td;
  int fd;
  struct io_event *events;
  struct timespec *timeout;
  io_context_t *ioctx;
};

struct thread_options {
  uint16_t type;
  char *name;
  uint64_t period_microseconds;
};

struct thread_data {
  uint32_t lcore;
  /*pthread_t thread_id;*/
  struct thread_options *t_options;
  struct thread_info *thread_info;
  struct list_head node;
  pthread_t pooler_td;
  pthread_t aio_td;
};

struct aio_handler {
  pthread_spinlock_t      lock;
  uint32_t nr_cache;
  uint32_t nr_backend;
  struct list_head cache_threads;
  struct list_head backend_threads;
};

static void *
cache_io_completion_cb(io_context_t ctx, struct iocb *iocb, long res,
                       long res2, struct ring_item *item) {
  //printf("<%s> AIO IO Completion success=%ld \n", __func__, res);
  free(iocb);
  assert(res2 == 0);
  item->io.success = true;
  item->iou_completion_cb(item->iou_arg);
}

void *
poller_fn(void *arg) {
  struct thread_data *td = (struct thread_data *) arg;
  struct io_event *events = td->thread_info->events;
  struct timespec *timeout = td->thread_info->timeout;
  int num_events = 0;
  int i = 0;
  while(1) {
    num_events = io_getevents(*td->thread_info->ioctx, 1, LIBAIO_EVENTS_PER_GET, events, timeout);
    if (num_events == 0)
      continue;
    for (i = 0; i < num_events; i++) {
      struct io_event event = events[i];
      cache_io_completion_cb(*td->thread_info->ioctx, event.obj,
                             event.res, event.res2, event.data);
    }
  }

}

struct thread_data *
get_thread_data(uint16_t type, struct aio_handler *handler) {
  struct thread_data *p = NULL, *tmp = NULL;
  pthread_t pthread_id = pthread_self();
  uint32_t need_seq;

  if ( !handler->nr_cache ) {
    CACHE_ERRORLOG(NULL, "thread empty nr_cache %d, need thread init\n",
        handler->nr_cache);
    assert(!handler->nr_cache);
  }

  switch (type) {
    case CACHE_THREAD_CACHE:
      list_for_each_entry(p, &handler->cache_threads, node) {
        if (p->aio_td == pthread_id || p->pooler_td == pthread_id) {
          return p;
        }
      }

      break;
    case CACHE_THREAD_BACKEND:
      list_for_each_entry(p, &handler->backend_threads, node) {
        if (p->aio_td == pthread_id || p->pooler_td == pthread_id) {
          return p;
        }
      }
      break;
    default:
      assert(" Unsupporte enqueue thread type" == 0);
  }

  //for random  select io_context
  // CACHE_WARNLOG(NULL, " random  select io_context \n");
  //Todo: not go here when cache poller write backend
  switch (type) {
    case CACHE_THREAD_CACHE:
      need_seq = pthread_id % handler->nr_cache;
      list_for_each_entry(p, &handler->cache_threads, node) {
        if (!need_seq--) {
          return p;
        }
      }

      break;
    case CACHE_THREAD_BACKEND:
      need_seq = pthread_id % handler->nr_backend;
      list_for_each_entry(p, &handler->backend_threads, node) {
        if (!need_seq--) {
          return p;
        }
      }
      break;
    default:
      assert(" Unsupporte enqueue thread type" == 0);
  }


  return NULL;
}


int aio_queue_submit(io_context_t ctx, unsigned len, struct iocb **iocbs)
{
  // 2^16 * 125us = ~8 seconds, so max sleep is ~16 seconds
  int attempts = 16;
  int delay = 125;
  int retries = 0;
  int r;
  unsigned submit_num = len;
  struct iocb **sbumit_iocbs = iocbs;
  while (submit_num) {
    assert(submit_num > 0);
    assert((sbumit_iocbs + submit_num) == (iocbs + len));
    r = io_submit(ctx, submit_num, sbumit_iocbs);
    if (r == -EAGAIN && attempts-- > 0) {
      usleep(delay);
      delay *= 2;
      retries++;
      continue;
    }
    if (r != len){
      CACHE_WARNLOG(CAT_AIO," io_submit len=%u submit=%u ret=%d retries=%d\n", len, submit_num, r, retries);
    }
    if (r < 0){
      CACHE_ERRORLOG(CAT_AIO," io_submit len=%u submit=%u ret=%d retries=%d\n", len, submit_num, r, retries);
      assert(r > 0);
    }
    submit_num -= r;
    sbumit_iocbs += r;
  }
  if (retries){
    CACHE_WARNLOG(CAT_AIO," aio submit retries=%d\n", retries);
  }
  return r;
}


struct iocb *get_iocb(struct thread_info *ct, struct ring_item *item){
  struct iocb *iocb;
  char *err;

  iocb = calloc(1, sizeof(struct iocb));
  if ( !iocb ) {
    err = " Could not alloc iocb ";
    CACHE_ERRORLOG(CAT_AIO, err);
    assert(err == 0);
  }
  switch (item->io.type) {
    case CACHE_IO_TYPE_WRITE:
      io_prep_pwrite(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
      break;
    case CACHE_IO_TYPE_READ:
      io_prep_pread(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
      break;
    default:
      CACHE_ERRORLOG(NULL, " Unsuporte IO type(%d)\n", item->io.type);
      assert(" Unsupporte IO type " == 0);
  }
  iocb->data = item;
  return iocb;
}

int
aio_enqueue(uint16_t type, struct aio_handler *h, struct ring_item *item) {
  struct thread_data *td = NULL;
  struct thread_info *ti;
  struct iocb *iocb;
  char *err;
  int rc;

  td = get_thread_data(type, h);
  ti = td->thread_info;
  iocb = get_iocb(ti, item);
  return aio_queue_submit(*ti->ioctx, 1, &iocb);
}

int
aio_enqueue_batch(uint16_t type, struct aio_handler *h, struct ring_items *items) {
  struct thread_data *td = NULL;
  struct thread_info *ti;
  struct ring_item *item;
  struct iocb *iocb;
  struct iocb **iocbs;
  char *err;
  int i;

  td = get_thread_data(type, h);
  ti = td->thread_info;
  iocbs = calloc(items->count, sizeof(struct iocb*));
  if ( !iocbs ) {
    err = " Could not alloc iocbs ";
    CACHE_ERRORLOG(CAT_AIO, err);
    assert(err == 0);
  }
  for (i = 0; i < items->count; i++){
    item = items->items[i];
    item->aio_start = cache_clock_now();
    iocb = get_iocb(ti, item);
    iocbs[i] = iocb;
  }

  aio_queue_submit(*ti->ioctx, items->count, iocbs);
  free(iocbs);

  return 0;
}

int
aio_thread_init(void *ca) {
  CACHE_DEBUGLOG(CAT_AIO, "libevent aio init\n");

  uint32_t i;
  cpu_set_t cpuset;
  struct thread_options *cache_options = NULL;
  struct thread_options *hdd_options = NULL;
  struct aio_handler *handler = g_handler;
  struct cache *myca = (struct cache *) ca;
  char *path = myca->bdev_path;
  char *cache_name = NULL;
  char *backend_name  = NULL;
  struct thread_info *thread_info;
  pthread_t poller_td, self_td;
  int rc = 0;
  io_context_t *iocxt;
  char *msg;
  struct conf *cf = conf_allocate();
  struct conf_section *sp;
  long poll_period;

  if (conf_read(cf, path)) {
    assert("Read config error!" == 0);
  }
  sp = conf_find_section(cf, "AIO");
  for (i=0;; i++) {
    static const char *name = NULL;

    char *file = conf_section_get_nmval(sp, "AIO", i, 0);
    if (!file)
      break;

    name = conf_section_get_nmval(sp, "AIO", i, 1);
    if (!name)
      break;

    if (!strncmp(name, "ssd", strlen("ssd"))) {
      cache_name = file;
    } else if (!strncmp(name, "hdd", strlen("hdd"))) {
      backend_name = file;
    }
  }
  assert(cache_name != NULL);
  assert(backend_name != NULL);

  self_td = pthread_self();
  rc = pthread_getaffinity_np(self_td, sizeof(cpu_set_t), &cpuset);
  if (rc != 0){
    msg = "failed to get thread affinity\n";
    goto err;
  }

  for (i = 0; i < 2; i++) {
    struct thread_data *td = calloc(1, sizeof(*td));

    iocxt = calloc(1, sizeof(io_context_t));
    rc = io_setup(LIBAIO_NR_EVENTS, iocxt);
    if (rc) {
      msg = "failed to setup aio\n";
      CACHE_ERRORLOG(NULL," %s: ret=%d\n", msg, rc);
      goto err;
    }

    thread_info = calloc(1, sizeof(*thread_info));
    if (!thread_info) {
      msg = "failed to allocate thread local context\n";
      goto err;
    }

    thread_info->events = malloc(sizeof(struct io_event) * LIBAIO_EVENTS_PER_GET);
    thread_info->timeout = calloc(1, sizeof(struct timespec));
    thread_info->timeout->tv_sec = 5;
    thread_info->timeout->tv_nsec = 100000000;
    thread_info->ioctx = iocxt;

    if (i < 1) {
      cache_options = calloc(1, sizeof(*cache_options));
      cache_options->type = CACHE_THREAD_CACHE;
      cache_options->name = cache_name;
      td->t_options = cache_options;

      thread_info->td = td;
      td->thread_info = thread_info;
      thread_info->fd = open(cache_options->name, O_RDWR | O_DIRECT, 0644);
      rc = pthread_create(&poller_td, NULL, poller_fn, td);
      if (rc) {
        free(thread_info);
        msg = "failed to allocate cache poller thread\n";
        goto err;
      }
      rc = pthread_setaffinity_np(poller_td, sizeof(cpu_set_t), &cpuset);
      if (rc != 0){
        msg = "failed to set thread cache affinity\n";
        goto err;
      }
      rc = pthread_setname_np(poller_td, "cache_poller");
      if (rc != 0){
        msg = "failed to set cache poller thread name\n";
        goto err;
      }
      td->pooler_td = poller_td;
      td->aio_td = self_td;

      pthread_spin_lock(&handler->lock);
      handler->nr_cache++;
      list_add(&td->node, &handler->cache_threads);
      pthread_spin_unlock(&handler->lock);
    } else {
      hdd_options = calloc(1, sizeof(*hdd_options));
      hdd_options->name = backend_name;
      hdd_options->type = CACHE_THREAD_BACKEND;

      td->t_options = hdd_options;

      thread_info->td = td;
      td->thread_info = thread_info;
      thread_info->fd = open(hdd_options->name, O_RDWR | O_DIRECT, 0644);
      rc = pthread_create(&poller_td, NULL, poller_fn, td);
      if (rc) {
        free(thread_info);
        msg = "failed to allocate backend poller thread\n";
        goto err;
      }
      rc = pthread_setaffinity_np(poller_td, sizeof(cpu_set_t), &cpuset);
      if (rc != 0){
        msg = "failed to set thread hdd affinity\n";
        goto err;
      }
      rc = pthread_setname_np(poller_td, "backend_poller");
      if (rc != 0){
        msg = "failed to set backend poller thread name\n";
        goto err;
      }
      td->pooler_td = poller_td;
      td->aio_td = self_td;

      pthread_spin_lock(&handler->lock);
      handler->nr_backend++;
      list_add(&td->node, &handler->backend_threads);
      pthread_spin_unlock(&handler->lock);
    }
  }
  conf_free(cf);
  return 0;

  err:
  assert(msg == 0);
}

void *
aio_init(void *ca) {
  CACHE_DEBUGLOG(CAT_AIO, "libevent aio init\n");

  if (g_handler) {
    return (void *) g_handler;
  }

  struct aio_handler *handler = NULL;

  handler = calloc(1, sizeof(*handler));
  pthread_spin_init(&handler->lock, 0);

  INIT_LIST_HEAD(&handler->cache_threads);
  INIT_LIST_HEAD(&handler->backend_threads);
  handler->nr_backend = 0;
  handler->nr_cache = 0;

  g_handler = handler;
  return (void *) handler;
}
