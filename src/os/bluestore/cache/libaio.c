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
#define LIBAIO_NR_EVENTS 1024
#define LIBAIO_EVENTS_PER_GET 32


struct cache_thread {
  pthread_mutex_t wait_mutex;
  pthread_cond_t wait_cond;
  struct thread_data *td;
  int fd;
  int efd;
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
  struct cache_thread *cache_thread;
  struct list_head node;
  pthread_t pooler_td;
  pthread_t aio_td;
};

struct aio_handler {
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
  struct io_event *events = td->cache_thread->events;
  struct timespec *timeout = td->cache_thread->timeout;
  int num_events = 0;
  int i = 0;
  while(1) {
    num_events = io_getevents(*td->cache_thread->ioctx, 1, LIBAIO_EVENTS_PER_GET, events, timeout);
    if (num_events == 0)
      continue;
    for (i = 0; i < num_events; i++) {
      struct io_event event = events[i];
      cache_io_completion_cb(*td->cache_thread->ioctx, event.obj,
                             event.res, event.res2, event.data);
    }
  }

}

struct thread_data *
get_thread_data(uint16_t type, struct aio_handler *handler) {
  struct thread_data *p = NULL, *tmp = NULL;
  pthread_t pthread_id = pthread_self();
  uint32_t need_seq;

  switch (type) {
    case CACHE_THREAD_CACHE:
      list_for_each_entry(p, &handler->cache_threads, node) {
        if (p->aio_td == pthread_id || p->pooler_td == pthread_id) {
          return p;
        }
      }

      break;
    case CACHE_THREAD_BACKEND:
      CACHE_DEBUGLOG("aio_en", "try get backend ioctx");
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
  CACHE_DEBUGLOG(NULL, " random  select io_context \n");
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
      CACHE_DEBUGLOG("aio_en", "try get backend ioctx");
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


int
aio_enqueue(uint16_t type, struct aio_handler *h, struct ring_item *item) {
  struct thread_data *td = NULL;
  struct cache_thread *ct;
  struct iocb *iocb;
  char *err;
  int rc;


  td = get_thread_data(type, h);

  ct = td->cache_thread;

  iocb = calloc(1, sizeof(struct iocb));
  switch (item->io.type) {
    case CACHE_IO_TYPE_WRITE:
      io_prep_pwrite(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
      err = " Libaio write error ";
      break;
    case CACHE_IO_TYPE_READ:
      io_prep_pread(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
      err = " Libaio read error ";
      break;
    default:
      CACHE_ERRORLOG(NULL, " Unsuporte IO type(%d)\n", item->io.type);
      assert(" Unsupporte IO type " == 0);
  }
  io_set_eventfd(iocb, ct->efd);
  iocb->data = item;
  // TODO: submit multi-request

    rc = -11;
    while (rc == -11){
      rc = io_submit(*ct->ioctx, 1, &iocb);
    }
  if (rc != 1){
    CACHE_ERRORLOG("aio_en"," %s: ret=%d\n", err, rc);
    assert(err == 0);
  }
  if ( rc < 0 ) {
    CACHE_ERRORLOG(NULL," %s: ret=%d\n", err, rc);
    // 只是一次IO错误，不应该下断言，测试阶段，这里暂时按断言处理
    assert(err == 0);
  }

  return 0;
}

int
aio_enqueue_batch(uint16_t type, struct aio_handler *h, struct ring_items *items) {
  struct thread_data *td = NULL;
  struct cache_thread *ct;
  struct ring_item *item;
  struct iocb *iocb;
  struct iocb **iocbs;
  char *err;
  int i, rc;

  td = get_thread_data(type, h);

  ct = td->cache_thread;

  iocbs = calloc(items->count, sizeof(struct iocb*));
  if ( !iocbs ) {
    err = " Could not alloc iocbs ";
    CACHE_ERRORLOG(NULL, err);
    assert(err == 0);
  }
  for (i = 0; i < items->count; i++){
    item = items->items[i];
    struct cache *ca = (struct cache *) item->ca_handler;


    iocb = calloc(1, sizeof(struct iocb));
    if ( !iocb ) {
      err = " Could not alloc iocb ";
      CACHE_ERRORLOG(NULL, err);
      assert(err == 0);
    }

    switch (item->io.type) {
      case CACHE_IO_TYPE_WRITE:
        //printf(" io prep pwrite   offset = %lu , len = %lu \n", item->io.offset/512, item->io.len/512);
        io_prep_pwrite(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
        err = " Libaio write error ";
        break;
      case CACHE_IO_TYPE_READ:
        //printf(" --------- read -----------\n");
        io_prep_pread(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
        err = " Libaio read error ";
        break;
      default:
        CACHE_ERRORLOG(NULL, " Unsuporte IO type(%d)\n", item->io.type);
        assert(" Unsupporte IO type " == 0);
    }
    iocb->data = item;
    iocbs[i] = iocb;
  }

  rc = -11;
  while (rc == -11){
    rc = io_submit(*ct->ioctx, items->count, iocbs);
  }

  if (rc != items->count){
    CACHE_ERRORLOG("aio_en", " %s: ret=%d\n", err, rc);
    assert(err == 0);
  }

  if ( rc < 0 ) {
    CACHE_ERRORLOG(NULL," %s: ret=%d\n", err, rc);
    // 只是一次IO错误，不应该下断言，测试阶段，这里暂时按断言处理
    assert(err == 0);
  }
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
  char *path = ((struct cache *) ca)->bdev_path;
  char *cache_name;
  char *backend_name;
  struct cache_thread *cache_thread;
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
  for (;; i++) {
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
  sp = conf_find_section(cf, "DPDK_ENV");
  poll_period = conf_section_get_intval(sp, "poll_period");

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

    cache_thread = calloc(1, sizeof(*cache_thread));
    if (!cache_thread) {
      msg = "failed to allocate thread local context\n";
      goto err;
    }

    cache_thread->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    cache_thread->events = malloc(sizeof(struct io_event) * LIBAIO_EVENTS_PER_GET);
    cache_thread->timeout = calloc(1, sizeof(struct timespec));
    cache_thread->timeout->tv_sec = 5;
    cache_thread->timeout->tv_nsec = 100000000;

    if (i < 1) {
      cache_options = calloc(1, sizeof(*cache_options));
      cache_options->type = CACHE_THREAD_CACHE;
      cache_options->name = cache_name;
      td->t_options = cache_options;

      cache_thread->td = td;
      td->cache_thread = cache_thread;
      cache_thread->ioctx = iocxt;
      cache_thread->fd = open(cache_options->name, O_RDWR | O_DIRECT, 0644);
      rc = pthread_create(&poller_td, NULL, poller_fn, td);
      if (rc) {
        free(cache_thread);
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

      handler->nr_cache++;
      list_add(&td->node, &handler->cache_threads);
    } else {
      hdd_options = calloc(1, sizeof(*hdd_options));
      hdd_options->name = backend_name;
      hdd_options->type = CACHE_THREAD_BACKEND;

      td->t_options = hdd_options;

      cache_thread->td = td;
      td->cache_thread = cache_thread;
      cache_thread->ioctx = iocxt;
      cache_thread->fd = open(hdd_options->name, O_RDWR | O_DIRECT, 0644);
      rc = pthread_create(&poller_td, NULL, poller_fn, td);
      if (rc) {
        free(cache_thread);
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

      handler->nr_backend++;
      list_add(&td->node, &handler->backend_threads);
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

  INIT_LIST_HEAD(&handler->cache_threads);
  INIT_LIST_HEAD(&handler->backend_threads);

  g_handler = handler;
  return (void *) handler;
}
