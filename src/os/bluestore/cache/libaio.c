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
#define RING_SIZE 4096
#define LIBAIO_NR_EVENTS 4096
#define LIBAIO_EVENTS_PER_GET 32


struct cache_thread {
  pthread_mutex_t wait_mutex;
  pthread_cond_t wait_cond;
  struct thread_data *td;
  DECLARE_KFIFO_PTR(ring, struct ring_item*);
  pthread_spinlock_t ring_lock;
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
  pthread_t td;
  bool runing;
};

struct aio_handler {
  uint32_t nr_cache;
  uint32_t nr_backend;
  struct list_head cache_threads;
  struct list_head backend_threads;
  io_context_t ioctx;
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
do_reap(evutil_socket_t fd, short event, void *arg) {
  struct thread_data *td = (struct thread_data *) arg;
  struct io_event *events = td->cache_thread->events;
  struct timespec *timeout = td->cache_thread->timeout;
  int i;
  int num_events;

  while (1) {
    num_events = io_getevents(*td->cache_thread->ioctx, 0, LIBAIO_EVENTS_PER_GET, events, timeout);
    if (num_events == 0) {
      break;
    }

    for (i = 0; i < num_events; i++) {
      struct io_event event = events[i];
      cache_io_completion_cb(*td->cache_thread->ioctx, event.obj,
                             event.res, event.res2, event.data);
    }
  }

}

void *
poller_fn(void *arg) {
  struct thread_data *td = (struct thread_data *) arg;

  struct event *signal_int;
  struct event_base *base;

  /* Initalize the event library */
  base = event_base_new();

  /* Initalize one event */
  signal_int = event_new(base, td->cache_thread->efd, EV_READ | EV_PERSIST, do_reap, arg);
  event_add(signal_int, NULL);
  event_base_dispatch(base);
  event_free(signal_int);
  event_base_free(base);
  free(td->cache_thread->events);
}

static int
cache_init(struct thread_data *td) {
  struct thread_options *t_op = td->t_options;
  struct cache_thread *cache_thread;
  pthread_t poller_td;
  int rc = 0;
  io_context_t *iocxt;

  iocxt = calloc(1, sizeof(io_context_t));
  io_setup(LIBAIO_NR_EVENTS, iocxt);

  cache_thread = calloc(1, sizeof(*cache_thread));
  if (!cache_thread) {
    //printf("failed to allocate thread local context\n");
    goto err;
  }

  cache_thread->td = td;
  td->cache_thread = cache_thread;
  cache_thread->ioctx = iocxt;

  pthread_spin_init(&cache_thread->ring_lock, 1);
  INIT_KFIFO(cache_thread->ring);
  rc = kfifo_alloc(&cache_thread->ring, RING_SIZE);
  if (rc) {
    //printf("failed to allocate ring\n");
    free(cache_thread);
    goto err;
  }

  cache_thread->fd = open(t_op->name, O_RDWR | O_DIRECT, 0644);
  cache_thread->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  cache_thread->events = malloc(sizeof(struct io_event) * LIBAIO_EVENTS_PER_GET);
  cache_thread->timeout = calloc(1, sizeof(struct timespec));
  cache_thread->timeout->tv_sec = 0;
  cache_thread->timeout->tv_nsec = 100000000;

  rc = pthread_create(&poller_td, NULL, poller_fn, td);
  if (rc) {
    kfifo_free(&cache_thread->ring);
    free(cache_thread);
    //printf("failed to allocate thread\n");
    goto err;
  }

  return 0;
  err:
  return rc;
}


void *
cache_thread_fn(void *cb) {
  struct thread_data *td = NULL;
  struct cache_thread *ct = NULL;
  struct ring_item *item = NULL;
  size_t ring_counts;
  int count;
  int rc;
  struct iocb *iocb;
  char *err;
  struct timespec out;

  assert(cb != NULL);

  td = cb;
  if (td->t_options == NULL) {
    assert("t_options is need for a thread");
  }
  rc = cache_init(td);
  if (rc < 0) {
    // 这里有待商榷，加入因为资源问题导致某一个线程创建失败，这时候应该如何处理？
    assert("cache init faild" == 0);
  }
  ct = td->cache_thread;

  while(1) {
    pthread_spin_lock(&ct->ring_lock);
    count = kfifo_get(&ct->ring, &item);
    pthread_spin_unlock(&ct->ring_lock);
    if ( count == 1) {
      iocb = calloc(1, sizeof(struct iocb));
      switch ( item->io.type ) {
        case CACHE_IO_TYPE_WRITE:
          io_prep_pwrite(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
          err = " Libaio write error ";
          break;
        case CACHE_IO_TYPE_READ:
          io_prep_pread(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
          err = " Libaio read error ";
          break;
        default:
          CACHE_ERRORLOG(" Unsuporte IO type(%d)\n", item->io.type);
          assert(" Unsupporte IO type " == 0);
      }
      io_set_eventfd(iocb, ct->efd);
      iocb->data = item;
      // TODO: submit multi-request
      rc = io_submit(*ct->ioctx, 1, &iocb);
      if ( rc < 0 ) {
        CACHE_ERRORLOG(" %s: ret=%d\n", err, rc);
        // 只是一次IO错误，不应该下断言，测试阶段，这里暂时按断言处理
        assert(err == 0);
      }
    } else {
      gettimeofday(&out, NULL);
      out.tv_sec+=0.5;
      pthread_mutex_lock(&ct->wait_mutex);
      pthread_cond_timedwait(&ct->wait_cond, &ct->wait_mutex, &out);
      pthread_mutex_unlock(&ct->wait_mutex);
    }
  }
}


struct thread_data *
get_thread_data(uint16_t type, struct aio_handler *handler) {
  struct thread_data *p = NULL, *tmp = NULL;
  uint32_t thread_seq = 0;
  uint32_t need_seq = 0;
  pthread_t pthread_id = pthread_self();
  need_seq = pthread_id % handler->nr_cache;
  switch (type) {
    case CACHE_THREAD_CACHE:
      list_for_each_entry(p, &handler->cache_threads, node) {
        if (thread_seq == need_seq) {
          return p;
        }
        thread_seq++;
      }
      break;
    case CACHE_THREAD_BACKEND:
      list_for_each_entry(p, &handler->backend_threads, node) {
        if (thread_seq == need_seq) {
          return p;
        }
        thread_seq++;
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
  int ret = 0;
  int count;

  td = get_thread_data(type, h);
  if (td == NULL) {
    ret = -1;
    goto err;
  }

  again:
  if (td) {
    pthread_spin_lock(&td->cache_thread->ring_lock);
    count = kfifo_put(&td->cache_thread->ring, item);
    pthread_spin_unlock(&td->cache_thread->ring_lock);

    pthread_mutex_lock(&td->cache_thread->wait_mutex);
    pthread_cond_signal(&td->cache_thread->wait_cond);
    pthread_mutex_unlock(&td->cache_thread->wait_mutex);
    if (count == 0) { // maybe ring is full, we should insert again
      goto again;
    }
  }

  err:
  return ret;
}

static struct thread_data *
create_new_thread_data(struct thread_options *t_options) {
  struct thread_data *td = NULL;
  td = calloc(1, sizeof(*td));
  if (td) {
    td->t_options = t_options;
    td->runing = true;
  }
  return td;
}

void
get_conf(char *path, char **cache_name, char **backend_name, uint32_t *lcore_count,
         uint32_t *cache_thread_cores) {
  int ret;
  int i = 0;
  struct conf *cf = conf_allocate();
  struct conf_section *sp;
  char *lcore_str;
  char *cache_percent = NULL;
  float cache_thread_core_percent = 0;

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
      *cache_name = calloc(1, strlen(file) + 1);
      strcpy(*cache_name, file);
    } else if (!strncmp(name, "hdd", strlen("hdd"))) {
      *backend_name = calloc(1, strlen(file) + 1);
      strcpy(*backend_name, file);
    }
  }

  sp = conf_find_section(cf, "DPDK_ENV");
  lcore_str = conf_section_get_val(sp, "core_mask");

  ret = strtol(lcore_str + 2, NULL, 16);
  *lcore_count = 0;
  while (ret) {
    (*lcore_count)++;
    ret = ret >> 1;
  }
  CACHE_INFOLOG("core_mask: %d\n", *lcore_count);
  if (*lcore_count < 1) {
    CACHE_ERRORLOG("fcore_mask: %d\n", *lcore_count);
    assert(*lcore_count > 0);
  }

  cache_percent = conf_section_get_val(sp, "cache_thread_core_percent");
  if (cache_percent == NULL) {
    CACHE_WARNLOG("cache_thread_core_percent will use default value 0.5");
    cache_thread_core_percent = 0.5;
  } else {
    cache_thread_core_percent = atof(cache_percent);
    CACHE_DEBUGLOG("cache_thread_core_percent value %f \n", cache_thread_core_percent);
  }
  *cache_thread_cores = (*lcore_count) * cache_thread_core_percent;
  conf_free(cf);
}

/*int main(int argc, char **argv)*/
void *
aio_init(void *ca) {
  if (g_handler) {
    return (void *) g_handler;
  }

  int ret = 0;
  uint32_t lcore;
  uint32_t lcore_count;
  uint32_t cache_thread_cores;
  struct thread_options *cache_options = NULL;
  struct thread_options *hdd_options = NULL;
  struct thread_data *td1 = NULL;
  struct aio_handler *handler = NULL;
  char *path = ((struct cache *) ca)->bdev_path;
  char *cache_name;
  char *backend_name;

  get_conf(path, &cache_name, &backend_name, &lcore_count,
           &cache_thread_cores);

  handler = calloc(1, sizeof(*handler));

  cache_options = calloc(1, sizeof(*cache_options));
  cache_options->type = CACHE_THREAD_CACHE;
  cache_options->name = cache_name;
  /*cache_options->period_microseconds = 1000000;*/
  cache_options->period_microseconds = 100000;

  td1 = create_new_thread_data(cache_options);
  assert(td1 != NULL);


  hdd_options = calloc(1, sizeof(*hdd_options));
  hdd_options->name = backend_name;
  hdd_options->period_microseconds = 1000000;
  hdd_options->type = CACHE_THREAD_BACKEND;

  INIT_LIST_HEAD(&handler->cache_threads);
  INIT_LIST_HEAD(&handler->backend_threads);
  for (lcore = 1; lcore < lcore_count; lcore++) {
    struct thread_data *td = NULL;
    if (lcore == 0) {
      assert("core_mask must config more then one!" == 0);
    }
    if (lcore <= cache_thread_cores) {
      td = create_new_thread_data(cache_options);
      pthread_create(&td->td, NULL, cache_thread_fn, (void *) td);
      td->lcore = lcore;
      handler->nr_cache++;
      list_add(&td->node, &handler->cache_threads);
    } else {
      td = create_new_thread_data(hdd_options);
      td->lcore = lcore;
      pthread_create(&td->td, NULL, cache_thread_fn, (void *) td);
      handler->nr_backend++;
      list_add(&td->node, &handler->backend_threads);
    }
  }
  sleep(2);
  g_handler = handler;
  return (void *) handler;
}
