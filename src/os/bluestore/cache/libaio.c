#include <pthread.h>
#include <libaio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rte_ring.h"

#include "aio.h"
#include "list.h"
#include "log.h"
#include "bcache.h"

struct thread_data;

struct aio_handler *g_handler = NULL;
struct rte_ring_handler *g_rte_ring_handler = NULL;
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
  bool running;
};

struct thread_data {
  uint32_t lcore;
  /*pthread_t thread_id;*/
  struct thread_options *t_options;
  struct thread_info *thread_info;
  struct list_head node;
  pthread_t pooler_td;
  pthread_t aio_td;
  struct cache *ca;
  pthread_t dequeue_td;
};

struct aio_handler {
  pthread_spinlock_t      lock;
  uint32_t nr_cache;
  uint32_t nr_backend;
  struct list_head cache_threads;
  struct list_head backend_threads;
};

struct rte_ring_handler {
  pthread_spinlock_t      lock;
  uint32_t nr_dequeue;
  struct list_head dequeue_threads;
  struct rte_ring *journal_ring;
};

static void cache_io_completion_cb(struct iocb *iocb, long res,
                       long res2, struct ring_item *item)
{
  struct cache *ca = item->ca_handler;

  free(iocb);
  cache_bug_on((res < 0 || res2 != 0), ca->set, "aio get error res %d res2 %d\n", res, res2);
  item->io.success = true;
  switch (item->type) {
    case ITEM_AIO_WRITE:
      bch_prep_journal(item->iou_arg);
      break;
    case ITEM_AIO_READ:
    case ITEM_WRITEBACK:
    case ITEM_MOVINGGC:
      item->iou_completion_cb(item->iou_arg);
      break;
    default:
      assert("item error" == 0);
  }
}

void *thr_insert_keys(void *arg) {
  struct thread_data *td = (struct thread_data *) arg;
  struct cache *ca = td->ca;
  struct cache_set *c = ca->set;
  struct rte_ring *r = c->journal_ring;
  struct ring_items *items = NULL;
  struct ring_item *item = NULL;
  int i;
  void *ring_data;

  while (td->t_options->running) {
    if (!rte_ring_dequeue(r, &ring_data)) {
      items = (struct ring_items*)ring_data;
      bch_insert_keys_batch(c, items->insert_keys, NULL, items->journal_ref);
      for (i = 0; i < items->count; i++) {
        item = items->items[i];
        item->iou_completion_cb(item);
      }
      ring_items_free(items);
    } else {
      struct timespec out = time_from_now(0, 100*NSEC_PER_USEC);
      pthread_mutex_lock(&c->journal_ring_mut);
      pthread_cond_timedwait(&c->journal_ring_cond, &c->journal_ring_mut, &out);
      pthread_mutex_unlock(&c->journal_ring_mut);
    }
  }
}

void *
poller_fn(void *arg) {
  struct thread_data *td = (struct thread_data *) arg;
  struct io_event *events = td->thread_info->events;
  struct timespec *timeout = td->thread_info->timeout;
  int num_events = 0;
  int i = 0;
  while(td->t_options->running) {
    num_events = io_getevents(*td->thread_info->ioctx, 1, LIBAIO_EVENTS_PER_GET, events, timeout);
    if (num_events == 0)
      continue;
    for (i = 0; i < num_events; i++) {
      struct io_event event = events[i];
      cache_io_completion_cb(event.obj, event.res, event.res2, event.data);
    }
  }

}

struct thread_data *
get_thread_data(uint16_t type, struct aio_handler *handler) {
  struct thread_data *p = NULL;
  pthread_t pthread_id = pthread_self();
  uint32_t need_seq;

  assert(handler != NULL);

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
  int r = 0;
  unsigned submit_num = len;
  struct iocb **sbumit_iocbs = iocbs;
  while (submit_num) {
    assert(submit_num > 0);
    submit_num = min_t(unsigned, submit_num ,LIBAIO_NR_EVENTS);
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
    sbumit_iocbs += r;
    submit_num = iocbs + len - sbumit_iocbs;
    attempts = 16;
    delay = 125;
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

#define RING_SIZE 4096
#define DE_INSERT 2

int
cache_rte_dequeue_init(struct cache *ca) {
  int i;
  pthread_t *pde;
  struct rte_ring_handler *handler = g_rte_ring_handler;
  struct thread_options *options = NULL;
  struct thread_data *td = NULL;
  struct cache_set *c = ca->set;

  c->journal_ring = rte_ring_create(RING_SIZE, 0);
  if (c->journal_ring == NULL) {
    CACHE_ERRORLOG(NULL, "error create journal rte ring\n");
    assert("no mem" == 0);
  }

  handler->journal_ring = c->journal_ring;
  pde = calloc(DE_INSERT, sizeof(*pde));
  if (pde == NULL ) {
    CACHE_ERRORLOG(NULL, "calloc pthread failed \n");
    assert("calloc pthread failed "==0);
  }
  for (i=0;i<DE_INSERT;i++) {
    td = calloc(1, sizeof(*td));
    if (td == NULL) {
      CACHE_ERRORLOG(NULL, "calloc thread_data failed \n");
      assert("calloc thread_data failed "==0);
    }
    options = calloc(1, sizeof(*options));
    if ( options == NULL ) {
      CACHE_ERRORLOG(NULL, "calloc thread_options failed \n");
      assert("calloc thread_options failed "==0);
    }
    options->running = true;
    options->type = CACHE_THREAD_CACHE;
    td->t_options = options;
    td->ca = ca;
    if(pthread_create(&pde[i], NULL, thr_insert_keys, (void*)td)){
      CACHE_ERRORLOG(NULL, "error create insert keys pthread\n");
      assert("error create pthread" == 0);
    }
    if (pthread_setname_np(pde[i], "insert_keys")){
      CACHE_ERRORLOG(NULL, "error set insert keys pthread name\n");
      assert("failed to set insert_keys" == 0);
    }
    td->dequeue_td = pde[i];
    pthread_spin_lock(&handler->lock);
    handler->nr_dequeue++;
    list_add(&td->node, &handler->dequeue_threads);
    pthread_spin_unlock(&handler->lock);
  }

  return 0;
}

int
aio_thread_init(void *ca) {
  CACHE_DEBUGLOG(CAT_AIO, "libevent aio init\n");

  uint32_t i;
  struct thread_options *cache_options = NULL;
  struct thread_options *hdd_options = NULL;
  struct aio_handler *handler = g_handler;
  struct cache *myca = (struct cache *) ca;
  struct thread_info *thread_info;
  pthread_t poller_td, self_td;
  int rc = 0;
  io_context_t *iocxt;
  char *msg;

  self_td = pthread_self();

  for (i = 0; i < 2; i++) {
    struct thread_data *td = calloc(1, sizeof(*td));
    if (td == NULL) {
      CACHE_ERRORLOG(NULL, "calloc thread_data failed \n");
      assert("calloc thread_data failed"==0);
    }
    td->ca = myca;

    iocxt = calloc(1, sizeof(io_context_t));
    if (iocxt == NULL) {
      CACHE_ERRORLOG(NULL, "calloc iocxt failed \n");
      assert("calloc iocxt failed"==0);
    }
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
    if (thread_info->timeout == NULL) {
      CACHE_ERRORLOG(NULL, "calloc thread_info timeout spec failed \n");
      assert("calloc thread_info timeout spec failed"==0);
    }
    thread_info->timeout->tv_sec = 5;
    thread_info->timeout->tv_nsec = 100000000;
    thread_info->ioctx = iocxt;

    if (i < 1) {
      cache_options = calloc(1, sizeof(*cache_options));
      if (cache_options == NULL)  {
        CACHE_ERRORLOG(NULL, "calloc cache_options failed \n");
        assert("calloc cache_options failed"==0);
      }
      cache_options->type = CACHE_THREAD_CACHE;
      cache_options->running = true;
      td->t_options = cache_options;

      thread_info->td = td;
      td->thread_info = thread_info;
      thread_info->fd = myca->fd;
      rc = pthread_create(&poller_td, NULL, poller_fn, td);
      if (rc) {
        free(thread_info);
        msg = "failed to allocate cache poller thread\n";
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
      if (hdd_options == NULL)  {
        CACHE_ERRORLOG(NULL, "calloc hdd_options failed \n");
        assert("calloc hdd_options failed"==0);
      }
      hdd_options->type = CACHE_THREAD_BACKEND;
      hdd_options->running = true;

      td->t_options = hdd_options;

      thread_info->td = td;
      td->thread_info = thread_info;
      thread_info->fd = myca->hdd_fd;
      rc = pthread_create(&poller_td, NULL, poller_fn, td);
      if (rc) {
        free(thread_info);
        msg = "failed to allocate backend poller thread\n";
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
  return 0;

  err:
  assert(msg == 0);
  return rc;
}

void *
cache_rte_ring_init() {

  if (g_rte_ring_handler) {
    return (void *) g_rte_ring_handler;
  }

  struct rte_ring_handler* handler = NULL;

  handler = calloc(1, sizeof(*handler));
  if (!handler) {
    CACHE_ERRORLOG(NULL, "error calloc handler\n");
    assert("error calloc handler" == 0);
  }
  pthread_spin_init(&handler->lock, 0);

  INIT_LIST_HEAD(&handler->dequeue_threads);
  handler->nr_dequeue = 0;

  g_rte_ring_handler = handler;
  return (void *) g_rte_ring_handler;
}

void *
rte_dequeue_ring_destroy() {
  struct thread_data *td;
  struct rte_ring_handler *handler = g_rte_ring_handler;

  list_for_each_entry(td, &handler->dequeue_threads, node)
    td->t_options->running = false;

  while(!list_empty(&handler->dequeue_threads)) {
    td = list_first_entry(&handler->dequeue_threads, typeof(*td), node);
    pthread_join(td->dequeue_td, NULL);
    T2Free(td->t_options);
    list_del(&td->node);
    T2Free(td);
  }

  rte_ring_free(handler->journal_ring);

  T2Free(handler);
}

void *
aio_init(void *ca) {
  CACHE_DEBUGLOG(CAT_AIO, "libevent aio init\n");

  if (g_handler) {
    return (void *) g_handler;
  }

  struct aio_handler *handler = NULL;

  handler = calloc(1, sizeof(*handler));
  if (handler == NULL) {
    CACHE_ERRORLOG(NULL, "calloc handler failed \n");
    assert("calloc handler failed" == 0);
  }
  pthread_spin_init(&handler->lock, 0);

  INIT_LIST_HEAD(&handler->cache_threads);
  INIT_LIST_HEAD(&handler->backend_threads);
  handler->nr_backend = 0;
  handler->nr_cache = 0;

  g_handler = handler;
  return (void *) handler;
}

void aio_destroy(void *arg){
  CACHE_INFOLOG(CAT_AIO, "stop aio\n");
  struct cache *ca = (struct cache *) arg;
  struct aio_handler *handler = g_handler;
  struct thread_data *td;
  int err;

  list_for_each_entry(td, &handler->cache_threads, node)
    td->t_options->running = false;
  list_for_each_entry(td, &handler->backend_threads, node)
    td->t_options->running = false;

  while(!list_empty(&handler->cache_threads)) {
    td = list_first_entry(&handler->cache_threads, typeof(*td), node);
    CACHE_INFOLOG(CAT_AIO, "stop cache pooler: %#lx\n", td->pooler_td);
    err = pthread_join(td->pooler_td, NULL);
    cache_bug_on(err != 0, ca->set, "Aio thread wait failed: %s\n", strerror(err));
    free(td->t_options);
    io_destroy(*td->thread_info->ioctx);
    free(td->thread_info->events);
    free(td->thread_info->timeout);
    free(td->thread_info);
    list_del(&td->node);
    free(td);
  }

  while(!list_empty(&handler->backend_threads)) {
    td = list_first_entry(&handler->backend_threads, typeof(*td), node);
    CACHE_INFOLOG(CAT_AIO, "stop backend pooler: %#lx\n", td->pooler_td);
    pthread_join(td->pooler_td, NULL);
    cache_bug_on(err != 0, ca->set, "Aio thread wait failed: %s\n", strerror(err));
    free(td->t_options);
    io_destroy(*td->thread_info->ioctx);
    free(td->thread_info->ioctx);
    free(td->thread_info->events);
    free(td->thread_info->timeout);
    free(td->thread_info);
    list_del(&td->node);
    free(td);
  }

  free(handler);
  ca->handler = g_handler = NULL;

  return ;
}

