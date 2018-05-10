

#include "spdk/stdinc.h"
#include "spdk/bdev.h"
#include "spdk/copy_engine.h"
#include "spdk/conf.h"
#include "spdk/env.h"
#include "spdk/io_channel.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/queue.h"
#include <pthread.h>
#include "aio.h"


/*struct aio_handler;*/
struct thread_data;

struct aio_handler *g_handler = NULL;
#define RING_SIZE 4096

struct spdk_cache_poller {
  spdk_poller_fn   poller_fn;
  void                    *io_channel_ctx;
  uint64_t        period_microseconds;
};

struct spdk_cache_thread {
  pthread_mutex_t wait_mutex;
  pthread_cond_t wait_cond;
  struct thread_data * td;
  struct spdk_thread *thread;
  struct spdk_ring *ring;
  struct spdk_bdev *bdev;
  struct spdk_bdev_desc *desc;
  struct spdk_io_channel *ch;
  struct spdk_cache_poller *cp;
};

struct thread_options {
  uint16_t type;
  char *conf;
  char *name;
  char *thread_name;
  uint64_t period_microseconds;
};

struct thread_data {
  uint32_t lcore;
  /*pthread_t thread_id;*/
  struct thread_options *t_options;
  struct spdk_cache_thread *cache_thread;
  TAILQ_ENTRY( thread_data)   node;
};

struct aio_handler {
  uint32_t nr_cache;
  uint32_t nr_backend;
  TAILQ_HEAD(, thread_data)   cache_threads;
  TAILQ_HEAD(, thread_data)   backend_threads;
};


void *
cache_thread_poller_fn( void *thread_ctx)
{
  struct spdk_cache_thread *tc = thread_ctx;
  struct spdk_cache_poller *cp = tc->cp;

  pthread_setname_np(pthread_self(), "poller_thread");

  while(1) {
    // 调用bdev_aio层，进行io_getevents，得到成功的io，会回调
    // spdk_bdev_write/read的时候，指定的io_completion回调函数
    cp->poller_fn(cp->io_channel_ctx);
    // 每隔多久进行一次轮询
    // 默认从bdev_aio给上来的周期是0，因此，可以在t_option中进行配置
    usleep(cp->period_microseconds);
  }
}

static struct spdk_poller *
spdk_cache_start_poller(void *thread_ctx,
              spdk_poller_fn fn,
              void *channel_ctx,
              uint64_t period_microseconds)
{
  struct spdk_cache_poller *cache_poller = NULL;
  struct spdk_cache_thread *ct = thread_ctx;
  struct thread_data *td = ct->td;
  uint32_t lcore = spdk_env_get_current_core();

  cache_poller = calloc(1, sizeof(*cache_poller));
  if ( !cache_poller ) {
    SPDK_ERRLOG("Unable to allocate poller\n");
    return NULL;
  }

  cache_poller->poller_fn = fn;
  cache_poller->io_channel_ctx = channel_ctx;
  /*cache_poller->period_microseconds = period_microseconds;*/
  cache_poller->period_microseconds = td->t_options->period_microseconds;

  ct->cp = cache_poller;

  // 因为主进程也会注册给spdk，主进行不需要进行poller
  if (lcore == 0 ) {
    return (struct spdk_poller *)cache_poller;
  }

  // 是否需要将poller保持起来？
  pthread_t poller_id;
  pthread_create(&poller_id, NULL, cache_thread_poller_fn, (void *)ct); 

  return (struct spdk_poller *)cache_poller;
}

static void
spdk_cache_stop_poller(struct spdk_poller *poller, void *thread_ctx)
{
  // 找到poller对应的线程，停掉该线程，并从cache -> cache_thread 移除
}

static void
spdk_cache_send_msg(spdk_thread_fn fn, void *ctx, void *thread_ctx)
{
  // 用来线程间交互的一种通信方式，暂时没用到
  // void * thread_ctx  = struct spdk_cache_thread
}

static int 
spdk_cache_init_thread(struct thread_data *td)
{
  assert ( td != NULL);
  struct spdk_cache_thread * cache_thread;
  cache_thread = calloc(1, sizeof(*cache_thread));
  if (!cache_thread) {
    SPDK_ERRLOG("failed to allocate thread local context\n");
    goto err;
  }
  cache_thread->td = td;
  td->cache_thread = cache_thread;
  cache_thread->ring = spdk_ring_create(SPDK_RING_TYPE_MP_SC, RING_SIZE, SPDK_ENV_SOCKET_ID_ANY);

  if (!cache_thread->ring) {
    SPDK_ERRLOG("failed to allocate ring\n");
    free(cache_thread);
    goto err;
  }
  cache_thread->thread = spdk_allocate_thread(spdk_cache_send_msg, spdk_cache_start_poller,
                                   spdk_cache_stop_poller, cache_thread, td->t_options->thread_name);

  if (!cache_thread->thread) {
    spdk_ring_free(cache_thread->ring);
    free(cache_thread);
    SPDK_ERRLOG("failed to allocate thread\n");
    goto err;
  }

  return 0;

err:
  return -1;
}

static void
spdk_cache_bdev_init_done(void *cb_arg, int rc)
{
  *(bool *)cb_arg = true;
}

static int
spdk_cache_init(struct thread_data *td)
{
  struct spdk_cache_thread *ct = NULL;
  struct thread_options *t_op = NULL;
  int rc = 0;

  rc = spdk_cache_init_thread(td);
  if (rc < 0) {
    printf(" Error: spdk_cache_init_thread \n");
    goto err;
  }
  t_op = td->t_options;
  ct = td->cache_thread;

  assert(t_op->name != NULL);
  // 这里决定了当前线程的io隧道的目标设备ssd还是hdd
  ct->bdev = spdk_bdev_get_by_name(t_op->name);
  if (!ct->bdev) {
    SPDK_ERRLOG("Unable to find bdev with name %s\n", t_op->name);
    rc = -1;
    goto err;
  }
      rc = spdk_bdev_open(ct->bdev, true, NULL, NULL, &ct->desc);
  if (rc < 0) {
    SPDK_ERRLOG("Unable to open bdev %s\n", t_op->name);
    goto err;
  }
  ct->ch = spdk_bdev_get_io_channel(ct->desc);
  if (!ct->ch) {
    SPDK_ERRLOG("Unable to get I/O channel for bdev.\n");
    spdk_bdev_close(ct->desc);
    rc = -1;
    goto err;
  }
  return 0;
err:
  return rc;
}

static void 
spdk_cache_io_completion_cb(struct spdk_bdev_io * bdev_io, bool success, void *cb_arg)
{
  printf("<%s> AIO IO Completion success=%d \n", __func__, success);
  struct ring_item *item = cb_arg;
  item->io.success=success;
  item->iou_completion_cb(item->iou_arg);
  // 对于AIO来说，一次IO完成成功，那么释放掉bdev_io，如果失败呢？
  // 是否直接抛给上层，然后释放掉bdev_io？还是说重新入队列?进入重试？
  spdk_bdev_free_io(bdev_io);
}

static int 
cache_thread_fn(void * cb)
{
  struct thread_data *td = NULL;
  struct thread_options *t_op = NULL;
  struct spdk_cache_thread *ct=NULL;
  spdk_bdev_io_completion_cb io_completion = NULL;
  struct ring_item *item = NULL;
  size_t ring_counts;
  int count;
  int rc;
  int ret = 0;

  assert( cb != NULL);

  td = cb;
  if ( td->t_options == NULL ) {
    assert("t_options is need for a thread");
  } 
  t_op = td->t_options;
  rc = spdk_cache_init(td);
  if (rc < 0) {
    // 这里有待商榷，加入因为资源问题导致某一个线程创建失败，这时候应该如何处理？
    assert("spdk cache init faild" == 0);
  }
  ct = td->cache_thread;
  // ssd和hdd的写完成处理在aio这一层逻辑保持一致，直接回调上层的cb，ssd和hdd的上层iou_completion_cb
  // 可以根据上层逻辑来处理
  io_completion = spdk_cache_io_completion_cb;
  /*switch (t_op->type) {*/
      /*case CACHE_THREAD_CACHE: */
          /*io_completion = spdk_cache_io_completion_cb;*/
          /*break;*/
      /*case CACHE_THREAD_BACKEND:*/
          /*io_completion = spdk_backend_io_completion_cb;*/
          /*break;*/
      /*default:*/
          /*assert(" Unknow cache thread type " == 0);*/
  /*}*/
  while(1) {
    ring_counts = spdk_ring_count(ct->ring);
    if ( ring_counts == 0 ) {
      pthread_mutex_lock(&ct->wait_mutex);
      pthread_cond_wait(&ct->wait_cond, &ct->wait_mutex);
      pthread_mutex_unlock(&ct->wait_mutex);
      continue;
    } 
    while ( ring_counts ) {
      // 1. dequeue不需要给ring_item分配空间
      // 2.ring_item会用作为io_completion的回调参数，因此，还不能在dequeue的时候释放
      // 这段区间，需要在上层根据IO的周期来释放
      count = spdk_ring_dequeue(ct->ring, (void **)&item, 1);
      if ( count == 1) {
        switch ( item->io.type ) {
          case CACHE_IO_TYPE_WRITE:
            printf(" start bdev write io.offset=%lu, io.len=%lu\n", item->io.offset, item->io.len);
            ret = spdk_bdev_write(ct->desc, ct->ch, item->io.pos, item->io.offset, item->io.len,
                            io_completion, item);
            if ( ret < 0 ) {
              assert(" write error ---------- " == 0);
            }
            break;
          case CACHE_IO_TYPE_READ:
            ret = spdk_bdev_read(ct->desc, ct->ch, item->io.pos, item->io.offset, item->io.len,
                            io_completion, item);
            if (ret < 0) {
              assert(" read error ---------- " == 0);
            }
            break;
          default:
            assert(" Unsupporte IO type " == 0);
          }
        }
      }
    ring_counts--;
    }
}

static int 
spdk_cache_setup(struct thread_data *td)
{
  int ret = 0;
  struct spdk_conf                *config = NULL;
  struct spdk_env_opts            opts;
  struct thread_options           *to = NULL;
  size_t                          count;
  int done;
    
  to = td->t_options;
	
  config = spdk_conf_allocate();
  if (!config) {
    SPDK_ERRLOG("Unable to allocate configuration file\n");
    goto err;
  }
  assert(config != NULL);
  ret = spdk_conf_read(config, to->conf);
  if (ret < 0) {
    SPDK_ERRLOG("Invalid configuration file format\n");
    goto err;
  }
  if (spdk_conf_first_section(config) == NULL) {
    SPDK_ERRLOG("Invalid configuration file format\n");
    goto free_conf;
  }
  spdk_conf_set_as_default(config);
  spdk_env_opts_init(&opts);
  opts.name = "t2cache";
  /*opts.core_mask = "0x03";*/
  /*opts.core_mask = "0x0f";*/
  opts.core_mask = "0x07";
  if (spdk_env_init(&opts) < 0) {
    SPDK_ERRLOG("Unable to initialize SPDK env\n");
    goto free_conf;
  }
  spdk_unaffinitize_thread();

  ret = spdk_cache_init_thread(td);
  if (ret < 0) {
    SPDK_ERRLOG("Failed to create initialization thread\n");
    goto free_conf;
  }
  spdk_bdev_initialize(spdk_cache_bdev_init_done, &done); 

  return 0;
free_conf:
  spdk_conf_free(config);
err:
  return -1;
}

struct thread_data *
get_thread_data(uint16_t type, struct aio_handler * handler)
{
  struct thread_data *p=NULL, *tmp=NULL;
  uint32_t thread_seq = 0;
  uint32_t need_seq = -1;
  pthread_t pthread_id = pthread_self();
  need_seq = pthread_id%handler->nr_cache;
  switch (type) {
    case CACHE_THREAD_CACHE:
      TAILQ_FOREACH_SAFE(p, &handler->cache_threads, node, tmp) {
        if ( thread_seq == need_seq ) {
          return p;
        }
        thread_seq++;
      }
      break;
    case CACHE_THREAD_BACKEND:
      TAILQ_FOREACH_SAFE(p, &handler->backend_threads, node, tmp) {
        if ( thread_seq == need_seq ) {
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
aio_enqueue(uint16_t type, struct aio_handler *h, struct ring_item *item)
{
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
    count = spdk_ring_enqueue(td->cache_thread->ring, (void **)&item, 1);
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
create_new_thread(struct thread_options *t_options)
{
  int rc = 0;
  struct thread_data *td = NULL;
  td = calloc(1, sizeof(*td));
  if (td) {
    td->t_options = t_options;
  }
  return td;
}

/*int main(int argc, char **argv)*/
void *
aio_init(void * ca)
{
  if ( g_handler ) {
    return (void *)g_handler;
  }

  int ret = 0;
  int lcore;
  char *path = "/etc/ceph/bdev.conf.in";
  struct thread_options *t_options = NULL;
  struct thread_data *td1 = NULL;
  struct aio_handler *handler = NULL;
  
  handler = calloc(1, sizeof(*handler));
  t_options = calloc(1, sizeof(*t_options));
  t_options->conf = path;
  t_options->type = CACHE_THREAD_CACHE;
  t_options->name = "AIO0";
  t_options->thread_name = "aio_init_thread";
  /*t_options->period_microseconds = 1000000;*/
  t_options->period_microseconds = 100000;

  td1 = create_new_thread(t_options);
  assert ( td1 != NULL);

  ret = spdk_cache_setup(td1);
  if ( ret < 0 ) {
    assert(" spdk_cache_setup faild " == 0);
  }

  /*uint32_t max;*/
  /*max = spdk_env_get_core_count();*/

  struct thread_options *hdd_options;
  struct thread_options *ssd_options;

  hdd_options = calloc(1, sizeof(*hdd_options));
  ssd_options = calloc(1, sizeof(*ssd_options));

  hdd_options->name = "AIO1";
  hdd_options->thread_name = "aio_hdd_thread";
  hdd_options->conf = path;
  hdd_options->period_microseconds = 1000000;
  hdd_options->type = CACHE_THREAD_BACKEND;

  ssd_options->name = "AIO0";
  ssd_options->thread_name = "aio_cache_thread";
  ssd_options->conf = path;
  ssd_options->type = CACHE_THREAD_CACHE;
  ssd_options->period_microseconds = 1000000;


  TAILQ_INIT(&handler->cache_threads);
  TAILQ_INIT(&handler->backend_threads);

  SPDK_ENV_FOREACH_CORE(lcore) {
    struct thread_data *td=NULL;
    if (lcore == 0) {
      continue;
    }
    if ( lcore <= 1 ) {
      td = create_new_thread(ssd_options);
      spdk_env_thread_launch_pinned(lcore, cache_thread_fn, (void *)td);
      td->lcore = lcore;
      handler->nr_cache++;
      TAILQ_INSERT_TAIL(&handler->cache_threads, td , node);
    } else {
      td = create_new_thread(hdd_options);
      td->lcore = lcore;
      spdk_env_thread_launch_pinned(lcore, cache_thread_fn, (void *)td);
      handler->nr_backend++;
      TAILQ_INSERT_TAIL(&handler->backend_threads, td , node);
      }
  }

  sleep(2);
  g_handler = handler;
  return (void *)handler;
}
