#include <string.h>
#include <pthread.h>

#include "bcache.h"
#include "delayed_work.h"
#include "log.h"

static struct event timer_ev;
static pthread_t thread_delayed_td = NULL;

void delayed_work_add(struct event *ev, struct timeval *tv)
{
  CACHE_DEBUGLOG(CAT_EVENT, "add delay event\n");
  event_add(ev, tv);
}

void delayed_work_del(struct event *ev)
{
  CACHE_DEBUGLOG(CAT_EVENT, "del delay event\n");
  event_del(ev);
}

void delayed_work_assign(struct event *ev, struct event_base *base, void (*callback)(evutil_socket_t, short, void *), void *arg, int flags)
{
  CACHE_DEBUGLOG(CAT_EVENT, "assign delay event\n");
  event_assign(ev, base, -1, flags, callback, arg);
}

static void timeout_cb(evutil_socket_t fd, short events, void *arg) {
  // Nothing to do for this func
  CACHE_DEBUGLOG(CAT_EVENT, "dispatch\n");
}

static int delayed_work_func(void *arg)
{
  struct event_base *base = arg;
  int flags = EV_PERSIST;
  struct timeval tv;

  // Note: pthread_setname_np will throw Segmentation fault.
  //pthread_setname_np(pthread_self(), "delayed work");
  event_assign(&timer_ev, base, -1, flags, timeout_cb, (void*)&timer_ev);
  evutil_timerclear(&tv);
  tv.tv_sec = 5;
  event_add(&timer_ev, &tv);

  event_base_dispatch(base);
  event_base_free(base);
  CACHE_INFOLOG(CAT_EVENT, "delayed_work_func exit\n");

  return 0;
}

struct event_base *bch_delayed_work_init()
{
  int err = 0;
  struct event_base *base;

  evthread_use_pthreads();
  base = event_base_new();

  err = pthread_create(&thread_delayed_td, NULL, (void *)delayed_work_func, (void *)base);
  if (err != 0) {
    CACHE_DEBUGLOG(CAT_EVENT, "can't create writeback thread:%s\n", strerror(err));
    return NULL;
  }

  return base;
}

void bch_delayed_work_stop(struct cache_set *c){
  int err;
  CACHE_INFOLOG(CAT_EVENT, "Try stop delayed work\n");
  if (!c->ev_base){
    return ;
  }
  event_base_loopbreak(c->ev_base);
  // Todo: stop event;
  err = pthread_join(thread_delayed_td, NULL);
  // todo: write log
  cache_bug_on(err != 0, c, "Delayed work wait failed: %s\n", strerror(err));
}
