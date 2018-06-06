#include "delayed_work.h"
#include "log.h"

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

void delayed_work_assign(struct event *ev, struct event_base *base, void (*callback)(evutil_socket_t, short, void *), void *arg)
{
  CACHE_DEBUGLOG(CAT_EVENT, "assign delay event\n");
  event_assign(ev, base, -1, 0, callback, arg);
}

static void timeout_cb(evutil_socket_t fd, short events, void *arg) {
  // Nothing to do for this func
  CACHE_DEBUGLOG(CAT_EVENT, "dispatch\n");
}

static int delayed_work_func(void *arg)
{
  struct event_base *base = arg;
  int flags = EV_PERSIST;
  struct event timer_ev;
  struct timeval tv;

  event_assign(&timer_ev, base, -1, flags, timeout_cb, (void*)&timer_ev);
  evutil_timerclear(&tv);
  tv.tv_sec = 5;
  event_add(&timer_ev, &tv);

  event_base_dispatch(base);
  event_base_free(base);

  return 0;
}

struct event_base *bch_delayed_work_init()
{
  int err = 0;
  struct event_base *base;
  pthread_t thread_delayed_event;

  evthread_use_pthreads();
  base = event_base_new();

  err = pthread_create(&thread_delayed_event, NULL, (void *)delayed_work_func, (void *)base);
  if (err != 0) {
    CACHE_DEBUGLOG(CAT_EVENT, "can't create writeback thread:%s\n", strerror(err));
    return err;
  }

  return base;
}
