#ifndef _BCACHE_DELAYED_WORK_H
#define _BCACHE_DELAYED_WORK_H

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/util.h>

typedef void (*event_callback_fn)(evutil_socket_t, short, void *);

void delayed_work_add(struct event *, unsigned int);
void delayed_work_del(struct event *);
void delayed_work_assign(struct event *, struct event_base *, event_callback_fn, void *);

struct event_base *bch_delayed_work_init();

#endif
