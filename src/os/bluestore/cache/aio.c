#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <libaio.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "aio.h"
#include "kfifo.h"
#include "list.h"


//#include <rte_lcore.h>

/*struct aio_handler;*/
struct thread_data;

struct aio_handler *g_handler = NULL;
#define RING_SIZE 4096


struct cache_thread {
    pthread_mutex_t wait_mutex;
    pthread_cond_t wait_cond;
    struct thread_data * td;
    DECLARE_KFIFO_PTR(ring, struct ring_item*);
    pthread_spinlock_t ring_lock;
    int fd;
    int efd;
    int epfd;
    struct epoll_event epevent;
};

struct thread_options {
    uint16_t type;
    char *name;
    io_context_t *ioctx;
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
    struct list_head   cache_threads;
    struct list_head  backend_threads;
    io_context_t ioctx;
};

static void *
cache_io_completion_cb(io_context_t ctx, struct iocb *iocb, long res,
                       long res2, struct ring_item *item)
{
    printf("<%s> AIO IO Completion success=%ld \n", __func__, res);
    free(iocb);
    assert(res2==0);
    item->iou_completion_cb(item->iou_arg);
}

void *
poller_fn(void *arg){
    struct thread_data *td = (struct thread_data *)arg;


    struct io_event* events = malloc(sizeof(struct  io_event) * 2);
    struct timespec timeout;
    int i;
    uint64_t finished_aio;

    int num_events;

    timeout.tv_sec = 0;
    timeout.tv_nsec = 100000000;

    while (td->runing){
        if(epoll_wait(td->cache_thread->epfd, &td->cache_thread->epevent, 1, -1) < 1){
            assert("epoll_wait" == 0);
        }
        if (read(td->cache_thread->efd, &finished_aio, sizeof(finished_aio)) != sizeof(finished_aio)) {
            assert("epoll read" == 0);
        }
        while(1){
            num_events = io_getevents(*td->t_options->ioctx, 1, 2, events, &timeout);
            if (num_events == 0){
                break;
            }

            for (i = 0; i < num_events; i++) {
                struct io_event event = events[i];
                cache_io_completion_cb(*td->t_options->ioctx, event.obj,
                                       event.res, event.res2, event.data);
            }
        }


    }
    free(events);
}

static int
cache_init(struct thread_data *td)
{
    struct thread_options *t_op = td->t_options;
    struct cache_thread * cache_thread;
    pthread_t poller_td;
    int rc = 0;

    cache_thread = calloc(1, sizeof(*cache_thread));
    if (!cache_thread) {
        printf("failed to allocate thread local context\n");
        goto err;
    }

    cache_thread->td = td;
    td->cache_thread = cache_thread;


    pthread_spin_init(&cache_thread->ring_lock, 1);
    INIT_KFIFO(cache_thread->ring);
    rc = kfifo_alloc(&cache_thread->ring, RING_SIZE);
    if (rc) {
        printf("failed to allocate ring\n");
        free(cache_thread);
        goto err;
    }

    cache_thread->fd = open(t_op->name , O_RDWR | O_DIRECT | O_CREAT, 0644);
    cache_thread->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    cache_thread->epfd = epoll_create(1);
    cache_thread->epevent.events = EPOLLIN | EPOLLET;
    cache_thread->epevent.data.ptr = NULL;
    epoll_ctl(cache_thread->epfd , EPOLL_CTL_ADD, cache_thread->efd, &cache_thread->epevent);
    assert(cache_thread->fd > -1);

    rc = pthread_create(&poller_td, NULL, poller_fn, td);
    if (rc) {
        kfifo_free(&cache_thread->ring);
        free(cache_thread);
        printf("failed to allocate thread\n");
        goto err;
    }

    return 0;
err:
    return rc;
}


void *
cache_thread_fn(void * cb)
{
    struct thread_data *td = NULL;
    struct cache_thread *ct=NULL;
    struct ring_item *item = NULL;
    size_t ring_counts;
    int count;
    int rc;
    struct iocb *iocb;

    assert( cb != NULL);

    td = cb;
    if ( td->t_options == NULL ) {
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
        ring_counts = kfifo_len(&ct->ring);
        pthread_spin_unlock(&ct->ring_lock);

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
            pthread_spin_lock(&ct->ring_lock);
            count = kfifo_get(&ct->ring, &item);
            pthread_spin_unlock(&ct->ring_lock);

            if ( count == 1) {
                iocb = calloc(1, sizeof(struct iocb));
                switch ( item->io.type ) {
                    case CACHE_IO_TYPE_WRITE:
                        io_prep_pwrite(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
                        break;
                    case CACHE_IO_TYPE_READ:
                        io_prep_pread(iocb, ct->fd, item->io.pos, item->io.len, item->io.offset);
                        break;
                    default:
                        assert(" Unsupporte IO type " == 0);
                }

                io_set_eventfd(iocb, ct->efd);
                iocb->data = item;
                // TODO: submit multi-request
                rc = io_submit(*td->t_options->ioctx, 1, &iocb);
                assert(rc==1);
            }
            ring_counts--;
        }
    }
}


struct thread_data *
get_thread_data(uint16_t type, struct aio_handler * handler)
{
    struct thread_data *p=NULL, *tmp=NULL;
    uint32_t thread_seq = 0;
    uint32_t need_seq = 0;
    pthread_t pthread_id = pthread_self();
    need_seq = pthread_id%handler->nr_cache;
    switch (type) {
        case CACHE_THREAD_CACHE:
            list_for_each_entry(p, &handler->cache_threads, node) {
                if ( thread_seq == need_seq ) {
                    return p;
                }
                thread_seq++;
            }
            break;
        case CACHE_THREAD_BACKEND:
            list_for_each_entry(p, &handler->backend_threads, node) {
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
create_new_thread_data(struct thread_options *t_options)
{
	struct thread_data *td = NULL;
	td = calloc(1, sizeof(*td));
    if (td) {
	    td->t_options = t_options;
	    td->runing = true;
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
    uint32_t lcore;
    struct thread_options *cache_options = NULL;
    struct thread_options *hdd_options = NULL;
	struct thread_data *td1 = NULL;
    struct aio_handler *handler = NULL;
    io_context_t *iocxt;
    
    handler = calloc(1, sizeof(*handler));
    io_setup(1000, &handler->ioctx);


	cache_options = calloc(1, sizeof(*cache_options));
    cache_options->type = CACHE_THREAD_CACHE;
    cache_options->name = "/dev/sdc";
    /*cache_options->period_microseconds = 1000000;*/
    cache_options->period_microseconds = 100000;
    cache_options->ioctx = &handler->ioctx;

	td1 = create_new_thread_data(cache_options);
    assert ( td1 != NULL);


    hdd_options = calloc(1, sizeof(*hdd_options));
    hdd_options->name = "/dev/sdd";
    hdd_options->period_microseconds = 1000000;
    hdd_options->type = CACHE_THREAD_BACKEND;
    hdd_options->ioctx = &handler->ioctx;

    INIT_LIST_HEAD(&handler->cache_threads);
    INIT_LIST_HEAD(&handler->backend_threads);

    for (lcore = 1; lcore < 4; lcore++){
	    struct thread_data *td=NULL;
        if (lcore == 0) {
            continue;
        }
        if ( lcore <= 2 ) {
	        td = create_new_thread_data(cache_options);
            pthread_create(&td->td, NULL, cache_thread_fn, (void *)td);
            td->lcore = lcore;
            handler->nr_cache++;
            list_add(&td->node, &handler->cache_threads);
        } else {
	        td = create_new_thread_data(hdd_options);
            td->lcore = lcore;
            pthread_create(&td->td, NULL, cache_thread_fn, (void *)td);
            handler->nr_backend++;
            list_add(&td->node, &handler->backend_threads);
        }
	}
    sleep(2);
    g_handler = handler;
	return (void *)handler;
}
