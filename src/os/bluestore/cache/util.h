/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BCACHE_UTIL_H
#define _BCACHE_UTIL_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <sys/time.h>
#include <sys/user.h>

#include "bcache_types.h"
#include "rbtree.h"
#include "rbtree_augmented.h"

#define HZ 100

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

static struct timespec cache_clock_now()
{
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  return tp;
}

static inline struct timespec time_from_now(uint64_t sec, uint64_t nsec)
{
  struct timeval now;
  struct timespec out;
  gettimeofday(&now, NULL);
  out.tv_sec = now.tv_sec + sec;
  out.tv_nsec = now.tv_usec * NSEC_PER_USEC + nsec;

  out.tv_sec += out.tv_nsec / NSEC_PER_SEC;
  out.tv_nsec = out.tv_nsec % NSEC_PER_SEC;

  return out;
}


static uint64_t cache_realtime_u64()
{
  struct timespec now = cache_clock_now();

  return now.tv_sec * NSEC_PER_SEC + now.tv_nsec;
}

/* PAGE_SIZE is defined in sys/user.h */
#define PAGE_SECTORS		(PAGE_SIZE / 512)

#define DECLARE_HEAP(type, name)                                \
  struct {                                              	\
    size_t size, used;                                          \
    type *data;                                                 \
  } name

#define init_heap(heap, _size)                                  \
({                                                              \
  size_t _bytes;                                                \
  (heap)->used = 0;                                             \
  (heap)->size = (_size);                                       \
  _bytes = (heap)->size * sizeof(*(heap)->data);                \
  (heap)->data = malloc(_bytes);                                \
  (heap)->data;                                                 \
})

#define free_heap(heap)                                         \
do {                                                            \
  free((heap)->data);                                           \
  (heap)->data = NULL;                                          \
} while (0)

#define heap_swap(h, i, j)	swap((h)->data[i], (h)->data[j])

#define heap_sift(h, i, cmp)						\
do {									\
	size_t _r, _j = i;						\
									\
	for (; _j * 2 + 1 < (h)->used; _j = _r) {			\
		_r = _j * 2 + 1;					\
		if (_r + 1 < (h)->used &&				\
		    cmp((h)->data[_r], (h)->data[_r + 1]))		\
			_r++;						\
									\
		if (cmp((h)->data[_r], (h)->data[_j]))			\
			break;						\
		heap_swap(h, _r, _j);					\
	}								\
} while (0)

#define heap_sift_down(h, i, cmp)					\
do {									\
	while (i) {							\
		size_t p = (i - 1) / 2;					\
		if (cmp((h)->data[i], (h)->data[p]))			\
			break;						\
		heap_swap(h, i, p);					\
		i = p;							\
	}								\
} while (0)

#define heap_add(h, d, cmp)						\
({									\
	bool _r = !heap_full(h);					\
	if (_r) {							\
		size_t _i = (h)->used++;				\
		(h)->data[_i] = d;					\
									\
		heap_sift_down(h, _i, cmp);				\
		heap_sift(h, _i, cmp);					\
	}								\
	_r;								\
})

#define heap_pop(h, d, cmp)						\
({									\
	bool _r = (h)->used;						\
	if (_r) {							\
		(d) = (h)->data[0];					\
		(h)->used--;						\
		heap_swap(h, 0, (h)->used);				\
		heap_sift(h, 0, cmp);					\
	}								\
	_r;								\
})

#define heap_peek(h)	((h)->used ? (h)->data[0] : NULL)

#define heap_full(h)	((h)->used == (h)->size)

#define DECLARE_FIFO(type, name)					\
	struct {							\
		size_t front, back, size, mask;				\
		type *data;						\
	} name

#define fifo_for_each(c, fifo, iter)					\
	for (iter = (fifo)->front;					\
	     c = (fifo)->data[iter], iter != (fifo)->back;		\
	     iter = (iter + 1) & (fifo)->mask)


/*
 * fifo的data是一个atomic_t类型（int），这里的size指的是这个队列中有多少个
 * atomic_t类型的数，可以理解为data是一个长度为size的整型数组。
 */
#define __init_fifo(fifo)						\
({									\
	size_t _allocated_size, _bytes;					\
	BUG_ON(!(fifo)->size);						\
									\
        _allocated_size = roundup_pow_of_two((fifo)->size + 1);         \
	_bytes = _allocated_size * sizeof(*(fifo)->data);		\
									\
	(fifo)->mask = _allocated_size - 1;				\
	(fifo)->front = (fifo)->back = 0;				\
									\
	(fifo)->data = malloc(_bytes);                  		\
	(fifo)->data;							\
})

#define init_fifo_exact(fifo, _size)    				\
({									\
	(fifo)->size = (_size);						\
	__init_fifo(fifo);						\
})

/*
 * roundup_pow_of_two(size): include/linux/log2.h
 * 意思是取最接近2的n次方且大于size的值，即向上扩展为2的整数次幂
 */
#define init_fifo(fifo, _size)  					\
({									\
	(fifo)->size = (_size);						\
	if ((fifo)->size > 4)						\
		(fifo)->size = (fifo)->size - 1;                	\
	__init_fifo(fifo);						\
})

#define free_fifo(fifo)							\
do {									\
	free((fifo)->data);						\
	(fifo)->data = NULL;						\
} while (0)

#define fifo_used(fifo)		(((fifo)->back - (fifo)->front) & (fifo)->mask)
#define fifo_free(fifo)		((fifo)->size - fifo_used(fifo))

#define fifo_empty(fifo)	(!fifo_used(fifo))
#define fifo_full(fifo)		(!fifo_free(fifo))

#define fifo_front(fifo)	((fifo)->data[(fifo)->front])
#define fifo_back(fifo)							\
	((fifo)->data[((fifo)->back - 1) & (fifo)->mask])

#define fifo_idx(fifo, p)	(((p) - &fifo_front(fifo)) & (fifo)->mask)

#define fifo_push_back(fifo, i)						\
({									\
	bool _r = !fifo_full((fifo));					\
	if (_r) {							\
		(fifo)->data[(fifo)->back++] = (i);			\
		(fifo)->back &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_pop_front(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r) {							\
		(i) = (fifo)->data[(fifo)->front++];			\
		(fifo)->front &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_push_front(fifo, i)					\
({									\
	bool _r = !fifo_full((fifo));					\
	if (_r) {							\
		--(fifo)->front;					\
		(fifo)->front &= (fifo)->mask;				\
		(fifo)->data[(fifo)->front] = (i);			\
	}								\
	_r;								\
})

#define fifo_pop_back(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r) {							\
		--(fifo)->back;						\
		(fifo)->back &= (fifo)->mask;				\
		(i) = (fifo)->data[(fifo)->back]			\
	}								\
	_r;								\
})

#define fifo_push(fifo, i)	fifo_push_back(fifo, (i))
#define fifo_pop(fifo, i)	fifo_pop_front(fifo, (i))

#define fifo_swap(l, r)							\
do {									\
	swap((l)->front, (r)->front);					\
	swap((l)->back, (r)->back);					\
	swap((l)->size, (r)->size);					\
	swap((l)->mask, (r)->mask);					\
	swap((l)->data, (r)->data);					\
} while (0)

#define fifo_move(dest, src)						\
do {									\
	typeof(*((dest)->data)) _t;					\
	while (!fifo_full(dest) &&					\
	       fifo_pop(src, _t))					\
		fifo_push(dest, _t);					\
} while (0)

/*
 * Simple array based allocator - preallocates a number of elements and you can
 * never allocate more than that, also has no locking.
 *
 * Handy because if you know you only need a fixed number of elements you don't
 * have to worry about memory allocation failure, and sometimes a mempool isn't
 * what you want.
 *
 * We treat the free elements as entries in a singly linked list, and the
 * freelist as a stack - allocating and freeing push and pop off the freelist.
 */

#define DECLARE_ARRAY_ALLOCATOR(type, name, size)			\
	struct {							\
		type	*freelist;					\
		type	data[size];					\
	} name

#define array_alloc(array)						\
({									\
	typeof((array)->freelist) _ret = (array)->freelist;		\
									\
	if (_ret)							\
		(array)->freelist = *((typeof((array)->freelist) *) _ret);\
									\
	_ret;								\
})

#define array_free(array, ptr)						\
do {									\
	typeof((array)->freelist) _ptr = ptr;				\
									\
	*((typeof((array)->freelist) *) _ptr) = (array)->freelist;	\
	(array)->freelist = _ptr;					\
} while (0)

#define array_allocator_init(array)					\
do {									\
	typeof((array)->freelist) _i;					\
									\
	(array)->freelist = NULL;					\
									\
	for (_i = (array)->data;					\
	     _i < (array)->data + ARRAY_SIZE((array)->data);		\
	     _i++)							\
		array_free(array, _i);					\
} while (0)

#define array_freelist_empty(array)	((array)->freelist == NULL)

#define ANYSINT_MAX(t)							\
	((((t) 1 << (sizeof(t) * 8 - 2)) - (t) 1) * (t) 2 + (t) 1)

int bch_strtoint_h(const char *, int *);
int bch_strtouint_h(const char *, unsigned int *);
int bch_strtoll_h(const char *, long long *);
int bch_strtoull_h(const char *, unsigned long long *);

bool bch_is_zero(const unsigned char *p, int n);
int bch_parse_uuid(const char *s, char *uuid);

ssize_t bch_read_string_list(const char *buf, const char * const list[]);

struct time_stats {
  //spinlock_t      lock; 
  pthread_spinlock_t lock;
  uint64_t	max_duration;
  uint64_t	average_duration;
  uint64_t	average_frequency;
  uint64_t	last;
};

void bch_time_stats_update(struct time_stats *stats, uint64_t time);

static inline unsigned local_clock_us(void)
{
  return 0;
  //return local_clock() >> 10;
}

#define NSEC_PER_ns			1L
#define NSEC_PER_us			NSEC_PER_USEC
#define NSEC_PER_ms			NSEC_PER_MSEC
#define NSEC_PER_sec			NSEC_PER_SEC

#define __print_time_stat(stats, name, stat, units)			\
	sysfs_print(name ## _ ## stat ## _ ## units,			\
		    div_u64((stats)->stat >> 8, NSEC_PER_ ## units))

#define ewma_add(ewma, val, weight, factor)				\
({									\
	(ewma) *= (weight) - 1;						\
	(ewma) += (val) << factor;					\
	(ewma) /= (weight);						\
	(ewma) >> factor;						\
})

struct bch_ratelimit {
  /* Next time we want to do some work, in nanoseconds */
  uint64_t		next;
  /*
   * Rate at which we want to do work, in units per nanosecond
   * The units here correspond to the units passed to bch_next_delay()
   */
  unsigned		rate;
};

static inline void bch_ratelimit_reset(struct bch_ratelimit *d)
{
  d->next = cache_realtime_u64();
}

uint64_t bch_next_delay(struct bch_ratelimit *d, uint64_t done);
int get_random_bytes(void *buf, int len);

#define __DIV_SAFE(n, d, zero)						\
({									\
	typeof(n) _n = (n);						\
	typeof(d) _d = (d);						\
	_d ? _n / _d : zero;						\
})

#define DIV_SAFE(n, d)	__DIV_SAFE(n, d, 0)

#define container_of_or_null(ptr, type, member)				\
({									\
	typeof(ptr) _ptr = ptr;						\
	_ptr ? container_of(_ptr, type, member) : NULL;			\
})

#define RB_INSERT(root, new, member, cmp)				\
({									\
	__label__ dup;							\
	struct rb_node **n = &(root)->rb_node, *parent = NULL;		\
	typeof(new) this;						\
	int res, ret = -1;						\
									\
	while (*n) {							\
		parent = *n;						\
		this = container_of(*n, typeof(*(new)), member);	\
		res = cmp(new, this);					\
		if (!res)						\
			goto dup;					\
		n = res < 0						\
			? &(*n)->rb_left				\
			: &(*n)->rb_right;				\
	}								\
									\
	rb_link_node(&(new)->member, parent, n);			\
	rb_insert_color(&(new)->member, root);				\
	ret = 0;							\
dup:									\
	ret;								\
})

#define RB_SEARCH(root, search, member, cmp)				\
({									\
	struct rb_node *n = (root)->rb_node;				\
	typeof(&(search)) this, ret = NULL;				\
	int res;							\
									\
	while (n) {							\
		this = container_of(n, typeof(search), member);		\
		res = cmp(&(search), this);				\
		if (!res) {						\
			ret = this;					\
			break;						\
		}							\
		n = res < 0						\
			? n->rb_left					\
			: n->rb_right;					\
	}								\
	ret;								\
})

#define RB_GREATER(root, search, member, cmp)				\
({									\
	struct rb_node *n = (root)->rb_node;				\
	typeof(&(search)) this, ret = NULL;				\
	int res;							\
									\
	while (n) {							\
		this = container_of(n, typeof(search), member);		\
		res = cmp(&(search), this);				\
		if (res < 0) {						\
			ret = this;					\
			n = n->rb_left;					\
		} else							\
			n = n->rb_right;				\
	}								\
	ret;								\
})

#define RB_FIRST(root, type, member)					\
	container_of_or_null(rb_first(root), type, member)

#define RB_LAST(root, type, member)					\
	container_of_or_null(rb_last(root), type, member)

#define RB_NEXT(ptr, member)						\
	container_of_or_null(rb_next(&(ptr)->member), typeof(*ptr), member)

#define RB_PREV(ptr, member)						\
	container_of_or_null(rb_prev(&(ptr)->member), typeof(*ptr), member)

/* Does linear interpolation between powers of two */
static inline unsigned fract_exp_two(unsigned x, unsigned fract_bits)
{
  unsigned fract = x & ~(~0 << fract_bits);
  x >>= fract_bits;
  x   = 1 << x;
  x  += (x * fract) >> fract_bits;

  return x;
}

uint64_t bch_crc64_update(uint64_t, const void *, size_t);
uint64_t bch_crc64(const void *, size_t);

void * T2Molloc(size_t size);
#define T2Free(data)            \
  memset(data, 0, sizeof(*data)); \
  free(data);             \
	data = NULL
#endif /* _BCACHE_UTIL_H */
