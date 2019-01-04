/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2015 Intel Corporation
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>

#include "rte_ring.h"


/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/**
 * Combines 32b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param x
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
static inline uint32_t
rte_combine32ms1b(register uint32_t x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x;
}

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to algin
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t
rte_align32pow2(uint32_t x)
{
	x--;
	x = rte_combine32ms1b(x);

	return x + 1;
}

int
rte_ring_init(struct rte_ring *r, unsigned count,
	unsigned flags)
{
	int ret;

	/* init the ring structure */
	memset(r, 0, sizeof(*r));
	r->flags = flags;
	r->prod.single = (flags & RING_F_SP_ENQ) ? __IS_SP : __IS_MP;
	r->cons.single = (flags & RING_F_SC_DEQ) ? __IS_SC : __IS_MC;

	if (flags & RING_F_EXACT_SZ) {
		r->size = rte_align32pow2(count + 1);
		r->mask = r->size - 1;
		r->capacity = count;
	} else {
		if ((!POWEROF2(count)) || (count > RTE_RING_SZ_MASK)) {
			assert(0 == "Requested size is invalid, must be power of 2, and not exceed the size limit \n");
			return -EINVAL;
		}
		r->size = count;
		r->mask = count - 1;
		r->capacity = r->mask;
	}
	r->prod.head = r->cons.head = 0;
	r->prod.tail = r->cons.tail = 0;

	return 0;
}

/* create the ring */
struct rte_ring *
rte_ring_create(unsigned count, unsigned flags)
{
	struct rte_ring *r;
	void *mz;
	int mz_flags = 0;
	const unsigned int requested_count = count;
	int ret;

	/* for an exact size ring, round up from count to a power of two */
	if (flags & RING_F_EXACT_SZ)
		count = rte_align32pow2(count + 1);


        r = malloc(sizeof(struct rte_ring));
        if (unlikely(r == NULL)) {
          return NULL;
        }
	rte_ring_init(r, requested_count, flags);

	/* reserve a memory zone for this ring. If we can't get rte_config or
	 * we are secondary process, the memzone_reserve function will set
	 * rte_errno for us appropriately - hence no check in this this function */
	mz = calloc(requested_count, sizeof(void *));
	if (mz != NULL) {
		r->memzone = mz;

	} else {
		free(r);
		r = NULL;
		assert(0 == "Cannot reserve memory\n");
	}
	return r;
}

/* free the ring */
void
rte_ring_free(struct rte_ring *r)
{

	if (r == NULL)
		return;

	/*
	 * Ring was not created with rte_ring_create,
	 * therefore, there is no memzone to free.
	 */
	if (r->memzone == NULL) {
		assert(0 == "Cannot free ring (not created with rte_ring_create()");
		return;
	}

	free(r->memzone);
	free(r);
}

