/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_BCACHE_H
#define _LINUX_BCACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "bitops.h"
#include "acconfig.h"

#define TEXT_NORMAL     "\033[0m"
/*#define TEXT_HAZARD   "\033[5;31m"*/
#define TEXT_RED        "\033[0;31m"
#define TEXT_GREEN      "\033[0;32m"
#define TEXT_YELLOW     "\033[0;33m"
#define TEXT_BLUE       "\033[0;34m"
#define TEXT_MAGENTA    "\033[0;35m"
#define TEXT_CYAN       "\033[0;36m"


static const char bcache_magic[] = {
        0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca,
        0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
        *remainder = dividend % divisor;
        return dividend / divisor;
}

static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
        *remainder = dividend % divisor;
        return dividend / divisor;
}

static inline u64 div_u64(u64 dividend, u32 divisor)
{
        u32 remainder;
        return div_u64_rem(dividend, divisor, &remainder);
}

/**
 * div_s64 - signed 64bit divide with 32bit divisor
 */
static inline s64 div_s64(s64 dividend, s32 divisor)
{
        s32 remainder;
        return div_s64_rem(dividend, divisor, &remainder);
}

#define typecheck(type,x) \
({      type __dummy; \
        typeof(x) __dummy2; \
        (void)(&__dummy == &__dummy2); \
        1; \
})

#define time_after64(a,b)       \
        (typecheck(uint64_t, a) && \
         typecheck(uint64_t, b) && \
         ((int64_t)((b) - (a)) < 0))

#define time_before64(a,b)      time_after64(b,a)

#define DIV_ROUND_UP_ULL(n, d)        (((n) + (d) - 1) / (d))

#define PAGE_SHIFT              12

#define BUG_ON(cond)    assert(!(cond))
#define EBUG_ON(cond)   BUG_ON(cond)
#define __printf(a, b) __attribute__((format(printf, a, b)))

#define min_t(type, x, y) ({                    \
        type __min1 = (x);                      \
        type __min2 = (y);                      \
        __min1 < __min2 ? __min1: __min2; })


#define max_t(type, x, y) ({                    \
        type __max1 = (x);                      \
        type __max2 = (y);                      \
        __max1 > __max2 ? __max1: __max2; })

#define clamp_t(type, val, min, max) ({         \
        type __val = (val);                     \
        type __min = (min);                     \
        type __max = (max);                     \
        __val = __val < __min ? __min: __val;   \
        __val > __max ? __max: __val; })

#define clamp_val(val, min, max) ({             \
        typeof(val) __val = (val);              \
        typeof(val) __min = (min);              \
        typeof(val) __max = (max);              \
        __val = __val < __min ? __min: __val;   \
        __val > __max ? __max: __val; })


#define swap(a, b) \
        do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define MAX_ERRNO       4095

#define roundup(x, y) (                                 \
{                                                       \
        const typeof(y) __y = y;                        \
        (((x) + (__y - 1)) / __y) * __y;                \
}                                                       \
)

#define rounddown(x, y) (                               \
{                                                       \
        typeof(x) __x = (x);                            \
        __x - (__x % (y));                              \
}                                                       \
)

static __always_inline int fls(int x)
{
	int r;

	/*
	 * AMD64 says BSRL won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before, except that the
	 * top 32 bits will be cleared.
	 *
	 * We cannot do this on 32 bits because at the very least some
	 * 486 CPUs did not behave this way.
	 */
	asm("bsrl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));
	return r + 1;
}

static __always_inline int fls64(__u64 x)
{
	int bitpos = -1;
	/*
	 * AMD64 says BSRQ won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before.
	 */
	asm("bsrq %1,%q0"
	    : "+r" (bitpos)
	    : "rm" (x));
	return bitpos + 1;
}

static inline unsigned fls_long(unsigned long l)
{
        if (sizeof(l) == 4)
                return fls(l);
        return fls64(l);
}


static inline __attribute__((const))
  int __ilog2_u32(u32 n)
{
          return fls(n) - 1;
}

static inline __attribute__((const))
  int __ilog2_u64(u64 n)
{
          return fls64(n) - 1;
}

#define ilog2(n)                                \
(                                               \
        __builtin_constant_p(n) ? (             \
                (n) < 2 ? 0 :                   \
                (n) & (1ULL << 63) ? 63 :       \
                (n) & (1ULL << 62) ? 62 :       \
                (n) & (1ULL << 61) ? 61 :       \
                (n) & (1ULL << 60) ? 60 :       \
                (n) & (1ULL << 59) ? 59 :       \
                (n) & (1ULL << 58) ? 58 :       \
                (n) & (1ULL << 57) ? 57 :       \
                (n) & (1ULL << 56) ? 56 :       \
                (n) & (1ULL << 55) ? 55 :       \
                (n) & (1ULL << 54) ? 54 :       \
                (n) & (1ULL << 53) ? 53 :       \
                (n) & (1ULL << 52) ? 52 :       \
                (n) & (1ULL << 51) ? 51 :       \
                (n) & (1ULL << 50) ? 50 :       \
                (n) & (1ULL << 49) ? 49 :       \
                (n) & (1ULL << 48) ? 48 :       \
                (n) & (1ULL << 47) ? 47 :       \
                (n) & (1ULL << 46) ? 46 :       \
                (n) & (1ULL << 45) ? 45 :       \
                (n) & (1ULL << 44) ? 44 :       \
                (n) & (1ULL << 43) ? 43 :       \
                (n) & (1ULL << 42) ? 42 :       \
                (n) & (1ULL << 41) ? 41 :       \
                (n) & (1ULL << 40) ? 40 :       \
                (n) & (1ULL << 39) ? 39 :       \
                (n) & (1ULL << 38) ? 38 :       \
                (n) & (1ULL << 37) ? 37 :       \
                (n) & (1ULL << 36) ? 36 :       \
                (n) & (1ULL << 35) ? 35 :       \
                (n) & (1ULL << 34) ? 34 :       \
                (n) & (1ULL << 33) ? 33 :       \
                (n) & (1ULL << 32) ? 32 :       \
                (n) & (1ULL << 31) ? 31 :       \
                (n) & (1ULL << 30) ? 30 :       \
                (n) & (1ULL << 29) ? 29 :       \
                (n) & (1ULL << 28) ? 28 :       \
                (n) & (1ULL << 27) ? 27 :       \
                (n) & (1ULL << 26) ? 26 :       \
                (n) & (1ULL << 25) ? 25 :       \
                (n) & (1ULL << 24) ? 24 :       \
                (n) & (1ULL << 23) ? 23 :       \
                (n) & (1ULL << 22) ? 22 :       \
                (n) & (1ULL << 21) ? 21 :       \
                (n) & (1ULL << 20) ? 20 :       \
                (n) & (1ULL << 19) ? 19 :       \
                (n) & (1ULL << 18) ? 18 :       \
                (n) & (1ULL << 17) ? 17 :       \
                (n) & (1ULL << 16) ? 16 :       \
                (n) & (1ULL << 15) ? 15 :       \
                (n) & (1ULL << 14) ? 14 :       \
                (n) & (1ULL << 13) ? 13 :       \
                (n) & (1ULL << 12) ? 12 :       \
                (n) & (1ULL << 11) ? 11 :       \
                (n) & (1ULL << 10) ? 10 :       \
                (n) & (1ULL <<  9) ?  9 :       \
                (n) & (1ULL <<  8) ?  8 :       \
                (n) & (1ULL <<  7) ?  7 :       \
                (n) & (1ULL <<  6) ?  6 :       \
                (n) & (1ULL <<  5) ?  5 :       \
                (n) & (1ULL <<  4) ?  4 :       \
                (n) & (1ULL <<  3) ?  3 :       \
                (n) & (1ULL <<  2) ?  2 :       \
                1 ) :                           \
        (sizeof(n) <= 4) ?                      \
        __ilog2_u32(n) :                        \
        __ilog2_u64(n)                          \
 )


static inline __attribute__((const))
unsigned long __roundup_pow_of_two(unsigned long n)
{
        return 1UL << fls_long(n - 1);
}

static inline __attribute__((const))
unsigned long __rounddown_pow_of_two(unsigned long n)
{
        return 1UL << (fls_long(n) - 1);
}

#define rounddown_pow_of_two(n)                 \
(                                               \
        __builtin_constant_p(n) ? (             \
                (1UL << ilog2(n))) :            \
        __rounddown_pow_of_two(n)               \
 )

#define roundup_pow_of_two(n)                   \
(                                               \
        __builtin_constant_p(n) ? (             \
                (n == 1) ? 1 :                  \
                (1UL << (ilog2((n) - 1) + 1))   \
                                   ) :          \
        __roundup_pow_of_two(n)                 \
)

#ifdef WITH_URCU
typedef int atomic_t;
typedef long atomic_long_t;
#else
typedef struct {
	int counter;
} atomic_t;

typedef atomic_t atomic_long_t;
#endif

#define false 0
#define true  1
#if 0
enum {
	false = 0,
	true  = 1
};
#endif

#define BITMASK(name, type, field, offset, size)		\
static inline __u64 name(const type *k)				\
{ return (k->field >> offset) & ~(~0ULL << size); }		\
								\
static inline void SET_##name(type *k, __u64 v)			\
{								\
	k->field &= ~(~(~0ULL << size) << offset);		\
	k->field |= (v & ~(~0ULL << size)) << offset;		\
}

/* Btree keys - all units are in sectors */

struct bkey {
	__u64	high;
	__u64	low;
	__u64	ptr[];
};

#define KEY_FIELD(name, field, offset, size)				\
	BITMASK(name, struct bkey, field, offset, size)

#define PTR_FIELD(name, offset, size)					\
static inline __u64 name(const struct bkey *k, unsigned i)		\
{ return (k->ptr[i] >> offset) & ~(~0ULL << size); }			\
									\
static inline void SET_##name(struct bkey *k, unsigned i, __u64 v)	\
{									\
	k->ptr[i] &= ~(~(~0ULL << size) << offset);			\
	k->ptr[i] |= (v & ~(~0ULL << size)) << offset;			\
}

#define PTR_OFFSET_to_bytes(k,ptr) PTR_OFFSET(k, ptr) << 9

#define KEY_SIZE_BITS		16
#define KEY_MAX_U64S		8

KEY_FIELD(KEY_PTRS,	high, 60, 3)
KEY_FIELD(HEADER_SIZE,	high, 58, 2)
KEY_FIELD(KEY_CSUM,	high, 56, 2)
KEY_FIELD(KEY_PINNED,	high, 55, 1)
KEY_FIELD(KEY_DIRTY,	high, 36, 1)

KEY_FIELD(KEY_SIZE,	high, 20, KEY_SIZE_BITS)
KEY_FIELD(KEY_INODE,	high, 0,  20)

/* Next time I change the on disk format, KEY_OFFSET() won't be 64 bits */

static inline __u64 KEY_OFFSET(const struct bkey *k)
{
	return k->low;
}

static inline void SET_KEY_OFFSET(struct bkey *k, __u64 v)
{
	k->low = v;
}

/*
 * The high bit being set is a relic from when we used it to do binary
 * searches - it told you where a key started. It's not used anymore,
 * and can probably be safely dropped.
 */
#define KEY(inode, offset, size)					\
((struct bkey) {							\
	.high = (1ULL << 63) | ((__u64) (size) << 20) | (inode),	\
	.low = (offset)							\
})

#define ZERO_KEY			KEY(0, 0, 0)

#define MAX_KEY_INODE			(~(~0 << 20))
#define MAX_KEY_OFFSET			(~0ULL >> 1)
#define MAX_KEY				KEY(MAX_KEY_INODE, MAX_KEY_OFFSET, 0)

#define KEY_START(k)			(KEY_OFFSET(k) - KEY_SIZE(k))
#define START_KEY(k)			KEY(KEY_INODE(k), KEY_START(k), 0)

#define PTR_DEV_BITS			12

PTR_FIELD(PTR_DEV,			51, PTR_DEV_BITS)
PTR_FIELD(PTR_OFFSET,			8,  43)
PTR_FIELD(PTR_GEN,			0,  8)

#define PTR_CHECK_DEV			((1 << PTR_DEV_BITS) - 1)

#define PTR(gen, offset, dev)						\
	((((__u64) dev) << 51) | ((__u64) offset) << 8 | gen)

/* Bkey utility code */

static inline unsigned long bkey_u64s(const struct bkey *k)
{
  return (sizeof(struct bkey) / sizeof(__u64)) + KEY_PTRS(k);
}

static inline unsigned long bkey_bytes(const struct bkey *k)
{
  return bkey_u64s(k) * sizeof(__u64);
}

#define bkey_copy(_dest, _src)	memcpy(_dest, _src, bkey_bytes(_src))

static inline void bkey_copy_key(struct bkey *dest, const struct bkey *src)
{
  SET_KEY_INODE(dest, KEY_INODE(src));
  SET_KEY_OFFSET(dest, KEY_OFFSET(src));
}

static inline struct bkey *bkey_next(const struct bkey *k)
{
  __u64 *d = (void *) k;
  return (struct bkey *) (d + bkey_u64s(k));
}

static inline struct bkey *bkey_idx(const struct bkey *k, unsigned nr_keys)
{
  __u64 *d = (void *) k;
  return (struct bkey *) (d + nr_keys);
}
/* Enough for a key with 6 pointers */
#define BKEY_PAD		8

#define BKEY_PADDED(key)					\
	union { struct bkey key; uint64_t key ## _pad[BKEY_PAD]; }

/* Superblock */

/* Version 0: Cache device
 * Version 1: Backing device
 * Version 2: Seed pointer into btree node checksum
 * Version 3: Cache device with new UUID format
 * Version 4: Backing device with data offset
 */
#define BCACHE_SB_VERSION_CDEV		0
#define BCACHE_SB_VERSION_BDEV		1
#define BCACHE_SB_VERSION_CDEV_WITH_UUID 3
#define BCACHE_SB_VERSION_BDEV_WITH_OFFSET 4
#define BCACHE_SB_MAX_VERSION		4

#define SB_SECTOR			8
#define SB_SIZE				4096
#define SB_LABEL_SIZE			32
#define SB_JOURNAL_BUCKETS		256U
#define SB_START                        (SB_SECTOR * 512)
/* SB_JOURNAL_BUCKETS must be divisible by BITS_PER_LONG */
#define MAX_CACHES_PER_SET		8

#define BDEV_DATA_START_DEFAULT		16	/* sectors */

#define MEMALIGN                        512

struct cache_sb {
	__u64			csum;
	__u64			offset;	/* sector where this sb was written */
	__u64			version;

	__u8			magic[16];

	__u8			uuid[16];
	union {
		__u8		set_uuid[16];
		__u64		set_magic;
	};
	__u8			label[SB_LABEL_SIZE];

	__u64			flags;
	__u64			seq;
	__u64			pad[8];

	union {
	struct {
		/* Cache devices */
		__u64		nbuckets;	/* device size */

		__u16		block_size;	/* sectors */
		__u16		bucket_size;	/* sectors */

		__u16		nr_in_set;
		__u16		nr_this_dev;
	};
	struct {
		/* Backing devices */
		__u64		data_offset;

		/*
		 * block_size from the cache device section is still used by
		 * backing devices, so don't add anything here until we fix
		 * things to not need it for backing devices anymore
		 */
	};
	};

	__u32			last_mount;	/* time_t */

	__u16			first_bucket;
	union {
		__u16		njournal_buckets;
		__u16		keys;
	};
	__u64			d[SB_JOURNAL_BUCKETS];	/* journal buckets */
};

static inline _Bool SB_IS_BDEV(const struct cache_sb *sb)
{
	return sb->version == BCACHE_SB_VERSION_BDEV
		|| sb->version == BCACHE_SB_VERSION_BDEV_WITH_OFFSET;
}

BITMASK(CACHE_SYNC,			struct cache_sb, flags, 0, 1);
BITMASK(CACHE_DISCARD,			struct cache_sb, flags, 1, 1);
BITMASK(CACHE_REPLACEMENT,		struct cache_sb, flags, 2, 3);
#define CACHE_REPLACEMENT_LRU		0U
#define CACHE_REPLACEMENT_FIFO		1U
#define CACHE_REPLACEMENT_RANDOM	2U

BITMASK(BDEV_CACHE_MODE,		struct cache_sb, flags, 0, 4);

BITMASK(BDEV_STATE,			struct cache_sb, flags, 61, 2);
#define BDEV_STATE_NONE			0U
#define BDEV_STATE_CLEAN		1U
#define BDEV_STATE_DIRTY		2U
#define BDEV_STATE_STALE		3U

/*
 * Magic numbers
 *
 * The various other data structures have their own magic numbers, which are
 * xored with the first part of the cache set's UUID
 */

#define JSET_MAGIC			0x245235c1a3625032ULL
#define PSET_MAGIC			0x6750e15f87337f91ULL
#define BSET_MAGIC			0x90135c78b99e07f5ULL

static inline __u64 jset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ JSET_MAGIC;
}

static inline __u64 pset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ PSET_MAGIC;
}

static inline __u64 bset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ BSET_MAGIC;
}

/*
 * Journal
 *
 * On disk format for a journal entry:
 * seq is monotonically increasing; every journal entry has its own unique
 * sequence number.
 *
 * last_seq is the oldest journal entry that still has keys the btree hasn't
 * flushed to disk yet.
 *
 * version is for on disk format changes.
 */

#define BCACHE_JSET_VERSION_UUIDv1	1
#define BCACHE_JSET_VERSION_UUID	1	/* Always latest UUID format */
#define BCACHE_JSET_VERSION		1

struct jset {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys;

	__u64			last_seq;

	BKEY_PADDED(uuid_bucket);
	BKEY_PADDED(btree_root);
	__u16			btree_level;
	__u16			pad[3];

	__u64			prio_bucket[MAX_CACHES_PER_SET];

	union {
		struct bkey	start[0];
		__u64		d[0];
	};
};

/* Bucket prios/gens */

struct prio_set {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			pad;

	__u64			next_bucket;

	struct bucket_disk {
		__u16		prio;
		__u8		gen;
	} __attribute((packed)) data[];
};

/* UUIDS - per backing device/flash only volume metadata */

struct uuid_entry {
	union {
		struct {
			__u8	uuid[16];
			__u8	label[32];
			__u32	first_reg;
			__u32	last_reg;
			__u32	invalidated;

			__u32	flags;
			/* Size of flash only volumes */
			__u64	sectors;
		};

		__u8		pad[128];
	};
};

BITMASK(UUID_FLASH_ONLY,	struct uuid_entry, flags, 0, 1);

/* Btree nodes */

/* Version 1: Seed pointer into btree node checksum
 */
#define BCACHE_BSET_CSUM		1
#define BCACHE_BSET_VERSION		1

/*
 * Btree nodes
 *
 * On disk a btree node is a list/log of these; within each set the keys are
 * sorted
 */
struct bset {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys;

	union {
		struct bkey	start[0];
		uint64_t	d[0];
	};
};



static inline __attribute__((const))
bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

static inline unsigned long int_sqrt(unsigned long x)
{
	unsigned long b, m, y = 0;

	if (x <= 1)
		return x;

	m = 1UL << (BITS_PER_LONG - 2);
	while (m != 0) {
		b = y + m;
		y >>= 1;

		if (x >= b) {
			x -= b;
			y += m;
		}
		m >>= 2;
	}

	return y;
}

static inline __attribute_const__
int __get_order(unsigned long size)
{
	int order;

	size--;
	size >>= PAGE_SHIFT;
	order = fls(size);
	return order;
}

#define get_order(n)						\
(								\
	__builtin_constant_p(n) ? (				\
		((n) == 0UL) ? BITS_PER_LONG - PAGE_SHIFT :	\
		(((n) < (1UL << PAGE_SHIFT)) ? 0 :		\
		 ilog2((n) - 1) - PAGE_SHIFT + 1)		\
	) :							\
	__get_order(n)						\
)

/* OBSOLETE */

/* UUIDS - per backing device/flash only volume metadata */

struct uuid_entry_v0 {
	__u8		uuid[16];
	__u8		label[32];
	__u32		first_reg;
	__u32		last_reg;
	__u32		invalidated;
	__u32		pad;
};

#define SAFE_FREE_INIT(item) atomic_set(&item->gc, 0)
#define SAFE_FREE_INC(item) atomic_inc(&item->gc)
#define SAFE_FREE_DEC(item, fn) \
{ \
  int r = atomic_dec_return(&item->gc); \
  if (!r) fn(item); \
}

#endif /* _LINUX_BCACHE_H */
