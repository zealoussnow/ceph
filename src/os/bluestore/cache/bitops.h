// Last Update:2018-03-06 18:42:41

#ifndef BITOPS_H
#define BITOPS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "acconfig.h"
#include "types.h"
//#include "bcache.h"

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min(a,b)  ((a)<=(b) ? (a):(b))
#define max(a,b)  ((a)>=(b) ? (a):(b))

#define _BITOPS_LONG_SHIFT 	6
#define BITS_PER_LONG 		64
#define BITS_PER_BYTE 		8

#if defined(__aarch64__)
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#endif


#if defined(__i386__) || defined(__x86_64__)
/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __ffs(unsigned long word)
{
        asm("rep; bsf %1,%0"
                : "=r" (word)
                : "rm" (word));
        return word;
}

static __always_inline unsigned long ffz(unsigned long word)
{
        asm("rep; bsf %1,%0"
                : "=r" (word)
                : "r" (~word));
        return word;
}
#else
static __always_inline unsigned long __ffs(unsigned long word)
{
        int num = 0;

#if BITS_PER_LONG == 64
        if ((word & 0xffffffff) == 0) {
                num += 32;
                word >>= 32;
        }
#endif
        if ((word & 0xffff) == 0) {
                num += 16;
                word >>= 16;
        }
        if ((word & 0xff) == 0) {
                num += 8;
                word >>= 8;
        }
        if ((word & 0xf) == 0) {
                num += 4;
                word >>= 4;
        }
        if ((word & 0x3) == 0) {
                num += 2;
                word >>= 2;
        }
        if ((word & 0x1) == 0)
                num += 1;
        return num;
}

/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))
#endif

# define likely(x)  __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)


#define LOCK_PREFIX_HERE \
                ".pushsection .smp_locks,\"a\"\n"       \
                ".balign 4\n"                           \
                ".long 671f - .\n" /* offset */         \
                ".popsection\n"                         \
                "671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))


#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
#else
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c) [_cc_ ## c] "=qm"
#endif


/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset);
unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
                            unsigned long offset);

unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size);

#if defined(__i386__) || defined(__x86_64__)
static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
{
        return ((1UL << (nr & (BITS_PER_LONG-1))) &
                (addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
}

static __always_inline bool variable_test_bit(long nr, volatile const unsigned long *addr)
{
        bool oldbit;

        asm volatile("bt %2,%1"
                     CC_SET(c)
                     : CC_OUT(c) (oldbit)
                     : "m" (*(unsigned long *)addr), "Ir" (nr));

        return oldbit;
}


#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))
#else
/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}
#endif


#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/* Technically wrong, but this avoids compilation errors on some gcc
   versions. */
#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif
#define ADDR				BITOP_ADDR(addr)

/*
 * We do the locked ops that don't return the old value as
 * a mask operation on a byte.
 */
#define IS_IMMEDIATE(nr)		(__builtin_constant_p(nr))
#define CONST_MASK_ADDR(nr, addr)	BITOP_ADDR((char *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)			(1 << ((nr) & 7))

#define small_const_nbits(nbits) \
        (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

#define DECLARE_BITMAP(name,bits) \
        unsigned long name[BITS_TO_LONGS(bits)]

static inline void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
        if (small_const_nbits(nbits))
                *dst = 0UL;
        else {
                unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
                memset(dst, 0, len);
        }
}


#if defined(__i386__) || defined(__x86_64__)
/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 *
 * Note: there are no guarantees that this function will not be reordered
 * on non x86 architectures, so if you are writing portable code,
 * make sure not to rely on its reordering guarantees.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static __always_inline void
set_bit(long nr, volatile unsigned long *addr)
{
        if (IS_IMMEDIATE(nr)) {
                asm volatile(LOCK_PREFIX "orb %1,%0"
                        : CONST_MASK_ADDR(nr, addr)
                        : "iq" ((u8)CONST_MASK(nr))
                        : "memory");
        } else {
                asm volatile(LOCK_PREFIX "bts %1,%0"
                        : BITOP_ADDR(addr) : "Ir" (nr) : "memory");
        }
}

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static __always_inline void __set_bit(long nr, volatile unsigned long *addr)
{
        asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
}


/**
 * change_bit - Toggle a bit in memory
 * @nr: Bit to change
 * @addr: Address to start counting from
 *
 * change_bit() is atomic and may not be reordered.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static __always_inline void change_bit(long nr, volatile unsigned long *addr)
{
        if (IS_IMMEDIATE(nr)) {
                asm volatile(LOCK_PREFIX "xorb %1,%0"
                        : CONST_MASK_ADDR(nr, addr)
                        : "iq" ((u8)CONST_MASK(nr)));
        } else {
                asm volatile(LOCK_PREFIX "btc %1,%0"
                        : BITOP_ADDR(addr)
                        : "Ir" (nr));
        }
}

static __always_inline void
clear_bit(long nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		asm volatile(LOCK_PREFIX "andb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)~CONST_MASK(nr)));
	} else {
		asm volatile(LOCK_PREFIX "btr %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}
#else

#ifdef WITH_URCU
#include <urcu/uatomic.h>
#define clear_bit(n, v)		(uatomic_clear_bit(n, v))
#define set_bit(n, v)		(uatomic_set_bit(n, v))
#define change_bit(n, v)	(uatomic_change_bit(n, v))

static inline void __set_bit(int nr, unsigned long *addr)
{
        addr[nr / BITS_PER_LONG] |= 1UL << (nr % BITS_PER_LONG);
}

static inline void uatomic_set_bit(int nr, unsigned long *addr)
{
	uatomic_or(addr + nr / BITS_PER_LONG, 1UL << (nr % BITS_PER_LONG));
}

static inline void uatomic_clear_bit(int nr, unsigned long *addr)
{
	uatomic_and(addr + nr / BITS_PER_LONG, ~(1UL << (nr % BITS_PER_LONG)));
}

static inline void uatomic_change_bit(int nr, unsigned long *addr)
{
	uatomic_set(addr, __sync_xor_and_fetch(addr + nr / BITS_PER_LONG, 1ULL << (nr % BITS_PER_LONG)));
}

#else
#error "We aren't implement it without urcu"
#endif

#endif

#endif
