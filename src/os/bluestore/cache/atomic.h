#ifndef _ASM_X86_ATOMIC_H
#define _ASM_X86_ATOMIC_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "bcache_types.h"

#define CONFIG_64BIT
#define barrier() __asm__ __volatile__("": : :"memory")

#define __READ_ONCE_SIZE                                                \
({                                                                      \
	switch (size) {                                                 \
	case 1: *(__u8 *)res = *(volatile __u8 *)p; break;              \
	case 2: *(__u16 *)res = *(volatile __u16 *)p; break;            \
	case 4: *(__u32 *)res = *(volatile __u32 *)p; break;            \
	case 8: *(__u64 *)res = *(volatile __u64 *)p; break;            \
	default:                                                        \
		barrier();                                              \
		__builtin_memcpy((void *)res, (const void *)p, size);   \
		barrier();                                              \
	}                                                               \
})

static __always_inline
void __read_once_size(const volatile void *p, void *res, int size)
{
	__READ_ONCE_SIZE;
}


#define __READ_ONCE(x, check)                                           \
({                                                                      \
        union { typeof(x) __val; char __c[1]; } __u;                    \
        if (check)                                                      \
                __read_once_size(&(x), __u.__c, sizeof(x));             \
        __u.__val;                                                      \
})
#define READ_ONCE(x) __READ_ONCE(x, 1)




static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
        switch (size) {
        case 1: *(volatile __u8 *)p = *(__u8 *)res; break;
        case 2: *(volatile __u16 *)p = *(__u16 *)res; break;
        case 4: *(volatile __u32 *)p = *(__u32 *)res; break;
        case 8: *(volatile __u64 *)p = *(__u64 *)res; break;
        default:
                barrier();
                __builtin_memcpy((void *)p, (const void *)res, size);
                barrier();
        }
}

# define __force

#define WRITE_ONCE(x, val) \
({                                                      \
        union { typeof(x) __val; char __c[1]; } __u =   \
                { .__val = (__force typeof(x)) (val) }; \
        __write_once_size(&(x), __u.__c, sizeof(x));    \
        __u.__val;                                      \
})

static __always_inline void atomic_set(atomic_t *v, int i)
{
        WRITE_ONCE(v->counter, i);
}


static inline void atomic_dec(atomic_t *v)
{
          asm volatile(LOCK_PREFIX "decl %0"
                                   : "+m" (v->counter));
}

static inline void atomic_inc(atomic_t *v)
{
        asm volatile(LOCK_PREFIX "incl %0"
                     : "+m" (v->counter));
}

static __always_inline void atomic_sub(int i, atomic_t *v)
{
        asm volatile(LOCK_PREFIX "subl %1,%0"
                     : "+m" (v->counter)
                     : "ir" (i));
}

static __always_inline void atomic_add(int i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "addl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static __always_inline int atomic_read(const atomic_t *v)
{
        return READ_ONCE((v)->counter);
}


#define atomic_dec_bug(v)       atomic_dec(v)
#define atomic_inc_bug(v, i)    atomic_inc(v)

#define __X86_CASE_B    1
#define __X86_CASE_W    2
#define __X86_CASE_L    4
#ifdef CONFIG_64BIT
#define __X86_CASE_Q    8
#else
#define __X86_CASE_Q    -1              /* sizeof will never return -1 */
#endif

#define __xchg_op(ptr, arg, op, lock)                                   \
        ({                                                              \
                __typeof__ (*(ptr)) __ret = (arg);                      \
                switch (sizeof(*(ptr))) {                               \
                case __X86_CASE_B:                                      \
                        asm volatile (lock #op "b %b0, %1\n"            \
                                      : "+q" (__ret), "+m" (*(ptr))     \
                                      : : "memory", "cc");              \
                        break;                                          \
                case __X86_CASE_W:                                      \
                        asm volatile (lock #op "w %w0, %1\n"            \
                                      : "+r" (__ret), "+m" (*(ptr))     \
                                      : : "memory", "cc");              \
                        break;                                          \
                case __X86_CASE_L:                                      \
                        asm volatile (lock #op "l %0, %1\n"             \
                                      : "+r" (__ret), "+m" (*(ptr))     \
                                      : : "memory", "cc");              \
                        break;                                          \
                case __X86_CASE_Q:                                      \
                        asm volatile (lock #op "q %q0, %1\n"            \
                                      : "+r" (__ret), "+m" (*(ptr))     \
                                      : : "memory", "cc");              \
                        break;                                          \
                default:                                                \
                        __ ## op ## _wrong_size();                      \
                }                                                       \
                __ret;                                                  \
        })

#define __xadd(ptr, inc, lock)  __xchg_op((ptr), (inc), xadd, lock)
#define xadd(ptr, inc)          __xadd((ptr), (inc), LOCK_PREFIX)

static __always_inline int atomic_add_return(int i, atomic_t *v)
{
        return i + xadd(&v->counter, i);
}

#define atomic_inc_return(v)  (atomic_add_return(1, v))

#define xchg(ptr, v)    __xchg_op((ptr), (v), xchg, "")

static inline int atomic_xchg(atomic_t *v, int new)
{
        return xchg(&v->counter, new);
}

static __always_inline int atomic_sub_return(int i, atomic_t *v)
{
        return atomic_add_return(-i, v);
}


# define __compiletime_error(message) __attribute__((error(message)))
/*# define __compiletime_error(message)*/

extern void __cmpxchg_wrong_size(void)
        __compiletime_error("Bad argument size for cmpxchg");


#define __raw_cmpxchg(ptr, old, new, size, lock)                        \
({                                                                      \
        __typeof__(*(ptr)) __ret;                                       \
        __typeof__(*(ptr)) __old = (old);                               \
        __typeof__(*(ptr)) __new = (new);                               \
        switch (size) {                                                 \
        case __X86_CASE_B:                                              \
        {                                                               \
                volatile u8 *__ptr = (volatile u8 *)(ptr);              \
                asm volatile(lock "cmpxchgb %2,%1"                      \
                             : "=a" (__ret), "+m" (*__ptr)              \
                             : "q" (__new), "0" (__old)                 \
                             : "memory");                               \
                break;                                                  \
        }                                                               \
        case __X86_CASE_W:                                              \
        {                                                               \
                volatile u16 *__ptr = (volatile u16 *)(ptr);            \
                asm volatile(lock "cmpxchgw %2,%1"                      \
                             : "=a" (__ret), "+m" (*__ptr)              \
                             : "r" (__new), "0" (__old)                 \
                             : "memory");                               \
                break;                                                  \
        }                                                               \
        case __X86_CASE_L:                                              \
        {                                                               \
                volatile u32 *__ptr = (volatile u32 *)(ptr);            \
                asm volatile(lock "cmpxchgl %2,%1"                      \
                             : "=a" (__ret), "+m" (*__ptr)              \
                             : "r" (__new), "0" (__old)                 \
                             : "memory");                               \
                break;                                                  \
        }                                                               \
        case __X86_CASE_Q:                                              \
        {                                                               \
                volatile u64 *__ptr = (volatile u64 *)(ptr);            \
                asm volatile(lock "cmpxchgq %2,%1"                      \
                             : "=a" (__ret), "+m" (*__ptr)              \
                             : "r" (__new), "0" (__old)                 \
                             : "memory");                               \
                break;                                                  \
        }                                                               \
        default:                                                        \
                __cmpxchg_wrong_size();                                 \
        }                                                               \
        __ret;                                                          \
})

#define __cmpxchg(ptr, old, new, size)                                  \
        __raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)

#define cmpxchg(ptr, old, new)                                          \
        __cmpxchg(ptr, old, new, sizeof(*(ptr)))

static __always_inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
        return cmpxchg(&v->counter, old, new);
}

#define ATOMIC_LONG_INIT(i)	ATOMIC_INIT(i)
#define ATOMIC_LONG_PFX(x)	atomic ## x

#define ATOMIC_LONG_OP(op)						\
static __always_inline void						\
atomic_long_##op(long i, atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	ATOMIC_LONG_PFX(_##op)(i, v);					\
}

ATOMIC_LONG_OP(add)
ATOMIC_LONG_OP(sub)

#undef ATOMIC_LONG_OP

#endif
