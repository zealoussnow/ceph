#ifndef PREFETCH_H
#define PREFETCH_H

#ifdef __cplusplus
extern "C" {
#endif

static inline void prefetch(const volatile void *p)
{
#if defined(__i386__) || defined(__x86_64__)
  asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *)p));
#elif defined(__arm__)
  asm volatile ("pld [%0]" : : "r" (p));
#elif defined(__aarch64__)
  asm volatile ("PRFM PLDL1KEEP, [%0]" : : "r" (p));
#elif defined(__powerpc__) || defined(__ppc__)
  asm volatile ("dcbt 0,%[p],0" : : [p] "r" (p));
#endif
}

#ifdef __cplusplus
}
#endif

#endif  /*PREFETCH_H*/
