/*
 * Copyright (c) 2010 Satoshi Ebisawa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. The names of its contributors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __DNS_ATOMIC_H__
#define __DNS_ATOMIC_H__

#define ATOMIC_INC(p)             atomic_increment((unsigned *) p)
#define ATOMIC_DEC(p)             atomic_decrement((unsigned *) p)
#define ATOMIC_XADD(p, v)         atomic_fetch_add((unsigned *) (p), (v))
#define ATOMIC_CAS(p, e, v)       atomic_compare_swap((unsigned *) (p), (e), (v))
#define ATOMIC_CAS_PTR(p, e, v)   atomic_compare_swap_ptr((void **) (p), (e), (v))

static inline void
atomic_increment(uint32_t *p)
{
    __asm__ __volatile__("lock; addl $1,%0"
                         : "+m"(*p)
                         :
                         : "memory", "cc");
}

static inline void
atomic_decrement(uint32_t *p)
{
    __asm__ __volatile__("lock; subl $1,%0"
                         : "+m"(*p)
                         :
                         : "memory", "cc");
}

static inline uint32_t
atomic_fetch_add(uint32_t *p, uint32_t val)
{
    uint32_t oldval;

    __asm__ __volatile__("lock; xaddl %1,%0"
                         : "+m"(*p), "=r"(oldval)
                         : "1"(val)
                         : "memory", "cc");

    return oldval;
}

static inline int
atomic_compare_swap(uint32_t *p, uint32_t expv, uint32_t newv)
{
    uint8_t r;
    uint32_t oldval;

    __asm__ __volatile__("lock; cmpxchg %3,%0; setz %2"
                         : "+m"(*p), "=a"(oldval), "=q"(r)
                         : "r"(newv), "1"(expv)
                         : "memory", "cc");

    return r;
}

static inline int
atomic_compare_swap_ptr(void **p, void *expv, void *newv)
{
    uint8_t r;
    void *oldval;

    __asm__ __volatile__("lock; cmpxchg %3,%0; setz %2"
                         : "+m"(*p), "=a"(oldval), "=q"(r)
                         : "r"(newv), "1"(expv)
                         : "memory", "cc");

    return r;
}


#if 0

static inline int
atomic_dcas32(uint32_t *p,
              uint32_t expv0, uint32_t newv0,
              uint32_t expv1, uint32_t newv1)
{
    uint8_t r;

    /*
     * compare EDX:EAX with m64
     * equal -> ZF=1, m64=ECX:EBX
     *  else -> ZF=0, EDX:EAX=m64
     */
    __asm__ __volatile__("lock; cmpxchg8b %0; setz %1"
                         : "+m"(*p), "=r"(r)
                         : "a"(expv0), "d"(expv1), "b"(newv0), "c"(newv1)
                         : "cc");

    return r;
}

static inline int
atomic_dcas64(uint64_t *p,
              uint64_t expv0, uint64_t newv0,
              uint64_t expv1, uint64_t newv1)
{
    uint8_t r;

    __asm__ __volatile__("lock; cmpxchg16b %0; setz %1"
                         : "+m"(*p), "=r"(r)
                         : "a"(expv0), "d"(expv1), "b"(newv0), "c"(newv1)
                         : "cc");

    return r;
}

#endif
#endif  /* __DNS_ATOMIC_H__ */
