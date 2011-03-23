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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "dns.h"
#include "dns_abq.h"
#include "dns_pool.h"

#define MODULE "pool"

int
dns_pool_init(dns_pool_t *pool, int esize, int count)
{
    int i;
    uint8_t *p;

    if ((pool->pool_data = calloc(1, esize * count)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return -1;
    }

    plog(LOG_DEBUG, "%s: allocate %dk", MODULE, (esize * count) / 1024);

    if (dns_abq_init(&pool->pool_abq, count, &AbqThreadSafeLockFree) < 0) {
        free(pool->pool_data);
        return -1;
    }

    p = (uint8_t *) pool->pool_data;

    for (i = 0; i < count; i++) {
        dns_abq_push(&pool->pool_abq, p);
        p += esize;
    }

    return 0;
}

void *
dns_pool_get(dns_pool_t *pool)
{
    return dns_abq_pop(&pool->pool_abq);
}

int
dns_pool_release(dns_pool_t *pool, void *pdata)
{
    return dns_abq_push(&pool->pool_abq, pdata);
}

int
dns_mpool_init(dns_mpool_t *mp, int esize, int count, int threads)
{
    int i;

    if ((mp->mp_abq_local = malloc(sizeof(dns_abq_t) * threads)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return -1;
    }

    for (i = 0; i < threads; i++)
        dns_abq_init(&mp->mp_abq_local[i], count / threads, &AbqThreadUnsafe);

    dns_pool_init(&mp->mp_pool_shared, esize, count);

    return 0;
}

void *
dns_mpool_get(dns_mpool_t *mp, int thread_id)
{
    void *p;
    dns_abq_t *local;

    local = &mp->mp_abq_local[thread_id];

    if ((p = dns_abq_pop(local)) == NULL)
        p = dns_pool_get(&mp->mp_pool_shared);

    return p;
}

int
dns_mpool_release(dns_mpool_t *mp, void *pdata, int thread_id)
{
    dns_abq_t *local;

    local = &mp->mp_abq_local[thread_id];

    if (dns_abq_push(local, pdata) < 0)
        return dns_pool_release(&mp->mp_pool_shared, pdata);

    return 0;
}
