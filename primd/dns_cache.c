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
#include <ctype.h>
#include <unistd.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_pool.h"

#define MODULE "cache"

#define CACHE_RRSET_PLOCK          0x0001
#define CACHE_RRSET_INVALID        (1 << (sizeof(unsigned) * 8 - 1))
#define CACHE_RRSET_FLAGMASK       (CACHE_RRSET_INVALID)

#define CACHE_RRSET_PTR(rrset)     ((dns_cache_rrset_t *) ((uintptr_t) (rrset) & ~CACHE_RRSET_PLOCK))
#define CACHE_RRSET_VALID(rrset)   (((uintptr_t) (rrset) & CACHE_RRSET_PLOCK) == 0)
#define CACHE_RRSET_REFS(rrset)    ((rrset)->rrset_refs & ~CACHE_RRSET_FLAGMASK)

#define NOSPIN  1

typedef struct {
    unsigned            stat_rrset_new;
    unsigned            stat_rrset_registered;
    unsigned            stat_rrset_negative;
    unsigned            stat_rrset_lookup;
    unsigned            stat_lookup_cmp;
    unsigned            stat_cache_hit;
    unsigned            stat_drain_rrset;
    unsigned            stat_drain_resource;
    unsigned            stat_drain_hashcol;
} cache_stats_t;

typedef struct {
    dns_cache_rrset_t  *hash_array[DNS_CACHE_HASH_ARRAY_SIZE];
} cache_hash_t;

static cache_stats_t CacheStats;
static cache_hash_t *CacheHash;
static unsigned CacheHashCount;
static dns_mpool_t CachePool;
static dns_mpool_t CacheSetPool;

static dns_cache_rrset_t *cache_rrset_get(dns_msg_question_t *q, dns_tls_t *tls);
static dns_cache_rrset_t *cache_rrset_new(dns_msg_question_t *q, dns_tls_t *tls);
static dns_cache_rrset_t *cache_rrset_lookup(dns_msg_question_t *q, int category, cache_hash_t *hash, unsigned hvalue, dns_tls_t *tls);
static int cache_rrset_compare(dns_cache_rrset_t *rrset, dns_msg_question_t *q, int category);
static int cache_rrset_refflag(dns_cache_rrset_t *rrset, int flag);
static int cache_rrset_invalidate(dns_cache_rrset_t *rrset, cache_hash_t *hash, unsigned hvalue, dns_tls_t *tls);
static int cache_rrset_retain(dns_cache_rrset_t *rrset);
static void cache_rrset_release(dns_cache_rrset_t *rrset, dns_tls_t *tls);
static dns_cache_rrset_t *cache_rrset_retain2(dns_cache_rrset_t **rr0, int nospin);
static int cache_rrset_plock(dns_cache_rrset_t **ptr, int nospin);
static void cache_rrset_free(dns_cache_rrset_t *rrset, dns_tls_t *tls);
static void cache_rrset_reset(dns_cache_rrset_t *rrset, dns_tls_t *tls);
static int cache_rrset_register(cache_hash_t *hash, dns_cache_rrset_t *rrset, unsigned hvalue, dns_tls_t *tls);
static int cache_rrset_register_force(cache_hash_t *hash, dns_cache_rrset_t *rrset, int index, dns_tls_t *tls);
static int cache_rrset_unregister(cache_hash_t *hash, dns_cache_rrset_t *rrset, unsigned hvalue, dns_tls_t *tls);
static dns_cache_rrset_t *cache_rrset_drain(dns_tls_t *tls);
static dns_cache_rrset_t *cache_rrset_drain_one(dns_tls_t *tls);
static dns_cache_rrset_t *cache_rrset_drain_hash(cache_hash_t *hash, dns_tls_t *tls);
static void cache_rrset_set_expire(dns_cache_rrset_t *rrset, dns_cache_t *cache);
static cache_hash_t *cache_hash(unsigned *value, dns_msg_question_t *q, int category);
static dns_cache_t *cache_get(dns_tls_t *tls);
static dns_cache_t *cache_drain(dns_tls_t *tls);
static void cache_init(dns_cache_t *cache, dns_msg_resource_t *res);
static void cache_update_ttl(dns_cache_rrset_t *rrset, int ttl);
static void cache_update_ttl_list(dns_list_t *list, int ttl);

int
dns_cache_init(int cache_mb, int threads)
{
    int units;
    static int N = 4;

    if (cache_mb < 1 || cache_mb > DNS_CACHE_SIZE_MAX) {
        plog(LOG_ERR, "%s: invalid cache size %d (max %d)", MODULE, cache_mb, DNS_CACHE_SIZE_MAX);
        return -1;
    }

    units = (cache_mb * 1024 * 1024) / (sizeof(dns_cache_rrset_t) + sizeof(dns_cache_t) * N);
    CacheHashCount = dns_util_euler_primish(units);

    if ((CacheHash = calloc(1, sizeof(cache_hash_t) * CacheHashCount)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return -1;
    }

    plog(LOG_DEBUG, "%s: allocate %d megabytes (%d units)", MODULE, cache_mb, units);

    dns_mpool_init(&CachePool, sizeof(dns_cache_t), units * N, threads);
    dns_mpool_init(&CacheSetPool, sizeof(dns_cache_rrset_t), units, threads);

    return 0;
}

dns_cache_rrset_t *
dns_cache_new(dns_msg_question_t *q, dns_tls_t *tls)
{
    dns_cache_rrset_t *rrset;

    ATOMIC_INC(&CacheStats.stat_rrset_new);
    rrset = cache_rrset_get(q, tls);

    return rrset;
}

dns_cache_rrset_t *
dns_cache_lookup(dns_msg_question_t *q, int category, dns_tls_t *tls)
{
    unsigned hvalue;
    cache_hash_t *hash;
    dns_cache_rrset_t *rrset;

    plog_question(LOG_DEBUG, MODULE, "cache lookup", q, category);
    ATOMIC_INC(&CacheStats.stat_rrset_lookup);

    hash = cache_hash(&hvalue, q, category);
    if ((rrset = cache_rrset_lookup(q, category, hash, hvalue, tls)) == NULL) {
        plog_question(LOG_DEBUG, MODULE, "cache not found", q, category);
        return NULL;
    }

    plog_question(LOG_DEBUG, MODULE, "cache found", q, category);

    if ((rrset->rrset_dns_flags & DNS_FLAG_AA) == 0) {
        if (rrset->rrset_expire != 0)
            cache_update_ttl(rrset, rrset->rrset_expire - time(NULL));
    }

    return rrset;
}

void
dns_cache_release(dns_cache_rrset_t *rrset, dns_tls_t *tls)
{
    cache_rrset_release(rrset, tls);
}

int
dns_cache_add_answer(dns_cache_rrset_t *rrset, dns_msg_resource_t *res, dns_tls_t *tls)
{
    dns_cache_t *cache;

    if ((cache = cache_get(tls)) == NULL)
        return -1;

    cache_init(cache, res);
    cache_rrset_set_expire(rrset, cache);

    if (cache->cache_res.mr_q.mq_type == DNS_TYPE_CNAME)
        dns_list_push(&rrset->rrset_list_cname, &cache->cache_elem);
    else
        dns_list_push(&rrset->rrset_list_answer, &cache->cache_elem);

    return 0;
}

int
dns_cache_count_answer(dns_cache_rrset_t *rrset)
{
    int count;

    count = dns_list_count(&rrset->rrset_list_cname);
    count += dns_list_count(&rrset->rrset_list_answer);

    return count;
}

void
dns_cache_negative(dns_cache_rrset_t *rrset, uint32_t ttl)
{
    /* assume no other thread accesses "rrset" simultaneously */
    if (ttl == 0)
        ttl = DNS_CACHE_TTL_NEGATIVE_DEFAULT;
    if (ttl > DNS_CACHE_TTL_NEGATIVE_MAX)
        ttl = DNS_CACHE_TTL_NEGATIVE_MAX;

    rrset->rrset_expire = time(NULL) + ttl;

    ATOMIC_INC(&CacheStats.stat_rrset_negative);
}

void
dns_cache_merge(dns_cache_rrset_t *rrset, dns_cache_rrset_t *rr_m, dns_tls_t *tls)
{
    dns_cache_t *cache;

    cache = DNS_CACHE_LIST_HEAD(&rr_m->rrset_list_cname);
    while (cache != NULL) {
        dns_cache_add_answer(rrset, &cache->cache_res, tls);
        cache = DNS_CACHE_LIST_NEXT(&rr_m->rrset_list_cname, cache);
    }

    cache = DNS_CACHE_LIST_HEAD(&rr_m->rrset_list_answer);
    while (cache != NULL) {
        dns_cache_add_answer(rrset, &cache->cache_res, tls);
        cache = DNS_CACHE_LIST_NEXT(&rr_m->rrset_list_answer, cache);
    }
}

void
dns_cache_register(dns_cache_rrset_t *rrset, int category, dns_tls_t *tls)
{
    unsigned hvalue;
    cache_hash_t *hash;
    dns_msg_question_t *q;

    rrset->rrset_category = category;
    q = &rrset->rrset_question;

    hash = cache_hash(&hvalue, q, category);
    if (cache_rrset_register(hash, rrset, hvalue, tls) < 0) {
        plog_question(LOG_DEBUG, MODULE, "cache not registered due to hash collision",
                      &rrset->rrset_question, category);
        return;
    }

    plog_question(LOG_DEBUG, MODULE, "cache registered", &rrset->rrset_question, category);
    ATOMIC_INC(&CacheStats.stat_rrset_registered);
}

void
dns_cache_setrcode(dns_cache_rrset_t *rrset, unsigned rcode)
{
    rrset->rrset_dns_rcode = rcode;
}

void
dns_cache_setflags(dns_cache_rrset_t *rrset, unsigned flags)
{
    rrset->rrset_dns_flags |= flags;
}

unsigned
dns_cache_getrcode(dns_cache_rrset_t *rrset)
{
    return rrset->rrset_dns_rcode;
}

unsigned
dns_cache_getflags(dns_cache_rrset_t *rrset)
{
    return rrset->rrset_dns_flags;
}

void
dns_cache_invalidate(dns_tls_t *tls)
{
    int i, j;
    time_t now;
    cache_hash_t *hash;
    dns_cache_rrset_t *rrset;

    now = time(NULL);

    for (i = 0; i < CacheHashCount; i++) {
        hash = &CacheHash[i];

        for (j = 0; j < NELEMS(hash->hash_array); j++) {
            if ((rrset = cache_rrset_retain2(&hash->hash_array[j], 0)) == NULL)
                continue;

            if (rrset->rrset_expire > 0)
                rrset->rrset_expire = now;

            cache_rrset_release(rrset, tls);
        }
    }
}

void
dns_cache_printstats(int s)
{
    dns_util_sendf(s, "Cache:\n");
    dns_util_sendf(s, "    %10u caches allocated\n",                               CacheStats.stat_rrset_new);
    dns_util_sendf(s, "    %10u caches registered\n",                              CacheStats.stat_rrset_registered);
    dns_util_sendf(s, "    %10u caches were negative cache\n",                     CacheStats.stat_rrset_negative);
    dns_util_sendf(s, "    %10u times cache looked up\n",                          CacheStats.stat_rrset_lookup);
    dns_util_sendf(s, "    %10u times cache key compared\n",                       CacheStats.stat_lookup_cmp);
    dns_util_sendf(s, "    %10u times cache hit\n",                                CacheStats.stat_cache_hit);
    dns_util_sendf(s, "    %10u caches drained due to rrset entry full\n",         CacheStats.stat_drain_rrset);
    dns_util_sendf(s, "    %10u caches drained due to resource entry full\n",      CacheStats.stat_drain_resource);
    dns_util_sendf(s, "    %10u caches drained due to hash collision\n",           CacheStats.stat_drain_hashcol);
    dns_util_sendf(s, "\n");
}

static dns_cache_rrset_t *
cache_rrset_get(dns_msg_question_t *q, dns_tls_t *tls)
{
    dns_cache_rrset_t *rrset;

    if ((rrset = cache_rrset_new(q, tls)) == NULL)
        return NULL;

    rrset->rrset_category = 0;
    rrset->rrset_hits = 1;
    rrset->rrset_expire = 0;
    rrset->rrset_dns_rcode = DNS_RCODE_NOERROR;
    rrset->rrset_dns_flags = 0;

    memcpy(&rrset->rrset_question, q, sizeof(*q));
    STRLOWER(rrset->rrset_question.mq_name);

    dns_list_init(&rrset->rrset_list_cname);
    dns_list_init(&rrset->rrset_list_answer);

    return rrset;
}

static dns_cache_rrset_t *
cache_rrset_new(dns_msg_question_t *q, dns_tls_t *tls)
{
    dns_cache_rrset_t *rrset;

    if ((rrset = (dns_cache_rrset_t *) dns_mpool_get(&CacheSetPool, tls->tls_id)) == NULL) {
        if ((rrset = cache_rrset_drain(tls)) == NULL)
            return NULL;
    }

    cache_rrset_reset(rrset, tls);

    if (cache_rrset_retain(rrset) < 0)
        plog(LOG_CRIT, "%s: new rrset retain failed. why?", __func__);

    return rrset;
}

static dns_cache_rrset_t *
cache_rrset_lookup(dns_msg_question_t *q, int category, cache_hash_t *hash, unsigned hvalue, dns_tls_t *tls)
{
    int index;
    time_t now;
    dns_cache_rrset_t *rrset;

    now = time(NULL);
    index = hvalue % NELEMS(hash->hash_array);

    if ((rrset = cache_rrset_retain2(&hash->hash_array[index], 0)) == NULL)
        return NULL;

    if (rrset->rrset_expire > 0 && rrset->rrset_expire <= now) {
        plog(LOG_DEBUG, "%s: found expired cache. invalidate it.", MODULE);
        cache_rrset_invalidate(rrset, hash, index, tls);
        cache_rrset_release(rrset, tls);
        return NULL;
    }

    if (cache_rrset_compare(rrset, q, category) == 0) {
        ATOMIC_INC(&CacheStats.stat_cache_hit);
        rrset->rrset_hits = 1;
        return rrset;
    }

    plog(LOG_DEBUG, "%s: rrset compare fail", MODULE);
    cache_rrset_release(rrset, tls);

    return NULL;
}

static int
cache_rrset_compare(dns_cache_rrset_t *rrset, dns_msg_question_t *q, int category)
{
    dns_msg_question_t *r;

    ATOMIC_INC(&CacheStats.stat_lookup_cmp);

    r = &rrset->rrset_question;
    if (q->mq_type == r->mq_type && q->mq_class == r->mq_class) {
        if (rrset->rrset_category == category) {
            if (strcasecmp(q->mq_name, r->mq_name) == 0)
                return 0;
        }
    }

    return -1;
}

static int
cache_rrset_refflag(dns_cache_rrset_t *rrset, int flag)
{
    unsigned l, n;

retry:
    l = rrset->rrset_refs;
    n = l | flag;

    if (l & flag)
        return -1;
    if (!ATOMIC_CAS(&rrset->rrset_refs, l, n))
        goto retry;

    return 0;
}

static int
cache_rrset_invalidate(dns_cache_rrset_t *rrset, cache_hash_t *hash, unsigned hvalue, dns_tls_t *tls)
{
    if (cache_rrset_refflag(rrset, CACHE_RRSET_INVALID) < 0)
        return -1;

    /* assume rrset is registered */
    if (cache_rrset_unregister(hash, rrset, hvalue, tls) < 0)
        plog(LOG_NOTICE, "%s: rrset %p is not registered", __func__, rrset);

    return 0;
}

static int
cache_rrset_retain(dns_cache_rrset_t *rrset)
{
    unsigned ref, nr;

retry:
    ref = rrset->rrset_refs;
    nr = ref + 1;

    if (ref & CACHE_RRSET_INVALID)
        return -1;
    if (!ATOMIC_CAS(&rrset->rrset_refs, ref, nr))
        goto retry;

    return 0;
}

static void
cache_rrset_release(dns_cache_rrset_t *rrset, dns_tls_t *tls)
{
    unsigned oldval;

    oldval = ATOMIC_XADD(&rrset->rrset_refs, -1);
    if ((oldval & ~CACHE_RRSET_FLAGMASK) == 1)
        cache_rrset_free(rrset, tls);
}

static dns_cache_rrset_t *
cache_rrset_retain2(dns_cache_rrset_t **rr0, int nospin)
{
    int r;
    dns_cache_rrset_t *rrset;

    if (cache_rrset_plock(rr0, nospin) < 0)
        return NULL;

    rrset = CACHE_RRSET_PTR(*rr0);
    r = cache_rrset_retain(rrset);
    *rr0 = rrset;   /* unlock */

    return (r < 0) ? NULL : rrset;
}

static int
cache_rrset_plock(dns_cache_rrset_t **ptr, int nospin)
{
    void *p0, *np;

retry:
    p0 = *ptr;
    np = (void *) ((uintptr_t) p0 | CACHE_RRSET_PLOCK);

    if (p0 == NULL)
        return -1;

    if ((uintptr_t) p0 & CACHE_RRSET_PLOCK) {
        if (nospin)
            return -1;
        else {
            usleep(100);
            goto retry;
        }
    }

    if (!ATOMIC_CAS_PTR(ptr, p0, np))
        goto retry;

    return 0;
}

static void
cache_rrset_free(dns_cache_rrset_t *rrset, dns_tls_t *tls)
{
    cache_rrset_reset(rrset, tls);
    dns_mpool_release(&CacheSetPool, rrset, tls->tls_id);
}

static void
cache_rrset_reset(dns_cache_rrset_t *rrset, dns_tls_t *tls)
{
    dns_cache_t *cache;

    while ((cache = (dns_cache_t *) dns_list_pop(&rrset->rrset_list_cname)) != NULL)
        dns_mpool_release(&CachePool, cache, tls->tls_id);
    while ((cache = (dns_cache_t *) dns_list_pop(&rrset->rrset_list_answer)) != NULL)
        dns_mpool_release(&CachePool, cache, tls->tls_id);

    rrset->rrset_refs = 0;
}

static int
cache_rrset_register(cache_hash_t *hash, dns_cache_rrset_t *rrset, unsigned hvalue, dns_tls_t *tls)
{
    int index;

    if (cache_rrset_retain(rrset) < 0)
        return -1;

    index = hvalue % NELEMS(hash->hash_array);
    if (hash->hash_array[index] == NULL) {
        if (ATOMIC_CAS_PTR(&hash->hash_array[index], NULL, rrset))
            return 0;
        else {
            /* retained in this function */
            cache_rrset_release(rrset, tls);
            return -1;
        }
    }

    if (cache_rrset_register_force(hash, rrset, index, tls) < 0) {
        /* retained in this function */
        cache_rrset_release(rrset, tls);
        return -1;
    }

    /* keep refcount */

    return 0;
}

static int
cache_rrset_register_force(cache_hash_t *hash, dns_cache_rrset_t *rrset, int index, dns_tls_t *tls)
{
    dns_cache_rrset_t *p;

    if ((p = cache_rrset_retain2(&hash->hash_array[index], NOSPIN)) == NULL)
        return -1;

    /* we prefer used entry */
    if (p->rrset_hits > 0) {
        p->rrset_hits = 0;
        cache_rrset_release(p, tls);
        return -1;
    }

    /* used by another thread? (check 1) */
    if (CACHE_RRSET_REFS(p) != 2) {
        cache_rrset_release(p, tls);
        return -1;
    }

    /* set invalid flag (slightly high-cost) */
    if (cache_rrset_refflag(p, CACHE_RRSET_INVALID) < 0) {
        cache_rrset_release(p, tls);
        return -1;
    }

    /* refs=2 -> registered + retained by us (check again) */
    if (CACHE_RRSET_REFS(p) != 2) {
        /* used by another thread */
        cache_rrset_release(p, tls);
        return -1;
    }

    /* got it */
retry:
    /* hash_array entry maybe locked */
    if (!ATOMIC_CAS_PTR(&hash->hash_array[index], p, rrset)) {
        usleep(1000);
        goto retry;   /* spin */
    }

    cache_rrset_release(p, tls);   /* retined by this function */
    cache_rrset_release(p, tls);   /* unregister cache */

    ATOMIC_INC(&CacheStats.stat_drain_hashcol);

    return 0;
}

static int
cache_rrset_unregister(cache_hash_t *hash, dns_cache_rrset_t *rrset, unsigned hvalue, dns_tls_t *tls)
{
    int index;

    index = hvalue % NELEMS(hash->hash_array);

retry:
    if (CACHE_RRSET_PTR(hash->hash_array[index]) == rrset) {
        /* check PLOCK flag */
        if (!ATOMIC_CAS_PTR(&hash->hash_array[index], rrset, NULL)) {
            /* hash_array[i] is temporarily locked or unregistered by other thread */
            goto retry;
        }

        cache_rrset_release(rrset, tls);
        return 0;
    }

    return -1;
}

static dns_cache_rrset_t *
cache_rrset_drain(dns_tls_t *tls)
{
    dns_cache_rrset_t *rrset;

    if ((rrset = cache_rrset_drain_one(tls)) != NULL) {
        cache_rrset_reset(rrset, tls);
        ATOMIC_INC(&CacheStats.stat_drain_rrset);
    }

    return rrset;
}

static dns_cache_rrset_t *
cache_rrset_drain_one(dns_tls_t *tls)
{
    int i;
    unsigned r;
    cache_hash_t *hash;
    dns_cache_rrset_t *rrset;

    r = xarc4random(&tls->tls_arctx);

    for (i = 0; i < CacheHashCount; i++, r++) {
        r %= CacheHashCount;
        hash = &CacheHash[r];

        if ((rrset = cache_rrset_drain_hash(hash, tls)) != NULL)
            return rrset;
    }

    return NULL;
}

static dns_cache_rrset_t *
cache_rrset_drain_hash(cache_hash_t *hash, dns_tls_t *tls)
{
    int i;
    unsigned r;
    dns_cache_rrset_t *rrset;

    r = xarc4random(&tls->tls_arctx);

    for (i = 0; i < NELEMS(hash->hash_array); i++, r++) {
        /*
         * cache freeing procedure:
         * (1) retian2
         * (2) invalidate
         * (3) release
         */
        r %= NELEMS(hash->hash_array);
        if ((rrset = cache_rrset_retain2(&hash->hash_array[r], NOSPIN)) == NULL)
            continue;

        cache_rrset_invalidate(rrset, hash, r, tls);
        if (CACHE_RRSET_REFS(rrset) == 1)
            return rrset;

        cache_rrset_release(rrset, tls);
    }

    return NULL;
}

static void
cache_rrset_set_expire(dns_cache_rrset_t *rrset, dns_cache_t *cache)
{
    time_t expire;

    /* the TTLs of all RRs in an RRSet must be the same. (RFC2181 5.2.) */
    expire = time(NULL) + cache->cache_res.mr_ttl;

    if (rrset->rrset_expire == 0 || rrset->rrset_expire > expire) {
        rrset->rrset_expire = expire;
        cache_update_ttl(rrset, cache->cache_res.mr_ttl);
    }
}

static cache_hash_t *
cache_hash(unsigned *value, dns_msg_question_t *q, int category)
{
    unsigned h;

    h = dns_util_hash_initial();
    h = dns_util_hash_calc(&q->mq_class, sizeof(q->mq_class), h);
    h = dns_util_hash_calc(&q->mq_type, sizeof(q->mq_type), h);
    h = dns_util_hash_calc(&category, sizeof(category), h);
    h = dns_util_hash_calc(q->mq_name, strlen(q->mq_name), h);
    *value = h;

    return &CacheHash[h % CacheHashCount];
}

static dns_cache_t *
cache_get(dns_tls_t *tls)
{
    dns_cache_t *cache;

    if ((cache = (dns_cache_t *) dns_mpool_get(&CachePool, tls->tls_id)) != NULL)
        return cache;
    if ((cache = cache_drain(tls)) != NULL)
        return cache;

    return NULL;
}

static dns_cache_t *
cache_drain(dns_tls_t *tls)
{
    dns_cache_t *cache;
    dns_cache_rrset_t *rrset;

    for (;;) {
        if ((rrset = cache_rrset_drain_one(tls)) == NULL)
            return NULL;
        else {
            if ((cache = (dns_cache_t *) dns_list_pop(&rrset->rrset_list_answer)) == NULL)
                cache = (dns_cache_t *) dns_list_pop(&rrset->rrset_list_cname);

            cache_rrset_reset(rrset, tls);
            dns_mpool_release(&CacheSetPool, rrset, tls->tls_id);

            if (cache != NULL)
                break;
        }
    }

    ATOMIC_INC(&CacheStats.stat_drain_resource);

    return cache;
}

static void
cache_init(dns_cache_t *cache, dns_msg_resource_t *res)
{
    memcpy(&cache->cache_res, res, sizeof(*res));
    STRLOWER(cache->cache_res.mr_q.mq_name);

    if (cache->cache_res.mr_ttl < DNS_CACHE_TTL_MIN)
        cache->cache_res.mr_ttl = DNS_CACHE_TTL_MIN;
    if (cache->cache_res.mr_ttl > DNS_CACHE_TTL_MAX)
        cache->cache_res.mr_ttl = DNS_CACHE_TTL_MAX;
}

static void
cache_update_ttl(dns_cache_rrset_t *rrset, int ttl)
{
    cache_update_ttl_list(&rrset->rrset_list_cname, ttl);
    cache_update_ttl_list(&rrset->rrset_list_answer, ttl);
}

static void
cache_update_ttl_list(dns_list_t *list, int ttl)
{
    dns_cache_t *cache;

    cache = DNS_CACHE_LIST_HEAD(list);
    while (cache != NULL) {
        cache->cache_res.mr_ttl = ttl;
        cache = DNS_CACHE_LIST_NEXT(list, cache);
    }
}
