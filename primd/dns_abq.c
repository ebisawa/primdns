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
#include <errno.h>
#include <unistd.h>
#include "dns.h"
#include "dns_abq.h"

#define MODULE "abq"

static void abq_init(dns_abq_base_t *abqb, int max, void **aptr);
static int abq_push_tslf(dns_abq_base_t *abqb, void *elem);
static void *abq_pop_tslf(dns_abq_base_t *abqb);
static int abq_push_tus(dns_abq_base_t *abqb, void *elem);
static void *abq_pop_tus(dns_abq_base_t *abqb);

dns_abq_func_t AbqThreadSafeLockFree = { abq_push_tslf, abq_pop_tslf };
dns_abq_func_t AbqThreadUnsafe = { abq_push_tus, abq_pop_tus };

int
dns_abq_init(dns_abq_t *abq, int count, dns_abq_func_t *func)
{
    void **aptr;

    if ((aptr = calloc(1, sizeof(void *) * count)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return -1;
    }

    abq->abq_func = func;
    abq_init(&abq->abq_base, count, aptr);

    return 0;
}

int
dns_abq_push(dns_abq_t *abq, void *elem)
{
    return abq->abq_func->abqf_push(&abq->abq_base, elem);
}

void *
dns_abq_pop(dns_abq_t *abq)
{
    return abq->abq_func->abqf_pop(&abq->abq_base);
}

static void
abq_init(dns_abq_base_t *abqb, int max, void **aptr)
{
    abqb->abqb_aptr = aptr;
    abqb->abqb_max = max;
    abqb->abqb_wcursor = 0;
    abqb->abqb_rcursor = 0;
}

static int
abq_radv_tslf(dns_abq_base_t *abqb)
{
    unsigned wcur, rcur, rpos;
    volatile dns_abq_base_t *v = (volatile dns_abq_base_t *) abqb;

    wcur = v->abqb_wcursor;
    rcur = v->abqb_rcursor;
    rpos = rcur % v->abqb_max;

    if (rcur < wcur) {
        if (v->abqb_aptr[rpos] == NULL) {
            ATOMIC_CAS(&v->abqb_rcursor, rcur, rcur + 1);
            return 0;
        }
    }

    return -1;
}

static int
abq_push_tslf(dns_abq_base_t *abqb, void *elem)
{
    unsigned wcur, wpos;
    volatile dns_abq_base_t *v = (volatile dns_abq_base_t *) abqb;

    for (;;) {
        if (v->abqb_wcursor == v->abqb_rcursor + v->abqb_max) {
            if (abq_radv_tslf(abqb) < 0)
                return -1;
            continue;
        }

        wcur = v->abqb_wcursor;
        wpos = wcur % v->abqb_max;

        if (v->abqb_aptr[wpos] != NULL) {
            ATOMIC_CAS(&v->abqb_wcursor, wcur, wcur + 1);
        } else {
            if (ATOMIC_CAS_PTR(&v->abqb_aptr[wpos], NULL, elem)) {
                ATOMIC_CAS(&v->abqb_wcursor, wcur, wcur + 1);
                return 0;
            }
        }
    }
}

static int
abq_wadv_tslf(dns_abq_base_t *abqb)
{
    unsigned wcur, wpos;
    volatile dns_abq_base_t *v = (volatile dns_abq_base_t *) abqb;

    wcur = v->abqb_wcursor;
    wpos = wcur % v->abqb_max;

    if (v->abqb_aptr[wpos] != NULL) {
        ATOMIC_CAS(&v->abqb_wcursor, wcur, wcur + 1);
        return 0;
    }

    return -1;
}

static void *
abq_pop_tslf(dns_abq_base_t *abqb)
{
    void *p;
    unsigned rcur, rpos;
    volatile dns_abq_base_t *v = (volatile dns_abq_base_t *) abqb;

    for (;;) {
        if (v->abqb_rcursor == v->abqb_wcursor) {
            if (abq_wadv_tslf(abqb) < 0)
                return NULL;
            continue;
        }

        rcur = v->abqb_rcursor;
        rpos = rcur % v->abqb_max;

        if ((p = v->abqb_aptr[rpos]) == NULL)
            ATOMIC_CAS(&v->abqb_rcursor, rcur, rcur + 1);
        else {
            if (ATOMIC_CAS_PTR(&v->abqb_aptr[rpos], p, NULL)) {
                ATOMIC_CAS(&v->abqb_rcursor, rcur, rcur + 1);
                return p;
            }
        }
    }
}

static int
abq_push_tus(dns_abq_base_t *abqb, void *elem)
{
    unsigned wpos;

    if (abqb->abqb_wcursor == abqb->abqb_rcursor + abqb->abqb_max)
        return -1;

    wpos = abqb->abqb_wcursor % abqb->abqb_max;
    abqb->abqb_aptr[wpos] = elem;
    abqb->abqb_wcursor++;

    return 0;
}

static void *
abq_pop_tus(dns_abq_base_t *abqb)
{
    void *p;
    unsigned rpos;

    if (abqb->abqb_rcursor == abqb->abqb_wcursor)
        return NULL;

    rpos = abqb->abqb_rcursor % abqb->abqb_max;
    p = abqb->abqb_aptr[rpos];
    abqb->abqb_aptr[rpos] = NULL;
    abqb->abqb_rcursor++;

    return p;
}
