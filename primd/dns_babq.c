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
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include "dns.h"
#include "dns_abq.h"
#include "dns_babq.h"

#define MODULE "babq"

static void babq_lock_init(dns_babq_lock_t *lock);
static void babq_lock_wait(dns_babq_lock_t *lock);
static void babq_lock_release(dns_babq_lock_t *lock);
static int babq_lock_tryget(dns_babq_lock_t *lock);

int
dns_babq_init(dns_babq_t *babq, int count)
{
    if (dns_abq_init(&babq->babq_abq, count, &AbqThreadSafeLockFree) < 0) {
        plog(LOG_ERR, "%s: dns_abq_init() failed", MODULE);
        return -1;
    }

    babq_lock_init(&babq->babq_lock_pop);

    return 0;
}

int
dns_babq_push_nb(dns_babq_t *babq, void *elem)
{
    if (dns_abq_push(&babq->babq_abq, elem) < 0)
        return -1;

    babq_lock_release(&babq->babq_lock_pop);

   return 0;
}

void *
dns_babq_pop(dns_babq_t *babq)
{
    void *p;

    babq_lock_wait(&babq->babq_lock_pop);

    while ((p = dns_abq_pop(&babq->babq_abq)) == NULL)
        usleep(100);

    return p;
}

void *
dns_babq_pop_nb(dns_babq_t *babq)
{
    void *p;

    if (babq_lock_tryget(&babq->babq_lock_pop) < 0)
        return NULL;

    while ((p = dns_abq_pop(&babq->babq_abq)) == NULL)
        usleep(100);

    return p;
}

static void
babq_lock_init(dns_babq_lock_t *lock)
{
    if (sem_init(&lock->bl_sem, 0, 0) < 0)
        plog_error(LOG_CRIT, MODULE, "sem_init() failed");
}

static void
babq_lock_wait(dns_babq_lock_t *lock)
{
    sem_wait(&lock->bl_sem);
}

static void
babq_lock_release(dns_babq_lock_t *lock)
{
    sem_post(&lock->bl_sem);
}

static int
babq_lock_tryget(dns_babq_lock_t *lock)
{
    return sem_trywait(&lock->bl_sem);
}
