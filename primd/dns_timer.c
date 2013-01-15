/*
 * Copyright (c) 2011-2013 Satoshi Ebisawa. All rights reserved.
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
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include "dns_log.h"
#include "dns_timer.h"

#define TIMER_MAGIC         0xbeefbeef
#define TIMER_CONTINUOUS    0x0001

#define TIMER_SEC2USEC(s)   ((s) * 1000 * 1000)

static void timer_request(dns_timer_t *timer, int msec, dns_timer_func_t *timer_func, void *param1, void *param2, unsigned flags);
static void timer_register(dns_timer_t *timer);
static void timer_unregister(dns_timer_t *timer);
static int timer_is_registered(dns_timer_t *timer);
static void timer_chain_next(dns_timer_t *parent, dns_timer_t *timer);
static void timer_tvafter(struct timeval *tv, int msec);
static int timer_tvcompare(struct timeval *a, struct timeval *b);

static dns_timer_t *TimerHead;
static dns_timer_t *TimerTail;

void
dns_timer_request(dns_timer_t *timer, int msec, dns_timer_func_t *timer_func, void *param1, void *param2)
{
    timer_request(timer, msec, timer_func, param1, param2, 0);
}

void
dns_timer_request_cont(dns_timer_t *timer, int msec, dns_timer_func_t *timer_func, void *param1, void *param2)
{
    timer_request(timer, msec, timer_func, param1, param2, TIMER_CONTINUOUS);
}

void
dns_timer_cancel(dns_timer_t *timer)
{
    if (!timer_is_registered(timer)) {
        /* plog(LOG_DEBUG, "%s: timer %p is not registered", __func__, timer); */
        return;
    }

    plog(LOG_DEBUG, "%s: cancel timer %p", __func__, timer);
    timer_unregister(timer);
}

void
dns_timer_execute(void)
{
    dns_timer_t *t;
    struct timeval now;

    gettimeofday(&now, NULL);

    while ((t = TimerHead) != NULL) {
        if (timer_tvcompare(&now, &t->t_time) < 0)
            return;

        if ((t->t_flags & TIMER_CONTINUOUS) == 0)
            timer_unregister(t);
        if (t->t_func != NULL)
            t->t_func(t->t_param1, t->t_param2);

        t->t_tocount++;
    }
}

int
dns_timer_tocount(dns_timer_t *timer)
{
    return timer->t_tocount;
}

int
dns_timer_next_timeout(struct timeval *timo)
{
    int s, u;
    dns_timer_t *next;
    struct timeval now;

    if ((next = TimerHead) == NULL)
        return -1;

    gettimeofday(&now, NULL);
    s = next->t_time.tv_sec - now.tv_sec;
    u = next->t_time.tv_usec - now.tv_usec;

    if (u < 0) {
        s--;
        u += TIMER_SEC2USEC(1);
    }

    if (s < 0) {
        s = 0;
        u = 1;
    }

    timo->tv_sec = s;
    timo->tv_usec = u;

    return 0;
}

static void
timer_request(dns_timer_t *timer, int msec, dns_timer_func_t *timer_func, void *param1, void *param2, unsigned flags)
{
    if (timer_is_registered(timer)) {
        plog(LOG_DEBUG, "%s: timer %p has already been registered. cancel old timer.", __func__, timer);
        timer_unregister(timer);
    }

    plog(LOG_DEBUG, "%s: request timer %p: %d ms", __func__, timer, msec);

    memset(timer, 0, sizeof(*timer));
    gettimeofday(&timer->t_time, NULL);
    timer_tvafter(&timer->t_time, msec);

    timer->t_flags = flags;
    timer->t_func = timer_func;
    timer->t_param1 = param1;
    timer->t_param2 = param2;

    timer_register(timer);
}


static void
timer_register(dns_timer_t *timer)
{
    dns_timer_t *t;

    timer->t_magic = TIMER_MAGIC;

    if (TimerHead == NULL) {
        timer->t_prev = NULL;
        timer->t_next = NULL;
        TimerHead = timer;
        TimerTail = timer;
    } else if (timer_tvcompare(&timer->t_time, &TimerHead->t_time) < 0) {
        timer->t_prev = NULL;
        timer->t_next = TimerHead;
        TimerHead->t_prev = timer;
        TimerHead = timer;
    } else if (timer_tvcompare(&timer->t_time, &TimerTail->t_time) > 0) {
        timer_chain_next(TimerTail, timer);
        TimerTail = timer;
    } else {
        for (t = TimerHead; t != NULL; t = t->t_next) {
            if (timer_tvcompare(&timer->t_time, &t->t_time) > 0) {
                timer_chain_next(t, timer);
                break;
            }
        }
    }
}

static void
timer_unregister(dns_timer_t *timer)
{
    if (timer->t_prev != NULL)
        timer->t_prev->t_next = timer->t_next;
    if (timer->t_next != NULL)
        timer->t_next->t_prev = timer->t_prev;

    if (TimerHead == timer)
        TimerHead = timer->t_next;
    if (TimerTail == timer)
        TimerTail = timer->t_prev;

    timer->t_magic = 0;
    timer->t_prev = NULL;
    timer->t_next = NULL;
}

static int
timer_is_registered(dns_timer_t *timer)
{
    dns_timer_t *t;

    if (timer->t_magic != TIMER_MAGIC)
        return 0;

    for (t = TimerHead; t != NULL; t = t->t_next) {
        if (t == timer)
            return 1;
    }

    return 0;
}

static void
timer_chain_next(dns_timer_t *parent, dns_timer_t *timer)
{
    timer->t_prev = parent;
    timer->t_next = parent->t_next;

    if (parent->t_next != NULL)
        parent->t_next->t_prev = timer;

    parent->t_next = timer;
}

static void
timer_tvafter(struct timeval *tv, int msec)
{
    tv->tv_sec += msec / 1000;
    tv->tv_usec += msec % 1000;

    while (tv->tv_usec > TIMER_SEC2USEC(1)) {
        tv->tv_usec -= TIMER_SEC2USEC(1);
        tv->tv_sec++;
    }
}

static int
timer_tvcompare(struct timeval *a, struct timeval *b)
{
    int r;

    if ((r = a->tv_sec - b->tv_sec) != 0)
        return r;
    if ((r = a->tv_usec - b->tv_usec) != 0)
        return r;

    return 0;
}
