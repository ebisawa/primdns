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
#ifndef __DNS_TIMER_H__
#define __DNS_TIMER_H__

typedef struct dns_timer dns_timer_t;
typedef void (dns_timer_func_t)(void *, void *);

struct dns_timer {
    struct timeval      t_time;
    unsigned            t_flags;
    unsigned            t_tocount;
    unsigned            t_magic;
    dns_timer_t        *t_prev;
    dns_timer_t        *t_next;
    dns_timer_func_t   *t_func;
    void               *t_param1;
    void               *t_param2;
};

void dns_timer_request(dns_timer_t *timer, int msec, dns_timer_func_t *timer_func, void *param1, void *param2);
void dns_timer_request_cont(dns_timer_t *timer, int msec, dns_timer_func_t *timer_func, void *param1, void *param2);
void dns_timer_cancel(dns_timer_t *timer);
void dns_timer_execute(void);
int dns_timer_tocount(dns_timer_t *timer);
int dns_timer_next_timeout(struct timeval *timo);

#endif
