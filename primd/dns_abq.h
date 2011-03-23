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
#ifndef __DNS_ABQ_H__
#define __DNS_ABQ_H__

typedef struct {
    void           **abqb_aptr;
    unsigned         abqb_max;
    unsigned         abqb_wcursor;
    unsigned         abqb_rcursor;
} dns_abq_base_t;

typedef struct {
    int            (*abqf_push)(dns_abq_base_t *abqb, void *elem);
    void *         (*abqf_pop)(dns_abq_base_t *abqb);
} dns_abq_func_t;

typedef struct {
    dns_abq_base_t   abq_base;
    dns_abq_func_t  *abq_func;
} dns_abq_t;

extern dns_abq_func_t AbqThreadSafeLockFree;
extern dns_abq_func_t AbqThreadUnsafe;

int dns_abq_init(dns_abq_t *abq, int count, dns_abq_func_t *func);
int dns_abq_push(dns_abq_t *abq, void *elem);
void *dns_abq_pop(dns_abq_t *abq);

#endif
