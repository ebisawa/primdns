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
#ifndef __DNS_SOCK_H__
#define __DNS_SOCK_H__
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "dns.h"

#define DNS_SOCK_THREADS       2
#define DNS_SOCK_TIMEOUT       1
#define DNS_SOCK_TCP_MAX    1024
#define DNS_SOCK_EVENT_MAX    32

typedef struct dns_sock_event dns_sock_event_t;
typedef struct dns_sock_prop dns_sock_prop_t;
typedef struct dns_sock dns_sock_t;

typedef int (dns_sock_select_func_t)(dns_sock_t *sock, int thread_id);
typedef int (dns_sock_recv_func_t)(void *buf, int bufmax, struct sockaddr *from, dns_sock_t *sock);
typedef int (dns_sock_send_func_t)(dns_sock_t *sock, struct sockaddr *to, void *buf, int len);
typedef void (dns_sock_release_func_t)(dns_sock_t *sock);

struct dns_sock_event {
    int                       sev_fd;
};

struct dns_sock_prop {
    char                      sp_char;
    int                       sp_msgmax;
    dns_sock_select_func_t   *sp_select_func;
    dns_sock_recv_func_t     *sp_recv_func;
    dns_sock_send_func_t     *sp_send_func;
    dns_sock_release_func_t  *sp_release_func;
};

struct dns_sock {
    unsigned                  sock_state;
    unsigned                  sock_refs;
    int                       sock_fd;
    time_t                    sock_lastused;
    dns_sock_prop_t          *sock_prop;
};

int dns_sock_init(void);
int dns_sock_start_thread(void);
int dns_sock_proc(void);
int dns_sock_recv(void *buf, int bufmax, struct sockaddr *from, dns_sock_t *sock);
int dns_sock_send(dns_sock_t *sock, struct sockaddr *to, void *buf, int len);
void dns_sock_release(dns_sock_t *sock);
void dns_sock_invalidate(dns_sock_t *sock);
void dns_sock_gc(void);

#endif
