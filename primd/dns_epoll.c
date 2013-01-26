/*
 * Copyright (c) 2010-2011 Satoshi Ebisawa. All rights reserved.
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
#include "config.h"
#ifdef HAVE_EPOLL

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include "dns.h"
#include "dns_sock.h"

#define MODULE "epoll"

int
dns_sock_event_init(dns_sock_event_t *swait)
{
    if ((swait->sev_fd = epoll_create(DNS_SOCK_EVENT_MAX)) < 0) {
        plog_error(LOG_ERR, MODULE, "epoll_create() failed");
        return -1;
    }

    return 0;
}

int
dns_sock_event_add(dns_sock_event_t *swait, dns_sock_t *sock)
{
    struct epoll_event event;

    memset(&event, 0, sizeof(event));
    event.events  = EPOLLIN | EPOLLET;
    event.data.ptr = sock;

    if (epoll_ctl(swait->sev_fd, EPOLL_CTL_ADD, sock->sock_fd, &event) < 0) {
        plog_error(LOG_ERR, MODULE, "epoll_ctl() failed");
        return -1;
    }

    plog(LOG_DEBUG, "%s: event add: fd = %d", MODULE, sock->sock_fd);

    return 0;
}

int
dns_sock_event_wait(dns_sock_t **socks, int sock_max, dns_sock_event_t *swait, struct timeval *timeout)
{
    int i, count, max_wait, timo_msec = -1;
    struct epoll_event events[DNS_SOCK_EVENT_MAX];

    max_wait = (sock_max < NELEMS(events)) ? sock_max : NELEMS(events);
    if (timeout != NULL)
        timo_msec = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;

    if ((count = epoll_wait(swait->sev_fd, events, max_wait, timo_msec)) < 0) {
        if (errno == EINTR)
            return 0;

        plog_error(LOG_ERR, MODULE, "epoll_wait() failed");
        return -1;
    }

    for (i = 0; i < count; i++) {
        socks[i] = (dns_sock_t *) events[i].data.ptr;
        plog(LOG_DEBUG, "%s: event on fd = %d", MODULE, socks[i]->sock_fd);
    }

    return count;
}

#endif  /* HAVE_EPOLL */
