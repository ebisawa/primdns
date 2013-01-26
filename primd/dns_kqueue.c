/*
 * Copyright (c) 2010-2013 Satoshi Ebisawa. All rights reserved.
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
#ifdef HAVE_KQUEUE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include "dns.h"
#include "dns_sock.h"

#define MODULE "kqueue"

int
dns_sock_event_init(dns_sock_event_t *swait)
{
    if ((swait->sev_fd = kqueue()) < 0) {
        plog_error(LOG_ERR, MODULE, "kqueue() failed");
        return -1;
    }

    return 0;
}

int
dns_sock_event_add(dns_sock_event_t *swait, dns_sock_t *sock)
{
    struct kevent kev;

    EV_SET(&kev, sock->sock_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, sock);
    if (kevent(swait->sev_fd, &kev, 1, NULL, 0, NULL) < 0) {
        plog_error(LOG_ERR, MODULE, "kevent() failed");
        return -1;
    }

    return 0;
}

int
dns_sock_event_wait(dns_sock_t **socks, int sock_max, dns_sock_event_t *swait, struct timeval *timeout)
{
    int i, count, max_wait;
    struct kevent kev[DNS_SOCK_EVENT_MAX];
    struct timespec ts, *tsp = NULL;

    max_wait = (sock_max < NELEMS(kev)) ? sock_max : NELEMS(kev);

    if (timeout != NULL) {
        ts.tv_sec = timeout->tv_sec;
        ts.tv_nsec = timeout->tv_usec * 1000;
        tsp = &ts;
    }

    if ((count = kevent(swait->sev_fd, NULL, 0, kev, max_wait, tsp)) < 0) {
        if (errno == EINTR)
            return 0;

        plog_error(LOG_ERR, MODULE, "kevent() failed");
        return -1;
    }

    for (i = 0; i < count; i++) {
        socks[i] = kev[i].udata;
        plog(LOG_DEBUG, "%s: event on fd = %d", MODULE, socks[i]->sock_fd);
    }

    return count;
}

#endif  /* HAVE_KQUEUE */
