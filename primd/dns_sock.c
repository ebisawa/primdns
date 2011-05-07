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
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include "dns.h"
#include "dns_session.h"
#include "dns_sock.h"

#define MODULE "sock"

#define SOCK_FREE        0
#define SOCK_RESERVED    1
#define SOCK_ACTIVE      2

#define SOCK_INVALID     (1 << (sizeof(unsigned) * 8 - 1))

int dns_sock_event_init(dns_sock_event_t *swait);
int dns_sock_event_add(dns_sock_event_t *swait, dns_sock_t *sock);
int dns_sock_event_wait(dns_sock_t **socks, int sock_max, dns_sock_event_t *swait);

static void *sock_thread_routine(void *param);
static int sock_proc(dns_sock_event_t *sev, int thread_id);
static int sock_listen(int type);
static int sock_listen2(int type, struct sockaddr *sa);
static int sock_nonblock(dns_sock_t *sock);
static dns_sock_t *sock_get(void);
static void sock_activate(dns_sock_event_t *sev, dns_sock_t *sock);
static void sock_free(dns_sock_t *sock);
static int sock_udp_init(struct sockaddr *baddr);
static int sock_udp_select(dns_sock_t *sock, int thread_id);
static int sock_udp_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock);
static int sock_udp_send(dns_sock_t *sock, dns_sock_buf_t *sbuf);
static int sock_tcp_init(struct sockaddr *baddr);
static int sock_tcp_select(dns_sock_t *sock, int thread_id);
static int sock_tcp_child_init(dns_sock_t *sock, int child_fd);
static int sock_tcp_child_select(dns_sock_t *sock, int thread_id);
static int sock_tcp_child_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock);
static int sock_tcp_child_getmsg(void *buf, int bufmax, int sock_fd, int flags);
static int sock_tcp_child_send(dns_sock_t *sock, dns_sock_buf_t *sbuf);
static void sock_tcp_child_release(dns_sock_t *sock);
static int sock_set_refflag(dns_sock_t *sock, unsigned flag);

static pthread_t SockThreads[DNS_SOCK_THREADS];
static dns_sock_t SockPool[DNS_SOCK_TCP_MAX + 4];
static dns_sock_event_t SockEventUdp, SockEventTcp;

#define SOCK_IS_TCP_CHILD(sock)   ((sock)->sock_prop->sp_char == DNS_SOCK_CHAR_TCP)

static dns_sock_prop_t SockPropUdp = {
    DNS_SOCK_CHAR_UDP, DNS_UDP_MSG_MAX,
    sock_udp_select, sock_udp_recv, sock_udp_send, NULL
};

static dns_sock_prop_t SockPropTcp = {
    DNS_SOCK_CHAR_TCP_L, 0,
    sock_tcp_select, NULL, NULL, NULL
};

static dns_sock_prop_t SockPropTcpChild = {
    DNS_SOCK_CHAR_TCP, DNS_TCP_MSG_MAX,
    sock_tcp_child_select, sock_tcp_child_recv, sock_tcp_child_send, sock_tcp_child_release
};

int
dns_sock_init(void)
{
    if (dns_sock_event_init(&SockEventUdp) < 0)
        return -1;
    if (dns_sock_event_init(&SockEventTcp) < 0)
        return -1;

    if (Options.opt_baddr.ss_family == 0) {
        if (sock_listen(SOCK_DGRAM) < 0)
            return -1;
        if (sock_listen(SOCK_STREAM) < 0)
            return -1;
    } else {
        dns_util_sasetport((SA *) &Options.opt_baddr, Options.opt_port);

        if (sock_listen2(SOCK_DGRAM, (SA *) &Options.opt_baddr) < 0)
            return -1;
        if (sock_listen2(SOCK_STREAM, (SA *) &Options.opt_baddr) < 0)
            return -1;
    }

    return 0;
}

int
dns_sock_start_thread(void)
{
    int i;

    for (i = 0; i < DNS_SOCK_THREADS; i++)
        pthread_create(&SockThreads[i], NULL, (void *(*)(void *)) sock_thread_routine, (void *) (i + 1));

    return 0;
}

int
dns_sock_proc(void)
{
    sock_proc(&SockEventTcp, 0);

    return 0;
}

int
dns_sock_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock)
{
    int len = 0;

    if (sock->sock_prop->sp_recv_func != NULL) {
        if ((len = sock->sock_prop->sp_recv_func(sbuf, sock)) < 0)
            return -1;
    }

    sbuf->sb_sock = sock;
    sbuf->sb_buflen = len;

    return len;
}

int
dns_sock_send(dns_sock_buf_t *sbuf)
{
    dns_sock_t *sock = sbuf->sb_sock;

    if (sock->sock_prop->sp_send_func != NULL)
        return sock->sock_prop->sp_send_func(sock, sbuf);

    return 0;
}

void
dns_sock_release(dns_sock_t *sock)
{
    unsigned oldval;

    if (SOCK_IS_TCP_CHILD(sock)) {
        oldval = ATOMIC_XADD(&sock->sock_refs, -1);
        if (oldval == (SOCK_INVALID + 1)) {
            if (sock->sock_prop->sp_release_func != NULL)
                sock->sock_prop->sp_release_func(sock);
        }
    }
}

void
dns_sock_invalidate(dns_sock_t *sock)
{
    if (SOCK_IS_TCP_CHILD(sock)) {
        plog(LOG_DEBUG, "%s: invalidate sock %p, fd = %d", MODULE, sock, sock->sock_fd);
        sock_set_refflag(sock, SOCK_INVALID);
    }
}

void
dns_sock_gc(void)
{
    int i;
    time_t now;
    dns_sock_t *sock;

    now = time(NULL);

    for (i = 0; i < NELEMS(SockPool); i++) {
        sock = &SockPool[i];
        if (sock->sock_state != SOCK_ACTIVE)
            continue;
        if (!SOCK_IS_TCP_CHILD(sock))
            continue;

        if (sock->sock_refs == 0 || sock->sock_refs == SOCK_INVALID) {
            if (now >= sock->sock_lastused + DNS_SOCK_TIMEOUT) {
                if (sock->sock_prop->sp_release_func != NULL)
                    sock->sock_prop->sp_release_func(sock);
            }
        }
    }
}

static void *
sock_thread_routine(void *param)
{
    int thread_id = (int) param;

    dns_util_sigmaskall();

    for (;;)
        sock_proc(&SockEventUdp, thread_id);

    return NULL;
}

static int
sock_proc(dns_sock_event_t *sev, int thread_id)
{
    int i, count;
    dns_sock_t *sock, *rsocks[DNS_SOCK_EVENT_MAX];

    if ((count = dns_sock_event_wait(rsocks, NELEMS(rsocks), sev)) < 0)
        return -1;

    for (i = 0; i < count; i++) {
        sock = rsocks[i];
        if (sock == NULL || sock->sock_state != SOCK_ACTIVE)
            continue;
        if (sock->sock_prop->sp_select_func != NULL) {
            plog(LOG_DEBUG, "%s: sock event (fd = %d)", MODULE, sock->sock_fd);
            if (sock->sock_prop->sp_select_func(sock, thread_id) < 0)
                rsocks[i] = NULL;
        }
    }

    return 0;
}

static int
sock_listen(int type)
{
    char ports[8];
    struct addrinfo hints, *res, *res0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = type;
    hints.ai_flags = AI_PASSIVE;
    snprintf(ports, sizeof(ports), "%u", Options.opt_port);

    if (getaddrinfo(NULL, ports, &hints, &res0)) {
        plog(LOG_ERR, "%s: getaddrinfo() failed", MODULE);
        return -1;
    }

    for (res = res0; res != NULL; res = res->ai_next) {
        if (sock_listen2(res->ai_socktype, res->ai_addr) < 0) {
            freeaddrinfo(res0);
            return -1;
        }
    }

    freeaddrinfo(res0);
    return 0;
}

static int
sock_listen2(int type, struct sockaddr *sa)
{
    char buf[256];

    if (sa->sa_family == AF_INET && !Options.opt_ipv4_enable)
        return 0;
    if (sa->sa_family == AF_INET6 && !Options.opt_ipv6_enable)
        return 0;

    switch (type) {
    case SOCK_DGRAM:
        dns_util_sa2str(buf, sizeof(buf), sa);
        plog(LOG_INFO, "listen on %s udp", buf);

        if (sock_udp_init(sa) < 0)
            return -1;
        break;

    case SOCK_STREAM:
        dns_util_sa2str(buf, sizeof(buf), sa);
        plog(LOG_INFO, "listen on %s tcp", buf);

        if (sock_tcp_init(sa) < 0)
            return -1;
        break;
    }

    return 0;
}

static int
sock_nonblock(dns_sock_t *sock)
{
    int flags;

    if ((flags = fcntl(sock->sock_fd, F_GETFL)) < 0) {
        plog_error(LOG_ERR, MODULE, "fcntl(F_GETFL) failed");
        return -1;
    }

    if (fcntl(sock->sock_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        plog_error(LOG_ERR, MODULE, "fcntl(F_SETFL) failed");
        return -1;
    }

    return 0;
}

static dns_sock_t *
sock_get(void)
{
    int i;
    dns_sock_t *sock;

    for (i = 0; i < NELEMS(SockPool); i++) {
        sock = &SockPool[i];
        if (sock->sock_state == SOCK_FREE) {
            if (ATOMIC_CAS(&sock->sock_state, SOCK_FREE, SOCK_RESERVED)) {
                sock->sock_fd = -1;
                return sock;
            }
        }
    }

    return NULL;
}

static void
sock_activate(dns_sock_event_t *sev, dns_sock_t *sock)
{
    dns_sock_event_add(sev, sock);
    sock->sock_state = SOCK_ACTIVE;
}

static void
sock_free(dns_sock_t *sock)
{
    if (sock->sock_fd > 0) {
        plog(LOG_DEBUG, "%s: close fd = %d", MODULE, sock->sock_fd);
        close(sock->sock_fd);
    }

    sock->sock_fd = 0;
    sock->sock_state = SOCK_FREE;
}

static int
sock_udp_init(struct sockaddr *baddr)
{
    int sock_fd;
    dns_sock_t *sock;

    if ((sock = sock_get()) == NULL) {
        plog(LOG_CRIT, "%s: socket resource full. why?", MODULE);
        return -1;
    }

    if ((sock_fd = dns_util_socket_sa(baddr->sa_family, SOCK_DGRAM, baddr)) < 0) {
        sock_free(sock);
        return -1;
    }

    memset(sock, 0, sizeof(*sock));
    sock->sock_fd = sock_fd;
    sock->sock_prop = &SockPropUdp;

    if (sock_nonblock(sock) < 0) {
        plog(LOG_ERR, "%s: sock_nonblock() failed", __func__);
        sock_free(sock);
        return -1;
    }

    sock_activate(&SockEventUdp, sock);

    return 0;
}

static int
sock_udp_select(dns_sock_t *sock, int thread_id)
{
    return dns_session_request(sock, thread_id);
}

static int
sock_udp_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock)
{
    int len;
    socklen_t fromlen;

    fromlen = sizeof(sbuf->sb_remote);
    if ((len = recvfrom(sock->sock_fd, sbuf->sb_buf, sizeof(sbuf->sb_buf), 0,
                        (SA *) &sbuf->sb_remote, &fromlen)) < 0) {
        if (errno != EAGAIN)
            plog_error(LOG_ERR, MODULE, "recvfrom() failed");

        return -1;
    }

    return len;
}

static int
sock_udp_send(dns_sock_t *sock, dns_sock_buf_t *sbuf)
{
    plog(LOG_DEBUG, "%s: udp send: fd = %d", MODULE, sock->sock_fd);

    return sendto(sock->sock_fd, sbuf->sb_buf, sbuf->sb_buflen, 0,
                  (SA *) &sbuf->sb_remote, SALEN(&sbuf->sb_remote));
}

static int
sock_tcp_init(struct sockaddr *baddr)
{
    int sock_fd;
    dns_sock_t *sock;

    if ((sock = sock_get()) == NULL) {
        plog(LOG_CRIT, "%s: socket resource full. why?", MODULE);
        return -1;
    }

    if ((sock_fd = dns_util_socket_sa(baddr->sa_family, SOCK_STREAM, baddr)) < 0) {
        sock_free(sock);
        return -1;
    }

    memset(sock, 0, sizeof(*sock));
    sock->sock_fd = sock_fd;
    sock->sock_prop = &SockPropTcp;

    if (listen(sock_fd, DNS_SOCK_TCP_MAX) < 0) {
        plog_error(LOG_ERR, MODULE, "listen() failed");
        sock_free(sock);
        return -1;
    }

    if (sock_nonblock(sock) < 0) {
        plog(LOG_ERR, "%s: sock_nonblock() failed", __func__);
        sock_free(sock);
        return -1;
    }

    sock_activate(&SockEventTcp, sock);

    return 0;
}

static int
sock_tcp_select(dns_sock_t *sock, int thread_id)
{
    int fd;
    socklen_t fromlen;
    dns_sock_t *sock_tcp;
    struct sockaddr_storage from;

    for (;;) {
        if ((sock_tcp = sock_get()) == NULL) {
            plog(LOG_DEBUG, "%s: socket resource full", MODULE);
            return -1;
        }

        fromlen = sizeof(struct sockaddr_storage);
        if ((fd = accept(sock->sock_fd, (SA *) &from, &fromlen)) < 0) {
            sock_free(sock_tcp);
            if (errno == EAGAIN)
                break;

            plog_error(LOG_ERR, MODULE, "accept() failed");
            return -1;
        }

        plog(LOG_DEBUG, "%s: accept fd = %d", __func__, fd);

        if (sock_tcp_child_init(sock_tcp, fd) < 0) {
            plog(LOG_ERR, "%s: sock_tcp_child_init() failed (fd = %d)", __func__, fd);
            sock_free(sock_tcp);
            /* try next socket */
        }
    }

    return -1;
}

static int
sock_tcp_child_init(dns_sock_t *sock, int child_fd)
{
    memset(sock, 0, sizeof(*sock));
    sock->sock_fd = child_fd;
    sock->sock_lastused = time(NULL);
    sock->sock_prop = &SockPropTcpChild;

    if (sock_nonblock(sock) < 0) {
        plog(LOG_ERR, "%s: sock_nonblock() failed", __func__);
        return -1;
    }

    sock_activate(&SockEventTcp, sock);

    return 0;
}

static int
sock_tcp_child_select(dns_sock_t *sock, int thread_id)
{
    unsigned refs;

    for (;;) {
        /*
         * do not process request if invalid flags is set,
         * otherwise increment reference counter to get
         * ownership of this socket.
         */
        if ((refs = sock->sock_refs) & SOCK_INVALID) {
            plog(LOG_DEBUG, "%s: XXX ignore event due to the socket is invalidated", MODULE);
            return -1;
        }

        if (ATOMIC_CAS(&sock->sock_refs, refs, refs + 1))
            break;
    }

    return dns_session_request(sock, thread_id);
}

static int
sock_tcp_child_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock)
{
    int len;
    socklen_t fromlen;

    /* peek */
    if ((len = sock_tcp_child_getmsg(sbuf->sb_buf, sizeof(sbuf->sb_buf), sock->sock_fd, MSG_PEEK)) < 0)
        return -1;

    /* incompeleted message */
    if (len == 0)
        return 0;

    /* receive */
    if ((len = sock_tcp_child_getmsg(sbuf->sb_buf, sizeof(sbuf->sb_buf), sock->sock_fd, 0)) <= 0) {
        plog(LOG_ERR, "%s: sock_tcp_child_getmsg() failed", MODULE);
        return -1;
    }

    fromlen = sizeof(sbuf->sb_remote);
    if (getpeername(sock->sock_fd, (SA *) &sbuf->sb_remote, &fromlen) < 0) {
        plog_error(LOG_ERR, MODULE, "getpeername() failed");
        return -1;
    }

    return len;
}

static int
sock_tcp_child_getmsg(void *buf, int bufmax, int sock_fd, int flags)
{
    int len;
    uint16_t msglen;

    len = recv(sock_fd, &msglen, sizeof(msglen), flags);
    if (len == 0)
        return -1;  /* closed by peer */
    if (len != sizeof(msglen))
        return 0;   /* incompleted */

    msglen = ntohs(msglen);
    if (msglen > bufmax) {
        plog(LOG_NOTICE, "%s: message too big: msglen = %d (%02x)", MODULE, msglen, msglen);
        return -1;  /* abort session */
    }

    len = recv(sock_fd, buf, msglen, flags);
    if (len != msglen)
        return 0;

    return len;
}

static int
sock_tcp_child_send(dns_sock_t *sock, dns_sock_buf_t *sbuf)
{
    int slen;
    uint16_t msglen;

    msglen = htons(sbuf->sb_buflen);
    slen = send(sock->sock_fd, &msglen, sizeof(msglen), 0);
    if (slen != sizeof(msglen)) {
        plog_error(LOG_ERR, MODULE, "send() failed: fd = %d", sock->sock_fd);
        return -1;
    }

    slen = send(sock->sock_fd, sbuf->sb_buf, sbuf->sb_buflen, 0);
    if (slen != sbuf->sb_buflen) {
        plog_error(LOG_ERR, MODULE, "send() failed: fd = %d", sock->sock_fd);
        return -1;
    }

    sock->sock_lastused = time(NULL);

    return 0;
}

static void
sock_tcp_child_release(dns_sock_t *sock)
{
    plog(LOG_DEBUG, "%s: free sock = %p, fd = %d", MODULE, sock, sock->sock_fd);
    sock_free(sock);
}

static int
sock_set_refflag(dns_sock_t *sock, unsigned flag)
{
    unsigned l, n;

    for (;;) {
        l = sock->sock_refs;
        n = l | flag;

        if (l & flag)
            return -1;
        if (ATOMIC_CAS(&sock->sock_refs, l, n))
            break;
    }

    return 0;
}
