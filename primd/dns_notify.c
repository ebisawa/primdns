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
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "dns.h"
#include "dns_config.h"
#include "dns_notify.h"
#include "dns_sock.h"

#define MODULE "notify"

#define NOTIFY_TIMEOUT  60
#define NOTIFY_RETRY     4

static void notify_each_addr4(uint32_t addr, uint32_t mask, void *zone_name);
static int notify_send(struct sockaddr *to, char *zone_name);
static int notify_send_message(dns_sock_t *sock, char *zone_name);
static int notify_make_message(char *buf, int bufmax, char *zone_name);

static int notify_sock_select(dns_sock_t *sock, int thread_id);
static int notify_sock_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock);
static int notify_sock_send(dns_sock_t *sock, dns_sock_buf_t *sbuf);
static void notify_timeout(dns_sock_t *sock, void *zone_name);
static void notify_log(dns_sock_t *sock, char *zone_name);

static dns_sock_prop_t SockPropNotify = {
    DNS_SOCK_CHAR_NOTIFY, DNS_UDP_MSG_MAX,
    notify_sock_select, notify_sock_recv, notify_sock_send,
};

void
dns_notify_all_slaves(void)
{
    dns_config_zone_t *zone;

    zone = (dns_config_zone_t *) dns_list_head(&ConfigRoot->r_zone);
    while (zone != NULL) {
        dns_acl_each(&zone->z_slaves.zss_acl, zone->z_name, notify_each_addr4);
        zone = (dns_config_zone_t *) dns_list_next(&ConfigRoot->r_zone, &zone->z_elem);
    }
}

static void
notify_each_addr4(uint32_t addr, uint32_t mask, void *zone_name)
{
    struct sockaddr_in sin;

    if (mask != 0xffffffff)
        return;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(addr);
    sin.sin_port = htons(DNS_PORT);
    /* XXX sin_len? */

    if (notify_send((SA *) &sin, zone_name) < 0) {
        plog(LOG_ERR, "%s: dns_notify_send() failed", MODULE);
        return;
    }
}

static int
notify_send(struct sockaddr *to, char *zone_name)
{
    int s;
    dns_sock_t *sock;

    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        plog_error(LOG_ERR, MODULE, "socket() failed");
        return -1;
    }

    if (connect(s, to, SALEN(to)) < 0) {
        plog_error(LOG_ERR, MODULE, "connect() failed");
        close(s);
        return -1;
    }

    if ((sock = dns_sock_udp_new(s, &SockPropNotify)) == NULL) {
        plog_error(LOG_ERR, MODULE, "dns_sock_add_udp() failed");
        close(s);
        return -1;
    }

    if (notify_send_message(sock, zone_name) < 0) {
        plog(LOG_ERR, "%s: dns_notify_send() failed", MODULE);
        dns_sock_free(sock);
        return -1;
    }

    return 0;
}

static int
notify_send_message(dns_sock_t *sock, char *zone_name)
{
    int len;
    dns_sock_buf_t sbuf;

    notify_log(sock, zone_name);

    if ((len = notify_make_message(sbuf.sb_buf, sizeof(sbuf.sb_buf), zone_name)) < 0)
        return -1;

    sbuf.sb_buflen = len;
    sbuf.sb_sock = sock;

    if (dns_sock_send(&sbuf) < 0)
        return -1;

    dns_timer_request_cont(&sock->sock_timer, SEC2MS(NOTIFY_TIMEOUT),
                           (dns_timer_func_t *) notify_timeout, sock, zone_name);

    return 0;
}

static int
notify_make_message(char *buf, int bufmax, char *zone_name)
{
    int len;
    uint16_t msgid, flags;
    dns_msg_handle_t handle;
    dns_msg_question_t q;
    arc4_ctx_t tmp_ctx;

    memset(&tmp_ctx, 0, sizeof(tmp_ctx));
    msgid = xarc4random(&tmp_ctx);
    flags = DNS_OP2FLAG(DNS_OP_NOTIFY) | DNS_FLAG_AA;

    if (dns_msg_write_open(&handle, buf, bufmax) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_open() failed", __func__);
        return -1;
    }

    if (dns_msg_write_header(&handle, msgid, flags) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_header() failed", __func__);
        dns_msg_write_close(&handle);
        return -1;
    }

    STRLCPY(q.mq_name, zone_name, sizeof(q.mq_name));
    q.mq_type = DNS_TYPE_SOA;
    q.mq_class = DNS_CLASS_IN;

    if (dns_msg_write_question(&handle, &q) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_question() failed", __func__);
        dns_msg_write_close(&handle);
        return -1;
    }

    if ((len = dns_msg_write_close(&handle)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_close() failed", __func__);
        return -1;
    }

    return len;
}

static int
notify_sock_select(dns_sock_t *sock, int thread_id)
{
    dns_sock_buf_t sbuf;

    plog(LOG_DEBUG, "%s: receive event: fd = %d", MODULE, sock->sock_fd);
    dns_timer_cancel(&sock->sock_timer);

    if (dns_sock_recv(&sbuf, sock) < 0) {
        /* connection refused? -> stop sending */
        dns_sock_free(sock);
        return -1;
    }

    /* XXX it shoule be ack-response from slave server. check it */

    /* notify session end */
    dns_sock_free(sock);

    return 0;
}

static int
notify_sock_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock)
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
notify_sock_send(dns_sock_t *sock, dns_sock_buf_t *sbuf)
{
    return send(sock->sock_fd, sbuf->sb_buf, sbuf->sb_buflen, 0);
}

static void
notify_timeout(dns_sock_t *sock, void *zone_name)
{
    int tocount = dns_timer_tocount(&sock->sock_timer);

    plog(LOG_DEBUG, "%s: timeout event: fd = %d, retry = %d",
         MODULE, sock->sock_fd, tocount);

    if (tocount >= NOTIFY_RETRY) {
        dns_timer_cancel(&sock->sock_timer);
        dns_sock_free(sock);
        return;
    }

    if (notify_send_message(sock, zone_name) < 0) {
        plog(LOG_ERR, "%s: dns_notify_send() failed", MODULE);
        dns_timer_cancel(&sock->sock_timer);
        dns_sock_free(sock);
        return;
    }
}

static void
notify_log(dns_sock_t *sock, char *zone_name)
{
    char buf[64];
    socklen_t slen;
    struct sockaddr_storage ss;

    slen = sizeof(ss);
    if (getpeername(sock->sock_fd, (SA *) &ss, &slen) < 0) {
        plog_error(LOG_ERR, MODULE, "getpeername() failed");
        return;
    }

    dns_util_sa2str_wop(buf, sizeof(buf), (SA *) &ss);
    plog(LOG_INFO, "send notify to %s (zone \"%s\")", buf, zone_name);
}
