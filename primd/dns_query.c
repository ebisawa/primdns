/*
 * Copyright (c) 2012 Satoshi Ebisawa. All rights reserved.
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
#include <arpa/inet.h>
#include "dns.h"
#include "dns_cache.h"

#define MODULE "query"

#define QUERY_PORT_MIN   1024

static int query_socket(struct sockaddr *to, dns_tls_t *tls);
static int query_connect(struct sockaddr *to, dns_tls_t *tls);
static int query_send(int s, dns_msg_question_t *q, uint16_t msgid);
static int query_msg_parse(dns_msg_resource_t *res, char *buf, int len, uint16_t msgid);
static int query_check_header(dns_header_t *header, uint16_t expid);

int
dns_query_start(struct sockaddr *to, dns_msg_question_t *q, uint16_t msgid, dns_tls_t *tls)
{
    int s;

    if ((s = query_connect(to, tls)) < 0)
        return -1;
    if (query_send(s, q, msgid) < 0) {
        close(s);
        return -1;
    }

    return s;
}

void
dns_query_finish(int sock)
{
    close(sock);
}

int
dns_query_receive(dns_msg_resource_t *res, int s, uint16_t msgid)
{
    int len;
    char buf[DNS_UDP_MSG_MAX];
    socklen_t fromlen;
    struct sockaddr_storage from;

    fromlen = sizeof(from);
    if ((len = recvfrom(s, buf, sizeof(buf), 0, (SA *) &from, &fromlen)) < 0) {
        plog_error(LOG_ERR, MODULE, "recvfrom() failed");
        return -1;
    }

    if (query_msg_parse(res, buf, len, msgid) < 0) {
        plog_error(LOG_ERR, MODULE, "query_msg_parse() failed");
        return -1;
    }

    return 0;
}

static int
query_socket(struct sockaddr *to, dns_tls_t *tls)
{
    uint16_t r;
    int i, s, port;

    for (i = 0; i < 100; i++) {
        r = xarc4random(&tls->tls_arctx);
        port = r % (0xffff - QUERY_PORT_MIN) + QUERY_PORT_MIN;

        if ((s = dns_util_socket(PF_INET, SOCK_DGRAM, port)) > 0) {
            plog(LOG_DEBUG, "%s: src port = %u", __func__, port);
            return s;
        }
    }

    return -1;
}

static int
query_connect(struct sockaddr *to, dns_tls_t *tls)
{
    int sock;

    if ((sock = query_socket(to, tls)) < 0)
        return -1;

    if (connect(sock, to, SALEN(to)) < 0) {
        plog_error(LOG_ERR, MODULE, "connect() failed");
        close(sock);
        return -1;
    }

    return sock;
}

static int
query_send(int s, dns_msg_question_t *q, uint16_t msgid)
{
    int len;
    char buf[DNS_UDP_MSG_MAX];
    dns_msg_handle_t handle;

    if (dns_msg_write_open(&handle, buf, sizeof(buf)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_open() failed", __func__);
        return -1;
    }

    if (dns_msg_write_header(&handle, msgid, DNS_FLAG_RD) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_header() failed", __func__);
        dns_msg_write_close(&handle);
        return -1;
    }

    if (dns_msg_write_question(&handle, q) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_question() failed", __func__);
        dns_msg_write_close(&handle);
        return -1;
    }

    if ((len = dns_msg_write_close(&handle)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_close() failed", __func__);
        return -1;
    }

    return send(s, buf, len, 0);
}

static int
query_msg_parse(dns_msg_resource_t *res, char *buf, int len, uint16_t msgid)
{
    int rcode;
    uint16_t flags;
    dns_header_t header;
    dns_msg_handle_t handle;
    dns_msg_question_t question;

    if (dns_msg_read_open(&handle, buf, len) < 0) {
        plog(LOG_NOTICE, "%s: open message failed. broken message?", MODULE);
        return -1;
    }

    if (dns_msg_read_header(&header, &handle) < 0)
        goto error;

    /* check result code */
    flags = ntohs(header.hdr_flags);
    rcode = DNS_RCODE(flags);

    if (flags & DNS_FLAG_TC) {
        plog(LOG_NOTICE, "%s: XXX truncated message is not supported", MODULE);
        goto error;
    }

    if (query_check_header(&header, msgid) < 0)
        goto error;
    if (dns_msg_read_question(&question, &handle) < 0)
        goto error;

    /* XXX check question? */

    if (ntohs(header.hdr_ancount) > 0) {
        if (dns_msg_read_resource(res, &handle) < 0) {
            plog(LOG_NOTICE, "%s: read resource failed. broken message?", MODULE);
            goto error;
        }
    }

    dns_msg_read_close(&handle);
    return 0;

error:
    dns_msg_read_close(&handle);
    return -1;
}

static int
query_check_header(dns_header_t *header, uint16_t expid)
{
    uint16_t msgid, flags;

    msgid = ntohs(header->hdr_id);
    flags = ntohs(header->hdr_flags);

    if (msgid != expid) {
        plog(LOG_NOTICE, "%s: message id mismatch", MODULE);
        return -1;
    }

    if ((flags & DNS_FLAG_QR) == 0) {
        plog(LOG_NOTICE, "%s: message is not a response", MODULE);
        return -1;
    }

    if (ntohs(header->hdr_qdcount) > 1) {
        plog(LOG_NOTICE, "%s: qdcount > 1", MODULE);
        return -1;
    }

    return 0;
}
