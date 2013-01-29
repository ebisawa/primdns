/*
 * Copyright (c) 2010-2012 Satoshi Ebisawa. All rights reserved.
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
#include "dns_engine.h"
#include "dns_forward.h"

#define MODULE "forward"

#define FORWARD_PORT_MIN   1024

typedef struct {
    struct sockaddr_storage  conf_addr;
} forward_config_t;

static int forward_setarg(dns_engine_param_t *ep, char *arg);
static int forward_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);

static int forward_connect(struct sockaddr *to, dns_tls_t *tls);
static int forward_socket(struct sockaddr *to, dns_tls_t *tls);
static int forward_send(int s, dns_msg_question_t *q, uint16_t msgid);
static int forward_udp_receive(dns_cache_rrset_t *rrset, dns_msg_question_t *q, int s, uint16_t msgid, dns_tls_t *tls);
static int forward_msg_parse(dns_cache_rrset_t *rrset, dns_msg_question_t *q, char *buf, int len, uint16_t msgid, dns_tls_t *tls);
static int forward_msg_parse_resource(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_msg_handle_t *handle, int count, dns_tls_t *tls);
static int forward_msg_parse_resource_soa(dns_cache_rrset_t *rrset, dns_msg_handle_t *handle, int count);
static int forward_validate_header(dns_header_t *header, uint16_t expid);

dns_engine_t ForwardEngine = {
    "forward", sizeof(forward_config_t),
    forward_setarg,
    NULL,  /* init */
    NULL,  /* destroy */
    forward_query,
    NULL,  /* notify */
    NULL,  /* dump */
};

static int
forward_setarg(dns_engine_param_t *ep, char *arg)
{
    struct sockaddr_storage ss;
    forward_config_t *conf = (forward_config_t *) ep->ep_conf;

    if (dns_util_str2sa((SA *) &ss, arg, DNS_PORT) < 0)
        return -1;

    memcpy(&conf->conf_addr, &ss, sizeof(conf->conf_addr));

    return 0;
}

static int
forward_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    int s;
    uint16_t msgid;
    struct sockaddr *to;
    forward_config_t *conf = (forward_config_t *) ep->ep_conf;

    msgid = xarc4random(&tls->tls_arctx);
    to = (SA *) &conf->conf_addr;

    if ((s = forward_connect(to, tls)) < 0)
        return -1;

    if (forward_send(s, q, msgid) < 0) {
        close(s);
        return -1;
    }

    if (dns_util_select(s, DNS_ENGINE_TIMEOUT) < 0) {
        plog(LOG_ERR, "%s: forward query timed out: %s", MODULE, q->mq_name);
        close(s);
        return -1;
    }

    if (forward_udp_receive(rrset, q, s, msgid, tls) < 0) {
        plog(LOG_ERR, "%s: receiving response failed: %s", MODULE, q->mq_name);
        close(s);
        return -1;
    }

    close(s);

    return 0;
}

static int
forward_connect(struct sockaddr *to, dns_tls_t *tls)
{
    int sock;

    if ((sock = forward_socket(to, tls)) < 0)
        return -1;

    if (connect(sock, to, SALEN(to)) < 0) {
        plog_error(LOG_ERR, MODULE, "connect() failed");
        close(sock);
        return -1;
    }

    return sock;
}

static int
forward_socket(struct sockaddr *to, dns_tls_t *tls)
{
    int i, s, port;
    uint16_t r;

    /* try 10 times */
    for (i = 0; i < 10; i++) {
        r = xarc4random(&tls->tls_arctx);
        port = FORWARD_PORT_MIN + (r & 0xf000);

        if ((s = dns_util_socket(PF_INET, SOCK_DGRAM, port)) > 0) {
            plog(LOG_DEBUG, "%s: src port = %u", __func__, port);
            return s;
        }
    }

    return -1;
}

static int
forward_send(int s, dns_msg_question_t *q, uint16_t msgid)
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
forward_udp_receive(dns_cache_rrset_t *rrset, dns_msg_question_t *q, int s, uint16_t msgid, dns_tls_t *tls)
{
    int len;
    char buf[DNS_UDP_MSG_MAX];
    socklen_t fromlen;
    struct sockaddr_storage from;

    fromlen = sizeof(from);
    if ((len = recvfrom(s, buf, sizeof(buf), 0,
                        (SA *) &from, &fromlen)) < 0) {
        plog_error(LOG_ERR, MODULE, "recvfrom() failed");
        return -1;
    }

    return forward_msg_parse(rrset, q, buf, len, msgid, tls);
}

static int
forward_msg_parse(dns_cache_rrset_t *rrset, dns_msg_question_t *q, char *buf, int len, uint16_t msgid, dns_tls_t *tls)
{
    int count, rcode;
    uint16_t flags;
    dns_header_t header;
    dns_msg_handle_t handle;
    dns_msg_question_t question;

    if (dns_msg_read_open(&handle, buf, len) < 0) {
        plog(LOG_NOTICE, "%s: open message failed. broken message?", MODULE);
        return -1;
    }

    if (dns_msg_read_header(&header, &handle) < 0) {
        plog(LOG_NOTICE, "%s: read header failed. broken message?", MODULE);
        dns_msg_read_close(&handle);
        return -1;
    }

    /* check result code */
    flags = ntohs(header.hdr_flags);
    rcode = DNS_RCODE(flags);

    if (flags & DNS_FLAG_TC) {
        /* XXX fallback to TCP */
        plog(LOG_NOTICE, "%s: XXX truncated message is not supported", MODULE);
        dns_msg_read_close(&handle);
        return -1;
    }

    if (forward_validate_header(&header, msgid) < 0) {
        dns_msg_read_close(&handle);
        return -1;
    }

    if (dns_msg_read_question(&question, &handle) < 0) {
        dns_msg_read_close(&handle);
        return -1;
    }

    /*
      XXX validate question
    */

    /*
     * resources in authority and addtioal sections should not be cached
     * because these RRs may not be entire of RRset. Partial RRsets cannot
     * be used for answer. (RFC2181 5.)
     */
    count = ntohs(header.hdr_ancount);
    if (forward_msg_parse_resource(rrset, q, &handle, count, tls) < 0) {
        dns_msg_read_close(&handle);
        return -1;
    }

    if (count == 0) {
        /* cache SOA for negative caching */
        count = ntohs(header.hdr_nscount);
        if (forward_msg_parse_resource_soa(rrset, &handle, count) < 0) {
            dns_msg_read_close(&handle);
            return -1;
        }
    }

    dns_msg_read_close(&handle);
    dns_cache_set_rcode(rrset, rcode);

    return 0;
}

static int
forward_msg_parse_resource(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_msg_handle_t *handle, int count, dns_tls_t *tls)
{
    int i;
    dns_msg_resource_t res;

    for (i = 0; i < count; i++) {
        if (dns_msg_read_resource(&res, handle) < 0) {
            plog(LOG_NOTICE, "%s: read resource failed. broken message?", MODULE);
            return -1;
        }

        /* XXX validate resource */

        if (dns_cache_add_answer(rrset, q, &res, tls) < 0) {
            plog(LOG_ERR, "%s: can't add cache resource", MODULE);
            return -1;
        }
    }

    return 0;
}

static int
forward_msg_parse_resource_soa(dns_cache_rrset_t *rrset, dns_msg_handle_t *handle, int count)
{
    int i;
    uint32_t ttl;
    dns_msg_resource_t res;

    for (i = 0; i < count; i++) {
        if (dns_msg_read_resource(&res, handle) < 0) {
            plog(LOG_NOTICE, "%s: read resource failed. broken message?", MODULE);
            return -1;
        }

        /* XXX validate resource */

        if (res.mr_q.mq_type == DNS_TYPE_SOA) {
            if (dns_msg_parse_soa(NULL, NULL, NULL, NULL, NULL, NULL, &ttl, &res) < 0) {
                plog(LOG_NOTICE, "%s: Can't get minimum ttl from SOA record", MODULE);
                ttl = 0;
            }

            dns_cache_negative(rrset, ttl);
        }
    }

    return 0;
}

static int
forward_validate_header(dns_header_t *header, uint16_t expid)
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
