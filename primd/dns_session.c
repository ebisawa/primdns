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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include "dns.h"
#include "dns_acl.h"
#include "dns_babq.h"
#include "dns_cache.h"
#include "dns_config.h"
#include "dns_engine.h"
#include "dns_pool.h"
#include "dns_session.h"
#include "dns_sock.h"
#include "dns_util.h"

#define MODULE "session"

#define NONBLOCK  1
#define SESSION_EDNS_REQUESTED   0x0001

#define IS_VALID_QUESTION(q)     ((q)->mq_class != 0 && (q)->mq_type != 0)

typedef struct {
    unsigned   stat_query;
    unsigned   stat_answer;
    unsigned   stat_notify;
    unsigned   stat_error;
    unsigned   stat_axfr_request;
    unsigned   stat_axfr_success;
} session_stats_t;

static int NumWorkers;
static dns_session_t *WorkerSessions;
static dns_session_t MainSessions[DNS_SOCK_THREADS + 1];
static session_stats_t SessionStats;

static dns_babq_t InQueue, OutQueue;
static dns_pool_t SessionBufPool;
static pthread_t SenderThread;

static void *session_thread_worker(dns_session_t *self);
static void *session_thread_sender(void *param);
static int session_request_basic(dns_sock_t *sock, int thread_id);
static int session_request_multi(dns_sock_t *sock, int thread_id);
static void session_init(dns_session_t *sessin, uint16_t msgid, uint16_t flags);
static void session_destroy(dns_session_t *session, dns_sock_buf_t *sbuf);
static void session_proc(dns_session_t *session, int nonblock);
static int session_request_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock);
static int session_request_proc(dns_session_t *session, dns_sock_buf_t *sbuf);
static int session_request_query(dns_session_t *session, dns_sock_buf_t *sbuf);
static int session_request_query_normal(dns_session_t *session, dns_sock_buf_t *sbuf);
static int session_request_query_axfr(dns_session_t *session, dns_sock_buf_t *sbuf);
static int session_request_notify(dns_session_t *session, dns_sock_buf_t *sbuf);
static int session_read_question(dns_session_t *session, dns_sock_buf_t *sbuf);
static int session_read_edns_opt(dns_session_t *session, dns_sock_buf_t *sbuf, dns_msg_handle_t *handle);
static int session_check_question_header(dns_header_t *header);
static dns_cache_rrset_t *session_query_answer(dns_session_t *session, dns_sock_buf_t *sbuf);
static dns_cache_rrset_t *session_query_authority(dns_session_t *session, dns_cache_rrset_t *rrset);
static dns_cache_rrset_t *session_query_recursive(dns_session_t *session, dns_msg_question_t *q, int nlevel);
static dns_cache_rrset_t *session_query_zone(dns_session_t *session, dns_msg_question_t *q, int type);
static dns_cache_rrset_t *session_query_internal(dns_session_t *session, dns_msg_question_t *q);
static int session_query_zone_resource(dns_msg_resource_t *res, dns_session_t *session, dns_msg_question_t *q, int type);
static void session_resolve_cname(dns_session_t *session, dns_msg_question_t *q, dns_cache_rrset_t *rrset, int nlevel);
static void session_send_response(dns_sock_buf_t *sbuf);
static void session_send_finish(dns_sock_buf_t *sbuf);
static int session_send_immediate(dns_sock_buf_t *sbuf);
static int session_send_axfr(dns_sock_buf_t *sbuf, dns_session_t *session, dns_msg_resource_t *soa);
static int session_send_axfr_resource(dns_sock_buf_t *sbuf, dns_session_t *session, dns_msg_resource_t *res);
static int session_make_response(dns_sock_buf_t *sbuf, dns_session_t *session, dns_cache_rrset_t *rrset);
static int session_make_axfr_response(dns_sock_buf_t *sbuf, dns_session_t *session, dns_msg_resource_t *res);
static int session_make_notify_response(dns_sock_buf_t *sbuf, dns_session_t *session);
static int session_make_error(dns_sock_buf_t *sbuf, dns_session_t *session, int rcode, int flags);
static int session_write_header(dns_session_t *session, dns_msg_handle_t *handle, void *buf, int rcode, int flags);
static void session_write_resources(dns_session_t *session, dns_msg_handle_t *handle, dns_list_t *list, int restype);
static void session_write_resources_rr(dns_session_t *session, dns_msg_handle_t *handle, dns_list_t *list, int restype);
static void session_write_resources_ar(dns_session_t *session, dns_msg_handle_t *handle, dns_list_t *list, int type);
static void session_write_resources_opt(dns_session_t *session, dns_msg_handle_t *handle);
static void session_shuffle_resources(dns_session_t *session, dns_msg_resource_t **res, int num);
static int session_max_payload_size(dns_session_t *session, int defmax);
static int session_compare_question(dns_msg_question_t *a, dns_msg_question_t *b);

int
dns_session_init(void)
{
    int i;

    for (i = 0; i < NELEMS(MainSessions); i++)
        MainSessions[i].sess_tls.tls_id = i;

    return 0;
}

int
dns_session_start_thread(int threads)
{
    int i, start_id;

    NumWorkers = threads;

    if (threads > 0) {
        plog(LOG_DEBUG, "%s: %d worker threads", MODULE, threads);

        if (dns_babq_init(&InQueue, threads) < 0)
            return -1;
        if (dns_babq_init(&OutQueue, threads) < 0)
            return -1;

        if (dns_pool_init(&SessionBufPool, sizeof(dns_sock_buf_t),
                          threads + threads           /* in/out queue */
                          + threads                   /* worker threads */
                          + NELEMS(MainSessions) + 1  /* sock threads */
                          + 1) < 0) {                 /* magic */
            return -1;
        }

        if ((WorkerSessions = calloc(1, sizeof(dns_session_t) * threads)) == NULL) {
            plog_error(LOG_ERR, MODULE, "insufficient memory");
            return -1;
        }

        start_id = NELEMS(MainSessions);
        for (i = 0; i < threads; i++) {
            WorkerSessions[i].sess_tls.tls_id = start_id + i;
            pthread_create(&WorkerSessions[i].sess_thread, NULL,
                           (void *(*)(void *)) session_thread_worker,
                           &WorkerSessions[i]);
        }

        if (pthread_create(&SenderThread, NULL, session_thread_sender, NULL) < 0) {
            plog_error(LOG_ERR, MODULE, "pthread_create() failed");
            return -1;
        }
    }

    return 0;
}

int
dns_session_request(dns_sock_t *sock, int thread_id)
{
    if (WorkerSessions == NULL)
        return session_request_basic(sock, thread_id);
    else
        return session_request_multi(sock, thread_id);
}

int
dns_session_check_config(void)
{
    int i;
    void *p;

    for (i = 0; i < NELEMS(MainSessions); i++) {
        p = MainSessions[i].sess_config;
        if (p != NULL && p != ConfigRoot)
            return -1;
    }

    for (i = 0; i < NumWorkers; i++) {
        p = WorkerSessions[i].sess_config;
        if (p != NULL && p != ConfigRoot)
            return -1;
    }

    return 0;
}

void
dns_session_printstats(int s)
{
    dns_util_sendf(s, "Session:\n");
    dns_util_sendf(s, "    %10u queries requested\n",          SessionStats.stat_query);
    dns_util_sendf(s, "    %10u answers responded\n",          SessionStats.stat_answer);
    dns_util_sendf(s, "    %10u notify messages recevied\n",   SessionStats.stat_notify);
    dns_util_sendf(s, "    %10u axfr requests recevied\n",     SessionStats.stat_axfr_request);
    dns_util_sendf(s, "    %10u axfr transfers succeeded\n",   SessionStats.stat_axfr_success);
    dns_util_sendf(s, "\n");
}

static void *
session_thread_worker(dns_session_t *self)
{
    dns_util_sigmaskall();

    for (;;)
        session_proc(self, 0);

    return NULL;
}

static void *
session_thread_sender(void *param)
{
    dns_sock_buf_t *sbuf;

    dns_util_sigmaskall();

    for (;;) {
        sbuf = dns_babq_pop(&OutQueue);
        session_send_immediate(sbuf);
        session_send_finish(sbuf);
    }

    return NULL;
}

static int
session_request_basic(dns_sock_t *sock, int thread_id)
{
    dns_sock_buf_t sbuf;
    dns_session_t *session;

    if (session_request_recv(&sbuf, sock) < 0)
        return -1;

    session = &MainSessions[thread_id];
    session_request_proc(session, &sbuf);
    session_destroy(session, &sbuf);

    return 0;
}

static int
session_request_multi(dns_sock_t *sock, int thread_id)
{
    dns_sock_buf_t *sbuf;
    dns_session_t *session;

    plog(LOG_DEBUG, "%s: multiworker mode", MODULE);

    if ((sbuf = dns_pool_get(&SessionBufPool)) == NULL) {
        plog(LOG_CRIT, "%s: bufpool empty!!", __func__);
        return -1;
    }

    if (session_request_recv(sbuf, sock) < 0) {
        dns_pool_release(&SessionBufPool, sbuf);
        return -1;
    }

    /* input */
    plog(LOG_DEBUG, "%s: ** input **", __func__);
    session = &MainSessions[thread_id];
    while (dns_babq_push_nb(&InQueue, sbuf) < 0) {
        plog(LOG_DEBUG, "%s: inqueue push failed", __func__);
        session_proc(session, NONBLOCK);
    }

    /* output */
    plog(LOG_DEBUG, "%s: ** output **", __func__);
    while ((sbuf = dns_babq_pop_nb(&OutQueue)) != NULL) {
        session_send_immediate(sbuf);
        session_send_finish(sbuf);
    }

    return 0;
}

static void
session_init(dns_session_t *session, uint16_t msgid, uint16_t flags)
{
    session->sess_msgid = msgid;
    session->sess_flags = flags;

    session->sess_edns_version = 0;
    session->sess_edns_bufsize = 0;
    session->sess_extflags = 0;
    session->sess_opcode = 0;

    memset(&session->sess_question, 0, sizeof(session->sess_question));
    session->sess_config = ConfigRoot;
}

static void
session_destroy(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    session->sess_config = NULL;
}

static void
session_proc(dns_session_t *session, int nonblock)
{
    dns_sock_buf_t *sbuf;

    if (nonblock)
        sbuf = dns_babq_pop_nb(&InQueue);
    else
        sbuf = dns_babq_pop(&InQueue);

    if (sbuf != NULL) {
        session_request_proc(session, sbuf);
        session_destroy(session, sbuf);
    }
}

static int
session_request_recv(dns_sock_buf_t *sbuf, dns_sock_t *sock)
{
    int len;

    if ((len = dns_sock_recv(sbuf, sock)) < 0) {
        /* read failed, socket closed by peer or receive incompleted */
        return -1;
    }

    if (len == 0) {
        plog(LOG_DEBUG, "%s: partial message received", MODULE);
        return -1;
    }

    return len;
}

static int
session_request_proc(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    int rcode;
    dns_msg_question_t *q;

    if ((rcode = session_read_question(session, sbuf)) != DNS_RCODE_NOERROR)
        goto error;

    q = &session->sess_question;
    if ((session->sess_zone = dns_config_find_zone(q->mq_name, q->mq_class)) == NULL) {
        rcode = DNS_RCODE_SERVFAIL;
        goto error;
    }

    plog(LOG_DEBUG, "%s: opcode = %d", MODULE, session->sess_opcode);

    switch (session->sess_opcode) {
    case DNS_OP_QUERY:
        if ((rcode = session_request_query(session, sbuf)) != DNS_RCODE_NOERROR)
            goto error;
        break;

    case DNS_OP_NOTIFY:
        if ((rcode = session_request_notify(session, sbuf)) != DNS_RCODE_NOERROR)
            goto error;
        break;
    }

    return 0;

error:
    if (rcode > 0 && session_make_error(sbuf, session, rcode, 0) >= 0)
        session_send_response(sbuf);
    else
        session_send_finish(sbuf);

    ATOMIC_INC(&SessionStats.stat_error);

    return -1;
}

static int
session_request_query(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    int rcode;
    dns_msg_question_t *q;

    q = &session->sess_question;

    if (!DNS_TYPE_QMETA(q->mq_type) || q->mq_type == DNS_TYPE_ALL)
        rcode = session_request_query_normal(session, sbuf);
    else {
        switch (q->mq_type) {
        case DNS_TYPE_AXFR:
            rcode = session_request_query_axfr(session, sbuf);
            break;
        default:
            rcode = DNS_RCODE_NOTIMP;
            break;
        }
    }

    return rcode;
}

static int
session_request_query_normal(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    dns_cache_rrset_t *rrset;

    ATOMIC_INC(&SessionStats.stat_query);

    if ((rrset = session_query_answer(session, sbuf)) == NULL)
        return DNS_RCODE_SERVFAIL;

    if (session_make_response(sbuf, session, rrset) < 0) {
        dns_cache_release(rrset, &session->sess_tls);
        return DNS_RCODE_SERVFAIL;
    }

    dns_cache_release(rrset, &session->sess_tls);
    session_send_response(sbuf);

    ATOMIC_INC(&SessionStats.stat_answer);

    return DNS_RCODE_NOERROR;
}

static int
session_request_query_axfr(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    int r;
    char from[64];
    uint32_t serial;
    dns_msg_question_t *q;
    dns_msg_resource_t soa;
    dns_config_zone_t *zone;

    ATOMIC_INC(&SessionStats.stat_axfr_request);

    q = &session->sess_question;  zone = session->sess_zone;
    dns_util_sa2str_wop(from, sizeof(from), (SA *) &sbuf->sb_remote);

    if (!dns_acl_match(&zone->z_slaves.zss_acl, (SA *) &sbuf->sb_remote)) {
        plog(LOG_NOTICE, "%s: unauthorized AXFR request from %s", MODULE, from);
        return DNS_RCODE_REFUSED;
    }

    if (SOCK_CHAR(sbuf->sb_sock) != DNS_SOCK_CHAR_TCP) {
        plog(LOG_ERR, "%s: AXFR requested but connection is not TCP", MODULE);
        return DNS_RCODE_SERVFAIL;
    }

    if (strcasecmp(q->mq_name, zone->z_name) != 0) {
        plog(LOG_ERR, "%s: AXFR requested but not authoritative for zone \"%s\"", MODULE, q->mq_name);
        return DNS_RCODE_NOTAUTH;   /* RFC5936 2.2.1. */
    }

    if (session_query_zone_resource(&soa, session, q, DNS_TYPE_SOA) < 0) {
        plog(LOG_ERR, "%s: no SOA record for zone \"%s\"", MODULE, zone->z_name);
        return DNS_RCODE_SERVFAIL;
    }

    dns_msg_parse_soa(NULL, NULL,  &serial, NULL, NULL, NULL, NULL, &soa);
    plog(LOG_INFO, "AXFR request from %s (zone \"%s\", serial %u)", from, zone->z_name, serial);

    if ((r = session_send_axfr(sbuf, session, &soa)) != 0)
        return r;

    ATOMIC_INC(&SessionStats.stat_axfr_success);

    return DNS_RCODE_NOERROR;
}

static int
session_request_notify(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    ATOMIC_INC(&SessionStats.stat_notify);

    if (dns_engine_notify(session->sess_zone, (SA *) &sbuf->sb_remote) < 0)
        return -1;
    if (session_make_notify_response(sbuf, session) < 0)
        return DNS_RCODE_SERVFAIL;

    session_send_response(sbuf);

    return DNS_RCODE_NOERROR;
}

static int
session_read_question(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    uint16_t msgid, flags, qdcount, arcount;
    dns_header_t header;
    dns_msg_handle_t handle;
    dns_msg_question_t question;

    if (dns_msg_read_open(&handle, sbuf->sb_buf, sbuf->sb_buflen) < 0) {
        plog(LOG_NOTICE, "%s: message read failed", MODULE);
        return -1;
    }

    if (dns_msg_read_header(&header, &handle) < 0) {
        plog(LOG_NOTICE, "%s: read header failed", MODULE);
        return -1;
    }

    msgid = ntohs(header.hdr_id);
    flags = ntohs(header.hdr_flags);
    qdcount = ntohs(header.hdr_qdcount);
    arcount = ntohs(header.hdr_arcount);

    session_init(session, msgid, flags);
    session->sess_opcode = DNS_OPCODE(flags);

    /* error response can be sent after session_init() */
    if (session_check_question_header(&header) < 0)
        return DNS_RCODE_FORMERR;

    if (qdcount > 0) {
        if (dns_msg_read_question(&question, &handle) < 0)
            return DNS_RCODE_FORMERR;

        plog_query(LOG_INFO, &question, (SA *) &sbuf->sb_remote, sbuf->sb_sock->sock_prop->sp_char);
        memcpy(&session->sess_question, &question, sizeof(question));
    }

    if (arcount == 1 && session_read_edns_opt(session, sbuf, &handle) < 0)
        return DNS_RCODE_FORMERR;

    dns_msg_read_close(&handle);

    return DNS_RCODE_NOERROR;
}

static int
session_read_edns_opt(dns_session_t *session, dns_sock_buf_t *sbuf, dns_msg_handle_t *handle)
{
    unsigned ver;
    dns_msg_resource_t opt;

    if (dns_msg_read_resource(&opt, handle) < 0)
        return -1;
    if (opt.mr_q.mq_type != DNS_TYPE_OPT)
        return -1;

    ver = (opt.mr_ttl & 0x00ff0000) >> 16;
    session->sess_edns_version = ver;
    session->sess_edns_bufsize = opt.mr_q.mq_class;
    session->sess_extflags |= SESSION_EDNS_REQUESTED;

    plog(LOG_DEBUG, "%s: edns version = %d", MODULE, session->sess_edns_version);
    plog(LOG_DEBUG, "%s: edns bufsize = %d", MODULE, session->sess_edns_bufsize);

    return 0;
}

static int
session_check_question_header(dns_header_t *header)
{
    if (ntohs(header->hdr_qdcount) != 1)
        return -1;
    if (ntohs(header->hdr_arcount) > 1)
        return -1;
    if (header->hdr_ancount != 0 || header->hdr_nscount != 0)
        return -1;

    return 0;
}

static dns_cache_rrset_t *
session_query_answer(dns_session_t *session, dns_sock_buf_t *sbuf)
{
    dns_msg_question_t *q;
    dns_cache_rrset_t *rrset;

    q = &session->sess_question;
    if ((rrset = dns_cache_lookup(q, 0, &session->sess_tls)) == NULL) {
        if ((rrset = session_query_recursive(session, q, 0)) == NULL)
            return NULL;

        dns_cache_register(rrset, 0, &session->sess_tls);
    }

    return rrset;
}

static dns_cache_rrset_t *
session_query_authority(dns_session_t *session, dns_cache_rrset_t *rrset)
{
    int ans_count;
    dns_msg_question_t *q;
    dns_cache_rrset_t *rrset_ns = NULL;

    if (dns_cache_getflags(rrset) & DNS_FLAG_AA) {
        plog(LOG_DEBUG, "%s: authoritative answer", MODULE);

        q = &session->sess_question;
        ans_count = dns_cache_count_answer(rrset);

        if (ans_count == 0) {
            /* no resources found */
            rrset_ns = session_query_zone(session, q, DNS_TYPE_SOA);
        } else {
            if (q->mq_type != DNS_TYPE_NS)
                rrset_ns = session_query_zone(session, q, DNS_TYPE_NS);
        }
    }

    return rrset_ns;
}

static dns_cache_rrset_t *
session_query_recursive(dns_session_t *session, dns_msg_question_t *q, int nlevel)
{
    dns_cache_rrset_t *rrset;

    if ((rrset = dns_engine_query(q, session->sess_zone, &session->sess_tls)) != NULL) {
        if (dns_list_count(&rrset->rrset_list_cname) > 0 &&
            dns_list_count(&rrset->rrset_list_answer) == 0) {
            session_resolve_cname(session, q, rrset, nlevel + 1);
        }
    }

    return rrset;
}

static dns_cache_rrset_t *
session_query_zone(dns_session_t *session, dns_msg_question_t *q, int type)
{
    dns_msg_question_t q_ns;

    STRLCPY(q_ns.mq_name, session->sess_zone->z_name, sizeof(q_ns.mq_name));
    q_ns.mq_type = type;
    q_ns.mq_class = q->mq_class;

    return session_query_internal(session, &q_ns);
}

static dns_cache_rrset_t *
session_query_internal(dns_session_t *session, dns_msg_question_t *q)
{
    dns_cache_rrset_t *rrset;

    plog(LOG_DEBUG, "%s: internal query: %s %s", MODULE, q->mq_name, dns_proto_type_string(q->mq_type));

    if ((rrset = dns_cache_lookup(q, DNS_CACHE_INTERNAL, &session->sess_tls)) == NULL) {
        if ((rrset = dns_engine_query(q, session->sess_zone, &session->sess_tls)) == NULL)
            return NULL;

        dns_cache_register(rrset, DNS_CACHE_INTERNAL, &session->sess_tls);
    }

    return rrset;
}

static int
session_query_zone_resource(dns_msg_resource_t *res, dns_session_t *session, dns_msg_question_t *q, int type)
{
    int result = -1;
    dns_cache_t *cache;
    dns_cache_rrset_t *rrset;

    if ((rrset = session_query_zone(session, q, type)) != NULL) {
        cache = DNS_CACHE_LIST_HEAD(&rrset->rrset_list_answer);
        if (cache != NULL) {
            memcpy(res, &cache->cache_res, sizeof(*res));
            result = 0;
        }

        dns_cache_release(rrset, &session->sess_tls);
    }

    return result;
}

static void
session_resolve_cname(dns_session_t *session, dns_msg_question_t *q, dns_cache_rrset_t *rrset, int nlevel)
{
    dns_cache_t *cache;
    dns_cache_rrset_t *rr_cname;
    dns_msg_question_t q_cname;

    if (nlevel > DNS_CNAME_NEST_MAX) {
        plog(LOG_DEBUG, "%s: CNAME nested too deep", MODULE);
        return;
    }

    /* we don't support multiple-cnames */
    cache = DNS_CACHE_LIST_HEAD(&rrset->rrset_list_cname);
    if (cache != NULL) {
        memcpy(&q_cname, q, sizeof(q_cname));
        dns_msg_parse_name(q_cname.mq_name, &cache->cache_res);

        plog(LOG_DEBUG, "%s: restart query for CNAME: %s", MODULE, q_cname.mq_name);

        if ((rr_cname = session_query_recursive(session, &q_cname, nlevel)) != NULL) {
            plog(LOG_DEBUG, "%s: %d answers for CNAME", MODULE, dns_list_count(&rr_cname->rrset_list_answer));
            dns_cache_merge(rrset, rr_cname, &session->sess_tls);
            dns_cache_release(rr_cname, &session->sess_tls);
        }
    }
}

static void
session_send_response(dns_sock_buf_t *sbuf)
{
    if (WorkerSessions != NULL) {
        if (dns_babq_push_nb(&OutQueue, sbuf) >= 0)
            return;
    }

    session_send_immediate(sbuf);
    session_send_finish(sbuf);
}

static void
session_send_finish(dns_sock_buf_t *sbuf)
{
    if (WorkerSessions != NULL)
        dns_pool_release(&SessionBufPool, sbuf);
}

static int
session_send_immediate(dns_sock_buf_t *sbuf)
{
    if (dns_sock_send(sbuf) < 0) {
        plog(LOG_ERR, "%s: message send failed", MODULE);
        return -1;
    }

    return 0;
}

static int
session_send_axfr(dns_sock_buf_t *sbuf, dns_session_t *session, dns_msg_resource_t *soa)
{
    dns_msg_resource_t res;
    dns_engine_dump_t edump;

    if (session_send_axfr_resource(sbuf, session, soa) < 0)
        return DNS_RCODE_SERVFAIL;

    if (dns_engine_dump_init(&edump, session->sess_zone) < 0)
        return DNS_RCODE_SERVFAIL;

    while (dns_engine_dump_next(&res, &edump) >= 0) {
        if (res.mr_q.mq_type == DNS_TYPE_SOA)
            continue;
        if (session_send_axfr_resource(sbuf, session, &res) < 0)
            return DNS_RCODE_SERVFAIL;
    }

    if (session_send_axfr_resource(sbuf, session, soa) < 0)
        return DNS_RCODE_SERVFAIL;

    session_send_finish(sbuf);

    return 0;
}

static int
session_send_axfr_resource(dns_sock_buf_t *sbuf, dns_session_t *session, dns_msg_resource_t *res)
{
    if (session_make_axfr_response(sbuf, session, res) < 0)
        return -1;
    if (session_send_immediate(sbuf) < 0)
        return -1;

    return 0;
}

static int
session_make_response(dns_sock_buf_t *sbuf, dns_session_t *session, dns_cache_rrset_t *rrset)
{
    int rcode, flags, resmax;
    dns_msg_handle_t handle;
    dns_cache_rrset_t *rr_ns;

    plog(LOG_DEBUG, "%s: send response", MODULE);

    rcode = dns_cache_getrcode(rrset);
    flags = dns_cache_getflags(rrset);

    resmax = SOCK_MSGMAX(sbuf->sb_sock);
    resmax = session_max_payload_size(session, resmax);

    if (dns_msg_write_open(&handle, sbuf->sb_buf, resmax) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_open() failed", MODULE);
        return -1;
    }

    if (session_write_header(session, &handle, sbuf->sb_buf, rcode, flags) < 0)
        return -1;

    /* answer */
    plog(LOG_DEBUG, "%s: %d CNAME answers", MODULE, dns_list_count(&rrset->rrset_list_cname));
    plog(LOG_DEBUG, "%s: %d normal answers", MODULE, dns_list_count(&rrset->rrset_list_answer));

    session_write_resources(session, &handle, &rrset->rrset_list_cname, DNS_MSG_RESTYPE_ANSWER);
    session_write_resources_rr(session, &handle, &rrset->rrset_list_answer, DNS_MSG_RESTYPE_ANSWER);

    /* authority & additional */
    if ((rr_ns = session_query_authority(session, rrset)) != NULL) {
        session_write_resources_rr(session, &handle, &rr_ns->rrset_list_answer, DNS_MSG_RESTYPE_AUTHORITY);
        session_write_resources_ar(session, &handle, &rr_ns->rrset_list_answer, DNS_TYPE_A);
        session_write_resources_ar(session, &handle, &rr_ns->rrset_list_answer, DNS_TYPE_AAAA);
        dns_cache_release(rr_ns, &session->sess_tls);
    }

    /* edns opt */
    if (session->sess_extflags & SESSION_EDNS_REQUESTED)
        session_write_resources_opt(session, &handle);

    if ((sbuf->sb_buflen = dns_msg_write_close(&handle)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_close() failed", MODULE);
        return -1;
    }

    return 0;
}

static int
session_make_axfr_response(dns_sock_buf_t *sbuf, dns_session_t *session, dns_msg_resource_t *res)
{
    dns_msg_handle_t handle;

    /*
     * RFC5936 2. says:
     * The DNS message size limit from [RFC1035] for DNS over UDP
     * (and its extension via the EDNS0 mechanism specified in [RFC2671])
     * is not relevant for AXFR
     */
    if (dns_msg_write_open(&handle, sbuf->sb_buf, SOCK_MSGMAX(sbuf->sb_sock)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_open() failed", MODULE);
        return -1;
    }

    /* AA bit MUST be 1 if the RCODE is 0 (no error) */
    if (session_write_header(session, &handle, sbuf->sb_buf, DNS_RCODE_NOERROR, DNS_FLAG_AA) < 0)
        return -1;
    if (dns_msg_write_resource(&handle, res, DNS_MSG_RESTYPE_ANSWER) < 0)
        return -1;

    /*
     * RFC5936 2.2.5. says:
     * if the client has supplied an EDNS OPT RR in the AXFR query and if
     * the server supports EDNS as well, it SHOULD include one OPT RR in the
     * first response message and MAY do so in subsequent response messages
     */
#if 0   /* we don't send OPT RR in AXFR response */
    if (session->sess_extflags & SESSION_EDNS_REQUESTED)
        session_write_resources_opt(session, &handle);
#endif

    if ((sbuf->sb_buflen = dns_msg_write_close(&handle)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_close() failed", MODULE);
        return -1;
    }

    return 0;
}

static int
session_make_notify_response(dns_sock_buf_t *sbuf, dns_session_t *session)
{
    /*
     * see RFC1996 4.7:
     *
     * query ID:   (same)
     * op:         NOTIFY (4)
     * resp:       NOERROR
     * flags:      QR AA
     * qcount:     1
     * qname:      (zone name)
     * qclass:     (zone class)
     * qtype:      T_SOA
     */
    return session_make_error(sbuf, session, DNS_RCODE_NOERROR, DNS_FLAG_AA);
}

static int
session_make_error(dns_sock_buf_t *sbuf, dns_session_t *session, int rcode, int flags)
{
    dns_msg_handle_t handle;

    if (dns_msg_write_open(&handle, sbuf->sb_buf, SOCK_MSGMAX(sbuf->sb_sock)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_open() failed", MODULE);
        return -1;
    }

    if (session_write_header(session, &handle, sbuf->sb_buf, rcode, flags) < 0)
        return -1;

    if ((sbuf->sb_buflen = dns_msg_write_close(&handle)) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_close() failed", MODULE);
        return -1;
    }

    return 0;
}

static int
session_write_header(dns_session_t *session, dns_msg_handle_t *handle, void *buf, int rcode, int flags)
{
    if (dns_msg_write_header(handle, session->sess_msgid,
                             session->sess_flags | DNS_FLAG_QR | flags) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_header() failed", MODULE);
        return -1;
    }

    if (dns_msg_write_rcode(handle, rcode) < 0) {
        plog(LOG_ERR, "%s: dns_msg_write_rcode() failed", MODULE);
        return -1;
    }

    if (IS_VALID_QUESTION(&session->sess_question)) {
        if (dns_msg_write_question(handle, &session->sess_question) < 0) {
            plog(LOG_ERR, "%s: dns_msg_write_question() failed", MODULE);
            return -1;
        }
    }

    return 0;
}

static void
session_write_resources(dns_session_t *session, dns_msg_handle_t *handle, dns_list_t *list, int restype)
{
    dns_cache_t *cache;

    cache = DNS_CACHE_LIST_HEAD(list);
    while (cache != NULL) {
        if (dns_msg_write_resource(handle, &cache->cache_res, restype) < 0)
            break;

        cache = DNS_CACHE_LIST_NEXT(list, cache);
    }
}

static void
session_write_resources_rr(dns_session_t *session, dns_msg_handle_t *handle, dns_list_t *list, int restype)
{
    int i, j;
    dns_cache_t *cache;
    dns_msg_resource_t *cres[32];

    cache = DNS_CACHE_LIST_HEAD(list);
    while (cache != NULL) {
        for (i = 0; cache != NULL && i < NELEMS(cres); i++) {
            cres[i] = &cache->cache_res;
            cache = DNS_CACHE_LIST_NEXT(list, cache);
        }

        session_shuffle_resources(session, cres, i);

        for (j = 0; j < i; j++) {
            if (dns_msg_write_resource(handle, cres[j], restype) < 0) {
                /* message truncated */
                return;
            }
        }
    }
}

static void
session_write_resources_ar(dns_session_t *session, dns_msg_handle_t *handle, dns_list_t *list, int type)
{
    dns_cache_t *cache, *ca_a;
    dns_cache_rrset_t *rrset;
    dns_msg_question_t *q, q_a;

    q = &session->sess_question;
    cache = DNS_CACHE_LIST_HEAD(list);

    while (cache != NULL) {
        if (cache->cache_res.mr_q.mq_type == DNS_TYPE_NS) {
            dns_msg_parse_name(q_a.mq_name, &cache->cache_res);
            q_a.mq_type = type;
            q_a.mq_class = cache->cache_res.mr_q.mq_class;

            if (session_compare_question(q, &q_a) == 0)
                return;

            if ((rrset = session_query_internal(session, &q_a)) != NULL) {
                if (dns_list_count(&rrset->rrset_list_cname) == 0) {
                    ca_a = DNS_CACHE_LIST_HEAD(&rrset->rrset_list_answer);
                    while (ca_a != NULL) {
                        if (dns_msg_write_resource(handle, &ca_a->cache_res, DNS_MSG_RESTYPE_ADDITIONAL) < 0)
                            break;

                        ca_a = DNS_CACHE_LIST_NEXT(&rrset->rrset_list_answer, ca_a);
                    }
                }

                dns_cache_release(rrset, &session->sess_tls);
            }
        }

        cache = DNS_CACHE_LIST_NEXT(list, cache);
    }
}

static void
session_write_resources_opt(dns_session_t *session, dns_msg_handle_t *handle)
{
    dns_msg_resource_t res;

    memset(&res, 0, sizeof(res));
    res.mr_q.mq_type = DNS_TYPE_OPT;
    res.mr_q.mq_class = DNS_MSG_MAX;

    if (session->sess_edns_version != 0)
        res.mr_ttl = DNS_XRCODE_BADVERS << 24;

    dns_msg_write_resource(handle, &res, DNS_MSG_RESTYPE_ADDITIONAL);
}

static void
session_shuffle_resources(dns_session_t *session, dns_msg_resource_t **res, int num)
{
    void *p;
    int i, s;
    unsigned rand;

    rand = xarc4random(&session->sess_tls.tls_arctx);

    for (i = 0; i < num; i++) {
        if (rand & 1) {
            s = rand % num;
            p = res[i];
            res[i] = res[s];
            res[s] = p;
        }

        rand = (rand >> 1) + rand;
    }
}

static int
session_max_payload_size(dns_session_t *session, int defmax)
{
    int max_size = defmax;

    if (session->sess_extflags & SESSION_EDNS_REQUESTED) {
        if (session->sess_edns_bufsize > defmax)
            max_size = session->sess_edns_bufsize;
        if (max_size > DNS_MSG_MAX)
            max_size = DNS_MSG_MAX;

        plog(LOG_DEBUG, "%s: max payload size = %d", MODULE, max_size);
    }

    return max_size;
}

static int
session_compare_question(dns_msg_question_t *a, dns_msg_question_t *b)
{
    int r;

    if (a->mq_type != DNS_TYPE_ALL && b->mq_type != DNS_TYPE_ALL) {
        if ((r = a->mq_type - b->mq_type) != 0)
            return r;
    }

    if (a->mq_class != DNS_CLASS_ANY && b->mq_type != DNS_CLASS_ANY) {
        if ((r = a->mq_class - b->mq_class) != 0)
            return r;
    }

    return strcasecmp(a->mq_name, b->mq_name);
}
