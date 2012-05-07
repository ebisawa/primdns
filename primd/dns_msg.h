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
#ifndef __DNS_MSG_H__
#define __DNS_MSG_H__
#include "dns_proto.h"

typedef struct {
    void               *mh_buf;
    void               *mh_pos;
    int                 mh_len;
    uint16_t            mh_qdcount;
    uint16_t            mh_ancount;
    uint16_t            mh_nscount;
    uint16_t            mh_arcount;
} dns_msg_handle_t;

typedef struct {
    char                mq_name[DNS_NAME_MAX];
    uint16_t            mq_type;
    uint16_t            mq_class;
} dns_msg_question_t;

typedef struct {
    dns_msg_question_t  mr_q;
    uint32_t            mr_ttl;
    uint16_t            mr_datalen;
    uint8_t             mr_data[DNS_RDATA_MAX];
} dns_msg_resource_t;

#define DNS_MSG_HEADER(handle)   ((dns_header_t *) (handle)->mh_buf)

#define DNS_MSG_RESTYPE_ANSWER       1
#define DNS_MSG_RESTYPE_AUTHORITY    2
#define DNS_MSG_RESTYPE_ADDITIONAL   3

int dns_msg_read_open(dns_msg_handle_t *handle, void *buf, int len);
int dns_msg_read_close(dns_msg_handle_t *handle);
int dns_msg_read_header(dns_header_t *header, dns_msg_handle_t *handle);
int dns_msg_read_question(dns_msg_question_t *qdata, dns_msg_handle_t *handle);
int dns_msg_read_resource(dns_msg_resource_t *res, dns_msg_handle_t *handle);

int dns_msg_write_open(dns_msg_handle_t *handle, void *buf, int len);
int dns_msg_write_close(dns_msg_handle_t *handle);
int dns_msg_write_header(dns_msg_handle_t *handle, uint16_t msgid, uint16_t flags);
int dns_msg_write_rcode(dns_msg_handle_t *handle, uint16_t rcode);
int dns_msg_write_flag(dns_msg_handle_t *handle, uint16_t flag);
int dns_msg_write_question(dns_msg_handle_t *handle, dns_msg_question_t *qdata);
int dns_msg_write_resource(dns_msg_handle_t *handle, dns_msg_resource_t *res, int restype);

void *dns_msg_buffer(dns_msg_handle_t *handle);

int dns_msg_parse_name(char *name, dns_msg_resource_t *res);
int dns_msg_parse_soa(char *mname, char *rname, uint32_t *serial, uint32_t *refresh, uint32_t *retry, uint32_t *expire, uint32_t *minimum, dns_msg_resource_t *res);
int dns_msg_parse_mx(uint16_t *pref, char *name, dns_msg_resource_t *res);

int dns_msg_encode_name(void *dst, int dstmax, char *name);

#endif
