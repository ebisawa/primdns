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
#ifndef __DNS_PROTO_H__
#define __DNS_PROTO_H__
#include <stdint.h>

#define DNS_PORT                   53
#define DNS_NAME_MAX              256
#define DNS_RDATA_MAX             256
#define DNS_UDP_MSG_MAX           512
#define DNS_TCP_MSG_MAX          4096
#define DNS_MSG_MAX   DNS_TCP_MSG_MAX
#define DNS_CNAME_NEST_MAX          8

typedef struct {
    uint16_t  hdr_id;
    uint16_t  hdr_flags;
    uint16_t  hdr_qdcount;
    uint16_t  hdr_ancount;
    uint16_t  hdr_nscount;
    uint16_t  hdr_arcount;
} __attribute__((packed)) dns_header_t;

#define DNS_OPCODE(flag)   (((flag) & 0x4800) >> 11)
#define DNS_RCODE(flag)    (((flag) & 0x000f))

#define DNS_OP_QUERY                0
#define DNS_OP_IQUERY               1   /* obsolete */
#define DNS_OP_STATUS               2   /* obsolete */

#define DNS_FLAG_QR            0x8000   /* query(0), response(1) */
#define DNS_FLAG_AA            0x0400   /* Authoritative Answer */
#define DNS_FLAG_TC            0x0200   /* TrunCation */
#define DNS_FLAG_RD            0x0100   /* Recursion Desired */
#define DNS_FLAG_RA            0x0080   /* Recursion Available */

/* RFC2136 */
#define DNS_RCODE_NOERROR           0
#define DNS_RCODE_FORMERR           1
#define DNS_RCODE_SERVFAIL          2
#define DNS_RCODE_NXDOMAIN          3
#define DNS_RCODE_NOTIMP            4
#define DNS_RCODE_REFUSED           5
#define DNS_RCODE_YXDOMAIN          6
#define DNS_RCODE_YXRRSET           7
#define DNS_RCODE_NXRRSET           8
#define DNS_RCODE_NOTAUTH           9
#define DNS_RCODE_NOTZONE          10

#define DNS_TYPE_A                  1
#define DNS_TYPE_NS                 2
#define DNS_TYPE_CNAME              5
#define DNS_TYPE_SOA                6
#define DNS_TYPE_PTR               12
#define DNS_TYPE_MX                15
#define DNS_TYPE_TXT               16
#define DNS_TYPE_AAAA              28   /* RFC1886 */
#define DNS_TYPE_AXFR             252
#define DNS_TYPE_ANY              255

#define DNS_CLASS_IN                1
#define DNS_CLASS_ANY             255

char *dns_proto_type_string(int type);
char *dns_proto_class_string(int klass);
char *dns_proto_rcode_string(int rcode);

int dns_proto_parse_type(char *string);
int dns_proto_parse_class(char *string);

#endif
