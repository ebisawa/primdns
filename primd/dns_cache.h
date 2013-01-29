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
#ifndef __DNS_CACHE_H__
#define __DNS_CACHE_H__
#include <time.h>
#include "dns.h"
#include "dns_list.h"

#define DNS_CACHE_SIZE_DEF               32              /* KB per thread */
#define DNS_CACHE_SIZE_MIN               (1024 * 1)      /* KB */
#define DNS_CACHE_SIZE_MAX               (1024 * 2048)   /* KB */

#define DNS_CACHE_HASH_ARRAY_SIZE        3

#define DNS_CACHE_TTL_MAX                604800
#define DNS_CACHE_TTL_MIN                0
#define DNS_CACHE_TTL_NEGATIVE_MAX       3600
#define DNS_CACHE_TTL_NEGATIVE_DEFAULT   300

#define DNS_CACHE_PUBLIC                 0
#define DNS_CACHE_IZL_BASE               0xf0000000
#define DNS_CACHE_IZL(zid)               (DNS_CACHE_IZL_BASE + (zid))

#define DNS_CACHE_LIST_HEAD(list)        ((dns_cache_res_t *) dns_list_head((list)))
#define DNS_CACHE_LIST_NEXT(list, elem)  ((dns_cache_res_t *) dns_list_next((list), (dns_list_elem_t *) (elem)))

typedef struct {
    dns_list_elem_t      cache_elem;
    dns_msg_resource_t   cache_res;
} dns_cache_res_t;

typedef struct {
    dns_msg_question_t   rrset_question;
    unsigned             rrset_category;
    unsigned             rrset_refs;
    unsigned             rrset_hits;
    unsigned             rrset_dns_rcode;
    unsigned             rrset_dns_flags;
    time_t               rrset_expire;
    dns_list_t           rrset_list_answer;
    dns_list_t           rrset_list_cname;
} dns_cache_rrset_t;

int dns_cache_init(int cache_kb, int threads);
dns_cache_rrset_t *dns_cache_new(dns_msg_question_t *q, dns_tls_t *tls);
dns_cache_rrset_t *dns_cache_lookup(dns_msg_question_t *q, unsigned category, dns_tls_t *tls);
void dns_cache_release(dns_cache_rrset_t *rrset, dns_tls_t *tls);
int dns_cache_add_answer(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_msg_resource_t *res, dns_tls_t *tls);
int dns_cache_count_answer(dns_cache_rrset_t *rrset);
void dns_cache_delete_answers(dns_cache_rrset_t *rrset, dns_tls_t *tls);
void dns_cache_negative(dns_cache_rrset_t *rrset, uint32_t ttl);
void dns_cache_merge(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_cache_rrset_t *rr_m, dns_tls_t *tls);
void dns_cache_register(dns_cache_rrset_t *rrset, unsigned category, dns_tls_t *tls);
void dns_cache_setrcode(dns_cache_rrset_t *rrset, unsigned rcode);
void dns_cache_setflags(dns_cache_rrset_t *rrset, unsigned flags);
void dns_cache_clearflags(dns_cache_rrset_t *rrset, unsigned flags);
unsigned dns_cache_getrcode(dns_cache_rrset_t *rrset);
unsigned dns_cache_getflags(dns_cache_rrset_t *rrset);
void dns_cache_invalidate(dns_tls_t *tls);
void dns_cache_printstats(int s);

#endif
