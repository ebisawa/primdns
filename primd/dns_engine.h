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
#ifndef __DNS_ENGINE_H__
#define __DNS_ENGINE_H__
#include "dns.h"
#include "dns_cache.h"
#include "dns_config.h"
#include "dns_session.h"

#define DNS_ENGINE_TIMEOUT   5

typedef struct {
    dns_config_zone_t          *ed_zone;
    dns_config_zone_engine_t   *ed_ze;
    uint8_t                     ed_data[8];
} dns_engine_dump_t;

typedef int (dns_engine_setarg_t)(void *conf, char *arg);
typedef int (dns_engine_init_t)(void *conf);
typedef int (dns_engine_destroy_t)(void *conf);
typedef int (dns_engine_query_t)(dns_cache_rrset_t *rrset, void *conf, dns_msg_question_t *q, dns_tls_t *tls);
typedef int (dns_engine_dumpnext_t)(dns_msg_resource_t *res, void *conf, dns_engine_dump_t *edump);

typedef struct {
    char                       *eng_name;
    int                         eng_conflen;
    int                         eng_flags;
    dns_engine_setarg_t        *eng_setarg;
    dns_engine_init_t          *eng_init;
    dns_engine_destroy_t       *eng_destroy;
    dns_engine_query_t         *eng_query;
    dns_engine_dumpnext_t      *eng_dumpnext;
} dns_engine_t;

dns_engine_t *dns_engine_find(char *name);
dns_cache_rrset_t *dns_engine_query(dns_msg_question_t *q, dns_config_zone_t *zone, int need_flags, dns_tls_t *tls);
int dns_engine_dump_open(dns_engine_dump_t *edump, dns_config_zone_t *zone);
int dns_engine_dump_next(dns_msg_resource_t *res, dns_engine_dump_t *edump);
void dns_engine_dump_close(dns_engine_dump_t *edump);

#endif
