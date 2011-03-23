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
#include "dns.h"
#include "dns_cache.h"
#include "dns_engine.h"

#define MODULE "random"

static int random_query(dns_cache_rrset_t *rrset, void *conf, dns_msg_question_t *q);
static int random_random_a(dns_cache_rrset_t *rrset, dns_msg_question_t *q);
static int random_negative(dns_cache_rrset_t *rrset, dns_msg_question_t *q);

dns_engine_t RandomEngine = {
    "random", 0, 0,
    NULL,
    NULL,
    NULL,
    (dns_engine_query_t *) random_query,
};

static int
random_query(dns_cache_rrset_t *rrset, void *conf, dns_msg_question_t *q)
{
    if (q->mq_class == DNS_CLASS_IN && q->mq_type == DNS_TYPE_A)
        return random_random_a(rrset, q);

    return random_negative(rrset, q);
}

static int
random_random_a(dns_cache_rrset_t *rrset, dns_msg_question_t *q)
{
    int i, j, num;
    dns_msg_resource_t res;

    num = dns_util_rand16() % 4;

    for (j = 0; j < num; j++) {
        memset(&res, 0, sizeof(res));
        memcpy(&res.mr_q, q, sizeof(res.mr_q));
        res.mr_ttl = 300;
        res.mr_datalen = 4;

        for (i = 0; i < 4; i++)
            res.mr_data[i] = dns_util_rand16() & 0xff;

        if (dns_cache_add_answer(rrset, &res) < 0) {
            plog(LOG_ERR, "%s: can't add cache resource", MODULE);
            return -1;
        }
    }

    plog(LOG_DEBUG, "%s: %d random answers", MODULE, num);
    dns_cache_setflags(rrset, DNS_FLAG_AA);

    return 0;
}

static int
random_negative(dns_cache_rrset_t *rrset, dns_msg_question_t *q)
{
    dns_cache_setrcode(rrset, DNS_RCODE_NOERROR);
    dns_cache_negative(rrset, 0);

    return 0;
}
