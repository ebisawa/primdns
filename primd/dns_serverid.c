/*
 * Copyright (c) 2011-2012 Satoshi Ebisawa. All rights reserved.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_engine.h"

#define MODULE "serverid"

static int serverid_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);

static int serverid_hostname(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);
static int serverid_version(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);
static int serverid_txt_record(dns_cache_rrset_t *rrset, dns_msg_question_t *q, char *txt_string, dns_tls_t *tls);

dns_engine_t ServerIdEngine = {
    "serverid", 0,
    NULL,  /* setrg */
    NULL,  /* init */
    NULL,  /* destroy */
    serverid_query,
    NULL,  /* notify */
    NULL,  /* dump */
};

static int
serverid_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    dns_cache_set_flags(rrset, DNS_FLAG_AA);

    if (q->mq_type == DNS_TYPE_TXT || q->mq_type == DNS_TYPE_ALL) {
        if (q->mq_class == DNS_CLASS_CH || q->mq_class == DNS_CLASS_ANY) {
            /* RFC4892 (id.server) */
            if (strcasecmp(q->mq_name, "id.server") == 0)
                return serverid_hostname(rrset, q, tls);
            if (strcasecmp(q->mq_name, "version.server") == 0)
                return serverid_version(rrset, q, tls);

            /* conventional resources */
            if (strcasecmp(q->mq_name, "hostname.bind") == 0)
                return serverid_hostname(rrset, q, tls);
            if (strcasecmp(q->mq_name, "version.bind") == 0)
                return serverid_version(rrset, q, tls);
        }
    }

    dns_cache_set_rcode(rrset, DNS_RCODE_NXDOMAIN);
    dns_cache_negative(rrset, 0);

    return 0;
}

static int
serverid_hostname(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    char buf[128];

    if (gethostname(buf, sizeof(buf)) < 0)
        return -1;

    return serverid_txt_record(rrset, q, buf, tls);
}

static int
serverid_version(dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    return serverid_txt_record(rrset, q, PACKAGE_STRING, tls);
}

static int
serverid_txt_record(dns_cache_rrset_t *rrset, dns_msg_question_t *q, char *txt_string, dns_tls_t *tls)
{
    int len;
    dns_msg_resource_t res;

    STRLCPY(res.mr_q.mq_name, q->mq_name, sizeof(res.mr_q.mq_name));
    res.mr_q.mq_class = DNS_CLASS_CH;
    res.mr_q.mq_type = DNS_TYPE_TXT;
    res.mr_ttl = 0;

    if ((len = strlen(txt_string)) >= DNS_RDATA_MAX)
        return -1;

    res.mr_datalen = len + 1;
    res.mr_data[0] = len;
    STRLCPY((char *) &res.mr_data[1], txt_string, sizeof(res.mr_data) - 1);

    if (dns_cache_add_answer(rrset, q, &res, tls) < 0) {
        plog(LOG_ERR, "%s: can't add cache resource", MODULE);
        return -1;
    }

    return 0;
}
