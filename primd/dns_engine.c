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
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_config.h"
#include "dns_engine.h"
#include "dns_data.h"
#include "dns_external.h"
#include "dns_forward.h"

#define MODULE "engine"

static dns_engine_t *QueryEngines[] = {
    &DataEngine, &ExternalEngine, &ForwardEngine,
};

dns_cache_rrset_t *
dns_engine_query(dns_msg_question_t *q, dns_config_zone_t *zone, int need_flags, dns_tls_t *tls)
{
    int rcode, noerror = 0;
    dns_engine_t *engine;
    dns_cache_rrset_t *rrset;
    dns_config_zone_engine_t *ze;

    if ((rrset = dns_cache_new(q, tls)) == NULL) {
        plog(LOG_ERR, "%s: can't allocate new cache", MODULE);
        return NULL;
    }

    ze = (dns_config_zone_engine_t *) dns_list_head(&zone->z_search.zs_engine);
    while (ze != NULL) {
        engine = (dns_engine_t *) ze->ze_engine;

        if (need_flags == 0 || engine->eng_flags & need_flags) {
            plog(LOG_DEBUG, "%s: use \"%s\" engine", MODULE, engine->eng_name);

            dns_cache_setrcode(rrset, DNS_RCODE_NOERROR);
            if (engine->eng_query(rrset, ze->ze_econf, q, tls) < 0)
                goto error;

            dns_cache_setflags(rrset, engine->eng_flags);
            rcode = dns_cache_getrcode(rrset);

            plog(LOG_DEBUG, "%s: rcode %s (%d)", MODULE, dns_proto_rcode_string(rcode), rcode);

            if (rcode == DNS_RCODE_NOERROR)
                noerror = 1;
            if (rcode != DNS_RCODE_NOERROR && rcode != DNS_RCODE_NXDOMAIN)
                return rrset;
            if (dns_cache_count_answer(rrset) > 0)
                return rrset;
        }

        ze = (dns_config_zone_engine_t *) dns_list_next(&zone->z_search.zs_engine, &ze->ze_elem);
    }

 error:
    dns_cache_setrcode(rrset, (noerror) ? DNS_RCODE_NOERROR : DNS_RCODE_NXDOMAIN);
    dns_cache_negative(rrset, 0);

    return rrset;
}

dns_engine_t *
dns_engine_find(char *name)
{
    int i;

    for (i = 0; i < NELEMS(QueryEngines); i++) {
        if (strcmp(QueryEngines[i]->eng_name, name) == 0)
            return QueryEngines[i];
    }

    return NULL;
}
