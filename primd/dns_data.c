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
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_data.h"
#include "dns_engine.h"

#define MODULE "data"

#define DATA_MAGIC     0x61727964   /* "aryd" */
#define DATA_VERSION   2

typedef struct {
    unsigned        stat_queries;
    unsigned        stat_bsearch;
    unsigned        stat_lsearch;
    unsigned        stat_found;
    unsigned        stat_not_found;
} data_stats_t;

/* network byte order */
typedef struct {
    uint32_t        df_magic;
    uint16_t        df_zero;
    uint16_t        df_version;
    uint32_t        df_hashsize;
    uint32_t        df_serial;
    uint32_t        df_refresh;
    uint32_t        df_retry;
    uint32_t        df_expire;
} __attribute__((packed)) data_header_t;

/* network byte order */
typedef struct {
    uint32_t        dh_offset;
    uint32_t        dh_count;
} __attribute__((packed)) data_hash_t;

/* network byte order */
typedef struct {
    uint16_t        dr_type;
    uint16_t        dr_class;
    uint32_t        dr_ttl;
    uint16_t        dr_namelen;
    uint16_t        dr_datalen;
    uint32_t        dr_name_offset;
    uint32_t        dr_data_offset;
} __attribute__((packed)) data_record_t;

typedef struct {
    char            conf_filename[PATH_MAX];
    int             conf_fd;
    uint8_t        *conf_data;
    data_hash_t    *conf_hash;
    unsigned        conf_datasize;
    unsigned        conf_hashsize;
} data_config_t;

typedef struct {
    uint32_t        dp_hashi;
    uint32_t        dp_datai;
} data_pos_t;

#define INVALID_PTR(conf, p)   ((void *)(p) < (void *)(conf)->conf_data || (void *)(p) >= (void *)((conf)->conf_data + (conf)->conf_datasize))

static int data_setarg(dns_engine_param_t *ep, char *arg);
static int data_init(dns_engine_param_t *ep);
static int data_destroy(dns_engine_param_t *ep);
static int data_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);
static int data_dumpnext(dns_engine_param_t *ep, dns_msg_resource_t *res, dns_engine_dump_t *edump);

static int data_validate(data_header_t *header);
static int data_query_resource(dns_cache_rrset_t *rrset, data_config_t *conf, dns_msg_question_t *q, dns_tls_t *tls);
static int data_query_search_head(data_config_t *conf, data_hash_t *hash, dns_msg_question_t *q);
static int data_query_bsearch(data_config_t *conf, data_hash_t *hash, dns_msg_question_t *q);
static int data_query_lsearch(data_config_t *conf, data_hash_t *hash, dns_msg_question_t *q, int low);
static int data_hash_index(char *name, int hashsize);
static data_record_t *data_hash_record(data_config_t *conf, data_hash_t *hash);
static int data_record_compare_name(data_record_t *record, data_config_t *conf, char *name);
static int data_record_compare_class_type(data_record_t *record, dns_msg_question_t *q);
static char *data_record_name(data_config_t *conf, data_record_t *record);
static void *data_record_data(data_config_t *conf, data_record_t *record);
static int data_dump_checkpos(data_pos_t *dpos, data_config_t *conf);
static int data_dump_nextpos(data_pos_t *dpos, data_config_t *conf);
static int data_record2res(dns_msg_resource_t *res, data_config_t *conf, data_record_t *record);

static data_stats_t DataStats;

dns_engine_t DataEngine = {
    "data", sizeof(data_config_t),
    DNS_FLAG_AA,
    data_setarg,
    data_init,
    data_destroy,
    data_query,
    data_dumpnext,
    NULL,  /* notify */
};

void
dns_data_printstats(int s)
{
    dns_util_sendf(s, "Data:\n");
    dns_util_sendf(s, "    %10u queries requested\n",      DataStats.stat_queries);
    dns_util_sendf(s, "    %10u binary search lookup\n",   DataStats.stat_bsearch);
    dns_util_sendf(s, "    %10u linear search lookup\n",   DataStats.stat_lsearch);
    dns_util_sendf(s, "    %10u resources found\n",        DataStats.stat_found);
    dns_util_sendf(s, "    %10u resources not found\n",    DataStats.stat_not_found);
    dns_util_sendf(s, "\n");
}

static int
data_setarg(dns_engine_param_t *ep, char *arg)
{
    data_config_t *conf = (data_config_t *) ep->ep_conf;

    if (arg[0] == '/')
        STRLCPY(conf->conf_filename, arg, sizeof(conf->conf_filename));
    else
        snprintf(conf->conf_filename, sizeof(conf->conf_filename), "%s/%s", ConfDir, arg);

    return 0;
}

static int
data_init(dns_engine_param_t *ep)
{
    int fd;
    void *p;
    off_t size;
    data_header_t *header;
    data_config_t *conf = (data_config_t *) ep->ep_conf;

    plog(LOG_DEBUG, "%s: file = %s", MODULE, conf->conf_filename);

    if ((fd = open(conf->conf_filename, O_RDONLY)) < 0) {
        plog(LOG_ERR, "%s: can't open: %s", MODULE, conf->conf_filename);
        return -1;
    }

    size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    p = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    if ((intptr_t) p == -1) {
        plog_error(LOG_ERR, MODULE, "mmap() failed");
        close(fd);
        return -1;
    }

    plog(LOG_DEBUG, "%s: fd = %d, mmap = %p", MODULE, fd, p);

    header = (data_header_t *) p;
    if (data_validate(header) < 0) {
        munmap(p, size);
        close(fd);
        return -1;
    }

    conf->conf_fd = fd;
    conf->conf_data = (uint8_t *) p;
    conf->conf_hash = (data_hash_t *) ((uint8_t *) p + sizeof(data_header_t));
    conf->conf_datasize = size;
    conf->conf_hashsize = ntohl(header->df_hashsize);

    plog(LOG_INFO, "zone \"%s\": serial %u", ep->ep_zone->z_name, ntohl(header->df_serial));

    return 0;
}

static int
data_destroy(dns_engine_param_t *ep)
{
    data_config_t *conf = (data_config_t *) ep->ep_conf;

    munmap(conf->conf_data, conf->conf_datasize);
    close(conf->conf_fd);
    memset(conf, 0, sizeof(*conf));

    return 0;
}

static int
data_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    int count;
    data_config_t *conf = (data_config_t *) ep->ep_conf;

    ATOMIC_INC(&DataStats.stat_queries);

    if ((count = data_query_resource(rrset, conf, q, tls)) < 0)
        return -1;

    /* authoritative answer */
    if (count > 0)
        ATOMIC_INC(&DataStats.stat_found);
    else
        ATOMIC_INC(&DataStats.stat_not_found);

    return 0;
}

static int
data_dumpnext(dns_engine_param_t *ep, dns_msg_resource_t *res, dns_engine_dump_t *edump)
{
    data_hash_t *hash;
    data_record_t *record, *p;
    data_config_t *conf = (data_config_t *) ep->ep_conf;
    data_pos_t *dpos = (data_pos_t *) edump->ed_data;

    if (sizeof(edump->ed_data) < sizeof(data_pos_t)) {
        plog(LOG_ERR, "%s: sizeof(edump->ed_data) < sizeof(data_pos_t)", MODULE);
        return -1;
    }

    if (data_dump_checkpos(dpos, conf) < 0) {
        if (data_dump_nextpos(dpos, conf) < 0)
            return -1;
    }

    hash = &conf->conf_hash[dpos->dp_hashi];
    if ((record = data_hash_record(conf, hash)) == NULL)
        return -1;

    p = &record[dpos->dp_datai];
    if (data_record2res(res, conf, p) < 0)
        return -1;

    data_dump_nextpos(dpos, conf);

    return 0;
}

static int
data_validate(data_header_t *header)
{
    if (ntohl(header->df_magic) != DATA_MAGIC) {
        plog(LOG_ERR, "%s: file magic mismatch", MODULE);
        return -1;
    }

    if (ntohs(header->df_version) != DATA_VERSION) {
        plog(LOG_ERR, "%s: file version mismatch (%d)", MODULE, ntohs(header->df_version));
        return -1;
    }

    return 0;
}

static int
data_query_resource(dns_cache_rrset_t *rrset, data_config_t *conf, dns_msg_question_t *q, dns_tls_t *tls)
{
    int i, hashval, index, count = 0;
    dns_msg_resource_t res;
    data_hash_t *hash;
    data_record_t *record, *p;

    if (conf->conf_hashsize == 0)
        return -1;

    hashval = data_hash_index(q->mq_name, conf->conf_hashsize);
    hash = &conf->conf_hash[hashval];

    if ((index = data_query_search_head(conf, hash, q)) < 0) {
        dns_cache_setrcode(rrset, DNS_RCODE_NXDOMAIN);
        dns_cache_negative(rrset, 0);
    } else {
        if ((record = data_hash_record(conf, hash)) == NULL)
            return -1;

        for (i = index; i < ntohl(hash->dh_count); i++) {
            p = &record[i];
            if (data_record_compare_name(p, conf, q->mq_name) != 0)
                break;
            if (data_record_compare_class_type(p, q) != 0)
                continue;

            if (data_record2res(&res, conf, p) < 0) {
                plog(LOG_ERR, "%s: resource data convert error", MODULE);
                return -1;
            }

            if (dns_cache_add_answer(rrset, &res, tls) < 0) {
                plog(LOG_ERR, "%s: can't add cache resource", MODULE);
                return -1;
            }

            count++;
        }

        if (count == 0) {
            dns_cache_setrcode(rrset, DNS_RCODE_NOERROR);
            dns_cache_negative(rrset, 0);
        }
    }

    return count;
}

static int
data_query_search_head(data_config_t *conf, data_hash_t *hash, dns_msg_question_t *q)
{
    int low, index;

    if ((low = data_query_bsearch(conf, hash, q)) < 0)
        return -1;
    if ((index = data_query_lsearch(conf, hash, q, low)) < 0)
        return -1;

    return index;
}

static int
data_query_bsearch(data_config_t *conf, data_hash_t *hash, dns_msg_question_t *q)
{
    int r, low, high, mid;
    data_record_t *record;

    if ((record = data_hash_record(conf, hash)) == NULL)
        return -1;

    low = 0;
    high = ntohl(hash->dh_count) - 1;

    for (;;) {
        ATOMIC_INC(&DataStats.stat_bsearch);

        if (high - low < 2)
            return low;

        mid = (high + low) / 2;
        r = data_record_compare_name(&record[mid], conf, q->mq_name);

        if (r < 0)
            low = mid;
        if (r >= 0)
            high = mid;
    }

    return -1;
}

static int
data_query_lsearch(data_config_t *conf, data_hash_t *hash, dns_msg_question_t *q, int low)
{
    int i, r;
    data_record_t *record;

    if ((record = data_hash_record(conf, hash)) == NULL)
        return -1;

    for (i = low; i < ntohl(hash->dh_count); i++) {
        ATOMIC_INC(&DataStats.stat_lsearch);

        if ((r = data_record_compare_name(&record[i], conf, q->mq_name)) == 0)
            return i;
        if (r > 0)
            break;
    }

    return -1;
}

static int
data_hash_index(char *name, int hashsize)
{
    char *p;
    uint32_t h = FNV1_INITIAL_BASIS;

    /* FNV-1a hash */
    for (p = name; *p != 0; p++) {
        h ^= tolower(*p);
        h *= 16777619;
    }

    return h % hashsize;
}

static data_record_t *
data_hash_record(data_config_t *conf, data_hash_t *hash)
{
    data_record_t *record;

    if (hash->dh_count == 0)
        return NULL;

    record = (data_record_t *) (conf->conf_data + ntohl(hash->dh_offset));
    if (INVALID_PTR(conf, record)) {
        plog(LOG_ERR, "%s: invalid data file (data_record)", MODULE);
        return NULL;
    }

    return record;
}

static int
data_record_compare_name(data_record_t *record, data_config_t *conf, char *name)
{
    int r;
    char *r_name;

    if ((r_name = data_record_name(conf, record)) == NULL)
        return -1;
    if ((r = strcasecmp(r_name, name)) != 0)
        return r;

    return 0;
}

static int
data_record_compare_class_type(data_record_t *record, dns_msg_question_t *q)
{
    int rc, rt;

    rc = ntohs(record->dr_class);
    rt = ntohs(record->dr_type);

    if (rc != q->mq_class) {
        if (rc != DNS_CLASS_ANY && q->mq_class != DNS_CLASS_ANY)
            return -1;
    }

    if (rt != q->mq_type && rt != DNS_TYPE_CNAME) {
        if (rt != DNS_TYPE_ALL && q->mq_type != DNS_TYPE_ALL)
            return -1;
    }

    return 0;
}

static char *
data_record_name(data_config_t *conf, data_record_t *record)
{
    void *name;

    name = conf->conf_data + ntohl(record->dr_name_offset);
    if (INVALID_PTR(conf, name)) {
        plog(LOG_ERR, "%s: invalid data file (data_name)", MODULE);
        return NULL;
    }

    return name;
}

static void *
data_record_data(data_config_t *conf, data_record_t *record)
{
    void *data;

    data = conf->conf_data + ntohl(record->dr_data_offset);
    if (INVALID_PTR(conf, data)) {
        plog(LOG_ERR, "%s: invalid data file (data_data)", MODULE);
        return NULL;
    }

    return data;
}

static int
data_dump_checkpos(data_pos_t *dpos, data_config_t *conf)
{
    data_hash_t *hash;

    if (dpos->dp_hashi >= conf->conf_hashsize)
        return -1;

    hash = &conf->conf_hash[dpos->dp_hashi];
    if (dpos->dp_datai >= ntohl(hash->dh_count))
        return -1;

    return 0;
}

static int
data_dump_nextpos(data_pos_t *dpos, data_config_t *conf)
{
    dpos->dp_datai++;
    while (data_dump_checkpos(dpos, conf) < 0) {
        dpos->dp_hashi++;
        dpos->dp_datai = 0;

        if (dpos->dp_hashi >= conf->conf_hashsize)
            return -1;
    }

    return 0;
}

static int
data_record2res(dns_msg_resource_t *res, data_config_t *conf, data_record_t *record)
{
    void *name, *data;

    if ((name = data_record_name(conf, record)) == NULL)
        return -1;
    if ((data = data_record_data(conf, record)) == NULL)
        return -1;

    STRLCPY(res->mr_q.mq_name, name, sizeof(res->mr_q.mq_name));
    res->mr_q.mq_type = ntohs(record->dr_type);
    res->mr_q.mq_class = ntohs(record->dr_class);
    res->mr_ttl = ntohl(record->dr_ttl);
    res->mr_datalen = ntohs(record->dr_datalen);
    memcpy(res->mr_data, data, ntohs(record->dr_datalen));

    return 0;
}
