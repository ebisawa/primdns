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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_config.h"
#include "dns_data.h"
#include "dns_engine.h"
#include "dns_timer.h"
#include "dns_util.h"
#include "dns_query.h"

#define MODULE "axfr"

#define AXFR_TIMER_MIN             5
#define AXFR_RETRY_DEFAULT         10
#define AXFR_EXPIRE_DEFAULT        180
#define AXFR_REFRESH_MAX           864000   /* 10 days */
#define AXFR_EXPIRE_MAX            5184000  /* 60 days */
#define AXFR_NOTIFY_INTERVAL_MIN   5
#define AXFR_QUERY_TIMEOUT         5

typedef struct {
    struct sockaddr_storage   ac_master;
    char                      ac_zone_name[DNS_CONFIG_ZONE_NAME_MAX];
    char                      ac_datname[256];
    uint32_t                  ac_serial;
    int                       ac_refresh;
    int                       ac_retry;
    int                       ac_expire;
    time_t                    ac_expire_time;
    time_t                    ac_last_notify;
    dns_timer_t               ac_timer;
    void                     *ac_dataconf;
} axfr_config_t;

static int axfr_setarg(dns_engine_param_t *ep, char *arg);
static int axfr_init(dns_engine_param_t *ep);
static int axfr_destroy(dns_engine_param_t *ep);
static int axfr_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);
static int axfr_notify(dns_engine_param_t *ep, struct sockaddr *remote, dns_tls_t *tls);
static int axfr_do_axfr(axfr_config_t *conf, dns_tls_t *tls);
static int axfr_exec_receiver(char *master_addr, char *zone_name, char *datname);
static int axfr_init_data_engine(dns_config_zone_t *zone, axfr_config_t *conf, char *datname);
static int axfr_adjust_timer(int t, unsigned maxi);
static void axfr_dataname(char *buf, int bufsize, char *zone_name);
static void axfr_set_retry_timer(axfr_config_t *conf);
static void axfr_refresh(axfr_config_t *conf);
static int axfr_need_refresh(axfr_config_t *conf, dns_tls_t *tls);
static uint32_t axfr_query_soa_serial(struct sockaddr *to, char *zone_name, dns_tls_t *tls);

static char *PrimAxfr = "primdns-axfr";

dns_engine_t AxfrEngine = {
    "axfr", sizeof(axfr_config_t),
    DNS_FLAG_AA,
    axfr_setarg,
    axfr_init,
    axfr_destroy,
    axfr_query,
    axfr_notify,
    NULL,  /* dump */
};

static int
axfr_setarg(dns_engine_param_t *ep, char *arg)
{
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    return dns_util_str2sa((SA *) &conf->ac_master, arg, 0);
}

static int
axfr_init(dns_engine_param_t *ep)
{
    uint32_t serial, refresh, retry, expire;
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    STRLCPY(conf->ac_zone_name, ep->ep_zone->z_name, sizeof(conf->ac_zone_name));
    axfr_dataname(conf->ac_datname, sizeof(conf->ac_datname), ep->ep_zone->z_name);

    if (axfr_init_data_engine(ep->ep_zone, conf, conf->ac_datname) < 0) {
        plog(LOG_ERR, "%s: axfr_init_data_engine() failed", MODULE);
        return -1;
    }

    if (conf->ac_dataconf == NULL) {
        plog(LOG_INFO, "%s: zone \"%s\": no data", MODULE, ep->ep_zone->z_name);

        conf->ac_retry = AXFR_RETRY_DEFAULT;
        conf->ac_expire_time = time(NULL) + AXFR_EXPIRE_DEFAULT;
    } else {
        dns_data_getsoa(&serial, &refresh, &retry, &expire, conf->ac_dataconf);

        plog(LOG_INFO, "%s: zone \"%s\": refresh %u, retry %u, expire %u",
             MODULE, ep->ep_zone->z_name, refresh, retry, expire);

        conf->ac_serial = serial;
        conf->ac_expire = axfr_adjust_timer(expire, AXFR_EXPIRE_MAX);
        conf->ac_refresh = axfr_adjust_timer(refresh, AXFR_REFRESH_MAX);
        conf->ac_retry = axfr_adjust_timer(retry, conf->ac_expire);
        conf->ac_expire_time = time(NULL) + conf->ac_expire;

        dns_timer_request(&conf->ac_timer, conf->ac_refresh * 1000, (dns_timer_func_t *) axfr_refresh, conf);
    }

    return 0;
}

static int
axfr_destroy(dns_engine_param_t *ep)
{
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    dns_timer_cancel(&conf->ac_timer);

    if (conf->ac_dataconf != NULL) {
        dns_engine_destroy(&DataEngine, conf->ac_dataconf);
        unlink(conf->ac_datname);
        free(conf->ac_dataconf);
        conf->ac_dataconf = NULL;
    }

    return 0;
}

static int
axfr_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    dns_engine_param_t data_param;
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    if (conf->ac_dataconf == NULL)
        return -1;

    data_param.ep_zone = ep->ep_zone;
    data_param.ep_conf = conf->ac_dataconf;

    return DataEngine.eng_query(&data_param, rrset, q, tls);
}

/* must be threadsafe */
static int
axfr_notify(dns_engine_param_t *ep, struct sockaddr *remote, dns_tls_t *tls)
{
    char maddr[256];
    time_t now;
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    now = time(NULL);

    if (remote != NULL) {
        dns_util_sa2str_wop(maddr, sizeof(maddr), remote);
        plog(LOG_INFO, "%s: NOIFY received from %s", MODULE, maddr);

        if (dns_util_sacmp_wop((SA *) &conf->ac_master, remote) != 0) {
            plog(LOG_NOTICE, "%s: invalid NOTIFY", __func__);
            return -1;
        }

        if (now < conf->ac_last_notify + AXFR_NOTIFY_INTERVAL_MIN) {
            plog(LOG_NOTICE, "%s: ignore too frequent NOTIFY", __func__);
            return -1;
        }
    }

    conf->ac_last_notify = now;

    return axfr_do_axfr(conf, tls);
}

static int
axfr_do_axfr(axfr_config_t *conf, dns_tls_t *tls)
{
    char maddr[256];

    if (!axfr_need_refresh(conf, tls)) {
        conf->ac_expire_time = time(NULL) + conf->ac_expire;
        dns_timer_request(&conf->ac_timer, conf->ac_refresh * 1000, (dns_timer_func_t *) axfr_refresh, conf);
        return 0;
    }

    axfr_set_retry_timer(conf);

    dns_util_sa2str_wop(maddr, sizeof(maddr), (SA *) &conf->ac_master);
    plog(LOG_INFO, "%s: zone \"%s\": AXFR request to %s", MODULE, conf->ac_zone_name, maddr);

    if (axfr_exec_receiver(maddr, conf->ac_zone_name, conf->ac_datname) < 0) {
        plog(LOG_ERR, "%s: axfr_exec_receiver() failed", MODULE);
        unlink(conf->ac_datname);
        return -1;
    }

    return 0;
}

static int
axfr_exec_receiver(char *master_addr, char *zone_name, char *datname)
{
    char *argv[] = { PrimAxfr, "-m", datname, master_addr, zone_name, NULL };

    return dns_util_spawn(PrimAxfr, argv, -1);
}

static int
axfr_init_data_engine(dns_config_zone_t *zone, axfr_config_t *conf, char *datname)
{
    void *dataconf;
    struct stat sb;
    dns_engine_t *engine = &DataEngine;

    if (stat(datname, &sb) < 0)
        return 0;

    if ((dataconf = calloc(1, engine->eng_conflen)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return -1;
    }

    if (dns_engine_setarg(engine, zone, dataconf, datname) < 0) {
        plog(LOG_ERR, "%s: dns_engine_setarg() failed", MODULE);
        free(dataconf);
        return -1;
    }

    if (dns_engine_init(engine, zone, dataconf) < 0) {
        plog(LOG_ERR, "%s: dns_engine_init() failed", MODULE);
        free(dataconf);
        return -1;
    }

    conf->ac_dataconf = dataconf;

    return 0;
}

static int
axfr_adjust_timer(int t, unsigned maxi)
{
    if (t < AXFR_TIMER_MIN)
        t = AXFR_TIMER_MIN;
    if (t > maxi)
        t = maxi;

    /* XXX randomize */

    return t;
}

static void
axfr_dataname(char *buf, int bufsize, char *zone_name)
{
    snprintf(buf, bufsize, "%s/.axfr_%s.dat", ConfDir, zone_name);
}

static void
axfr_set_retry_timer(axfr_config_t *conf)
{
    unsigned remt, retry;

    remt = conf->ac_expire_time - time(NULL);
    retry = (remt < conf->ac_retry) ? remt : conf->ac_retry;

    if (retry < AXFR_TIMER_MIN)
        retry = AXFR_TIMER_MIN;

    dns_timer_request(&conf->ac_timer, retry * 1000, (dns_timer_func_t *) axfr_refresh, conf);
}

static void
axfr_refresh(axfr_config_t *conf)
{
    dns_tls_t *tls;

    if (time(NULL) >= conf->ac_expire_time) {
        plog(LOG_INFO, "%s: zone \"%s\": transfer failed", MODULE, conf->ac_zone_name);

        unlink(conf->ac_datname);
        kill(getpid(), SIGHUP);
    } else {
        /* assume main thread */
        tls = dns_session_main_tls();
        axfr_do_axfr(conf, tls);
    }
}

static int
axfr_need_refresh(axfr_config_t *conf, dns_tls_t *tls)
{
    uint32_t serial_new;
    struct sockaddr_storage ss;

    if (conf->ac_dataconf != NULL && SALEN(&conf->ac_master) > 0) {
        dns_util_sacopy((SA *) &ss, (SA *) &conf->ac_master);
        dns_util_sasetport((SA *) &ss, DNS_PORT);

        plog(LOG_DEBUG, "%s: zone \"%s\": query master's zone serial",
             MODULE, conf->ac_zone_name);

        serial_new = axfr_query_soa_serial((SA *) &ss, conf->ac_zone_name, tls);

        plog(LOG_INFO, "%s: zone \"%s\": master's serial %u, our serial %u",
             MODULE, conf->ac_zone_name, serial_new, conf->ac_serial);

        if (serial_new != 0 && !dns_util_is_greater_serial(serial_new, conf->ac_serial)) {
            plog(LOG_INFO, "%s: zone \"%s\" is up-to-date", MODULE, conf->ac_zone_name);
            return 0;
        }
    }

    return 1;
}

static uint32_t
axfr_query_soa_serial(struct sockaddr *to, char *zone_name, dns_tls_t *tls)
{
    int s;
    uint16_t msgid;
    uint32_t serial;
    dns_msg_question_t q;
    dns_msg_resource_t res;

    STRLCPY(q.mq_name, zone_name, sizeof(q.mq_name));
    q.mq_type = DNS_TYPE_SOA;
    q.mq_class = DNS_CLASS_IN;

    msgid = xarc4random(&tls->tls_arctx);
    if ((s = dns_query_start(to, &q, msgid, tls)) < 0) {
        plog(LOG_ERR, "%s: dns_query_start() failed", MODULE);
        return 0;
    }

    if (dns_util_select(s, AXFR_QUERY_TIMEOUT) < 0) {
        plog(LOG_ERR, "%s: dns_util_select() failed", MODULE);
        goto error;
    }

    if (dns_query_receive(&res, s, msgid) < 0) {
        plog(LOG_ERR, "%s: dns_query_receive() failed", MODULE);
        goto error;
    }

    dns_query_finish(s);
    dns_msg_parse_soa(NULL, NULL,  &serial, NULL, NULL, NULL, NULL, &res);

    return serial;

error:
    dns_query_finish(s);
    return 0;
}
