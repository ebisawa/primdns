/*
 * Copyright (c) 2011 Satoshi Ebisawa. All rights reserved.
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

#define MODULE "axfr"

#define AXFR_REFRESH_MAX  864000   /* 10 days */

typedef struct {
    struct sockaddr_storage   ac_master;
    char                      ac_zonename[DNS_CONFIG_ZONE_NAME_MAX];
    char                      ac_datname[256];
    int                       ac_retry;
    time_t                    ac_expire_time;
    dns_timer_t               ac_timer;
    void                     *ac_dataconf;
} axfr_config_t;

static int axfr_setarg(dns_engine_param_t *ep, char *arg);
static int axfr_init(dns_engine_param_t *ep);
static int axfr_destroy(dns_engine_param_t *ep);
static int axfr_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);
static int axfr_notify(dns_engine_param_t *ep, struct sockaddr *remote);
static int axfr_do_axfr(axfr_config_t *conf);
static int axfr_exec_receiver(char *master_addr, char *zone_name, char *datname);
static int axfr_init_data_engine(dns_config_zone_t *zone, axfr_config_t *conf, char *datname);
static int axfr_adjust_timer(int t, unsigned maximum);
static void axfr_dataname(char *buf, int bufsize, char *zone_name);
static void axfr_refresh(axfr_config_t *conf);

static char *PrimAxfr = "primdns-axfr";

dns_engine_t AxfrEngine = {
    "axfr", sizeof(axfr_config_t),
    DNS_FLAG_AA,
    axfr_setarg,
    axfr_init,
    axfr_destroy,
    axfr_query,
    NULL,  /* dump */
    axfr_notify,
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
    unsigned refresh, expire;
    data_header_t *header;
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    dns_util_strlcpy(conf->ac_zonename, ep->ep_zone->z_name, sizeof(conf->ac_zonename));
    axfr_dataname(conf->ac_datname, sizeof(conf->ac_datname), ep->ep_zone->z_name);

    if (axfr_init_data_engine(ep->ep_zone, conf, conf->ac_datname) < 0) {
        plog(LOG_ERR, "%s: axfr_init_data_engine() failed", MODULE);
        return -1;
    }

    if (conf->ac_dataconf == NULL)
        return 0;

    header = dns_data_getheader(conf->ac_dataconf);
    plog(LOG_INFO, "%s: zone \"%s\": refresh %u, retry %u, expire %u",
         MODULE, ep->ep_zone->z_name,
         ntohl(header->df_refresh), ntohl(header->df_retry), ntohl(header->df_expire));

    expire = ntohl(header->df_expire);
    refresh = axfr_adjust_timer(ntohl(header->df_refresh), 0xffffffff);
    conf->ac_retry = axfr_adjust_timer(ntohl(header->df_retry), expire);
    conf->ac_expire_time = time(NULL) + expire;

    dns_timer_request(&conf->ac_timer, refresh * 1000, (dns_timer_func_t *) axfr_refresh, conf);

    return 0;
}

static int
axfr_destroy(dns_engine_param_t *ep)
{
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    dns_timer_cancel(&conf->ac_timer);

    if (conf->ac_dataconf != NULL) {
        dns_engine_destroy(&DataEngine, conf->ac_dataconf);
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
axfr_notify(dns_engine_param_t *ep, struct sockaddr *remote)
{
    char maddr[256];
    axfr_config_t *conf = (axfr_config_t *) ep->ep_conf;

    if (dns_util_sacmp_wop((SA *) &conf->ac_master, remote) != 0) {
        dns_util_sa2str_wop(maddr, sizeof(maddr), remote);
        plog(LOG_NOTICE, "%s: invalid NOTIFY from %s", __func__, maddr);
        return -1;
    }

    return axfr_do_axfr(conf);
}

static int
axfr_do_axfr(axfr_config_t *conf)
{
    char maddr[256];

    dns_util_sa2str_wop(maddr, sizeof(maddr), (SA *) &conf->ac_master);

    if (axfr_exec_receiver(maddr, conf->ac_zonename, conf->ac_datname) < 0) {
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
axfr_adjust_timer(int t, unsigned maximum)
{
    if (t > AXFR_REFRESH_MAX || t < 0)
        t = AXFR_REFRESH_MAX;
    if (t > maximum)
        t = maximum;

    return t;
}

static void
axfr_dataname(char *buf, int bufsize, char *zone_name)
{
    snprintf(buf, bufsize, "%s/.axfr_%s.dat", ConfDir, zone_name);
}

static void
axfr_refresh(axfr_config_t *conf)
{
    if (time(NULL) > conf->ac_expire_time) {
        plog(LOG_INFO, "%s: zone \"%s\" expired", MODULE, conf->ac_zonename);

        unlink(conf->ac_datname);
        kill(getpid(), SIGHUP);
    } else {
        dns_timer_request(&conf->ac_timer, conf->ac_retry * 1000, (dns_timer_func_t *) axfr_refresh, conf);
        axfr_do_axfr(conf);
    }
}
