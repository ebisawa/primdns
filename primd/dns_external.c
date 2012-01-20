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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_engine.h"

#define MODULE "external"

typedef struct {
    unsigned    stat_queries;
} external_stats_t;

typedef struct {
    char        conf_cmdpath[PATH_MAX];
} external_config_t;

static int external_setarg(dns_engine_param_t *ep, char *arg);
static int external_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls);

static int external_popen(char *cmd, dns_msg_question_t *q);
static int external_wait(int s, pid_t pid);
static int external_read_response(dns_cache_rrset_t *rrset, int fd, dns_msg_question_t *q, dns_tls_t *tls);
static int external_read_buf(dns_cache_rrset_t *rrset, char *buf, int len, dns_tls_t *tls);
static int external_read_line(dns_cache_rrset_t *rrset, char *line, dns_tls_t *tls);
static int external_read_rcode(char *line);
static int external_name_parse(dns_msg_resource_t *res, char *p);
static int external_ttl_parse(dns_msg_resource_t *res, char *p);
static int external_class_parse(dns_msg_resource_t *res, char *p);
static int external_type_parse(dns_msg_resource_t *res, char *p);
static int external_data_parse(dns_msg_resource_t *res, char *p);

static external_stats_t ExternalStats;

static int (*ResParseFunc[])(dns_msg_resource_t *, char *) = {
    external_name_parse,
    external_ttl_parse,
    external_class_parse,
    external_type_parse,
    external_data_parse,
};

dns_engine_t ExternalEngine = {
    "external", sizeof(external_config_t),
    DNS_FLAG_AA,
    external_setarg,
    NULL,  /* init */
    NULL,  /* destroy */
    external_query,
    NULL,  /* dump */
    NULL,  /* notify */
};

void
dns_external_printstats(int s)
{
    dns_util_sendf(s, "External:\n");
    dns_util_sendf(s, "    %10u queries requested\n",  ExternalStats.stat_queries);
    dns_util_sendf(s, "\n");
}

static int
external_setarg(dns_engine_param_t *ep, char *arg)
{
    external_config_t *conf = (external_config_t *) ep->ep_conf;

    STRLCPY(conf->conf_cmdpath, arg, sizeof(conf->conf_cmdpath));

    return 0;
}

static int
external_query(dns_engine_param_t *ep, dns_cache_rrset_t *rrset, dns_msg_question_t *q, dns_tls_t *tls)
{
    int fd;
    external_config_t *conf = (external_config_t *) ep->ep_conf;

    ATOMIC_INC(&ExternalStats.stat_queries);

    if ((fd = external_popen(conf->conf_cmdpath, q)) < 0)
        return -1;
    if (external_read_response(rrset, fd, q, tls) < 0) {
        close(fd);
        return -1;
    }

    plog(LOG_DEBUG, "%s: fd = %d", MODULE, fd);
    close(fd);

    return 0;
}

static int
external_popen(char *cmd, dns_msg_question_t *q)
{
    int fd[2];
    pid_t pid;

    if (pipe(fd) < 0) {
        plog_error(LOG_ERR, MODULE, "pipe() failed");
        return -1;
    }

    if ((pid = fork()) < 0) {
        plog_error(LOG_ERR, MODULE, "fork() failed");
        close(fd[0]);
        close(fd[1]);
        return -1;
    } else if (pid == 0) {
        /*
         * child process:
         * don't call log functions because these are not async-signal-safe.
         */
        if (dup2(fd[1], 1) < 0)
            exit(1);

        close(fd[0]);
        close(fd[1]);

        execlp(cmd, cmd, q->mq_name,
               dns_proto_class_string(q->mq_class),
               dns_proto_type_string(q->mq_type),
               NULL);

        exit(1);
    }

    close(fd[1]);

    if (external_wait(fd[0], pid) < 0) {
        close(fd[0]);
        return -1;
    }

    return fd[0];
}

static int
external_wait(int s, pid_t pid)
{
    int i, status;

    if (dns_util_select(s, DNS_ENGINE_TIMEOUT) < 0)
        goto error;

    for (i = 0; i < 1000 * DNS_ENGINE_TIMEOUT; i++, usleep(1000)) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                plog(LOG_ERR, "%s: external process error", MODULE);
                goto error;
            }

            return 0;
        }
    }

error:
    kill(pid, SIGTERM);
    waitpid(pid, &status, 0);

    return -1;
}

static int
external_read_response(dns_cache_rrset_t *rrset, int fd, dns_msg_question_t *q, dns_tls_t *tls)
{
    int len;
    char buf[256];

    if ((len = read(fd, buf, sizeof(buf) - 1)) <= 0) {
        plog_error(LOG_ERR, MODULE, "read() failed");
        return -1;
    }

    buf[len] = 0;
    if (external_read_buf(rrset, buf, len, tls) < 0) {
        plog(LOG_ERR, "%s: invalid external response", MODULE);
        return -1;
    }

    return 0;
}

static int
external_read_buf(dns_cache_rrset_t *rrset, char *buf, int len, dns_tls_t *tls)
{
    char *p, *q;
    int count = 0, rcode = -1;

    q = buf;
    for (p = buf; len > 0; p++, len--) {
        if (*p == '\n') {
            *p = 0;
            if (rcode < 0) {
                if ((rcode = external_read_rcode(q)) == DNS_RCODE_NXDOMAIN)
                    break;
            } else {
                if (external_read_line(rrset, q, tls) < 0)
                    return -1;

                count++;
            }

            q = p + 1;
        }
    }

    if (count == 0)
        dns_cache_negative(rrset, 0);

    dns_cache_setrcode(rrset, rcode);

    return 0;
}

static int
external_read_line(dns_cache_rrset_t *rrset, char *line, dns_tls_t *tls)
{
    int i;
    char *p, *last, *sep = " ";
    dns_msg_resource_t res;

    memset(&res, 0, sizeof(res));

    /*
     * response string format:
     * "<name> <ttl> <class> <type> <data>"
     */
    if ((p = strtok_r(line, sep, &last)) == NULL) {
        plog(LOG_ERR, "%s: invalid response format (name)", MODULE);
        return -1;
    }

    for (i = 0; i < NELEMS(ResParseFunc) && p != NULL; i++) {
        if (ResParseFunc[i](&res, p) < 0) {
            plog(LOG_ERR, "%s: invalid response format (element)", MODULE);
            return -1;
        }

        p = strtok_r(NULL, sep, &last);
    }

    if (i != NELEMS(ResParseFunc)) {
        plog(LOG_ERR, "%s: invalid response format (number of elements)", MODULE);
        return -1;
    }

    if (dns_cache_add_answer(rrset, &res, tls) < 0) {
        plog(LOG_ERR, "%s: can't add cache resource", MODULE);
        return -1;
    }

    return 0;
}

static int
external_read_rcode(char *line)
{
    return atoi(line);
}

static int
external_name_parse(dns_msg_resource_t *res, char *p)
{
    STRLCPY(res->mr_q.mq_name, p, sizeof(res->mr_q.mq_name));
    return 0;
}

static int
external_ttl_parse(dns_msg_resource_t *res, char *p)
{
    res->mr_ttl = strtoul(p, NULL, 10);
    return 0;
}

static int
external_class_parse(dns_msg_resource_t *res, char *p)
{
    res->mr_q.mq_class = dns_proto_parse_class(p);
    return 0;
}

static int
external_type_parse(dns_msg_resource_t *res, char *p)
{
    res->mr_q.mq_type = dns_proto_parse_type(p);
    return 0;
}

static int
external_data_parse(dns_msg_resource_t *res, char *p)
{
    int len;

    if (res->mr_q.mq_class != DNS_CLASS_IN)
        return -1;

    switch (res->mr_q.mq_type) {
    case DNS_TYPE_A:
        inet_pton(AF_INET, p, res->mr_data);
        res->mr_datalen = 4;
        break;

    case DNS_TYPE_PTR:
        if ((len = dns_msg_encode_name(res->mr_data, sizeof(res->mr_data), p)) < 0) {
            plog(LOG_ERR, "%s: domain name encoding failed", MODULE);
            return -1;
        }
        res->mr_datalen = len;
        break;

    default:
        plog(LOG_ERR, "%s: unsupported resource type (%u)", MODULE, res->mr_q.mq_type);
        return -1;
    }

    return 0;
}
