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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include "dns.h"

static void plog_print(int level, char *msg, va_list ap);
static void plog_syslog(int level, char *msg, va_list ap);

static int LogFlags;
static int MaskLevel = LOG_INFO;

void
plog_setflag(int flag)
{
    LogFlags |= flag;

    if (flag & DNS_LOG_FLAG_SYSLOG)
        openlog(PROGNAME, 0, LOG_DAEMON);
}

void
plog_setmask(int upto)
{
    MaskLevel = upto;
}

void
plog(int level, char *msg, ...)
{
    va_list ap;

    if (level > MaskLevel)
        return;

    va_start(ap, msg);

    if (LogFlags & DNS_LOG_FLAG_SYSLOG)
        plog_syslog(level, msg, ap);
    else
        plog_print(level, msg, ap);

    va_end(ap);

    if (level == LOG_CRIT)
        exit(EXIT_FAILURE);
}


void
plog_func(int level, const char *func, const char *msg)
{
    if (LogFlags & DNS_LOG_FLAG_TRACE)
        plog(level, "%s: %s", func, msg);
}

void
plog_error(int level, const char *prefix, const char *msg, ...)
{
    char buf[256], *errmsg;
    va_list ap;

    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);

    errmsg = strerror(errno);
    if (prefix == NULL)
        plog(level, "%s: %s", buf, errmsg);
    else
        plog(level, "%s: %s: %s", prefix, buf, errmsg);
}

void
plog_dump(int level, const char *prefix, void *buf, int len)
{
    int i;
    uint8_t *p;

    p = (uint8_t *) buf;
    for (i = 0; i < len; i++)
        plog(level, "%s: %02x %c", prefix, p[i], p[i]);
}

void
plog_question(int level, char *module, char *msg, dns_msg_question_t *q, int category)
{
    char *catstr;

    catstr = (category == 1) ? "(internal)" : "";

    plog(level, "%s: %s: \"%s\" %s %s %s",
         module, msg,
         q->mq_name,
         dns_proto_class_string(q->mq_class),
         dns_proto_type_string(q->mq_type),
         catstr);
}

void
plog_query(int level, dns_msg_question_t *q, struct sockaddr *from, char sockchar)
{
    char buf[256];

    if (LogFlags & DNS_LOG_FLAG_QUERY) {
        dns_util_sa2str(buf, sizeof(buf), from);
        plog(level, "query from %s [%c]: \"%s\" %s %s",
             buf, sockchar, q->mq_name,
             dns_proto_class_string(q->mq_class),
             dns_proto_type_string(q->mq_type));
    }
}

void
plog_response(int level, struct sockaddr *to, char sockchar, dns_msg_question_t *q, dns_header_t *h)
{
    int rcode;
    char buf[256];

    if (LogFlags & DNS_LOG_FLAG_QUERY) {
        dns_util_sa2str(buf, sizeof(buf), to);
        rcode = DNS_RCODE(ntohs(h->hdr_flags));

        plog(level, "response to %s %c: %s %s %s %s",
             buf, sockchar,
             dns_proto_rcode_string(rcode),
             q->mq_name,
             dns_proto_class_string(q->mq_class),
             dns_proto_type_string(q->mq_type));
    }
}

static void
plog_syslog(int level, char *msg, va_list ap)
{
    vsyslog(level, msg, ap);
}

static void
plog_print(int level, char *msg, va_list ap)
{
    char buf[256];
    time_t now;
    struct tm t;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mutex);

    now = time(NULL);
    localtime_r(&now, &t);
    strftime(buf, sizeof(buf), "%F %T ", &t);
    printf("%s", buf);

    printf("%5u ", (unsigned) getpid());
    printf("0x%x ", (unsigned) pthread_self());

    switch (level) {
    case LOG_CRIT:      printf("[CRIT] ");      break;
    case LOG_ERR:       printf("[ERR] ");       break;
    case LOG_WARNING:   printf("[WARNING] ");   break;
    case LOG_NOTICE:    printf("[NOTICE] ");    break;
    case LOG_INFO:      printf("[INFO] ");      break;
    case LOG_DEBUG:     printf("[DEBUG] ");     break;
    }

    vsnprintf(buf, sizeof(buf), msg, ap);
    puts(buf);

    pthread_mutex_unlock(&mutex);
}
