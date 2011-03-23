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
#ifndef __DNS_LOG_H__
#define __DNS_LOG_H__
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include "dns_proto.h"
#include "dns_msg.h"

#define LOG_FUNC_ENTER()      plog_func(LOG_DEBUG, __func__, "enter")

#define DNS_LOG_FLAG_SYSLOG   0x0001
#define DNS_LOG_FLAG_TRACE    0x0002
#define DNS_LOG_FLAG_QUERY    0x0004

void plog_setflag(int flag);
void plog_setmask(int upto);

void plog(int level, char *fmt, ...);
void plog_func(int level, const char *func, const char *msg);
void plog_error(int level, const char *prefix, const char *msg, ...);
void plog_dump(int level, const char *prefix, void *buf, int len);
void plog_question(int level, char *module, char *msg, dns_msg_question_t *q, int category);
void plog_query(int level, dns_msg_question_t *q, struct sockaddr *from, char sockchar);
void plog_response(int level, struct sockaddr *to, char sockchar, dns_msg_question_t *q, dns_header_t *h);

#endif
