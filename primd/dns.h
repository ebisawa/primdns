/*
 * Copyright (c) 2010-2011 Satoshi Ebisawa. All rights reserved.
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
#ifndef __DNS_H__
#define __DNS_H__
#include "config.h"
#include "dns_arc4random.h"
#include "dns_atomic.h"
#include "dns_proto.h"
#include "dns_msg.h"
#include "dns_util.h"
#include "dns_log.h"

#define PROGNAME      "primd"
#define PATH_PID      "/var/run/primd.pid"
#define PATH_CONTROL  "/var/run/primd.control"

#define DNS_DEFAULT_CACHE_SIZE       1
#define DNS_DEFAULT_WORKER_THREADS   0

typedef struct {
    char                     *opt_config;
    unsigned                  opt_ipv4_enable : 1;
    unsigned                  opt_ipv6_enable : 1;
    unsigned                  opt_debug       : 1;
    unsigned                  opt_foreground  : 1;
    int                       opt_cache_size;
    int                       opt_threads;
    int                       opt_user;
    int                       opt_group;
    int                       opt_port;
    struct sockaddr_storage   opt_baddr;
} dns_opts_t;

typedef struct {
    int                       tls_id;
    arc4_ctx_t                tls_arctx;
} dns_tls_t;

extern dns_opts_t Options;
extern char ConfPath[], ConfDir[];

#endif
