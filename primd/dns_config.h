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
#ifndef __DNS_CONFIG_H__
#define __DNS_CONFIG_H__
#include "dns.h"
#include "dns_list.h"
#include "dns_acl.h"

#define DNS_CONFIG_ZONE_NAME_MAX   128

typedef struct {
    dns_list_elem_t            ze_elem;
    void                      *ze_engine;
    void                      *ze_econf;
} dns_config_zone_engine_t;

typedef struct {
    dns_acl_t                  zss_acl;
} dns_config_zone_slaves_t;

typedef struct {
    dns_list_t                 zs_engine;
} dns_config_zone_search_t;

typedef struct {
    dns_list_elem_t            z_elem;
    char                       z_name[DNS_CONFIG_ZONE_NAME_MAX];
    int                        z_class;
    dns_config_zone_search_t   z_search;
    dns_config_zone_slaves_t   z_slaves;
} dns_config_zone_t;

typedef struct {
    dns_list_t                 r_zone;
} dns_config_root_t;

int dns_config_update(char *name);
dns_config_zone_t *dns_config_find_zone(char *name, int class);

extern dns_config_root_t *ConfigRoot;

#endif
