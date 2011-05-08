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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "dns.h"
#include "dns_acl.h"

#define MODULE "acl"

#define ACL_EXTEND_UNIT  8

static int acl_extend_addr4(dns_acl_t *acl);
static int acl_add4(dns_acl_t *acl, uint32_t addr, uint32_t mask);
static int acl_match4(dns_acl_t *acl, uint32_t addr);

int
dns_acl_init(dns_acl_t *acl)
{
    memset(acl, 0, sizeof(*acl));
    return 0;
}

void
dns_acl_free(dns_acl_t *acl)
{
    if (acl->acl_entry != NULL)
        free(acl->acl_entry);
}

int
dns_acl_add(dns_acl_t *acl, struct sockaddr *sa)
{
    struct sockaddr_in *sin;

    switch (sa->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        return acl_add4(acl, ntohl(sin->sin_addr.s_addr), 0xffffffff);
    }

    return 0;
}

int
dns_acl_match(dns_acl_t *acl, struct sockaddr *sa)
{
    struct sockaddr_in *sin;

    switch (sa->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        return acl_match4(acl, ntohl(sin->sin_addr.s_addr));
    }

    return 0;
}

void
dns_acl_each(dns_acl_t *acl, void *param, void (*func)(uint32_t addr, uint32_t mask, void *param))
{
    int i;
    dns_acl_entry4_t *entry4;

    for (i = 0; i < acl->acl_count; i++) {
        entry4 = &acl->acl_entry[i];
        func(entry4->ae4_addr, entry4->ae4_mask, param);
    }
}

static int
acl_extend_addr4(dns_acl_t *acl)
{
    void *newbuf;
    int max_count, newsize;

    max_count = acl->acl_entry_max + ACL_EXTEND_UNIT;
    newsize = sizeof(dns_acl_entry4_t) * max_count;

    if ((newbuf = realloc(acl->acl_entry, newsize)) == NULL) {
        plog(LOG_ERR, "%s: can't allocate acl entry", MODULE);
        return -1;
    }

    acl->acl_entry_max = max_count;
    acl->acl_entry = newbuf;

    return 0;
}

static int
acl_add4(dns_acl_t *acl, uint32_t addr, uint32_t mask)
{
    dns_acl_entry4_t *entry;

    if (acl->acl_count == acl->acl_entry_max) {
        if (acl_extend_addr4(acl) < 0)
            return -1;
    }

    entry = &acl->acl_entry[acl->acl_count];
    entry->ae4_addr = addr;
    entry->ae4_mask = mask;
    acl->acl_count++;

    return 0;
}

static int
acl_match4(dns_acl_t *acl, uint32_t addr)
{
    int i;
    uint32_t masked;

    /* XXX need better algorithms */
    for (i = 0; i < acl->acl_count; i++) {
        masked = addr & acl->acl_entry[i].ae4_mask;
        if (acl->acl_entry[i].ae4_addr == masked)
            return 1;
    }

    return 0;
}
