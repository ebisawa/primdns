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
#include <unistd.h>
#include "dns.h"
#include "dns_list.h"

#define MODULE "list"

/* NOTICE: This linked-list implementation is not thread-safe. */

void
dns_list_init(dns_list_t *list)
{
    list->l_head.le_next = &list->l_head;
    list->l_head.le_prev = &list->l_head;
    list->l_count = 0;
}

void
dns_list_push(dns_list_t *list, dns_list_elem_t *elem)
{
    if (list->l_head.le_next == NULL)
        dns_list_init(list);

    elem->le_prev = list->l_head.le_next;
    elem->le_next = &list->l_head;

    list->l_head.le_prev->le_next = elem;
    list->l_head.le_prev = elem;

    list->l_count++;
}

void
dns_list_unchain(dns_list_t *list, dns_list_elem_t *elem)
{
    elem->le_prev->le_next = elem->le_next;
    elem->le_next->le_prev = elem->le_prev;
    list->l_count--;
}

dns_list_elem_t *
dns_list_head(dns_list_t *list)
{
    dns_list_elem_t *elem;

    elem = list->l_head.le_next;
    if (elem == &list->l_head)
        return NULL;

    return elem;
}

dns_list_elem_t *
dns_list_next(dns_list_t *list, dns_list_elem_t *elem)
{
    elem = elem->le_next;
    if (elem == &list->l_head)
        return NULL;

    return elem;
}

dns_list_elem_t *
dns_list_prev(dns_list_t *list, dns_list_elem_t *elem)
{
    elem = elem->le_prev;
    if (elem == &list->l_head)
        return NULL;

    return elem;
}

dns_list_elem_t *
dns_list_pop(dns_list_t *list)
{
    dns_list_elem_t *elem;

    if ((elem = dns_list_head(list)) != NULL)
        dns_list_unchain(list, elem);

    return elem;
}

unsigned
dns_list_count(dns_list_t *list)
{
    return list->l_count;
}

void
dns_list_foreach(dns_list_t *list, void (*func)(void *elem))
{
    void *elem;

    elem = dns_list_head(list);
    while (elem != NULL) {
        func(elem);
        elem = dns_list_next(list, elem);
    }
}
