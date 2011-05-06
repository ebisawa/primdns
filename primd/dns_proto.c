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

typedef struct {
    int code;
    char *string;
} dns_codes_t;

static dns_codes_t TypeString[] = {
    {  DNS_TYPE_A,     "A"     },
    {  DNS_TYPE_NS,    "NS"    },
    {  DNS_TYPE_CNAME, "CNAME" },
    {  DNS_TYPE_SOA,   "SOA"   },
    {  DNS_TYPE_PTR,   "PTR"   },
    {  DNS_TYPE_MX,    "MX"    },
    {  DNS_TYPE_TXT,   "TXT"   },
    {  DNS_TYPE_AAAA,  "AAAA"  },
    {  DNS_TYPE_OPT,   "OPT"   },
    {  DNS_TYPE_IXFR,  "IXFR"  },
    {  DNS_TYPE_AXFR,  "AXFR"  },
    {  DNS_TYPE_ALL,   "ALL"   },
};

static dns_codes_t ClassString[] = {
    {  DNS_CLASS_IN,   "IN"    },
    {  DNS_CLASS_CH,   "CH"    },
    {  DNS_CLASS_ANY,  "ANY"   },
};

static dns_codes_t RcodeString[] = {
    {  DNS_RCODE_NOERROR,   "NOERROR"   },
    {  DNS_RCODE_FORMERR,   "FORMERR"   },
    {  DNS_RCODE_SERVFAIL,  "SERVFAIL"  },
    {  DNS_RCODE_NXDOMAIN,  "NXDOMAIN"  },
    {  DNS_RCODE_NOTIMP,    "NOTIMP"    },
    {  DNS_RCODE_REFUSED,   "REFUSED"   },
    {  DNS_RCODE_YXDOMAIN,  "YXDOMAIN"  },
    {  DNS_RCODE_YXRRSET,   "YXRRSET"   },
    {  DNS_RCODE_NXRRSET,   "NXRRSET"   },
    {  DNS_RCODE_NOTAUTH,   "NOAUTH"    },
    {  DNS_RCODE_NOTZONE,   "NOTZONE"   },
};

static char UNKNOWN[] = "unknown";
static char *proto_find_string(dns_codes_t *table, int elems, int code);

char *
dns_proto_type_string(int type)
{
    return proto_find_string(TypeString, NELEMS(TypeString), type);
}

char *
dns_proto_class_string(int klass)
{
    return proto_find_string(ClassString, NELEMS(ClassString), klass);
}

char *
dns_proto_rcode_string(int rcode)
{
    return proto_find_string(RcodeString, NELEMS(RcodeString), rcode);
}

int
dns_proto_parse_type(char *string)
{
    int i;

    for (i = 0; i < NELEMS(TypeString); i++) {
        if (strcasecmp(TypeString[i].string, string) == 0)
            return TypeString[i].code;
    }
    
    return -1;
}

int
dns_proto_parse_class(char *string)
{
    int i;

    for (i = 0; i < NELEMS(ClassString); i++) {
        if (strcasecmp(ClassString[i].string, string) == 0)
            return ClassString[i].code;
    }
    
    return -1;
}

static char *
proto_find_string(dns_codes_t *table, int elems, int code)
{
    int i;

    for (i = 0; i < elems; i++) {
        if (table[i].code == code)
            return table[i].string;
    }

    return UNKNOWN;
}
