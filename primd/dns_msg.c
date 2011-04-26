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
#include <arpa/inet.h>
#include "dns.h"

#define MODULE "msg"

#define VBEGIN(h)                  ((void *) (h)->mh_buf)
#define VEND(h)                    ((void *) ((uint8_t *)(h)->mh_buf) + (h)->mh_len - 1)
#define VALID_PTR(h, p)            (((void *) (p)) >= VBEGIN(h) && ((void *) (p)) <= VEND(h))
#define VALID_RANGE(h, b, len)     (VALID_PTR((h), (b)) && VALID_PTR(h, (uint8_t *) (b) + len - 1))
#define VALID_POS(h, len)          (VALID_RANGE((h), (h)->mh_pos, len))
#define POS_ADD(h, len)            ((h)->mh_pos = ((uint8_t *) (h)->mh_pos + len))
#define REMLEN(h)                  ((h)->mh_len - ((h)->mh_pos - (h)->mh_buf))

#define MSG_READ16(dest, handle)   do { int x; if ((x = msg_read16(handle)) < 0) { return -1; } (dest) = x; } while (0)
#define MSG_READ32(dest, handle)   do { int x; if ((x = msg_read32(handle)) < 0) { return -1; } (dest) = x; } while (0)

static void *msg_mfetch32(void *dst, void *src);
static int msg_read16(dns_msg_handle_t *handle);
static int msg_read32(dns_msg_handle_t *handle);
static int msg_read_data(void *dst, int dstmax, int len, dns_msg_handle_t *handle);
static int msg_write16(dns_msg_handle_t *handle, uint16_t value);
static int msg_write32(dns_msg_handle_t *handle, uint32_t value);
static int msg_write_data(dns_msg_handle_t *handle, void *src, int len);
static int msg_skip_name(dns_msg_handle_t *handle);
static char *msg_skip_name2(char *name, dns_msg_handle_t *handle);
static int msg_decode_name(dns_msg_handle_t *handle, char *dst, int dstmax);
static int msg_decode_raw_name(char *buf, int bufmax, void *data);
static int msg_decomp_name(dns_msg_handle_t *handle, void *dst, int dstmax);
static int msg_read_decomp(dns_msg_resource_t *res, dns_msg_handle_t *handle);
static int msg_read_decomp_soa(void *dst, int dstmax, int datalen, dns_msg_handle_t *handle);
static int msg_read_decomp_mx(void *dst, int dstmax, int datalen, dns_msg_handle_t *handle);
static int msg_read_decomp_name(void *dst, int dstmax, int datalen, dns_msg_handle_t *handle);
static int msg_encode_name(char *dst, int dstmax, char *name);
static int msg_compress(char *data, int datalen, dns_msg_resource_t *res, dns_msg_handle_t *handle);
static int msg_compress_soa(char *data, int datalen, dns_msg_handle_t *handle);
static int msg_compress_mx(char *data, dns_msg_handle_t *handle);
static int msg_compress_name(char *name, dns_msg_handle_t *handle);
static int msg_compress_index(char *name, dns_msg_handle_t *handle);
static int msg_compress_match_name(char **result, char *buf, char *name);
static void msg_update_rescount(dns_msg_handle_t *handle, int restype);

int
dns_msg_read_open(dns_msg_handle_t *handle, void *buf, int len)
{
    if (len < sizeof(dns_header_t)) {
        plog(LOG_NOTICE, "%s: too short message length (len = %d)", MODULE, len);
        return -1;
    }

    memset(handle, 0, sizeof(*handle));
    handle->mh_buf = buf;
    handle->mh_pos = buf;
    handle->mh_len = len;

    return 0;
}

int
dns_msg_read_close(dns_msg_handle_t *handle)
{
    /* nop */

    return 0;
}

int
dns_msg_read_header(dns_header_t *header, dns_msg_handle_t *handle)
{
    memcpy(header, handle->mh_buf, sizeof(*header));
    POS_ADD(handle, sizeof(dns_header_t));

    return 0;
}

int
dns_msg_read_question(dns_msg_question_t *qdata, dns_msg_handle_t *handle)
{
    if (msg_decode_name(handle, qdata->mq_name, sizeof(qdata->mq_name)) < 0)
        return -1;
    if (msg_skip_name(handle) < 0)
        return -1;

    MSG_READ16(qdata->mq_type, handle);
    MSG_READ16(qdata->mq_class, handle);

    return 0;
}

int
dns_msg_read_resource(dns_msg_resource_t *res, dns_msg_handle_t *handle)
{
    int r;

    if (msg_decode_name(handle, res->mr_q.mq_name, sizeof(res->mr_q.mq_name)) < 0)
        return -1;
    if (msg_skip_name(handle) < 0)
        return -1;

    MSG_READ16(res->mr_q.mq_type, handle);
    MSG_READ16(res->mr_q.mq_class, handle);
    MSG_READ32(res->mr_ttl, handle);
    MSG_READ16(res->mr_datalen, handle);

    if (res->mr_q.mq_class == DNS_CLASS_IN) {
        if ((r = msg_read_decomp(res, handle)) < 0)
            return -1;
        if (r > 0)
            return 0;
    }

    return msg_read_data(res->mr_data, sizeof(res->mr_data), res->mr_datalen, handle);
}

int
dns_msg_write_open(dns_msg_handle_t *handle, void *buf, int len)
{
    if (len < sizeof(dns_header_t))
        return -1;

    memset(handle, 0, sizeof(*handle));
    handle->mh_buf = buf;
    handle->mh_pos = buf;
    handle->mh_len = len;

    return 0;
}

int
dns_msg_write_close(dns_msg_handle_t *handle)
{
    dns_header_t *header;

    memset(&header, 0, sizeof(header));

    header = (dns_header_t *) handle->mh_buf;
    header->hdr_qdcount = htons(handle->mh_qdcount);
    header->hdr_ancount = htons(handle->mh_ancount);
    header->hdr_nscount = htons(handle->mh_nscount);
    header->hdr_arcount = htons(handle->mh_arcount);

    return handle->mh_pos - handle->mh_buf;
}

int
dns_msg_write_header(dns_msg_handle_t *handle, uint16_t msgid, uint16_t flags)
{
    dns_header_t header;

    memset(&header, 0, sizeof(header));
    header.hdr_id = htons(msgid);
    header.hdr_flags = htons(flags);

    return msg_write_data(handle, &header, sizeof(header));
}

int
dns_msg_write_rcode(dns_msg_handle_t *handle, uint16_t rcode)
{
    dns_header_t *header;

    header = (dns_header_t *) handle->mh_buf;
    header->hdr_flags |= htons(rcode);

    return 0;
}

int
dns_msg_write_flag(dns_msg_handle_t *handle, uint16_t flag)
{
    dns_header_t *header;

    header = (dns_header_t *) handle->mh_buf;
    header->hdr_flags |= htons(flag);

    return 0;
}

int
dns_msg_write_question(dns_msg_handle_t *handle, dns_msg_question_t *qdata)
{
    if (msg_encode_name(handle->mh_pos, REMLEN(handle), qdata->mq_name) < 0)
        return -1;
    if (msg_compress_name(handle->mh_pos, handle) < 0)
        return -1;
    if (msg_skip_name(handle) < 0)
        return -1;

    msg_write16(handle, qdata->mq_type);
    msg_write16(handle, qdata->mq_class);

    handle->mh_qdcount++;

    return 0;
}

int
dns_msg_write_resource(dns_msg_handle_t *handle, dns_msg_resource_t *res, int restype)
{
    int datalen;
    char *opos, data[DNS_RDATA_MAX];

    opos = (char *) handle->mh_pos;

    /* name */
    if (msg_encode_name(handle->mh_pos, REMLEN(handle), res->mr_q.mq_name) < 0)
        goto error;
    if (msg_compress_name(handle->mh_pos, handle) < 0)
        goto error;
    if (msg_skip_name(handle) < 0)
        goto error;

    /* type, class, ttl */
    if (msg_write16(handle, res->mr_q.mq_type) < 0)
        goto error;
    if (msg_write16(handle, res->mr_q.mq_class) < 0)
        goto error;
    if (msg_write32(handle, res->mr_ttl) < 0)
        goto error;

    /* data */
    datalen = msg_compress(data, sizeof(data), res, handle);

    if (msg_write16(handle, datalen) < 0)
        goto error;
    if (msg_write_data(handle, data, datalen) < 0)
        goto error;

    msg_update_rescount(handle, restype);
    return 0;

error:
    handle->mh_pos = opos;

    if (restype != DNS_MSG_RESTYPE_ADDITIONAL) {
        plog(LOG_DEBUG, "%s: set trucated flag", MODULE);
        dns_msg_write_flag(handle, DNS_FLAG_TC);
    }

    return -1;
}

void *
dns_msg_buffer(dns_msg_handle_t *handle)
{
    return handle->mh_buf;
}

int
dns_msg_parse_name(char *cname, dns_msg_resource_t *res)
{
    return msg_decode_raw_name(cname, DNS_NAME_MAX, res->mr_data);
}

int
dns_msg_parse_soa(char *mname, char *rname, uint32_t *serial, uint32_t *refresh, uint32_t *retry, uint32_t *expire, uint32_t *minimum, dns_msg_resource_t *res)
{
    uint8_t *p;

    p = (uint8_t *) res->mr_data;
    p += msg_decode_raw_name(mname, DNS_NAME_MAX, p);
    p += msg_decode_raw_name(rname, DNS_NAME_MAX, p);

    p = msg_mfetch32(serial, p);
    p = msg_mfetch32(refresh, p);
    p = msg_mfetch32(retry, p);
    p = msg_mfetch32(expire, p);
    p = msg_mfetch32(minimum, p);

    return 0;
}

int
dns_msg_encode_name(void *dst, int dstmax, char *name)
{
    return msg_encode_name(dst, dstmax, name);
}

static void *
msg_mfetch32(void *dst, void *src)
{
    uint32_t *s = (uint32_t *) src;

    if (dst != NULL)
        *((uint32_t *) dst) = ntohl(*s);

    return s + 1;
}

static int
msg_read16(dns_msg_handle_t *handle)
{
    uint16_t value;

    if (!VALID_POS(handle, 2)) {
        plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
        return -1;
    }

    value = ntohs(*(uint16_t *) handle->mh_pos);
    POS_ADD(handle, 2);

    return value;
}

static int
msg_read32(dns_msg_handle_t *handle)
{
    uint32_t value;

    if (!VALID_POS(handle, 4)) {
        plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
        return -1;
    }

    value = ntohl(*(uint32_t *) handle->mh_pos);
    POS_ADD(handle, 4);

    return value;
}

static int
msg_read_data(void *dst, int dstmax, int len, dns_msg_handle_t *handle)
{
    if (len == 0)
        return 0;
    if (len > dstmax)
        return -1;

    if (!VALID_POS(handle, len)) {
        plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
        return -1;
    }

    memcpy(dst, handle->mh_pos, len);
    POS_ADD(handle, len);

    return 0;
}

static int
msg_write16(dns_msg_handle_t *handle, uint16_t value)
{
    uint16_t *p;

    if (!VALID_POS(handle, 2))
        return -1;

    p = (uint16_t *) handle->mh_pos;
    *p = htons(value);
    POS_ADD(handle, 2);

    return 0;
}

static int
msg_write32(dns_msg_handle_t *handle, uint32_t value)
{
    uint32_t *p;

    if (!VALID_POS(handle, 4))
        return -1;

    p = (uint32_t *) handle->mh_pos;
    *p = htonl(value);
    POS_ADD(handle, 4);

    return 0;
}

static int
msg_write_data(dns_msg_handle_t *handle, void *src, int len)
{
    if (!VALID_POS(handle, len))
        return -1;

    memcpy(handle->mh_pos, src, len);
    POS_ADD(handle, len);

    return 0;
}

static int
msg_skip_name(dns_msg_handle_t *handle)
{
    char *p;

    if ((p = msg_skip_name2(handle->mh_pos, handle)) == NULL)
        return -1;

    handle->mh_pos = p;

    return 0;
}

static char *
msg_skip_name2(char *name, dns_msg_handle_t *handle)
{
    uint8_t len;

    while (*name != 0) {
        if (handle != NULL) {
            if (!VALID_PTR(handle, name)) {
                plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
                return NULL;
            }
        }

        len = *name;
        if (len & 0xc0) {
            name++;
            break;
        } else {
            name += len + 1;
        }
    }

    return name + 1;
}

static int
msg_decode_name(dns_msg_handle_t *handle, char *dst, int dstmax)
{
    char buf[DNS_NAME_MAX];

    if (msg_decomp_name(handle, buf, sizeof(buf)) < 0)
        return -1;
    if (msg_decode_raw_name(dst, dstmax, buf) < 0)
        return -1;

    return 0;
}

static int
msg_decode_raw_name(char *buf, int bufmax, void *data)
{
    int lmax;
    char *p, *q, lbuf[DNS_NAME_MAX];
    uint8_t len;

    p = (char *) data;
    q = (char *) lbuf;
    lmax = sizeof(lbuf);

    if (p[0] == 0)
        q[0] = 0;
    else {
        while (*p != 0) {
            len = *p++;
            if (lmax < len + 1) {
                plog(LOG_ERR, "%s: buffer too small", __func__);
                return -1;
            }

            memcpy(q, p, len);
            p += len; q += len;

            *q++ = '.';
            lmax -= len + 1;
        }

        *(q - 1) = 0;
    }

    if (buf != NULL)
        STRLCPY(buf, lbuf, bufmax);

    return p - (char *) data + 1;
}

static int
msg_decomp_name(dns_msg_handle_t *handle, void *dst, int dstmax)
{
    int len, offs;
    uint8_t *p, *d, *o;

    p = handle->mh_pos;
    d = dst;
    o = NULL;

    while (*p != 0) {
        if (!VALID_PTR(handle, p)) {
            plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
            return -1;
        }

        len = *p;
        if (len & 0xc0) {
            /* compressed */
            if (o == NULL)
                o = p + 2;

            offs = ntohs(*((uint16_t *) p)) & ~0xc000;
            p = handle->mh_buf + offs;
        } else {
            len++;
            if (dstmax < len)
                return -1;
            if (!VALID_RANGE(handle, p, len)) {
                plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
                return -1;
            }
            
            memcpy(d, p, len);
            p += len;
            d += len;
            dstmax -= len;
        }
    }

    *d = 0;

    return ((o == NULL) ? p + 1: o) - (uint8_t *) handle->mh_pos;
}

static int
msg_read_decomp(dns_msg_resource_t *res, dns_msg_handle_t *handle)
{
    int len;

    switch (res->mr_q.mq_type) {
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        if ((len = msg_read_decomp_name(res->mr_data, sizeof(res->mr_data), res->mr_datalen, handle)) < 0)
            return -1;

        res->mr_datalen = len;
        return len;

    case DNS_TYPE_SOA:
        if ((len = msg_read_decomp_soa(res->mr_data, sizeof(res->mr_data), res->mr_datalen, handle)) < 0)
            return -1;

        res->mr_datalen = len;
        return len;

    case DNS_TYPE_MX:
        if ((len = msg_read_decomp_mx(res->mr_data, sizeof(res->mr_data), res->mr_datalen, handle)) < 0)
            return -1;

        res->mr_datalen = len;
        return len;
    }

    return 0;
}

static int
msg_read_decomp_soa(void *dst, int dstmax, int datalen, dns_msg_handle_t *handle)
{
    char *d;
    int rlen, dlen;

    d = (char *) dst;

    /* mname */
    if ((rlen = msg_decomp_name(handle, d, dstmax)) < 0)
        return -1;

    POS_ADD(handle, rlen);
    dlen = strlen(d) + 1;
    d += dlen; dstmax -= dlen;

    /* rname */
    if ((rlen = msg_decomp_name(handle, d, dstmax)) < 0)
        return -1;

    POS_ADD(handle, rlen);
    dlen = strlen(d) + 1;
    d += dlen; dstmax -= dlen;

    /* check buflen */
    if (dstmax < 20) {
        plog(LOG_DEBUG, "%s: buffer too small", __func__);
        return -1;
    }

    if (!VALID_POS(handle, 20)) {
        plog(LOG_NOTICE, "%s: pointer validation failed (%s)", MODULE, __func__);
        return -1;
    }

    memcpy(d, handle->mh_pos, 20);
    POS_ADD(handle, 20);

    return d - (char *) dst + 20;
}

static int
msg_read_decomp_mx(void *dst, int dstmax, int datalen, dns_msg_handle_t *handle)
{
    int len, pref;

    MSG_READ16(pref, handle);
    *((uint16_t *) dst) = htons(pref);
    dst += 2; dstmax -= 2;

    if ((len = msg_decomp_name(handle, dst, dstmax)) < 0)
        return -1;

    POS_ADD(handle, len);

    return sizeof(uint16_t) + strlen(dst) + 1;
}

static int
msg_read_decomp_name(void *dst, int dstmax, int datalen, dns_msg_handle_t *handle)
{
    if (msg_decomp_name(handle, dst, dstmax) < 0)
        return -1;

    POS_ADD(handle, datalen);

    return strlen(dst) + 1;
}

static int
msg_encode_name(char *dst, int dstmax, char *name)
{
    uint8_t len;
    char *s, *p, *d, buf[DNS_NAME_MAX];

    STRLCPY(buf, name, sizeof(buf));

    s = buf;
    d = dst;
    p = s;

    while (p != NULL && *s != 0) {
        if ((p = strchr(s, '.')) != NULL)
            *p = 0;

        len = strlen(s);
        if (dstmax < len || len > 63) {
            plog(LOG_DEBUG, "%s: name buffer too small", __func__);
            return -1;
        }

        *d++ = (uint8_t) len;
        memcpy(d, s, len);
        d += len; s += len;

        if (p == NULL)
            break;

        s = p + 1;
        dstmax -= len;
    }
    
    if (dstmax < 1) {
        plog(LOG_DEBUG, "%s: name buffer too small", __func__);
        return -1;
    }

    *d = 0;

    return (d - dst) + 1;
}

static int
msg_compress(char *data, int datalen, dns_msg_resource_t *res, dns_msg_handle_t *handle)
{
    if (res->mr_datalen > datalen)
        return -1;

    memcpy(data, res->mr_data, res->mr_datalen);

    switch (res->mr_q.mq_type) {
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        return msg_compress_name(data, handle);
    case DNS_TYPE_SOA:
        return msg_compress_soa(data, res->mr_datalen, handle);
    case DNS_TYPE_MX:
        return msg_compress_mx(data, handle);

    default:
        return res->mr_datalen;
    }
}

static int
msg_compress_soa(char *data, int datalen, dns_msg_handle_t *handle)
{
    int mlen, rlen;
    char buf[DNS_RDATA_MAX], *mname, *rname, *serial;

    memcpy(buf, data, datalen);
    mname = buf;

    if ((rname = msg_skip_name2(mname, NULL)) == NULL)
        return datalen;
    if ((serial = msg_skip_name2(rname, NULL)) == NULL)
        return datalen;

    mlen = msg_compress_name(mname, handle);
    memcpy(data, mname, mlen);
    data += mlen;

    rlen = msg_compress_name(rname, handle);
    memcpy(data, rname, rlen);
    data += rlen;

    memcpy(data, serial, 20);

    return mlen + rlen + 20;
}

static int
msg_compress_mx(char *data, dns_msg_handle_t *handle)
{
    return msg_compress_name(&data[2], handle) + 2;
}

static int
msg_compress_name(char *name, dns_msg_handle_t *handle)
{
    int r, len;
    char *p = name;

    while (*p != 0) {
        if ((r = msg_compress_index(p, handle)) > 0) {
            p[0] = ((((r) & 0xff00) >> 8) | 0xc0);
            p[1] = ((r) & 0x00ff);
            return p - name + 2;
        }

        len = *p;
        p += len + 1;
    }

    return p - name + 1;
}

static int
msg_compress_index(char *name, dns_msg_handle_t *handle)
{
    int i;
    char *p, *r;

    p = handle->mh_buf + sizeof(dns_header_t);

    /* question */
    for (i = 0; i < handle->mh_qdcount; i++) {
        if (msg_compress_match_name(&r, p, name))
          return r - (char *) handle->mh_buf;

        p = r + 4;
    }

    /* resources */
    for (i = 0; i < handle->mh_ancount + handle->mh_nscount + handle->mh_arcount; i++) {
        if (msg_compress_match_name(&r, p, name))
            return r - (char *) handle->mh_buf;

        p = r + 8;   /* type, class, ttl */
        p += ntohs(*((uint16_t *) p)) + 2;
    }

    return -1;
}

static int
msg_compress_match_name(char **result, char *buf, char *name)
{
    int len;

    for (;;) {
        if (strcasecmp(buf, name) == 0) {
            *result = buf;
            return 1;
        }

        len = *buf;
        if (len == 0) {
            *result = buf + 1;
            break;
        } else if (len & 0xc0) {
            *result = buf + 2;
            break;
        } else
            buf += len + 1;
    }

    return 0;
}

static void
msg_update_rescount(dns_msg_handle_t *handle, int restype)
{
    /* XXX update header directly */
    switch (restype) {
    case DNS_MSG_RESTYPE_ANSWER:
        handle->mh_ancount++;
        break;

    case DNS_MSG_RESTYPE_AUTHORITY:
        handle->mh_nscount++;
        break;

    case DNS_MSG_RESTYPE_ADDITIONAL:
        handle->mh_arcount++;
        break;
    }
}
