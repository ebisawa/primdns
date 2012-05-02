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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include "dns.h"
#include "dns_file.h"

#define MODULE "file"

static int file_next_line(dns_file_handle_t *handle);
static int file_read_buf(dns_file_handle_t *handle, int plen);
static int file_split(char *buf, int bufmax, dns_file_handle_t *handle);
static int file_isspace(char *line);
static void file_ignore_comment(char *line);

int
dns_file_open(dns_file_handle_t *handle, char *filename)
{
    memset(handle, 0, sizeof(*handle));
    if (filename[0] == 0)
        return -1;

    if ((handle->fh_fd = open(filename, O_RDONLY)) < 0) {
        plog_error(LOG_ERR, MODULE, "file can't open: %s", filename);
        return -1;
    }

    if (file_next_line(handle) < 0) {
        close(handle->fh_fd);
        return -1;
    }

    return 0;
}

void
dns_file_close(dns_file_handle_t *handle)
{
    close(handle->fh_fd);
    memset(&handle, 0, sizeof(handle));
}

char *
dns_file_get_line(dns_file_handle_t *handle)
{
    if (file_next_line(handle) < 0)
        return NULL;

    return handle->fh_curp;
}

int
dns_file_get_token(char *buf, int bufmax, dns_file_handle_t *handle)
{
retry:
    if (file_split(buf, bufmax, handle) < 0) {
        if (file_next_line(handle) < 0)
            return -1;
        goto retry;
    }

    if (file_isspace(buf))
        goto retry;

    return 0;
}

static int
file_next_line(dns_file_handle_t *handle)
{
    char *p, *lnext_org;
    int len;

redo:
    lnext_org = handle->fh_lnext;

    p = handle->fh_lnext;
    len = handle->fh_len;

    if (p != NULL) {
        handle->fh_line++;

        for (; len > 0; p++, len--) {
            if (*p == '\n') {
                *p = 0;
                handle->fh_len = len - 1;
                handle->fh_lnext = p + 1;
                handle->fh_curp = lnext_org;
                file_ignore_comment(lnext_org);
                return 0;
            }
        }

        memcpy(handle->fh_buf, handle->fh_lnext, handle->fh_len);
    }

    if (file_read_buf(handle, handle->fh_len) <= 0)
        return -1;

    goto redo;
}

static int
file_read_buf(dns_file_handle_t *handle, int plen)
{
    char *p;
    int len, rlen;

    p = handle->fh_buf + plen;
    rlen = sizeof(handle->fh_buf) - 1 - plen;

    if ((len = read(handle->fh_fd, p, rlen)) < 0) {
        plog_error(LOG_ERR, MODULE, "read() failed");
        return -1;
    }

    handle->fh_len = len + plen;
    handle->fh_lnext = handle->fh_buf;
    handle->fh_buf[handle->fh_len] = 0;

    return handle->fh_len;
}

static int
file_split(char *buf, int bufmax, dns_file_handle_t *handle)
{
    int len;
    char *line, *p, *q, *sep = "\"'(){}[],;: \t\r\n";

    line = handle->fh_curp;
    if (*line == 0)
        return -1;

    if ((p = strpbrk(line, sep)) == NULL) {
        len = strlen(line);
        p = &line[len];
    }

    len = p - line;
    if (len == 0) {
        len = 1;
        p++;
    }

    if (len == 1 && (*line == '"' || *line == '\'')) {
        if ((q = strpbrk(line + 1, "'\"")) == NULL) {
            plog(LOG_ERR, "syntax error: \" or ' missing");
            return -1;
        }

        /* "hogehoge" -> hogehoge */
        len = q + 1 - line - 2;
        p = q + 1;
        line++;
    }

    if (len >= bufmax)
        return -1;

    memcpy(buf, line, len);
    buf[len] = 0;

    handle->fh_curp = p;

    return 0;
}

static int
file_isspace(char *line)
{
    for (; *line != 0; line++) {
        if (!isspace(*line))
            return 0;
    }

    return 1;
}

static void
file_ignore_comment(char *line)
{
    for (; *line != 0; line++) {
        if (isspace(*line))
            continue;
        if (*line == '#') {
            *line = 0;
            return;
        }
    }
}
