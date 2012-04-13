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
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "dns.h"

#define MODULE "util"

static int util_compare_sin(struct sockaddr_in *a, struct sockaddr_in *b);
static int util_compare_sin_wop(struct sockaddr_in *a, struct sockaddr_in *b);
static int util_compare_sin6(struct sockaddr_in6 *a, struct sockaddr_in6 *b);
static int util_compare_sin6_wop(struct sockaddr_in6 *a, struct sockaddr_in6 *b);

void
dns_util_strlcpy(char *dst, char *src, int max)
{
    strncpy(dst, src, max);
    dst[max - 1] = 0;
}

void
dns_util_strlcat(char *dst, char *src, int max)
{
    int len;

    len = strlen(dst);
    dns_util_strlcpy(dst + len, src, max - len);
}

void
dns_util_strlower(char *str)
{
    for (; *str != 0; str++)
        *str = tolower(*str);
}

void
dns_util_sigmaskall(void)
{
    sigset_t mask;

    sigfillset(&mask);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

void
dns_util_sainit(struct sockaddr *sa, int af)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    /* XXX on FreeBSD, bind(2) seems not to require that sa_len is set correctly. but... */
    switch (af) {
    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        break;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        break;
    }
}

void
dns_util_sacopy(struct sockaddr *dst, struct sockaddr *src)
{
    switch (src->sa_family) {
    case AF_INET:
        memcpy(dst, src, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        memcpy(dst, src, sizeof(struct sockaddr_in6));
        break;
    }
}

void
dns_util_sasetport(struct sockaddr *sa, uint16_t port)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    switch (sa->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        sin->sin_port = htons(port);
        break;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        sin6->sin6_port = htons(port);
        break;
    }
}

int
dns_util_sagetport(struct sockaddr *sa)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    switch (sa->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        return ntohs(sin->sin_port);

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        return ntohs(sin6->sin6_port);
    }

    return -1;
}

int
dns_util_sacmp(struct sockaddr *a, struct sockaddr *b)
{
    switch (a->sa_family) {
    case AF_INET:
        return util_compare_sin((struct sockaddr_in *) a, (struct sockaddr_in *) b);
    case AF_INET6:
        return util_compare_sin6((struct sockaddr_in6 *) a, (struct sockaddr_in6 *) b);
    }

    return -1;
}

int
dns_util_sacmp_wop(struct sockaddr *a, struct sockaddr *b)
{
    switch (a->sa_family) {
    case AF_INET:
        return util_compare_sin_wop((struct sockaddr_in *) a, (struct sockaddr_in *) b);
    case AF_INET6:
        return util_compare_sin6_wop((struct sockaddr_in6 *) a, (struct sockaddr_in6 *) b);
    }

    return -1;
}

int
dns_util_str2sa(struct sockaddr *sa, char *addr, uint16_t port)
{
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(addr, NULL, &hints, &res) != 0) {
        plog(LOG_ERR, "%s: getaddrinfo() failed", MODULE);
        return -1;
    }

    memcpy(sa, res->ai_addr, SALEN(res->ai_addr));
    freeaddrinfo(res);

    dns_util_sasetport(sa, port);

    return 0;
}

int
dns_util_sa2str(char *buf, int bufmax, struct sockaddr *sa)
{
    int port;
    char host[256];

    if (dns_util_sa2str_wop(host, sizeof(host), sa) < 0)
        return -1;

    if ((port = dns_util_sagetport(sa)) == 0)
        STRLCPY(buf, host, bufmax);
    else {
        if (sa->sa_family == AF_INET)
            snprintf(buf, bufmax, "%s:%d", host, port);
        if (sa->sa_family == AF_INET6)
            snprintf(buf, bufmax, "[%s]:%d", host, port);
    }

    return 0;
}

int
dns_util_sa2str_wop(char *buf, int bufmax, struct sockaddr *sa)
{
    if (getnameinfo(sa, SALEN(sa), buf, bufmax, NULL, 0, NI_NUMERICHOST) != 0) {
        plog_error(LOG_ERR, MODULE, "getnameinfo() failed");
        return -1;
    }

    return 0;
}

int
dns_util_socket(int pf, int type, int port)
{
    struct sockaddr_storage ss;

    dns_util_sainit((SA *) &ss, pf);
    dns_util_sasetport((SA *) &ss, port);

    return dns_util_socket_sa(pf, type, (SA *) &ss);
}

int
dns_util_socket_sa(int pf, int type, struct sockaddr *sa)
{
    int s, on = 1;

    if ((s = socket(pf, type, 0)) < 0) {
        plog_error(LOG_ERR, MODULE, "socket() failed");
        return -1;
    }

    if (pf == PF_INET6) {
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
            plog_error(LOG_ERR, MODULE, "setsockopt(IPV6_V6ONLY) failed");
            return -1;
        }
    }

    if (type == SOCK_STREAM) {
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            plog_error(LOG_ERR, MODULE, "setsockopt(SO_REUSEADDR) failed");
            return -1;
        }
    }

    if (bind(s, (SA *) sa, SALEN(sa)) < 0) {
        plog_error(LOG_ERR, MODULE, "bind() failed");
        return -1;
    }

    return s;
}

int
dns_util_select(int s, int timeout)
{
    int r;
    fd_set fds;
    struct timeval tv, *timo;

    FD_ZERO(&fds);
    FD_SET(s, &fds);

    tv.tv_sec = timeout;
    tv.tv_usec = 0;

again:
    timo = (timeout > 0) ? &tv : NULL;
    if ((r = select(s + 1, &fds, NULL, NULL, timo)) < 0) {
        if (errno == EAGAIN || errno == EINTR)
            goto again;

        plog_error(LOG_ERR, MODULE, "select() failed");
    }

    if (r > 0 && FD_ISSET(s, &fds))
        return 0;

    return -1;
}

int
dns_util_sendf(int s, char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    return send(s, msg, strlen(msg), 0);
}

int
dns_util_getuid(char *user)
{
    char buf[256];
    struct passwd pwd, *r;

    if (getpwnam_r(user, &pwd, buf, sizeof(buf), &r) < 0)
        return -1;

    return (r != NULL) ? r->pw_uid : -1;
}

int
dns_util_getgid(char *group)
{
    char buf[256];
    struct group grp, *r;

    if (getgrnam_r(group, &grp, buf, sizeof(buf), &r) < 0)
        return -1;

    return (r != NULL) ? r->gr_gid : -1;
}

int
dns_util_setugid(int uid, int gid)
{
    if (gid > 0) {
        if (setgid(gid) < 0) {
            plog_error(LOG_ERR, NULL, "setgid() failed");
            return -1;
        }
    }

    if (uid > 0) {
        if (setuid(uid) < 0) {
            plog_error(LOG_ERR, NULL, "setuid() failed");
            return -1;
        }
    }

    return 0;
}

int
dns_util_fexist(char *filename)
{
    struct stat sb;

    return (stat(filename, &sb) < 0) ? 0 : 1;
}

int
dns_util_spawn(char *cmd, char **argv, int stdout)
{
    int status;
    pid_t pchild, pgchild, rpid;

    if ((pchild = fork()) < 0) {
        plog_error(LOG_ERR, MODULE, "fork() failed");
        return -1;
    }

    if (pchild == 0) {
        /*
         * child process:
         * don't call log functions because these are not async-signal-safe.
         */
        if (stdout > 0 && dup2(stdout, 1) < 0)
            exit(EXIT_FAILURE);
        if ((pgchild = fork()) < 0)
            exit(EXIT_FAILURE);

        if (pgchild == 0) {
            if (execvp(cmd, argv) < 0) {
                plog_error(LOG_ERR, MODULE, "execvp() faild: %s", cmd);
                exit(EXIT_FAILURE);
            }
        }

        exit(EXIT_SUCCESS);
    } else {
        /* parent process */
        if ((rpid = waitpid(pchild, &status, 0)) < 0) {
            plog_error(LOG_ERR, MODULE, "%s: waitpid() faild");
            return -1;
        } else if (rpid == pchild) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                plog(LOG_ERR, "%s: exec() faild: %s", MODULE, cmd);
                return -1;
            }
        }
    }

    return 0;
}

int
dns_util_is_greater_serial(uint32_t serial, uint32_t serial_orig)
{
    /*
     * RFC1982 3.2. says:
     * s1 is said to be greater than s2 if, and only if,
     * s1 is not equal to s2, and
     *
     * (i1 < i2 and i2 - i1 > 2^(SERIAL_BITS - 1)) or
     * (i1 > i2 and i1 - i2 < 2^(SERIAL_BITS - 1)
     */

    /* 2^(32 -1) = 2147483648 */
    if ((serial < serial_orig && serial_orig - serial > 2147483648U) ||
        (serial > serial_orig && serial - serial_orig < 2147483648U)) {
        return 1;
    }

    return 0;  /* less, equal or undefined */
}

unsigned
dns_util_hash_initial(void)
{
    return FNV1_INITIAL_BASIS;
}

unsigned
dns_util_hash_calc(void *buf, int len, unsigned basis)
{
    int i;
    unsigned hash = basis;

    /* FNV-1a hash */
    for (i = 0; i < len; i++) {
        hash ^= *((unsigned char *) buf);
        hash *= 16777619;
        buf = ((unsigned char *) buf) + 1;
    }

    return hash;
}

unsigned
dns_util_euler_primish(unsigned n)
{
    unsigned i, value;

    for (i = 0; i < 1000; i++) {
        value = (i * i) + i + 41;
        if (value > n)
            return value;
    }

    return n;
}

static int
util_compare_sin(struct sockaddr_in *a, struct sockaddr_in *b)
{
    int r;

    if ((r = util_compare_sin_wop(a, b)) < 0)
        return r;
    if ((r = a->sin_port - b->sin_port) != 0)
        return r;

    return 0;
}

static int
util_compare_sin_wop(struct sockaddr_in *a, struct sockaddr_in *b)
{
    return memcmp(&a->sin_addr, &b->sin_addr, sizeof(a->sin_addr));
}

static int
util_compare_sin6(struct sockaddr_in6 *a, struct sockaddr_in6 *b)
{
    int r;

    if ((r = util_compare_sin6_wop(a, b)) < 0)
        return r;
    if ((r = a->sin6_port - b->sin6_port) != 0)
        return r;

    return 0;
}

static int
util_compare_sin6_wop(struct sockaddr_in6 *a, struct sockaddr_in6 *b)
{
    return memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr));
}
