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
#ifndef __DNS_UTIL_H__
#define __DNS_UTIL_H__
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FNV1_INITIAL_BASIS       2166136261U   /* 32bit FNV-1 hash */

#define ALIGN(p)                 (((((uintptr_t) (p)) + (sizeof(int) - 1)) / sizeof(int)) * sizeof(int))
#define NELEMS(array)            (sizeof(array) / sizeof(array[0]))

#define SA                       struct sockaddr
#define SALEN(sa)                                                       \
    ((((struct sockaddr *) (sa))->sa_family == AF_INET)                 \
     ? sizeof(struct sockaddr_in)                                       \
     : ((((struct sockaddr *) (sa))->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : 0))

#define STRLCPY(dst, src, max)   dns_util_strlcpy((dst), (src), (max))
#define STRLCAT(dst, src, max)   dns_util_strlcat((dst), (src), (max))
#define STRLOWER(str)            dns_util_strlower(str)

void dns_util_strlcpy(char *dst, char *src, int max);
void dns_util_strlcat(char *dst, char *src, int max);
void dns_util_strlower(char *str);
void dns_util_sigmaskall(void);
void dns_util_sainit(struct sockaddr *sa, int af);
void dns_util_sacopy(struct sockaddr *dst, struct sockaddr *src);
void dns_util_sasetport(struct sockaddr *sa, uint16_t port);
int dns_util_sagetport(struct sockaddr *sa);
int dns_util_sacmp(struct sockaddr *a, struct sockaddr *b);
int dns_util_sacmp_wop(struct sockaddr *a, struct sockaddr *b);
int dns_util_str2sa(struct sockaddr *sa, char *addr, uint16_t port);
int dns_util_sa2str(char *buf, int bufmax, struct sockaddr *sa);
int dns_util_sa2str_wop(char *buf, int bufmax, struct sockaddr *sa);
int dns_util_socket(int pf, int type, int port);
int dns_util_socket_sa(int pf, int type, struct sockaddr *sa);
int dns_util_select(int s, int timeout);
int dns_util_sendf(int s, char *fmt, ...);
int dns_util_getuid(char *user);
int dns_util_getgid(char *group);
int dns_util_setugid(int uid, int gid);
int dns_util_fexist(char *filename);
int dns_util_spawn(char *cmd, char **argv, int stdout);
unsigned dns_util_hash_initial(void);
unsigned dns_util_hash_calc(void *buf, int len, unsigned basis);
unsigned dns_util_euler_primish(unsigned n);

#endif
