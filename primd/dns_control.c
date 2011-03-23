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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <pthread.h>
#include "dns.h"
#include "dns_control.h"
#include "dns_data.h"
#include "dns_external.h"
#include "dns_session.h"

#define MODULE "control"

#define CONTROL_TIMEOUT   1

#define SUNSET(sun, path)                                           \
    do {                                                            \
        memset((sun), 0, sizeof(*(sun)));                           \
        (sun)->sun_family = AF_LOCAL;                               \
        STRLCPY((sun)->sun_path, (path), sizeof((sun)->sun_path));  \
    } while(0)

static void control_atexit(void);
static void *control_routine(void *param);
static int control_socket(char *path);
static int control_connect(char *path);
static int control_accept(int s);
static int control_receive(int s, int (*func)(int s, char *line));
static int control_check_line(char *buf, int len);
static int control_each_line(int s, char *buf, int len, int (*func)(int s, char *line));
static int control_parse_line(int s, char *line);
static int control_print_line(int s, char *line);
static int control_send(int s, char *msg);
static int control_command_stats(int s, char *sep, char *last);

static int ControlSocket;
static pthread_t ControlThread;

int
dns_control_init(void)
{
    int uid, gid;

    if ((ControlSocket = control_socket(PATH_CONTROL)) < 0) {
        plog(LOG_WARNING, "%s: can't open control socket", MODULE);
        return 0;
    }

    uid = (Options.opt_user > 0) ? Options.opt_user : -1;
    gid = (Options.opt_group > 0) ? Options.opt_group : -1;

    if (chown(PATH_CONTROL, uid, gid) < 0) {
        plog(LOG_ERR, "%s: chown() failed", MODULE);
        close(ControlSocket);
        return -1;
    }

    atexit(control_atexit);

    return 0;
}

int
dns_control_start_thread(void)
{
    if (ControlSocket < 0)
        return 0;

    if (pthread_create(&ControlThread, NULL, control_routine, NULL) < 0) {
        plog_error(LOG_ERR, MODULE, "pthread_create() failed");
        return -1;
    }

    return 0;
}

int
dns_control_show_status(void)
{
    int s;

    if ((s = control_connect(PATH_CONTROL)) < 0) {
        plog(LOG_ERR, "%s: can't connect to server", MODULE);
        return -1;
    }

    if (control_send(s, "STATS") < 0) {
        plog(LOG_ERR, "%s: send message failed", MODULE);
        close(s);
        return -1;
    }

    for (;;) {
        if (dns_util_select(s, CONTROL_TIMEOUT) < 0)
            break;
        if (control_receive(s, control_print_line) < 0)
            break;
    }

    close(s);

    return 0;
}

static void
control_atexit(void)
{
    unlink(PATH_CONTROL);
}

static void *
control_routine(void *param)
{
    dns_util_sigmaskall();

    for (;;) {
        dns_util_select(ControlSocket, -1);
        control_accept(ControlSocket);
    }

    return NULL;
}

static void *
control_conn_routine(void *param)
{
    int s;

    dns_util_sigmaskall();
    s = (intptr_t) param;

    for (;;) {
        if (dns_util_select(s, CONTROL_TIMEOUT) < 0)
            break;
        if (control_receive(s, control_parse_line) < 0)
            break;
    }

    close(s);

    return NULL;
}

static int
control_socket(char *path)
{
    int s;
    struct sockaddr_un sun;

    if ((s = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
        plog_error(LOG_ERR, MODULE, "socket() failed");
        return -1;
    }

    SUNSET(&sun, path);
    unlink(path);

    if (bind(s, (SA *) &sun, sizeof(sun)) < 0) {
        plog_error(LOG_ERR, MODULE, "bind() failed");
        close(s);
        return -1;
    }

    if (listen(s, 1) < 0) {
        plog_error(LOG_ERR, MODULE, "listen() failed");
        close(s);
        return -1;
    }

    return s;
}

static int
control_connect(char *path)
{
    int s;
    struct sockaddr_un sun;

    if ((s = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
        plog_error(LOG_ERR, MODULE, "socket() failed");
        return -1;
    }

    SUNSET(&sun, path);

    if (connect(s, (SA *) &sun, sizeof(sun)) < 0) {
        plog_error(LOG_ERR, MODULE, "connect() failed");
        close(s);
        return -1;
    }

    return s;
}

static int
control_accept(int s)
{
    int child_fd;
    pthread_t cthread;

    if ((child_fd = accept(s, NULL, NULL)) < 0) {
        plog_error(LOG_ERR, MODULE, "accept() failed");
        return -1;
    }

    if (pthread_create(&cthread, NULL, control_conn_routine, (void *) ((uintptr_t) child_fd)) < 0) {
        plog_error(LOG_ERR, MODULE, "pthread_create() failed");
        close(child_fd);
        return -1;
    }

    if (pthread_detach(cthread) < 0) {
        plog_error(LOG_ERR, MODULE, "pthread_detach() failed");
        pthread_cancel(cthread);
        close(child_fd);
        return -1;
    }

    return 0;
}

static int
control_receive(int s, int (*func)(int s, char *line))
{
    char buf[256];
    int len, oklen;

    if ((len = recv(s, buf, sizeof(buf), MSG_PEEK)) < 0) {
        plog_error(LOG_ERR, MODULE, "recv() failed");
        return -1;
    }

    if (len == 0) {   /* closed by peer */
        plog(LOG_DEBUG, "%s: socket closed by peer", MODULE);
        return -1;
    }

    if ((oklen = control_check_line(buf, len)) == 0)
        return 0;

    if ((len = recv(s, buf, oklen, 0)) != oklen) {
        plog_error(LOG_ERR, MODULE, "recv() failed");
        return -1;
    }

    if (control_each_line(s, buf, len, func) < 0)
        return -1;

    return 0;
}

static int
control_check_line(char *buf, int len)
{
    char *p, *done;

    done = buf;
    for (p = buf; *p != 0 && len > 0; p++, len--) {
        if (*p == '\n')
            done = p + 1;
    }

    return (done - buf);
}

static int
control_each_line(int s, char *buf, int len, int (*func)(int s, char *line))
{
    char *p, *done;

    done = buf;
    for (p = buf; *p != 0 && len > 0; p++, len--) {
        if (*p == '\n') {
            *p = 0;
            if (func(s, done) < 0)
                return -1;

            done = p + 1;
        }
    }

    return (done - buf);
}

static int
control_parse_line(int s, char *line)
{
    char *p, *last, *sep = " ";

    if ((p = strtok_r(line, sep, &last)) == NULL) {
        plog(LOG_ERR, "%s: strtok_r() failed", MODULE);
        return -1;
    }

    while (p != NULL) {
        if (strcmp(p, "STATS") == 0)
            return control_command_stats(s, sep, last);

        p = strtok_r(NULL, sep, &last);
    }

    return 0;
}

static int
control_print_line(int s, char *line)
{
    puts(line);

    return 0;
}

static int
control_send(int s, char *msg)
{
    char buf[256];

    STRLCPY(buf, msg, sizeof(buf));
    STRLCAT(buf, "\n", sizeof(buf));

    if (send(s, buf, strlen(buf), 0) < 0)
        return -1;

    return 0;
}

static int
control_command_stats(int s, char *sep, char *last)
{
    dns_session_printstats(s);
    dns_cache_printstats(s);
    dns_data_printstats(s);
    dns_external_printstats(s);

    /* close connection */
    return -1;
}
