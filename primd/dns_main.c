/*
 * Copyright (c) 2010-2012 Satoshi Ebisawa. All rights reserved.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dns.h"
#include "dns_cache.h"
#include "dns_config.h"
#include "dns_control.h"
#include "dns_engine.h"
#include "dns_notify.h"
#include "dns_sock.h"
#include "dns_session.h"
#include "dns_timer.h"

#define MODULE "main"

static void main_arginit(char *argv0);
static void main_args(int argc, char *argv[]);
static void main_usage(void);
static void main_version(void);
static void main_basedir(char *buf, int bufmax, char *argv0);
static void main_confdir(char *confdir, int confdir_max, char *confpath);
static int main_realargv0(char *argv0, char *real);
static int main_findconf(char *basedir);
static int main_init(void);
static int main_make_pidfile(void);
static int main_loop(void);
static void main_init_signal(void);
static void main_signal_handler(int signum);
static void main_signal_proc(void);
static void main_sighup_proc(void);
static void main_sigterm_proc(void);

dns_opts_t Options;

char ConfPath[PATH_MAX];
char ConfDir[PATH_MAX];

static char *ConfNames[] = {
    "etc/primdns/primd.conf",
    "etc/primd/primd.conf",
    "etc/primd.conf",
};

static struct {
    int sig_no;
    void (*sig_func)(void);
} SignalTable[] = {
    { SIGHUP,   main_sighup_proc  },
    { SIGINT,   main_sigterm_proc },
    { SIGTERM,  main_sigterm_proc },
    { SIGPIPE,  NULL              },
};

static uint32_t SignalReceived;

int
main(int argc, char *argv[])
{
    main_arginit(argv[0]);
    main_args(argc, argv);
    main_confdir(ConfDir, sizeof(ConfDir), ConfPath);
    main_init_signal();

    plog(LOG_DEBUG, "%s: confdir = %s", __func__, ConfDir);

    if (!Options.opt_foreground) {
        plog_setflag(DNS_LOG_FLAG_SYSLOG);
        if (daemon(0, 0) < 0) {
            plog_error(LOG_ERR, MODULE, "daemon() failed");
            return EXIT_FAILURE;
        }
    }

    if (dns_config_update(Options.opt_config) < 0)
        return EXIT_FAILURE;

    if (main_init() < 0)
        return EXIT_FAILURE;
    if (main_make_pidfile() < 0)
        return EXIT_FAILURE;
    if (dns_util_setugid(Options.opt_user, Options.opt_group) < 0)
        return EXIT_FAILURE;

    if (dns_sock_start_thread() < 0)
        return EXIT_FAILURE;
    if (dns_control_start_thread() < 0)
        return EXIT_FAILURE;
    if (dns_session_start_thread(Options.opt_threads) < 0)
        return EXIT_FAILURE;

    plog(LOG_INFO, "%s started", PROGNAME);
    dns_config_notify_all_engines();
    dns_notify_all_slaves();
    main_loop();

    return EXIT_SUCCESS;
}

static void
main_arginit(char *argv0)
{
    char basedir[PATH_MAX];

    main_basedir(basedir, sizeof(basedir), argv0);

    if (main_findconf(basedir) < 0)
        main_findconf("");

    Options.opt_config = ConfPath;
    Options.opt_ipv4_enable = 1;
    Options.opt_ipv6_enable = 1;
    Options.opt_cache_size = DNS_DEFAULT_CACHE_SIZE;
    Options.opt_threads = DNS_DEFAULT_WORKER_THREADS;
    Options.opt_port = DNS_PORT;
}

static void
main_args(int argc, char *argv[])
{
    int i;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
            case '4':
                Options.opt_ipv6_enable = 0;
                break;
            case '6':
                Options.opt_ipv4_enable = 0;
                break;
            case 'b':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing address\n");
                    exit(EXIT_FAILURE);
                }

                if (dns_util_str2sa((SA *) &Options.opt_baddr, argv[i], 0) < 0) {
                    fprintf(stderr, "error: invalid address: %s\n", argv[i]);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'c':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing config file name\n");
                    exit(EXIT_FAILURE);
                }
                STRLCPY(ConfPath, argv[i], sizeof(ConfPath));
                Options.opt_config = ConfPath;
                break;
            case 'd':
                if (Options.opt_debug)
                    plog_setflag(DNS_LOG_FLAG_TRACE);
                else {
                    Options.opt_debug = 1;
                    plog_setmask(LOG_DEBUG);
                }
                break;
            case 'f':
                Options.opt_foreground = 1;
                break;
            case 'g':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing group name\n");
                    exit(EXIT_FAILURE);
                }

                if ((Options.opt_group = dns_util_getgid(argv[i])) < 0) {
                    fprintf(stderr, "error: invalid group name\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing port number\n");
                    exit(EXIT_FAILURE);
                }
                Options.opt_port = atoi(argv[i]);
                break;
            case 'q':
                plog_setflag(DNS_LOG_FLAG_QUERY);
                break;
            case 's':
                dns_control_show_status();
                exit(EXIT_SUCCESS);
                break;
            case 't':
                /* XXX chroot dir */
                break;
            case 'u':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing user name\n");
                    exit(EXIT_FAILURE);
                }

                if ((Options.opt_user = dns_util_getuid(argv[i])) < 0) {
                    fprintf(stderr, "error: invalid user name\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'v':
                main_version();
                break;

            case 'M':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing cache pool size\n");
                    exit(EXIT_FAILURE);
                }
                Options.opt_cache_size = atoi(argv[i]);
                break;
            case 'T':
                if (argv[++i] == NULL) {
                    fprintf(stderr, "error: missing number of threads\n");
                    exit(EXIT_FAILURE);
                }
                Options.opt_threads = atoi(argv[i]);
                break;
            case '-':
                break;   /* ignore */
            case 'h':
                main_usage();
                break;
            default:
                fprintf(stderr, "error: invalid option: %s\n", argv[i]);
                main_usage();
                break;
            }
        }
    }
}

static void
main_usage(void)
{
    puts("usage: primd [options..]");
    puts("options:  -4           ipv4 only");
    puts("          -6           ipv6 only");
    puts("          -b [addr]    listen on addr");
    puts("          -c [path]    config file path");
    puts("          -d           enable debug log");
    puts("          -f           foreground mode");
    puts("          -g [group]   setgid");
    puts("          -p [port]    listen on port");
    puts("          -q           enable query log");
    puts("          -u [user]    setuid");
    puts("          -v           show version");
    puts("          -M [size]    cache pool size in MB");
    puts("          -T [num]     number of worker threads");

    exit(EXIT_FAILURE);
}

static void
main_version(void)
{
    puts(PACKAGE_STRING);
    exit(EXIT_FAILURE);
}

static void
main_basedir(char *buf, int bufmax, char *argv0)
{
    char *p, rargv0[PATH_MAX];

    buf[0] = 0;

    if (main_realargv0(argv0, rargv0) < 0)
        return;

    if ((p = strrchr(rargv0, '/')) != NULL) {
        *p = 0;
        if ((p = strrchr(rargv0, '/')) != NULL)
            *p = 0;
    }

    STRLCPY(buf, rargv0, bufmax);
}

static void
main_confdir(char *confdir, int confdir_max, char *confpath)
{
    char *p;

    STRLCPY(confdir, confpath, confdir_max);

    if ((p = strrchr(ConfDir, '/')) != NULL)
        *p = 0;
}

static int
main_realargv0(char *argv0, char *real)
{
    char *p, *next, *path, buf[256];

    if (strchr(argv0, '/') != NULL) {
        if (realpath(argv0, real) == NULL) {
            plog_error(LOG_ERR, MODULE, "realpath() failed: %s", argv0);
            return -1;
        }
        return 0;
    } else {
        if ((path = getenv("PATH")) != NULL) {
            STRLCPY(buf, path, sizeof(buf));
            p = buf;

            for (; p != NULL; p = next) {
                if ((next = strchr(p, ':')) != NULL) {
                    *next = 0;
                    next++;
                }

                snprintf(real, PATH_MAX, "%s/%s", p, argv0);
                if (dns_util_fexist(real))
                    return 0;
            }
        }
    }

    return -1;
}

static int
main_findconf(char *basedir)
{
    int i;
    char buf[PATH_MAX], rbuf[PATH_MAX];

    for (i = 0; i < NELEMS(ConfNames); i++) {
        snprintf(buf, sizeof(buf), "%s/%s", basedir, ConfNames[i]);
        if (realpath(buf, rbuf) == NULL)
            continue;
        if (dns_util_fexist(rbuf)) {
            STRLCPY(ConfPath, rbuf, sizeof(ConfPath));
            return 0;
        }
    }

    return -1;
}

static int
main_init(void)
{
    if (dns_cache_init(Options.opt_cache_size * 1024, Options.opt_threads + DNS_SOCK_THREADS + 1) < 0)
        return -1;

    if (dns_sock_init() < 0)
        return -1;
    if (dns_control_init() < 0)
        return -1;
    if (dns_session_init() < 0)
        return -1;

    return 0;
}

static int
main_make_pidfile(void)
{
    char buf[64];
    int fd, uid, gid, len;

    if ((fd = open(PATH_PID, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
        plog_error(LOG_WARNING, MODULE, "can't open pid file");
        return 0;
    }

    snprintf(buf, sizeof(buf), "%d", getpid());
    len = strlen(buf);

    if (write(fd, buf, len) != len) {
        plog_error(LOG_ERR, MODULE, "can't write pid file");
        close(fd);
        return -1;
    }

    uid = (Options.opt_user > 0) ? Options.opt_user : -1;
    gid = (Options.opt_group > 0) ? Options.opt_group : -1;

    if (fchown(fd, uid, gid) < 0) {
        plog_error(LOG_ERR, MODULE, "fchown() failed");
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}

static int
main_loop(void)
{
    for (;;) {
        dns_sock_proc();
        dns_sock_timer_proc();  /* XXX */
        dns_timer_execute();
        main_signal_proc();
    }

    return 0;
}

static void
main_init_signal(void)
{
    int i;

    for (i = 0; i < NELEMS(SignalTable); i++) {
        if (SignalTable[i].sig_no >= 32)
            plog(LOG_CRIT, "XXX signal number must be less than 32");

        if (SignalTable[i].sig_func == NULL)
            signal(SignalTable[i].sig_no, SIG_IGN);
        else
            signal(SignalTable[i].sig_no, main_signal_handler);
    }
}

static void
main_signal_handler(int signum)
{
    SignalReceived |= (1 << signum);
}

static void
main_signal_proc(void)
{
    int i;
    uint32_t sigflag;

    for (i = 0; i < NELEMS(SignalTable); i++) {
        sigflag = 1 << SignalTable[i].sig_no;
        if (SignalReceived & sigflag) {
            SignalReceived &= ~sigflag;
            SignalTable[i].sig_func();
        }
    }
}

static void
main_sighup_proc(void)
{
    plog(LOG_INFO, "SIGHUP received");
    dns_sock_timer_cancel(DNS_SOCK_TIMER_NOTIFY);
    dns_config_update(Options.opt_config);
    dns_cache_invalidate(NULL);

    plog(LOG_INFO, "reconfigured");
    dns_notify_all_slaves();
}

static void
main_sigterm_proc(void)
{
    plog(LOG_INFO, "SIGTERM received. shutting down...");
    dns_config_shutdown();
    unlink(PATH_PID);
    exit(EXIT_SUCCESS);
}
