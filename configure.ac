#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([primdns], [0.7])
AC_CONFIG_SRCDIR([primd/dns.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign no-installinfo no-installman])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h syslog.h unistd.h])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([atexit dup2 gettimeofday localtime_r memset munmap select socket strcasecmp strchr strerror strpbrk strtoul])

# Checks for OS-specific features.
AC_CHECK_FUNC(kqueue, [AC_DEFINE([HAVE_KQUEUE], [1], [Define to 1 if you have kqueue features.])])
AC_CHECK_FUNC(epoll_create, [AC_DEFINE([HAVE_EPOLL], [1], [Define to 1 if you have epoll features.])])

# Generate files.
AC_CONFIG_FILES([Makefile
                 primd/Makefile
                 scripts/Makefile
                 etc/Makefile])
AC_OUTPUT
