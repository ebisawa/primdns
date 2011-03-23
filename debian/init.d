#!/bin/sh

### BEGIN INIT INFO
# Provides:          primdns
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DNS contents server
# Description:
### END INIT INFO

set -e

NAME="primdns"
DESC="DNS contents server"

PROGNAME=primd
ETCDIR=/etc/primdns
PIDFILE=/var/run/primd.pid
DAEMON=/usr/sbin/$PROGNAME
DAEMON_OPTS="-c $ETCDIR/primd.conf"

test -x $DAEMON || exit 0

. /lib/lsb/init-functions

if [ -f /etc/default/$NAME ] ; then
    . /etc/default/$NAME
fi

export PATH=/sbin:/bin:/usr/sbin:/usr/bin

do_updatezone() {
  primdns-updatezone $ETCDIR
}

do_start() {
  do_updatezone
  start-stop-daemon --start --quiet --oknodo --pidfile $PIDFILE --exec $DAEMON -- $DAEMON_OPTS
  return $?
}

do_stop() {
  start-stop-daemon --stop --quiet --oknodo --pidfile $PIDFILE
  return $?
}

do_reload() {
  do_updatezone
  start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE
  return $?
}

case "$1" in
  start)
    log_daemon_msg "Starting $DESC" "$NAME"

    if do_start; then
      log_end_msg 0
    else
      log_end_msg 1
    fi
    ;;
  stop|force-stop)
    log_daemon_msg "Stopping $DESC" "$NAME"

    if do_stop; then
      log_end_msg 0
    else
      log_end_msg 1
    fi
    ;;
  restart|force-reload)
    log_daemon_msg "Restarting $DESC" "$NAME"

    do_stop
    if do_start; then
      log_end_msg 0
    else
      log_end_msg 1
    fi
    ;;
  reload)
    log_daemon_msg "Reloading $DESC configuration files" "$NAME"

    if do_reload; then
      log_end_msg 0
    else
      log_end_msg 1
    fi
    ;;
  status)
    status_of_proc -p $PIDFILE $DAEMON $PROGNAME
    ;;

  *)
    echo "Usage: /etc/init.d/$NAME {start|stop|force-stop|restart|reload|force-reload|status}" >&2
    exit 1
    ;;
esac

exit 0
