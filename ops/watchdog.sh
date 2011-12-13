#!/bin/sh
#
# A watchdog that checks if the mserver process is still running
# and restarts it if it is gone.

HOME_DIR=/home/mpisws_broadband
ETH=$(/sbin/ifconfig | grep eth0: | cut -d" " -f1)

cd $HOME_DIR

if ! ps xa | grep gserver | grep -v grep >/dev/null; then
    killall -q gserver
    echo "Restarting gserver"
    TS=`date +%s`
    sudo nohup ./gserver -i $ETH -d logs -s scripts/protocols.spec -scriptdir scripts >> logs/gserver-${TS}.log 2>&1 &
    exit 0
fi

