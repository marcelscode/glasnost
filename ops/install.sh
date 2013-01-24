

case "$1" in
    start)
        sh /home/mpisws_broadband/watchdog.sh
	;;

    stop)
  	sudo killall -q gserver
	;;

    restart)
  	sudo killall -q gserver
	sh /home/mpisws_broadband/watchdog.sh
	;;

    uninstall)
        if ! grep watchdog /etc/crontab >/dev/null; then
	    sudo grep -v "watchdog.sh" /etc/crontab > /etc/crontab.new
	    sudo mv /etc/crontab.new /etc/crontab
	fi
	sudo /etc/init.d/crond stop
	sudo rm -f /etc/rc.d/rc3.d/S60crond
	killall -q gserver rsyncd
	;;

  *)
  	if ! grep watchdog /etc/crontab >/dev/null; then
	  	sudo echo "*/2 * * * * root sh /home/mpisws_broadband/watchdog.sh" >> /etc/crontab
		sudo crontab /etc/crontab
	fi
	sudo /etc/init.d/crond restart
	sudo sh /home/mpisws_broadband/watchdog.sh

	# On PlanetLab crond is not started on startup
	if [ ! -h  /etc/rc.d/rc3.d/S60crond ]; then
	    sudo ln -s /etc/init.d/crond /etc/rc.d/rc3.d/S60crond
	fi

	# Fire up rsync daemon
	if ! ps xa | grep rsync | grep -v grep >/dev/null; then
	    echo "Restarting rsyncd"
	    rsync --daemon --config=/home/mpisws_broadband/rsyncd.conf --port 7999
	fi

	;;
esac
