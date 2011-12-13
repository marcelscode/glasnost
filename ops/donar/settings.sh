#!/bin/bash

# this scritp runs on multiple mlab nodes, so use this hack to get the IP addr
IP=`/sbin/ifconfig | grep inet | awk -F: '{print $2}' | awk '{print $1}'`

##### Variables that need to be set ######

INTER_REGISTRATION_PERIOD=$((60 * 5)) # How often to re-register
TEST_LIVENESS_PERIOD=5                # How frequently to test liveness
SLIVER_IP="$IP"     # IP of this sliver 
SLIVER_SUBDOMAIN="glasnost.mpi-sws" # subdomain, eg *.donar.measurment-lab.org

EXPIRY_PERIOD=$((INTER_REGISTRATION_PERIOD * 2 + 60))
RECORD_TTL=$((INTER_REGISTRATION_PERIOD))

UPDATE_SERVER="ns1.mlab.donardns.net"

##########################################

