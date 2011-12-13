#!/bin/bash

source ./settings.sh

if [ -f update/nupkey.seq ]; then
  rm update/nupkey.seq -f
fi

previous_state=0
last_registration_time=0
while true; do
  curr_time=`date +%s`
  ./node_state.sh
  curr_state=$?
  cd update
  if [[ ($curr_state != 0) && ($previous_state == 0) ]]; then
    echo Removing record
    java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
      -s $UPDATE_SERVER del subdomain=$SLIVER_SUBDOMAIN type=A data=$SLIVER_IP
    java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
      -s $UPDATE_SERVER del subdomain=$SLIVER_SUBDOMAIN2 type=A data=$SLIVER_IP
    java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
      -s $UPDATE_SERVER del subdomain=$SLIVER_SUBDOMAIN3 type=A data=$SLIVER_IP

  elif [[ $curr_state == 0 ]]; then
    reg_success=-1;
    cut_off=$((last_registration_time + INTER_REGISTRATION_PERIOD))
    if [[ $previous_state != 0 ]]; then
      echo Service online, adding record
      java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
        -s $UPDATE_SERVER add donar-ttl=$EXPIRY_PERIOD \
        subdomain=$SLIVER_SUBDOMAIN type=A ttl=$RECORD_TTL data=$SLIVER_IP
      java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
        -s $UPDATE_SERVER add donar-ttl=$EXPIRY_PERIOD \
        subdomain=$SLIVER_SUBDOMAIN2 type=A ttl=$RECORD_TTL data=$SLIVER_IP
      java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
        -s $UPDATE_SERVER add donar-ttl=$EXPIRY_PERIOD \
        subdomain=$SLIVER_SUBDOMAIN3 type=A ttl=$RECORD_TTL data=$SLIVER_IP

      reg_success=$?
    elif [ $curr_time -gt $cut_off ] 
    then
      echo Timer expired, adding record
      java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
        -s $UPDATE_SERVER add donar-ttl=$EXPIRY_PERIOD \
        subdomain=$SLIVER_SUBDOMAIN type=A ttl=$RECORD_TTL data=$SLIVER_IP
      java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
        -s $UPDATE_SERVER add donar-ttl=$EXPIRY_PERIOD \
        subdomain=$SLIVER_SUBDOMAIN2 type=A ttl=$RECORD_TTL data=$SLIVER_IP
      java -cp .:`ls *.jar | tr '\n', ':'` donar.update.client.UpdateClient \
        -s $UPDATE_SERVER add donar-ttl=$EXPIRY_PERIOD \
        subdomain=$SLIVER_SUBDOMAIN3 type=A ttl=$RECORD_TTL data=$SLIVER_IP
      reg_success=$?
    fi
    
    if [[ $reg_success == 0 ]]; then
      last_registration_time=`date +%s`
    fi
  fi
  cd ..
  sleep $TEST_LIVENESS_PERIOD
done
