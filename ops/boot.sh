#!/bin/bash

# Script for PlanetLab / M-Lab that gets executed at boot time
# (if added to the database by PL-central)

set -ex
cd /home/mpisws_broadband

if [ -x ./install.sh ]; then
   ./install.sh
   echo "Started."
fi
