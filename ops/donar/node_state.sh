#!/bin/bash

##### MODIFY THIS SCRIPT! #####

# This script should perform whatever checks are necessary to determine
# the liveness of your node. It should exit 0 if the node is alive, 
# non-zero if the node is dead.

# this is the same script as in watchdog.sh
if ! ps xa | grep gserver | grep -v grep >/dev/null; then
    exit 1
fi

exit 0