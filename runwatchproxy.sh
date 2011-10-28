#!/bin/bash -x

if ps aux | grep '[w]atch_proxy.py'
then
       echo 'Watchdog Running.'
else 
       python -O watch_proxy.py -b capture-daemon/data -d eth0 -c ./capture-daemon/capture-daemon
fi
