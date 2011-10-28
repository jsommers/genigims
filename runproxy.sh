#!/bin/bash -x

python -O capd_proxy.py -b capture-daemon/data -d eth0 -c ./capture-daemon/capture-daemon

