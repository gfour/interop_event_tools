#!/usr/bin/env bash

IP=$(hostname -I | awk '{print $1}')
set -x
python3 -m http.server 8082 --bind ${IP} -d crl
