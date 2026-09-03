#!/usr/bin/env bash

IP=$(hostname -I | awk '{print $1}')
PORT=5607
set -x
python3 -m http.server ${PORT} --bind ${IP} -d crl
