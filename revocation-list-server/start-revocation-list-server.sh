#!/usr/bin/env bash

if [[ -f ".config.ip" ]]; then
    IP=$(cat .config.ip)
else
    IP=$(hostname -I | awk '{print $1}')
fi

PORT=5607
set -x
python3 -m http.server ${PORT} --bind ${IP} -d crl
