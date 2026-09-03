#!/usr/bin/env bash

mkdir -p crl
openssl ca -gencrl -keyfile ../grnet.key -cert ../root-ca-grnet.pem -out crl/crl.pem -config crl_openssl.conf
