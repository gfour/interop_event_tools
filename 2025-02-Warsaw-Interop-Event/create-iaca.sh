#!/usr/bin/env bash

echo Creating root certificate...
openssl ecparam -name prime256v1 -genkey -noout -out grnet.key

echo '[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca  # Section to use for cert extensions

[ req_distinguished_name ]
CN = PID Issuer CA - GR 01
O = GRNET
C = GR

[ v3_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage = critical, 1.3.130.2.0.0.1.7
crlDistributionPoints = URI:http://83.212.72.114:8082/crl.pem
keyUsage = critical, keyCertSign, cRLSign
' > eudi-cert.conf

openssl req -new -key grnet.key -x509 -nodes -days 365 \
    -subj "/CN=PID Issuer CA - GR 01/O=GRNET/C=GR" \
    -out root-ca-grnet.pem \
    -config eudi-cert.conf \
    -extensions v3_ca

step-cli certificate inspect root-ca-grnet.pem
