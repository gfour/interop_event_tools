#!/usr/bin/env bash

export TOKEN_CLIENT_ID=eudiw_login
export TOKEN_CLIENT_SECRET=secret
export ISSUER_AUTHORIZATIONSERVER_INTROSPECTION=https://snf-74864.ok-kno.grnetcloud.net/oidc/introspect/
export ISSUER_AUTHORIZATIONSERVER_USERINFO=https://snf-74864.ok-kno.grnetcloud.net/oidc/userinfo/
export ISSUER_PID_SD_JWT_VC_DEFERRED=false
export DEBUG=false

JQ=${JQ:-"jq -C"}

function hit() {
    echo $1:
    curl -k -s $1 | ${JQ}
    echo
}

if [ "$1" == "" ]; then
    echo "Usage: issue-sd-jwt-vc-pid.sh ACCESS_TOKEN"
    exit
else
    ACCESS_TOKEN="$1"
    echo ACCESS_TOKEN: ${ACCESS_TOKEN}
fi

if [ "$DEBUG" == "true" ]; then
    echo "== GET USERINFO (IDP) =="
    curl -k -s ${ISSUER_AUTHORIZATIONSERVER_USERINFO} \
	 -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" | ${JQ}
    echo

    echo "== INTROSPECT TOKEN (IDP) =="
    curl -k -s -XPOST ${ISSUER_AUTHORIZATIONSERVER_INTROSPECTION} -d "token=${ACCESS_TOKEN}" \
	 -H "Content-Type: application/x-www-form-urlencoded" -u "${TOKEN_CLIENT_ID}:${TOKEN_CLIENT_SECRET}" | ${JQ}
    echo
fi

ISSUER="http://snf-74864.ok-kno.grnetcloud.net:8080"

echo "== CREDENTIAL ISSUER METADATA =="
hit ${ISSUER}/.well-known/openid-credential-issuer
echo

echo "== GET USERINFO FROM ISSUER =="
curl -k -s ${ISSUER}/wallet/credentialEndpoint \
     -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" | ${JQ}
echo

echo "== PID REQUEST (SD-JWT-VC) [test invocation, for c_nonce] =="
PID_SD_JWT_VC=$(mktemp)
curl -k -s -XPOST ${ISSUER}/wallet/credentialEndpoint \
    -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    --data '{
  "format": "vc+sd-jwt",
  "vct": "eu.europa.ec.eudiw.pid.1",
  "proof": {
    "proof_type": "jwt",
    "jwt": ""
  }
}' --output ${PID_SD_JWT_VC}
cat ${PID_SD_JWT_VC} | ${JQ}
C_NONCE=$(cat ${PID_SD_JWT_VC} | jq -r .c_nonce)
echo "C_NONCE=${C_NONCE}"
echo

echo "== PID REQUEST (SD-JWT-VC) [proper invocation] =="
PROOF_JWT=$(./create_proof_jwt.py ${C_NONCE})
PID_SD_JWT_VC=$(mktemp)
curl -k -s -XPOST ${ISSUER}/wallet/credentialEndpoint \
    -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    --data '{
  "format": "vc+sd-jwt",
  "vct": "eu.europa.ec.eudiw.pid.1",
  "proof": {
    "proof_type": "jwt",
    "jwt": "'${PROOF_JWT}'"
  }
}' --output ${PID_SD_JWT_VC}
cat ${PID_SD_JWT_VC} | ${JQ}
C_NONCE=$(cat ${PID_SD_JWT_VC} | jq -r .c_nonce)
echo "C_NONCE=${C_NONCE}"

if [ "${ISSUER_PID_SD_JWT_VC_DEFERRED}" == "true" ]; then
  TRANSACTION_ID=$(cat ${PID_SD_JWT_VC} | jq -r .transaction_id)
  echo "Deferred, TRANSACTION_ID=${TRANSACTION_ID}"
else
  CREDENTIAL=$(cat ${PID_SD_JWT_VC} | jq -r .credential)
  # echo "Credential: ${CREDENTIAL}"
  echo Decoded credential:
  echo ${CREDENTIAL} | cut -d '.' -f 2 | base64 --decode | ${JQ}
fi
echo

if [ "${ISSUER_PID_SD_JWT_VC_DEFERRED}" == "true" ]; then
  echo "== DEFERRED REQUEST =="
  curl -k -s -XPOST ${ISSUER}/wallet/deferredEndpoint \
      -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      --data '{"transaction_id" : "'${TRANSACTION_ID}'"}' --output ${PID_SD_JWT_VC}
  cat ${PID_SD_JWT_VC} | ${JQ}
  CREDENTIAL=$(cat ${PID_SD_JWT_VC} | jq -r .credential)
  echo Decoded credential:
  echo ${CREDENTIAL} | cut -d '.' -f 2 | base64 --decode | ${JQ}
fi
echo
