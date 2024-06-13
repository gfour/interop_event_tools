#!/usr/bin/env bash

export TOKEN_CLIENT_ID=eudiw_login
export TOKEN_CLIENT_SECRET=secret
export ISSUER_AUTHORIZATIONSERVER_INTROSPECTION=https://snf-74864.ok-kno.grnetcloud.net/oidc/introspect/
export ISSUER_AUTHORIZATIONSERVER_USERINFO=https://snf-74864.ok-kno.grnetcloud.net/oidc/userinfo/
export DEBUG=false

JQ=${JQ:-"jq -C"}

function hit() {
    echo $1:
    curl -s $1 | ${JQ}
    echo
}

if [ "$1" == "" ]; then
    echo "Usage: issue-mdoc-pid-and-mdl.sh ACCESS_TOKEN"
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
curl -s ${ISSUER}/wallet/credentialEndpoint \
     -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" | ${JQ}
echo

echo "== PID REQUEST (mso-mdoc) [test invocation, for c_nonce] =="
MSD_MDOC_OUT=$(mktemp)

curl -s -XPOST ${ISSUER}/wallet/credentialEndpoint \
    -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    --data '{
  "format": "mso_mdoc",
  "doctype": "eu.europa.ec.eudiw.pid.1",
  "proof": {
    "proof_type": "jwt",
    "jwt": "'${PROOF_JWT}'"
  }
}' --output ${MSD_MDOC_OUT}
cat ${MSD_MDOC_OUT} | ${JQ}
C_NONCE=$(cat ${MSD_MDOC_OUT} | jq -r .c_nonce)
echo "C_NONCE=${C_NONCE}"
echo

echo "== PID REQUEST (mso-mdoc) =="
PROOF_JWT=$(./create_proof_jwt.py ${C_NONCE})
MSD_MDOC_OUT=$(mktemp)

curl -s -XPOST ${ISSUER}/wallet/credentialEndpoint \
    -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    --data '{
  "format": "mso_mdoc",
  "doctype": "eu.europa.ec.eudiw.pid.1",
  "proof": {
    "proof_type": "jwt",
    "jwt": "'${PROOF_JWT}'"
  }
}' --output ${MSD_MDOC_OUT}
cat ${MSD_MDOC_OUT} | ${JQ}
C_NONCE=$(cat ${MSD_MDOC_OUT} | jq -r .c_nonce)
echo "C_NONCE=${C_NONCE}"
echo

echo "== mDL REQUEST (mso_mdoc/mdl) =="
PROOF_JWT=$(./create_proof_jwt.py ${C_NONCE})

curl -s -XPOST ${ISSUER}/wallet/credentialEndpoint \
    -H "Content-type: application/json" -H "Accept: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    --data '{
  "format": "mso_mdoc",
  "doctype": "org.iso.18013.5.1.mDL",
  "claims": {
      "org.iso.18013.5.1": {
          "given_name": {},
          "family_name": {},
          "birth_date": {}
      }
  },
  "proof": {
    "proof_type": "jwt",
    "jwt": "'${PROOF_JWT}'"
  }
}' | ${JQ}
echo
