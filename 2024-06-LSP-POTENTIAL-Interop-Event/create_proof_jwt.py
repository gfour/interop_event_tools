#!/usr/bin/env python
import json
import jwt
import sys
import time
from jwt.algorithms import get_default_algorithms

private_jwk = {
    "kty": "EC",
    "d": "BMtpLFf4dxoPeJSg917huMaIs9rgHlU4EmIymbKIOZo",
    "use": "sig",
    "crv": "P-256",
    "x": "lPytfPjf1XOfcsF-8ceI5MXxLd4HDGrdlTwcO8VS3go",
    "y": "m6OUQbcruidyrOEQKLWuALlWaB5Z8_Zqwy-LOmYMFuA",
    "alg": "ES256"
}
public_jwk = {
    "kty": "EC",
    "use": "sig",
    "crv": "P-256",
    "x": "lPytfPjf1XOfcsF-8ceI5MXxLd4HDGrdlTwcO8VS3go",
    "y": "m6OUQbcruidyrOEQKLWuALlWaB5Z8_Zqwy-LOmYMFuA",
    "alg": "ES256"
}


def encode_jwt(payload, jwk, header, algorithm):
    key = get_default_algorithms()[algorithm].from_jwk(json.dumps(jwk))
    return jwt.encode(
        payload, key, algorithm=algorithm, headers=header,
    )


now = int(time.time())

payload = {
  "exp": now + 100000,
  "iat": now,
  "jti": "ac66b86e-1ca4-4229-9622-360fcf17d2ea",
  "iss": "https://snf-74864.ok-kno.grnetcloud.net",
  "sub": "60b8ba5f-c73f-4976-b0da-48d0e53335de",
  "typ": "Bearer",
  "azp": "wallet-dev",
  "session_state": "6085dc68-467a-4819-983d-e30c3e273133",
  "allowed-origins": [
    "/*"
  ],
  "scope": "openid eu.europa.ec.eudiw.pid_vc_sd_jwt eu.europa.ec.eudiw.pid_mso_mdoc",
  "sid": "6085dc68-467a-4819-983d-e30c3e273133",
  "aud": [
      # "http://snf-74864.ok-kno.grnetcloud.net:8080",
      "https://snf-74864.ok-kno.grnetcloud.net:9090",
  ],
  "nonce": sys.argv[1],
}

jwt_token = encode_jwt(
    payload=payload,
    jwk=private_jwk,
    # algorithm="RS256",
    algorithm="ES256",
    header={
        "typ": "openid4vci-proof+jwt",
        "jwk": public_jwk,
    },
)
print(jwt_token)
