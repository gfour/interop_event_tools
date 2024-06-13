# interop_event_tools

This repo contains any tools needed for the POTENTIAL "interop event".

## Setup

Create and activate a virtual environment:

```
python3 -m venv .venv
```

Install dependencies:

```
source .venv/bin/activate
pip install cryptography pyjwt requests
```

Install jq, for example on Ubuntu run the following command:

```
sudo apt install jq
```

## Use

### Automatic authentication

Activate the virtual environment:

```
source .venv/bin/activate
```

Run the following command to go through authentication via a predefined set of users:

```
python auto_auth.py --scope openid,eu.europa.ec.eudiw.pid_vc_sd_jwt,eu.europa.ec.eudiw.pid_mso_mdoc,org.iso.18013.5.1.mDL --client-id eudiw_login --client-secret secret --auth-url https://snf-74864.ok-kno.grnetcloud.net --skip-tls-verification
```

Note that the command above opens a browser window/tab and you may have to manually accept the self-signed TLS certificate on first use.

The result will contain an access token that can be used with the credential issuer.

### Demo credential issuance flow

Use the access token to run the demo flow:

* mdoc formats (PID and mDL):

```
./issue-mdoc-pid-and-mdl.sh "ACCESS_TOKEN"
```

* SD-JWT-VC format (PID only):

```
./issue-sd-jwt-vc-pid.sh "ACCESS_TOKEN"
```
