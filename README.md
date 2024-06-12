# interop_event_tools

This repo contains any tools needed for the POTENTIAL "interop event".

## Setup

Create and activate a virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```
pip install pyjwt requests
```

## Use

Run the following command to go through authentication via a predefined set of users:

```
python auto_auth.py --scope openid,eu.europa.ec.eudiw.pid_vc_sd_jwt,eu.europa.ec.eudiw.pid_mso_mdoc,org.iso.18013.5.1.mDL --client-id eudiw_login --client-secret secret --auth-url https://snf-74864.ok-kno.grnetcloud.net --skip-tls-verification
```

Note that the command above opens a browser window/tab and you may have to manually accept the self-signed TLS certificate on first use.
