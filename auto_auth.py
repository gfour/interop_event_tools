import argparse
import base64
import hashlib
import hmac
import http.server
import json
import logging
import os
import random
import secrets
import socketserver
import string
import webbrowser
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


def is_error_response(r):
    return r.status_code != 200


PORT = 5055
REDIRECT_URI = f"http://localhost:{PORT}"
DILOSI_URL = "http://localhost"
AUTH_URL = "http://localhost"
CLIENT_ID = "client"
CLIENT_SECRET = "secret"
SCOPE = "openid,provider,profile,dilosi,govgr_login,offline_access"
GRANT_TYPE = "authorization_code"
DUMMY_BACKEND = "dummy"


def generate_code_verifier(length=128):
    code_verifier = secrets.token_urlsafe(96)[:length]
    return code_verifier


def get_code_challenge(code_verifier):
    hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode('ascii')[:-1]
    return code_challenge


def generate_state():
    return secrets.token_urlsafe(96)[:64]


def generate_pkce_pair(code_verifier_length=128):
    code_verifier = generate_code_verifier(code_verifier_length)
    code_challenge = get_code_challenge(code_verifier)
    return code_verifier, code_challenge


class Config:
    def __init__(self, conf):
        self.conf = conf
        self.set_port_domain()
        self.check_grant_type()
        self.format_scopes()
        self.logging_verbosity()

    def __getattr__(self, key):
        return self.__dict__["conf"].get(key)

    def __setattr__(self, key, value):
        if key == "conf":
            self.__dict__[key] = value
        else:
            self.conf[key] = value

    def set_port_domain(self):
        uri = urlparse(self.redirect_uri)
        if not uri.port:
            raise ValueError("No port provided in Redirect uri.")
        self.port = uri.port
        self.domain = uri.netloc.split(":")[0]

    def check_grant_type(self):
        allowed_grant_types = ["authorization_code", "refresh_token"]
        if self.grant_type not in allowed_grant_types:
            raise ValueError(f"Allowed grant types: {allowed_grant_types}")

    def logging_verbosity(self):
        if self.verbose == 0:
            logging.basicConfig(level=logging.INFO)
        elif self.verbose >= 1:
            logging.basicConfig(level=logging.DEBUG)

    def format_scopes(self):
        self.scope = " ".join(self.scope.split(","))


def get_code(url):
    logger.info(f"Getting authorization code from {url}")
    parsed = urlparse(url)
    code = parse_qs(parsed.query).get("code")
    if not code:
        logger.error("No authorization code found in URL.")
        return None
    code = code[0]
    logger.info(f"Got authorization code {code} from URL.")
    return code


def log_error_response(r):
    try:
        logger.error(f"Got response {r.json()}")
    except ValueError as e:
        logger.exception(e)
        filename = "error.html"
        with open(filename, "w") as error_file:
            error_file.write(r.content.decode("utf-8"))
        webbrowser.open_new_tab(os.path.abspath(filename))
        logger.error(f"Got response {r.content.decode('utf-8')}")


def get_token_response(
    code, auth_url, client_id, client_secret, grant_type, redirect_uri,
    code_verifier, skip_tls_verification: bool, refresh_token=None
):
    url = f"{auth_url}/oidc/token"
    logger.info(f"Getting token from {url}")
    data = {
        "grant_type": grant_type,
    }
    if grant_type == "authorization_code":
        data["redirect_uri"] = redirect_uri
        data["code"] = code
    elif grant_type == "refresh_token" and refresh_token is not None:
        data["refresh_token"] = refresh_token
    if code_verifier is not None:
        data["code_verifier"] = code_verifier
    r = requests.post(
        url,
        data=data,
        auth=HTTPBasicAuth(client_id, client_secret),
        verify=not skip_tls_verification,
    )
    if is_error_response(r):
        log_error_response(r)
        return None

    r_json = r.json()
    logger.info("Got token.")
    logger.debug(f"Got token response: {r_json}")
    return r_json


def introspect(config, token, hint):
    logger.info(f"Introspecting token with hint: {hint}...")
    auth_url = config.auth_url
    url = f"{auth_url}/oidc/introspect/"
    data = {
        "token": token,
        "token_type_hint": hint,
        "client_id": config.client_id,
        "client_secret": config.client_secret,
    }
    auth = HTTPBasicAuth(config.client_id, config.client_secret)
    r = requests.post(
        url, data=data, auth=auth, verify=not config.skip_tls_verification
    )
    if is_error_response(r):
        log_error_response(r)
        return None
    r_json = r.json()
    logger.info(f"Successful token introspection: |{r_json}|")
    return r_json


def get_userinfo(auth_url, access_token, skip_tls_verification: bool):
    logger.info("Retrieving user's info...")
    url = f"{auth_url}/oidc/userinfo/"
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    r = requests.post(url, headers=headers, verify=not skip_tls_verification)
    if is_error_response(r):
        log_error_response(r)
        return None

    r_json = r.json()
    logger.info("Successful user's info retrieval.")
    logger.debug(f"Got user's info: {r_json}")
    return r_json


def pretty(data, **kwargs):
    return json.dumps(data, indent=4, ensure_ascii=False, **kwargs)


def dilosi_oidc_login(dilosi_url, id_token, skip_tls_verification: bool):
    url = f"{dilosi_url}/api/oidc_login/"
    logger.info(f"Performing dilosi login ({url})...")
    data = {
        "token": id_token,
    }
    logger.info(f"data: {pretty(data)}")
    r = requests.post(url, data=data, verify=not skip_tls_verification)
    if is_error_response(r):
        log_error_response(r)
        return None

    try:
        r_json = r.json()
    except json.decoder.JSONDecodeError:
        print("Error while decoding response:", r.content)
        raise
    logger.info("Successful dilosi login.")
    logger.debug(f"Got dilosi response: {r_json}")
    return r_json.get("token")


class OIDCAutomationServer(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info(args)

    def _set_headers(self, config):
        if config.no_browser_print:
            content_type = "text"
        else:
            content_type = "application/json"

        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _set_output(self, data, config):
        if not config.no_cli_print:
            print(pretty(data, sort_keys=True))

        if config.no_browser_print:
            d = b"OAUTH2 code flow succeeded. Check your terminal. \n\n You may now close this tab."
        else:
            d = bytes(json.dumps(data, ensure_ascii=False), "utf-8")
        self.wfile.write(d)

    def do_GET(self):
        config = self.server.config

        self._set_headers(config)

        code = get_code(self.path)
        if not code:
            return

        token_response = get_token_response(
            code,
            config.auth_url,
            config.client_id,
            config.client_secret,
            config.grant_type,
            config.redirect_uri,
            config.code_verifier,
            config.skip_tls_verification,
        )
        if not token_response:
            return

        data = process_token_data(config, token_response)
        data["code"] = code
        self._set_output(data, config)


def process_token_data(config, token_response):
    id_token = token_response.get("id_token")
    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")

    data = {
        "token_response": token_response,
    }
    id_claims = None
    if id_token:
        id_claims = jwt.decode(
            id_token, options={'verify_signature': False}
        )
        data["decoded_id_token"] = id_claims
    if config.userinfo:
        data["userinfo"] = get_userinfo(
            config.auth_url, access_token, config.skip_tls_verification
        )
    if config.introspect:
        r_acc = introspect(config, access_token, "access_token")
        r_id = introspect(config, id_token, "id_token")
        data["introspection"] = {"access_token": r_acc, "id_token": r_id}
        if id_claims:
            r_jti = introspect(config, id_claims["jti"], "jti")
            data["introspection"]["jti"] = r_jti
        if refresh_token:
            r_refresh = introspect(
                config, refresh_token, "refresh_token"
            )
            data["introspection"]["refresh_token"] = r_refresh
    if config.dilosi_api_token and id_token:
        data["dilosi_api_token"] = dilosi_oidc_login(
            config.dilosi_url, id_token, not config.skip_tls_verification,

        )
    return data


def new_auth_key(client_secret):
    DATA = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8").rstrip("=")
    return compute_auth_key(client_secret, DATA)


def compute_auth_key(client_secret, DATA):
    digest_bytes = hmac.new(
        client_secret.encode("utf-8"),
        DATA.encode("utf-8"),
        hashlib.sha256
    ).digest()
    HMAC = base64.urlsafe_b64encode(digest_bytes).decode("utf-8").rstrip("=")
    return f"{HMAC}.{DATA}"


def open_browser(config):
    params = {
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": config.scope,
        "response_type": "code",
        "response_mode": "form_post",
        "nonce": "".join(
            random.choice(string.ascii_lowercase) for _ in range(11)
        ),
    }
    if config.backend:
        params["backend"] = config.backend
        if config.backend == DUMMY_BACKEND:
            if config.user_id:
                params["user_id"] = config.user_id
            else:
                logger.error("Backend requires user id.")
        elif config.user_id:
            logger.error(
                f"Ignoring user_id={config.user_id} (backend={config.backend})"
            )

    if config.pkce:
        code_verifier, code_challenge = generate_pkce_pair(
            code_verifier_length=128)
        config.code_verifier = code_verifier
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    if config.prompt:
        params["prompt"] = config.prompt
    if config.state:
        params["state"] = generate_state()
    if config.auth_key:
        params["auth_key"] = new_auth_key(config.client_secret)

    url = f"{config.auth_url}/oidc/authorization/?" + urlencode(params)
    logger.info(f"Opening URL in browser: {url}")
    webbrowser.open_new_tab(url)


def run_server(config):
    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(
            (config.domain, config.port), OIDCAutomationServer
        ) as proxy:
            proxy.config = config

            logger.info(f"Redirect receiver running on: {config.redirect_uri}")
            logger.info("Waiting for browser redirect.")
            proxy.handle_request()
    except KeyboardInterrupt:
        return


def make_args_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "--backend",
        action="store",
        default=None,
        help="Authentication backend used by Authbroker.",
    )
    parser.add_argument(
        "--client-id",
        action="store",
        default=CLIENT_ID,
        help="Authbroker client id.",
    )
    parser.add_argument(
        "--client-secret",
        action="store",
        default=CLIENT_SECRET,
        help="Authbroker client secret.",
    )
    parser.add_argument(
        "--dilosi-url",
        action="store",
        default=DILOSI_URL,
        help="URL of running dilosi. Used for API token request.",
    )
    parser.add_argument(
        "--auth-url",
        action="store",
        default=AUTH_URL,
        help="URL of running auth service. Used for API token request.",
    )
    parser.add_argument(
        "--redirect-uri",
        action="store",
        default=REDIRECT_URI,
        help="Authbroker client redirect URI.",
    )
    parser.add_argument(
        "--scope",
        action="store",
        default=SCOPE,
        help="One or more comma separated scopes to request from Authbroker client.",
    )
    parser.add_argument(
        "--grant-type",
        action="store",
        default=GRANT_TYPE,
        help="Authbroker client grant type to request. (Currently supporting only authorization_code)",
    )
    parser.add_argument(
        "--dilosi-api-token",
        action="store_true",
        default=False,
        help="Get dilosi API token.",
    )
    parser.add_argument(
        "--introspect",
        action="store_true",
        default=False,
        help="Introspect access tokens, id tokens, and jti values.",
    )
    parser.add_argument(
        "--userinfo",
        action="store_true",
        default=False,
        help="Get user info.",
    )
    parser.add_argument(
        "--no-cli-print",
        action="store_true",
        default=False,
        help="Don't print in cli.",
    )
    parser.add_argument(
        "--no-browser-print",
        action="store_true",
        default=False,
        help="Don't print in browser.",
    )
    parser.add_argument(
        "--pkce",
        action="store_true",
        default=False,
        help="Use code challenge.",
    )
    parser.add_argument(
        "--prompt",
        action="store",
        default=None,
        help="Add prompt request parameter.",
    )
    parser.add_argument(
        "--state",
        action="store_true",
        default=False,
        help="Add state request parameter.",
    )
    parser.add_argument(
        "--auth-key",
        action="store_true",
        default=False,
        help="Add authorization key parameter.",
    )
    parser.add_argument(
        "--do-refresh",
        action="store",
        default="",
        help="Perform refresh using given token.",
    )
    parser.add_argument(
        "--user-id",
        action="store",
        help=f"User id when using backend '{DUMMY_BACKEND}'.",
    )
    parser.add_argument(
        "--appconfig",
        action="store_true",
        default=False,
        help="Perform GET request in oidc/appconfig/ endpoint.",
    )
    parser.add_argument(
        "--skip-tls-verification",
        action="store_true",
        default=False,
        help="Skip TLS verification (e.g., accept self-signed certificates)",
    )
    parser.add_argument("--verbose", "-v", action="count", default=0)

    return parser.parse_args()


def do_token_refresh(config):
    refresh_token = config.do_refresh
    logger.info(f"Using refresh_token: {refresh_token}")
    token_refresh_response = get_token_response(
        None,
        config.auth_url,
        config.client_id,
        config.client_secret,
        "refresh_token",
        None,
        None,
        config.skip_tls_verification,
        refresh_token=refresh_token,
    )
    logger.info(f"token_refresh_response={token_refresh_response}")
    print(pretty(token_refresh_response, sort_keys=True))
    data = process_token_data(config, token_refresh_response)
    print(pretty(data, sort_keys=True))


def get_appconfig(config: Config):
    logger.info("Sending request to /appconfig")
    url = f"{config.auth_url}/oidc/appconfig"
    r = requests.get(
        url,
        auth=HTTPBasicAuth(
            config.client_id,
            config.client_secret
        ),
        verify=not config.skip_tls_verification,
    )

    logger.info(f"Got /appconfig response: {pretty(r.json())}")


def main():
    try:
        args = make_args_parser()
        config = Config(vars(args))

        if config.appconfig:
            get_appconfig(config)
            return

        if config.do_refresh:
            do_token_refresh(config)
            return

        open_browser(config)
        run_server(config)
    except ValueError as e:
        logger.error(e)


if __name__ == "__main__":
    main()
