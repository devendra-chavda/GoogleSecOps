"""Google service-account JWT -> OAuth2 access token exchange.

The service account JSON (from GCP IAM) is supplied through the
`ChronicleServiceAccountJson` app setting as the full JSON string.
A JWT is signed with the private key (RS256) and exchanged for an
access token at https://oauth2.googleapis.com/token.

Tokens are cached in-process until they are near expiry.
"""
import json
import time
from typing import Optional

import jwt
import requests

from . import consts
from .exceptions import ChronicleAuthError
from .logger import applogger


class GoogleServiceAccountAuth:
    """Build and cache Google OAuth2 access tokens from a service account."""

    def __init__(self, service_account_json: str = consts.SERVICE_ACCOUNT_JSON):
        if not service_account_json:
            raise ChronicleAuthError("ChronicleServiceAccountJson is not configured.")
        try:
            self._sa = json.loads(service_account_json)
        except json.JSONDecodeError as exc:
            raise ChronicleAuthError(
                "ChronicleServiceAccountJson is not valid JSON."
            ) from exc
        required = ("client_email", "private_key", "token_uri")
        missing = [k for k in required if not self._sa.get(k)]
        if missing:
            raise ChronicleAuthError(
                f"Service account JSON missing fields: {missing}"
            )
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    def _build_assertion(self) -> str:
        now = int(time.time())
        payload = {
            "iss": self._sa["client_email"],
            "scope": consts.OAUTH_SCOPE,
            "aud": self._sa.get("token_uri", consts.OAUTH_TOKEN_URL),
            "iat": now,
            "exp": now + 3600,
        }
        return jwt.encode(payload, self._sa["private_key"], algorithm="RS256")

    def get_access_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expiry - consts.TOKEN_EXPIRY_BUFFER_SECONDS:
            return self._token
        assertion = self._build_assertion()
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        try:
            resp = requests.post(
                self._sa.get("token_uri", consts.OAUTH_TOKEN_URL),
                data=data,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise ChronicleAuthError(f"Token request failed: {exc}") from exc
        if resp.status_code != 200:
            raise ChronicleAuthError(
                f"Token exchange failed ({resp.status_code}): {resp.text}"
            )
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = now + int(body.get("expires_in", 3600))
        applogger.info("%s: acquired new Google access token", consts.LOG_PREFIX)
        return self._token
