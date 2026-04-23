"""Google service account OAuth2 token provider."""

import time
from typing import Optional

from google.oauth2 import service_account
from google.auth.transport.requests import Request
import json

from . import consts
from .exceptions import ChronicleAuthError
from .logger import applogger


class GoogleServiceAccountAuth:
    """Manage Google OAuth2 tokens from service account credentials."""

    def __init__(self, service_account_json: str = consts.SERVICE_ACCOUNT_JSON):
        self._validate_and_load(service_account_json)
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    def _validate_and_load(self, service_account_json: str) -> None:
        if not service_account_json:
            raise ChronicleAuthError("ChronicleServiceAccountJson not configured")

        try:
            sa_dict = json.loads(service_account_json)
        except json.JSONDecodeError as exc:
            raise ChronicleAuthError(
                "ChronicleServiceAccountJson invalid JSON"
            ) from exc

        missing = [k for k in ("client_email", "private_key") if not sa_dict.get(k)]
        if missing:
            raise ChronicleAuthError(f"Missing fields: {missing}")

        try:
            self._creds = service_account.Credentials.from_service_account_info(
                sa_dict, scopes=[consts.OAUTH_SCOPE]
            )
        except Exception as exc:
            raise ChronicleAuthError(f"Failed to create credentials: {exc}") from exc

    def get_access_token(self) -> str:
        """Get or refresh access token."""
        now = time.time()
        if self._is_token_valid(now):
            return self._token

        try:
            self._creds.refresh(Request())
            self._token = self._creds.token

            # Set expiry: use credential expiry if available, otherwise 3600 seconds
            if self._creds.expiry:
                self._token_expiry = self._creds.expiry.timestamp()
            else:
                self._token_expiry = now + 3600

            applogger.info("%s: acquired new Google access token", consts.LOG_PREFIX)
            return self._token
        except Exception as exc:
            raise ChronicleAuthError(f"Token refresh failed: {exc}") from exc

    def _is_token_valid(self, now: float) -> bool:
        return (
            self._token
            and now < self._token_expiry - consts.TOKEN_EXPIRY_BUFFER_SECONDS
        )
