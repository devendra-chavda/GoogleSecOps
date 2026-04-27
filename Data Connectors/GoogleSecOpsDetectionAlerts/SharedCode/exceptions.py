"""Exceptions for SecOps connector."""


class SecOpsConnectorError(Exception):
    """Base error for the SecOps connector."""


class SecOpsAuthError(SecOpsConnectorError):
    """Raised when Google OAuth token acquisition fails."""


class SecOpsApiError(SecOpsConnectorError):
    """Raised when the SecOps API returns a non-retryable error."""

    def __init__(self, message: str, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class SentinelIngestionError(SecOpsConnectorError):
    """Raised when posting to Sentinel DCR fails."""
