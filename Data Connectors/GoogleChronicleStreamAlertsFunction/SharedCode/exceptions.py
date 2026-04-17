"""Exceptions for Chronicle connector."""


class ChronicleConnectorError(Exception):
    """Base error for the Chronicle connector."""


class ChronicleAuthError(ChronicleConnectorError):
    """Raised when Google OAuth token acquisition fails."""


class ChronicleApiError(ChronicleConnectorError):
    """Raised when the Chronicle API returns a non-retryable error."""

    def __init__(self, message: str, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class SentinelIngestionError(ChronicleConnectorError):
    """Raised when posting to Sentinel DCR fails."""
