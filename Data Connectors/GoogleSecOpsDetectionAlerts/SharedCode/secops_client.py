"""Client for Google SecOps Detection Alerts API.

This module provides a client for polling Google SecOps for
detection alerts. The API sends a never-ending JSON stream of detection batches.

Key Concepts:
  - Stream Format: Array of JSON objects: [{batch1}, {batch2}, ...]
  - Streaming: Responses are never-closing streams to reduce buffering
  - Pagination: Uses pageToken for mid-window and pageStartTime for new windows
  - Heartbeats: Server sends heartbeat messages to keep connection alive
  - Timeouts: Per-message timeout detects connection stalls (Demisto approach)
"""

import json
import random
import time
from typing import Iterator, Optional, Tuple
import inspect

import requests
from google.auth.transport import requests as auth_requests

from . import consts
from .exceptions import SecOpsApiError, SecOpsConnectorError
from .google_auth import GoogleServiceAccountAuth
from .logger import applogger

# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Batch extraction: Progress logging threshold
PROGRESS_LOG_THRESHOLD = 1024 * 1024  # Log every 1 MB


def parse_stream(response: "requests.Response") -> Iterator[dict]:
    """Parse detection batches from SecOps API streaming response.

    Reads the response line by line. Each line is a JSON object. Trims
    all characters before the first opening brace and after the last closing
    brace before parsing.

    Yields:
        Parsed JSON batch dicts from the stream (including heartbeats)

    Raises:
        SecOpsApiError: On stream read error
    """
    lines_received = 0
    batches_found = 0

    try:
        for line in response.iter_lines(decode_unicode=True, delimiter="\r\n"):
            if not line:
                continue
            lines_received += 1
            # Trim all characters before first opening brace, and after last closing brace
            # Example: "  {'key1': 'value1'},  " -> "{'key1': 'value1'}"
            json_string = "{" + line.split("{", 1)[1].rsplit("}", 1)[0] + "}"
            batches_found += 1
            applogger.debug(
                consts.LOG_FORMAT.format(
                    consts.LOG_PREFIX,
                    "parse_stream",
                    "SecOpsAPI",
                    f"Data arrived: batch={batches_found}, size={len(line)} bytes",
                )
            )
            yield json.loads(json_string)

    except Exception as exc:
        error_msg = f"Stream read error: {exc}"
        applogger.error(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX, "parse_stream", "SecOpsAPI", error_msg
            )
        )
        raise SecOpsApiError(error_msg) from exc
    finally:
        applogger.info(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                "parse_stream",
                "SecOpsAPI",
                f"Stream complete: lines_received={lines_received}, batches_found={batches_found}",
            )
        )


class SecOpsClient:
    """Client for polling Google SecOps Detection Alerts API.

    Handles:
    - Authentication via Google service account
    - Streaming HTTP connections
    - JSON stream parsing with brace-depth tracking
    - Automatic retry with exponential backoff
    - Per-message timeout detection
    """

    def __init__(
        self,
        auth: GoogleServiceAccountAuth,
        project_id: str = consts.SECOPS_PROJECT_ID,
        region: str = consts.SECOPS_REGION,
        instance_id: str = consts.SECOPS_INSTANCE_ID,
    ):
        """Initialize SecOps client.

        Args:
            auth: GoogleServiceAccountAuth instance for API authentication
            project_id: SecOps project ID
            region: SecOps region (us, europe, asia-southeast1)
            instance_id: SecOps instance ID

        Raises:
            ValueError: If any required configuration is missing
        """
        __method_name = inspect.currentframe().f_code.co_name

        if not all([project_id, region, instance_id]):
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Missing SecOps config: project_id={project_id}, region={region}, instance_id={instance_id}",
            )
            applogger.error(error_msg)
            raise ValueError(error_msg)

        self._auth = auth
        self._endpoint = self._build_endpoint(project_id, region, instance_id)
        self.http_client = auth_requests.AuthorizedSession(auth.get_credentials())

        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Initialized SecOps client with endpoint: {self._endpoint[:50]}...",
            )
        )

    @staticmethod
    def _build_endpoint(project_id: str, region: str, instance_id: str) -> str:
        """Build SecOps API endpoint URL."""
        return (
            f"https://{region}-chronicle.googleapis.com/v1alpha/"
            f"projects/{project_id}/locations/{region}/"
            f"instances/{instance_id}/legacy:legacyStreamDetectionAlerts"
        )

    # ═══════════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════════════

    def poll_detection_batches(
        self,
        page_start_time: str = "",
        page_token: Optional[str] = None,
        deadline_epoch: Optional[float] = None,
    ) -> Iterator[Tuple[dict, Optional[str], Optional[str]]]:
        """Poll SecOps API for detection batches.

        Yields detection batches from the SecOps API with automatic retry on
        transient failures. Returns when: (1) time budget exhausted, or
        (2) pagination window complete (nextPageStartTime received).

        Args:
            page_start_time: Start of time window to fetch (ISO timestamp)
            page_token: Pagination token from previous call (continues mid-window)
            deadline_epoch: Unix timestamp when to stop polling

        Yields:
            Tuple of (batch_dict, next_token, next_start_time) where:
              - batch_dict: Detection batch from API
              - next_token: Pagination token if mid-window (for continuation)
              - next_start_time: New start time if window complete (for next window)

        Raises:
            SecOpsConnectorError: If too many consecutive API failures
        """
        __method_name = inspect.currentframe().f_code.co_name
        current_token = page_token
        current_start = page_start_time
        consecutive_failures = 0

        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Starting detection batch polling from {page_start_time}",
            )
        )

        while True:
            # Give up after too many failures
            if consecutive_failures > consts.MAX_CONSECUTIVE_FAILURES:
                error_msg = consts.LOG_FORMAT.format(
                    consts.LOG_PREFIX,
                    __method_name,
                    "SecOpsClient",
                    f"Too many consecutive API failures: {consecutive_failures}",
                )
                applogger.error(error_msg)
                raise SecOpsConnectorError(error_msg)

            # Exponential backoff on retry
            if consecutive_failures > 0:
                self._sleep_with_backoff(consecutive_failures)

            # Make API call
            try:
                batch = self._make_api_call(
                    current_start, current_token, deadline_epoch
                )
            except Exception as exc:
                # Check if error is retryable (transient vs permanent)
                if not self._should_retry(exc):
                    raise  # Permanent error - fail fast

                # Transient error - retry
                consecutive_failures += 1
                applogger.warning(
                    consts.LOG_FORMAT.format(
                        consts.LOG_PREFIX,
                        __method_name,
                        "SecOpsClient",
                        f"API call failed, retrying (attempt {consecutive_failures}/{consts.MAX_CONSECUTIVE_FAILURES}): {str(exc)[:100]}",
                    )
                )
                continue

            # Success: reset failure counter
            consecutive_failures = 0

            # Parse pagination tokens from response
            next_token = batch.get("nextPageToken")
            next_start = batch.get("nextPageStartTime")

            yield batch, next_token, next_start

            # Stop conditions
            if next_start:
                applogger.info(
                    consts.LOG_FORMAT.format(
                        consts.LOG_PREFIX,
                        __method_name,
                        "SecOpsClient",
                        "Window complete, moving to next",
                    )
                )
                return

            if deadline_epoch and time.time() >= deadline_epoch:
                applogger.warning(
                    consts.LOG_FORMAT.format(
                        consts.LOG_PREFIX,
                        __method_name,
                        "SecOpsClient",
                        "Time budget exhausted",
                    )
                )
                return

            # Update pagination state for next iteration
            current_token = next_token or current_token
            current_start = next_start or current_start

    # ═══════════════════════════════════════════════════════════════════════════════
    # INTERNAL: API COMMUNICATION
    # ═══════════════════════════════════════════════════════════════════════════════

    def _make_api_call(
        self,
        page_start: str,
        page_token: Optional[str],
        deadline: Optional[float],
    ) -> dict:
        """Make single streaming HTTP request to SecOps API.

        Args:
            page_start: Window start time
            page_token: Pagination token (if continuing mid-window)
            deadline: Function timeout deadline (raises error if exceeded)

        Returns:
            Parsed JSON batch dict

        Raises:
            SecOpsApiError: On HTTP errors or stream read failures
            SecOpsConnectorError: If deadline exceeded
        """
        __method_name = inspect.currentframe().f_code.co_name

        # Check deadline before making request
        if deadline and time.time() >= deadline:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                "Time budget exhausted before API call",
            )
            applogger.error(error_msg)
            raise SecOpsConnectorError(error_msg)

        # Build request body
        request_body = self._build_request_body(page_start, page_token)

        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"API call (batch={consts.DETECTION_BATCH_SIZE}, max={consts.MAX_DETECTIONS}, timeout={consts.API_TIMEOUT_SECONDS}s)",
            )
        )

        try:
            response = self.http_client.post(
                self._endpoint,
                json=request_body,
                stream=True,
            )

            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOG_PREFIX,
                    __method_name,
                    "SecOpsClient",
                    f"Response received with status {response.status_code}, now parsing stream",
                )
            )

            self._check_response_status(response, page_token, page_start)

            for batch in parse_stream(response):
                if not isinstance(batch, dict):
                    continue
                if batch.get("heartbeat"):
                    applogger.debug(
                        consts.LOG_FORMAT.format(
                            consts.LOG_PREFIX,
                            __method_name,
                            "SecOpsClient",
                            "Heartbeat received (connection active)",
                        )
                    )
                    continue
                applogger.info(
                    consts.LOG_FORMAT.format(
                        consts.LOG_PREFIX,
                        __method_name,
                        "SecOpsClient",
                        f"Batch received with {len(batch.get('detections', []))} detections",
                    )
                )
                return batch

            return {}

        except requests.exceptions.Timeout as exc:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Request timed out after {consts.API_TIMEOUT_SECONDS}s: {exc}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg) from exc
        except requests.exceptions.RequestException as exc:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Network error: {exc}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg) from exc
        except Exception as exc:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Unexpected error during API call: {exc}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg) from exc

    @staticmethod
    def _build_request_body(page_start: str, page_token: Optional[str]) -> dict:
        """Build SecOps API request body.

        Args:
            page_start: Time window start (used if no token)
            page_token: Pagination token (used if continuing mid-window)

        Returns:
            Request body dict
        """
        body = {
            "detectionBatchSize": consts.DETECTION_BATCH_SIZE,
            "maxDetections": consts.MAX_DETECTIONS,
        }

        # Choose pagination method: token (mid-window) or start time (new window)
        if page_token:
            body["pageToken"] = page_token
        else:
            body["pageStartTime"] = page_start

        return body

    @staticmethod
    def _check_response_status(
        response: "requests.Response",
        page_token: Optional[str],
        page_start: str,
    ) -> None:
        """Check HTTP response status and raise errors if needed.

        Args:
            response: HTTP response from API
            page_token: Request's pagination token
            page_start: Request's start time

        Raises:
            SecOpsApiError: On HTTP error responses
        """
        __method_name = inspect.currentframe().f_code.co_name

        if response.status_code == 401:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                "Unauthorized (401) - check service account credentials",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg, status_code=401)

        if response.status_code == 400:
            try:
                error_details = response.text[:500]
            except Exception:
                error_details = "Could not read error details"

            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Bad Request (400): {error_details}. Params: batchSize={consts.DETECTION_BATCH_SIZE}, pageToken={'set' if page_token else 'not set'}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg, status_code=400)

        if response.status_code >= 400:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"HTTP error {response.status_code}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg, status_code=response.status_code)

    # INTERNAL: RETRY LOGIC
    # ═══════════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _should_retry(exc: Exception) -> bool:
        """Determine if exception is retryable (transient) or permanent.

        Retryable errors:
        - HTTP 429 (rate limit), 500, 502, 503, 504 (server errors)
        - Network timeouts and connection errors

        Not retryable:
        - HTTP 400 (bad request), 401 (unauthorized)
        - JSON parse errors

        Args:
            exc: Exception to evaluate

        Returns:
            True if error is transient and should trigger retry
        """
        if isinstance(exc, SecOpsApiError):
            return exc.status_code in consts.RETRYABLE_STATUS_CODES

        return isinstance(exc, (requests.exceptions.Timeout, requests.exceptions.RequestException))

    @staticmethod
    def _sleep_with_backoff(attempt: int) -> None:
        """Sleep with exponential backoff before retrying.

        Formula: delay = base * 2^attempt + random(0, 1)
        This prevents thundering herd when multiple retries happen

        Args:
            attempt: Attempt number (1, 2, 3, ...)
        """
        __method_name = inspect.currentframe().f_code.co_name
        delay = consts.RETRY_BASE_DELAY_SECONDS * (2**attempt) + random.uniform(0, 1.0)
        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Backoff {delay:.1f}s before retry {attempt}/{consts.MAX_CONSECUTIVE_FAILURES}",
            )
        )
        time.sleep(delay)
