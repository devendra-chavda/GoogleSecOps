"""Client for Google Chronicle Detection Alerts API.

This module provides a client for polling Google SecOps (Chronicle) for
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

import httpx

from . import consts
from .exceptions import ChronicleApiError, ChronicleConnectorError
from .google_auth import GoogleServiceAccountAuth
from .logger import applogger


# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# HTTP timeout settings (in seconds)
HTTP_CONNECT_TIMEOUT = 30.0
HTTP_WRITE_TIMEOUT = 30.0
HTTP_POOL_TIMEOUT = 30.0

# Batch extraction: Progress logging threshold
PROGRESS_LOG_THRESHOLD = 1024 * 1024  # Log every 1 MB


class ChronicleClient:
    """Client for polling Google Chronicle Detection Alerts API.

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
        project_id: str = consts.CHRONICLE_PROJECT_ID,
        region: str = consts.CHRONICLE_REGION,
        instance_id: str = consts.CHRONICLE_INSTANCE_ID,
    ):
        """Initialize Chronicle client.

        Args:
            auth: GoogleServiceAccountAuth instance for API authentication
            project_id: Chronicle project ID
            region: Chronicle region (us, europe, asia-southeast1)
            instance_id: Chronicle instance ID

        Raises:
            ValueError: If any required configuration is missing
        """
        if not all([project_id, region, instance_id]):
            raise ValueError(
                f"Missing Chronicle config: project_id={project_id}, "
                f"region={region}, instance_id={instance_id}"
            )

        self._auth = auth
        self._endpoint = self._build_endpoint(project_id, region, instance_id)

    @staticmethod
    def _build_endpoint(project_id: str, region: str, instance_id: str) -> str:
        """Build Chronicle API endpoint URL."""
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
        """Poll Chronicle API for detection batches.

        Yields detection batches from the Chronicle API with automatic retry on
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
            ChronicleConnectorError: If too many consecutive API failures
        """
        current_token = page_token
        current_start = page_start_time
        consecutive_failures = 0

        while True:
            # Give up after too many failures
            if consecutive_failures > consts.MAX_CONSECUTIVE_FAILURES:
                raise ChronicleConnectorError(
                    f"Too many consecutive API failures: {consecutive_failures}"
                )

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
                    "%s: API call failed, retrying (attempt %d/%d)",
                    consts.LOG_PREFIX,
                    consecutive_failures,
                    consts.MAX_CONSECUTIVE_FAILURES,
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
                applogger.info("%s: window complete, moving to next", consts.LOG_PREFIX)
                return

            if deadline_epoch and time.time() >= deadline_epoch:
                applogger.warning("%s: time budget exhausted", consts.LOG_PREFIX)
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
        """Make single streaming HTTP request to Chronicle API.

        Args:
            page_start: Window start time
            page_token: Pagination token (if continuing mid-window)
            deadline: Function timeout deadline (raises error if exceeded)

        Returns:
            Parsed JSON batch dict

        Raises:
            ChronicleApiError: On HTTP errors or stream read failures
            ChronicleConnectorError: If deadline exceeded
        """
        # Check deadline before making request
        if deadline and time.time() >= deadline:
            raise ChronicleConnectorError("Time budget exhausted before API call")

        # Build request body
        request_body = self._build_request_body(page_start, page_token)

        # Build headers with authentication
        headers = {
            "Authorization": f"Bearer {self._auth.get_access_token()}",
            "Content-Type": "application/json",
        }

        # Build timeout configuration
        timeout = httpx.Timeout(
            connect=HTTP_CONNECT_TIMEOUT,
            read=float(consts.API_TIMEOUT_SECONDS),
            write=HTTP_WRITE_TIMEOUT,
            pool=HTTP_POOL_TIMEOUT,
        )

        applogger.debug(
            "%s: API call (batch=%d, max=%d, timeout=%ds)",
            consts.LOG_PREFIX,
            consts.DETECTION_BATCH_SIZE,
            consts.MAX_DETECTIONS,
            consts.API_TIMEOUT_SECONDS,
        )

        try:
            # Use streaming to avoid buffering entire response in memory
            with httpx.Client(timeout=timeout) as client:
                with client.stream(
                    "POST", self._endpoint, headers=headers, json=request_body
                ) as response:
                    # Handle HTTP errors
                    self._check_response_status(response, page_token, page_start)

                    batch = self._read_stream_batch(
                        response, consts.API_TIMEOUT_SECONDS
                    )
                    return batch

        except httpx.RequestError as exc:
            applogger.error("%s: network error: %s", consts.LOG_PREFIX, exc)
            raise ChronicleApiError(f"Network error: {exc}") from exc
        except Exception as exc:
            applogger.error(
                "%s: unexpected error during API call: %s",
                consts.LOG_PREFIX,
                exc,
            )
            raise ChronicleApiError(f"API call failed: {exc}") from exc

    @staticmethod
    def _build_request_body(page_start: str, page_token: Optional[str]) -> dict:
        """Build Chronicle API request body.

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
        response: httpx.Response,
        page_token: Optional[str],
        page_start: str,
    ) -> None:
        """Check HTTP response status and raise errors if needed.

        Args:
            response: HTTP response from API
            page_token: Request's pagination token
            page_start: Request's start time

        Raises:
            ChronicleApiError: On HTTP error responses
        """
        if response.status_code == 401:
            applogger.error("%s: Unauthorized (401) - check service account", consts.LOG_PREFIX)
            raise ChronicleApiError("Unauthorized - invalid credentials", status_code=401)

        if response.status_code == 400:
            # Log details to help diagnose bad request errors
            try:
                error_details = response.text[:500]
                applogger.error("%s: Bad Request (400): %s", consts.LOG_PREFIX, error_details)
            except Exception:
                applogger.error("%s: Bad Request (400): could not read body", consts.LOG_PREFIX)

            applogger.error(
                "%s: request params: batchSize=%d, maxDetections=%d, "
                "pageToken=%s, pageStartTime=%s",
                consts.LOG_PREFIX,
                consts.DETECTION_BATCH_SIZE,
                consts.MAX_DETECTIONS,
                "set" if page_token else "not set",
                page_start[:30] if page_start else "none",
            )
            raise ChronicleApiError("Bad Request (400) - check parameters", status_code=400)

        if response.status_code >= 400:
            applogger.error(
                "%s: HTTP error %d", consts.LOG_PREFIX, response.status_code
            )
            raise ChronicleApiError(
                f"HTTP {response.status_code}",
                status_code=response.status_code,
            )

    # ═══════════════════════════════════════════════════════════════════════════════
    # INTERNAL: STREAM PARSING (Brace-Depth Tracking)
    # ═══════════════════════════════════════════════════════════════════════════════

    def _read_stream_batch(
        self,
        response: "httpx.Response",
        timeout_seconds: int,
    ) -> dict:
        """Extract first complete JSON batch from never-ending streaming array.

        Chronicle sends: [{batch1}, {batch2}, {batch3}, ...]

        This method uses character-level brace-depth tracking to identify where
        one batch object ends and the next begins. This allows extracting
        complete JSON objects from a continuous stream without buffering.

        Algorithm:
        1. Track brace depth: depth++ on {, depth-- on }
        2. Ignore braces inside strings (handle \" escapes)
        3. When depth goes 0→0 (object complete), parse and return
        4. Skip heartbeat-only messages and continue reading
        5. Timeout if no new line arrives for timeout_seconds

        Args:
            response: Open httpx streaming response
            timeout_seconds: Max seconds to wait between line arrivals

        Returns:
            First non-heartbeat batch dict

        Raises:
            ChronicleApiError: On timeout, JSON parse error, or stream error
        """
        # Parser state
        brace_depth = 0
        current_batch_chars = []
        inside_string = False
        escape_next = False
        last_line_received = time.time()
        total_bytes_read = 0

        try:
            for line in response.iter_lines():
                # Check: have we waited too long without data?
                now = time.time()
                time_since_last_line = now - last_line_received
                if time_since_last_line > timeout_seconds and brace_depth > 0:
                    applogger.error(
                        "%s: stream timeout (no data for %ds)",
                        consts.LOG_PREFIX,
                        timeout_seconds,
                    )
                    raise ChronicleApiError(
                        f"Stream timeout: no data for {timeout_seconds}s"
                    )

                # Skip empty/whitespace lines
                if not line or line.isspace():
                    continue

                last_line_received = now
                total_bytes_read += len(line.encode("utf-8"))

                # Log progress every 1 MB (helps diagnose hangs)
                if total_bytes_read > 0 and total_bytes_read % PROGRESS_LOG_THRESHOLD == 0:
                    applogger.info(
                        "%s: reading stream... %.1f MB",
                        consts.LOG_PREFIX,
                        total_bytes_read / (1024 * 1024),
                    )

                # Process each character to track braces
                for char in line:
                    # Handle escape sequences in strings
                    if escape_next:
                        escape_next = False
                        if brace_depth > 0:
                            current_batch_chars.append(char)
                        continue

                    if char == "\\" and inside_string:
                        escape_next = True
                        if brace_depth > 0:
                            current_batch_chars.append(char)
                        continue

                    # Toggle string state on unescaped quotes
                    if char == '"':
                        inside_string = not inside_string
                        if brace_depth > 0:
                            current_batch_chars.append(char)
                        continue

                    # Add everything inside strings as-is
                    if inside_string:
                        if brace_depth > 0:
                            current_batch_chars.append(char)
                        continue

                    # Track brace depth (outside strings only)
                    if char == "{":
                        brace_depth += 1
                        current_batch_chars.append(char)
                    elif char == "}":
                        if brace_depth > 0:
                            current_batch_chars.append(char)
                            brace_depth -= 1

                            # Object complete: parse and check
                            if brace_depth == 0:
                                batch_json = "".join(current_batch_chars)
                                current_batch_chars = []

                                try:
                                    batch = json.loads(batch_json)

                                    # Skip heartbeat messages (keep-alives)
                                    if isinstance(batch, dict) and batch.get("heartbeat"):
                                        continue

                                    # Return first real batch
                                    return batch

                                except json.JSONDecodeError as err:
                                    applogger.warning(
                                        "%s: JSON parse error: %s", consts.LOG_PREFIX, err
                                    )
                    elif brace_depth > 0:
                        current_batch_chars.append(char)

        except httpx.TimeoutException as exc:
            applogger.error("%s: HTTP read timeout: %s", consts.LOG_PREFIX, exc)
            raise ChronicleApiError(f"Stream read timeout: {exc}") from exc
        except ChronicleApiError:
            raise
        except Exception as exc:
            applogger.error("%s: error reading stream: %s", consts.LOG_PREFIX, exc)
            raise ChronicleApiError(f"Stream read error: {exc}") from exc

    # ═══════════════════════════════════════════════════════════════════════════════
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
        if isinstance(exc, ChronicleApiError):
            return exc.status_code in consts.RETRYABLE_STATUS_CODES

        return isinstance(exc, (httpx.TimeoutException, httpx.RequestError))

    @staticmethod
    def _sleep_with_backoff(attempt: int) -> None:
        """Sleep with exponential backoff before retrying.

        Formula: delay = base * 2^attempt + random(0, 1)
        This prevents thundering herd when multiple retries happen

        Args:
            attempt: Attempt number (1, 2, 3, ...)
        """
        delay = (
            consts.RETRY_BASE_DELAY_SECONDS * (2 ** attempt)
            + random.uniform(0, 1.0)
        )
        applogger.debug(
            "%s: backoff %.1fs before retry %d/%d",
            consts.LOG_PREFIX,
            delay,
            attempt,
            consts.MAX_CONSECUTIVE_FAILURES,
        )
        time.sleep(delay)
