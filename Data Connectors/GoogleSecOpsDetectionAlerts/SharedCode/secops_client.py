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

import httpx

from . import consts
from .exceptions import SecOpsApiError, SecOpsConnectorError
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


def parse_stream(response: "httpx.Response") -> Iterator[dict]:
    """Parse detection batches from SecOps API streaming response.

    Based on XSOAR/Demisto implementation. Accumulates bytes from stream
    and detects complete JSON objects by tracking brace depth.
    The response is a continuous stream of JSON objects.

    Yields:
        Parsed JSON batch dictionaries from the stream

    Raises:
        SecOpsApiError: On parse failure or stream read error
    """
    total_bytes_read = 0
    #TODO: remove
    lines_received = 0
    batches_found = 0
    heartbeats_skipped = 0
    #TODO: remove

    try:
        for chunk in response.iter_bytes(chunk_size=8192, decode_unicode=True):
            buffer += chunk
            total_bytes_read += len(chunk.encode("utf-8"))

            # Log progress every 1 MB
            if total_bytes_read > 0 and total_bytes_read % PROGRESS_LOG_THRESHOLD == 0:
                applogger.info(
                    consts.LOG_FORMAT.format(
                        consts.LOG_PREFIX,
                        "parse_stream",
                        "SecOpsAPI",
                        f"Streaming... {total_bytes_read / (1024 * 1024):.1f}MB",
                    )
                )

            # Extract complete JSON objects from buffer by tracking brace depth
            while buffer:
                # Skip whitespace and find first opening brace
                start_idx = buffer.find("{")
                if start_idx == -1:
                    buffer = buffer[buffer.rfind("}") + 1:] if buffer.rfind("}") != -1 else ""
                    break

                # Track brace depth to find matching closing brace
                brace_depth = 0
                end_idx = -1
                for i in range(start_idx, len(buffer)):
                    if buffer[i] == "{":
                        brace_depth += 1
                    elif buffer[i] == "}":
                        brace_depth -= 1
                        if brace_depth == 0:
                            end_idx = i
                            break

                # Incomplete object - wait for more data
                if end_idx == -1:
                    buffer = buffer[start_idx:]
                    break

                # Extract and parse complete object
                batch_json = buffer[start_idx:end_idx + 1]
                buffer = buffer[end_idx + 1:]

                try:
                    batch = json.loads(batch_json)
                    applogger.debug(
                        consts.LOG_FORMAT.format(
                            consts.LOG_PREFIX,
                            "parse_stream",
                            "SecOpsAPI",
                            f"Batch received: {batch}",
                        )
                    )
                    batches_found += 1

                    # Skip heartbeat messages
                    if isinstance(batch, dict) and batch.get("heartbeat"):
                        heartbeats_skipped += 1
                        applogger.debug(
                            consts.LOG_FORMAT.format(
                                consts.LOG_PREFIX,
                                "parse_stream",
                                "SecOpsAPI",
                                f"Heartbeat received (total: {heartbeats_skipped})",
                            )
                        )
                        continue

                    yield batch

                except json.JSONDecodeError as err:
                    applogger.warning(
                        consts.LOG_FORMAT.format(
                            consts.LOG_PREFIX,
                            "parse_stream",
                            "SecOpsAPI",
                            f"JSON parse error: {err.msg}",
                        )
                    )
                    continue

        # for line in response.iter_lines(decode_unicode=True, delimiter="\r\n"):
        #     #TODO: remove
        #     lines_received += 1
        #     # Skip empty/whitespace lines
        #     if not line or not line.strip():
        #         continue

        #     # total_bytes_read += len(line.encode("utf-8"))

        #     # # Log progress every 1 MB
        #     # if total_bytes_read > 0 and total_bytes_read % PROGRESS_LOG_THRESHOLD == 0:
        #     #     applogger.info(
        #     #         consts.LOG_FORMAT.format(
        #     #             consts.LOG_PREFIX,
        #     #             "parse_stream",
        #     #             "SecOpsAPI",
        #     #             f"Streaming... {total_bytes_read / (1024 * 1024):.1f}MB",
        #     #         )
        #     #     )

        #     # Trim characters before first { and after last }
        #     # This handles whitespace/malformed JSON around the object
        #     # start_idx = line.find("{")
        #     # end_idx = line.rfind("}")

        #     # if start_idx == -1 or end_idx == -1 or start_idx > end_idx:
        #     #     #TODO: remove
        #     #     applogger.debug(
        #     #         consts.LOG_FORMAT.format(
        #     #             consts.LOG_PREFIX,
        #     #             "parse_stream",
        #     #             "SecOpsAPI",
        #     #             f"Line {lines_received}: No braces found (skipped)",
        #     #         )
        #     #     )
        #     #     continue

        #     # batch_json = line[start_idx : end_idx + 1]
        #     batch_json = "{" + line.split("{", 1)[1].rsplit("}", 1)[0] + "}"

        #     try:
        #         batch = json.loads(batch_json)
        #         applogger.debug(
        #                 consts.LOG_FORMAT.format(
        #                     consts.LOG_PREFIX,
        #                     "parse_stream",
        #                     "SecOpsAPI",
        #                     f"batch received : {batch})",
        #                 )
        #             )
        #         #TODO: remove
        #         batches_found += 1

        #         # Skip heartbeat messages
        #         if isinstance(batch, dict) and batch.get("heartbeat"):
        #             #TODO: remove -->
        #             heartbeats_skipped += 1
        #             applogger.debug(
        #                 consts.LOG_FORMAT.format(
        #                     consts.LOG_PREFIX,
        #                     "parse_stream",
        #                     "SecOpsAPI",
        #                     f"Heartbeat received (total: {heartbeats_skipped})",
        #                 )
        #             )
        #             #TODO: remove <--
        #             continue

        #         yield batch

        #     except json.JSONDecodeError as err:
        #         applogger.warning(
        #             consts.LOG_FORMAT.format(
        #                 consts.LOG_PREFIX,
        #                 "parse_stream",
        #                 "SecOpsAPI",
        #                 f"JSON parse error: {err.msg}",
        #             )
        #         )
        #         continue

    except httpx.TimeoutException as exc:
        error_msg = f"Stream read timeout: {exc}"
        applogger.error(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX, "parse_stream", "SecOpsAPI", error_msg
            )
        )
        raise SecOpsApiError(error_msg) from exc
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
                f"Stream complete: batches_found={batches_found}, heartbeats_skipped={heartbeats_skipped}, total_bytes={total_bytes_read}",
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
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"API call (batch={consts.DETECTION_BATCH_SIZE}, max={consts.MAX_DETECTIONS}, timeout={consts.API_TIMEOUT_SECONDS}s)",
            )
        )

        try:
            # Use streaming to avoid buffering entire response in memory
            with httpx.Client(timeout=timeout) as client:
                with client.stream(
                    "POST", self._endpoint, headers=headers, json=request_body
                ) as response:
                    # Handle HTTP errors
                    self._check_response_status(response, page_token, page_start)

                    # Extract first JSON batch from streaming response
                    try:
                        for batch in parse_stream(response):
                            return batch
                        raise SecOpsApiError("No batches received")
                    except SecOpsApiError:
                        raise
                    except Exception as exc:
                        raise SecOpsApiError(f"Error reading batch: {exc}") from exc

        except httpx.RequestError as exc:
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

        return isinstance(exc, (httpx.TimeoutException, httpx.RequestError))

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
