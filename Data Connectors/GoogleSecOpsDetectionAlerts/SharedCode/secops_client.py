"""Client for Google SecOps Detection Alerts API.

Polls Google SecOps for detection alerts. The API responds with a streaming
JSON array of detection batches that may stay open for extended periods.

Key Concepts:
  - Stream Format: JSON array of objects: [{batch1}, {batch2}, ...]
  - Streaming: Responses stream line-by-line to reduce buffering
  - Pagination: pageToken continues mid-window, pageStartTime starts new window
  - Heartbeats: Server sends heartbeat messages to keep connection alive
"""

import inspect
import json
import random
import time
from typing import Iterator, Optional, Tuple

import httpx
import google.auth.transport.requests

from . import consts
from .exceptions import SecOpsApiError, SecOpsConnectorError
from .google_auth import GoogleServiceAccountAuth
from .logger import applogger


class GoogleAuthTransport(httpx.BaseTransport):
    """HTTPX transport that signs each request with Google service account credentials."""

    def __init__(self, credentials, transport: Optional[httpx.BaseTransport] = None):
        self._transport = transport or httpx.HTTPTransport()
        self._auth_request = google.auth.transport.requests.Request()
        self._credentials = credentials

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Attach Google auth headers and forward the request."""
        self._credentials.before_request(
            self._auth_request,
            request.method,
            str(request.url),
            request.headers,
        )
        return self._transport.handle_request(request)


def parse_stream(response: httpx.Response) -> Iterator[dict]:
    """Parse detection batches from a SecOps streaming response.

    Accumulates all lines from the stream into a single buffer, then
    parses the resulting JSON array and yields each batch.

    Yields:
        Parsed JSON batch dicts (including heartbeats).

    Raises:
        SecOpsApiError: On stream read or JSON decode failure.
    """
    response.raise_for_status()

    # Parse stream (same as secops_client.parse_stream)
    lines_received = 0
    batches_found = 0
    batch = ""

    try:
        for line in response.iter_lines():
            if not line:
                continue
            lines_received += 1

            batches_found += 1
            batch += line

        if not batch:
            return

        for item in json.loads(batch):
            yield item

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
      - Authentication via Google service account (HTTPX transport)
      - Streaming HTTP connections
      - Line-by-line JSON stream parsing
      - Automatic retry with exponential backoff
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
            auth: GoogleServiceAccountAuth instance for API authentication.
            project_id: SecOps project ID.
            region: SecOps region (us, europe, asia-southeast1).
            instance_id: SecOps instance ID.

        Raises:
            ValueError: If any required configuration is missing.
        """
        __method_name = inspect.currentframe().f_code.co_name

        if not all([project_id, region, instance_id]):
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Missing SecOps config: project_id={project_id}, "
                f"region={region}, instance_id={instance_id}",
            )
            applogger.error(error_msg)
            raise ValueError(error_msg)

        self._auth = auth
        self._endpoint = self._build_endpoint(project_id, region, instance_id)

        transport = GoogleAuthTransport(credentials=auth.get_credentials())
        self.http_client = httpx.Client(transport=transport)

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

    # ─── Public API ────────────────────────────────────────────────────────────

    def poll_detection_batches(
        self,
        page_start_time: str = "",
        page_token: Optional[str] = None,
        deadline_epoch: Optional[float] = None,
    ) -> Iterator[Tuple[dict, Optional[str], Optional[str]]]:
        """Poll SecOps API for detection batches.

        Yields detection batches with automatic retry on transient failures.
        Returns when the time budget is exhausted or the pagination window
        is complete (nextPageStartTime received).

        Args:
            page_start_time: Start of time window to fetch (ISO timestamp).
            page_token: Pagination token from previous call (continues mid-window).
            deadline_epoch: Unix timestamp at which to stop polling.

        Yields:
            Tuple of (batch_dict, next_token, next_start_time).

        Raises:
            SecOpsConnectorError: If too many consecutive API failures occur.
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
            if consecutive_failures > consts.MAX_CONSECUTIVE_FAILURES:
                error_msg = consts.LOG_FORMAT.format(
                    consts.LOG_PREFIX,
                    __method_name,
                    "SecOpsClient",
                    f"Too many consecutive API failures: {consecutive_failures}",
                )
                applogger.error(error_msg)
                raise SecOpsConnectorError(error_msg)

            if consecutive_failures > 0:
                self._sleep_with_backoff(consecutive_failures)

            try:
                batch = self._make_api_call(
                    current_start, current_token, deadline_epoch
                )
            except Exception as exc:
                if not self._should_retry(exc):
                    raise

                consecutive_failures += 1
                applogger.warning(
                    consts.LOG_FORMAT.format(
                        consts.LOG_PREFIX,
                        __method_name,
                        "SecOpsClient",
                        f"API call failed, retrying "
                        f"(attempt {consecutive_failures}/{consts.MAX_CONSECUTIVE_FAILURES}): "
                        f"{str(exc)[:100]}",
                    )
                )
                continue

            consecutive_failures = 0

            next_token = batch.get("nextPageToken")
            next_start = batch.get("nextPageStartTime")

            yield batch, next_token, next_start

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

            current_token = next_token or current_token
            current_start = next_start or current_start

    # ─── Internal: API Communication ───────────────────────────────────────────

    def _make_api_call(
        self,
        page_start: str,
        page_token: Optional[str],
        deadline: Optional[float],
    ) -> dict:
        """Make a single streaming HTTP request to the SecOps API.

        Args:
            page_start: Window start time.
            page_token: Pagination token (if continuing mid-window).
            deadline: Function timeout deadline.

        Returns:
            Parsed JSON batch dict.

        Raises:
            SecOpsApiError: On HTTP errors or stream read failures.
            SecOpsConnectorError: If deadline exceeded.
        """
        __method_name = inspect.currentframe().f_code.co_name

        if deadline and time.time() >= deadline:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                "Time budget exhausted before API call",
            )
            applogger.error(error_msg)
            raise SecOpsConnectorError(error_msg)

        request_body = self._build_request_body(page_start, page_token)

        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"API call (batch={consts.DETECTION_BATCH_SIZE}, "
                f"max={consts.MAX_DETECTIONS}, "
                f"timeout={consts.API_TIMEOUT_SECONDS}s)",
            )
        )

        buffer = ""
        try:
            with self.http_client.stream(
                "POST",
                url=self._endpoint,
                content=json.dumps(request_body),
                timeout=consts.API_TIMEOUT_SECONDS,
            ) as response:
                response.raise_for_status()

                try:
                    for line in response.iter_lines():
                        if not line:
                            continue
                        buffer += line
                finally:
                    applogger.info(
                        consts.LOG_FORMAT.format(
                            consts.LOG_PREFIX,
                            __method_name,
                            "SecOpsClient",
                            f"Stream complete: bytes_received={len(buffer)}",
                        )
                    )

        except httpx.TimeoutException as exc:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Request timed out after {consts.API_TIMEOUT_SECONDS}s: {exc}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg) from exc
        except httpx.HTTPStatusError as exc:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"HTTP error {exc.response.status_code}: {exc}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(
                error_msg, status_code=exc.response.status_code
            ) from exc
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

        if not buffer:
            return {}

        try:
            parsed = json.loads(buffer)
        except json.JSONDecodeError as exc:
            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Failed to parse stream JSON: {exc}",
            )
            applogger.error(error_msg)
            raise SecOpsApiError(error_msg) from exc

        # Stream is a JSON array; pick the first batch with real data,
        # logging and skipping heartbeats along the way.
        if isinstance(parsed, dict):
            return parsed

        if not isinstance(parsed, list):
            return {}

        for item in parsed:
            if not isinstance(item, dict):
                continue
            if item.get("heartbeat"):
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
                    f"Batch received with "
                    f"{len(item.get('detections', []))} detections",
                )
            )
            return item

        return {}

    @staticmethod
    def _build_request_body(page_start: str, page_token: Optional[str]) -> dict:
        """Build SecOps API request body.

        Picks pageToken when continuing mid-window, otherwise pageStartTime.
        """
        body = {
            "detectionBatchSize": consts.DETECTION_BATCH_SIZE,
            "maxDetections": consts.MAX_DETECTIONS,
        }

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
        """Check HTTP response status and raise on errors.

        Args:
            response: HTTPX streaming response.
            page_token: Request's pagination token (for diagnostics).
            page_start: Request's start time (for diagnostics).

        Raises:
            SecOpsApiError: On HTTP error responses.
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
                # Streaming responses must be read before .text is accessible
                response.read()
                error_details = response.text[:500]
            except Exception:
                error_details = "Could not read error details"

            error_msg = consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SecOpsClient",
                f"Bad Request (400): {error_details}. "
                f"Params: batchSize={consts.DETECTION_BATCH_SIZE}, "
                f"pageToken={'set' if page_token else 'not set'}",
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

    # ─── Internal: Retry Logic ─────────────────────────────────────────────────

    @staticmethod
    def _should_retry(exc: Exception) -> bool:
        """Return True if the exception is transient and worth retrying.

        Retryable: HTTP 429/5xx, network timeouts, transport errors.
        Not retryable: HTTP 400/401, JSON parse errors.
        """
        if isinstance(exc, SecOpsApiError):
            return exc.status_code in consts.RETRYABLE_STATUS_CODES

        # httpx.TimeoutException is a subclass of RequestError, so this covers both
        return isinstance(exc, httpx.RequestError)

    @staticmethod
    def _sleep_with_backoff(attempt: int) -> None:
        """Sleep with exponential backoff plus jitter before retrying.

        delay = base * 2^attempt + random(0, 1)
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
