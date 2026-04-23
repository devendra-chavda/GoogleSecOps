"""Chronicle API polling client for detection alerts."""

import json
import random
import time
from typing import Iterator, Optional, Tuple

import httpx

from . import consts
from .exceptions import ChronicleApiError, ChronicleConnectorError
from .google_auth import GoogleServiceAccountAuth
from .logger import applogger


class ChronicleClient:
    """Chronicle Detection Alerts API polling client."""

    def __init__(
        self,
        auth: GoogleServiceAccountAuth,
        project_id: str = consts.CHRONICLE_PROJECT_ID,
        region: str = consts.CHRONICLE_REGION,
        instance_id: str = consts.CHRONICLE_INSTANCE_ID,
    ):
        if not all([project_id, region, instance_id]):
            raise ValueError("Missing Chronicle project/region/instance config")
        self._auth = auth
        self._endpoint = (
            f"https://{region}-chronicle.googleapis.com/v1alpha/"
            f"projects/{project_id}/locations/{region}/"
            f"instances/{instance_id}/legacy:legacyStreamDetectionAlerts"
        )

    def poll_detection_batches(
        self,
        page_start_time: str = "",
        page_token: Optional[str] = None,
        deadline_epoch: Optional[float] = None,
    ) -> Iterator[Tuple[dict, Optional[str], Optional[str]]]:
        """Poll API for detection batches with automatic retry on failure.

        Yields: (batch_dict, next_page_token, next_page_start_time)
        """
        current_token = page_token
        current_start = page_start_time
        failures = 0

        while True:
            if failures > consts.MAX_CONSECUTIVE_FAILURES:
                raise ChronicleConnectorError(f"Too many API failures: {failures}")

            if failures > 0:
                self._sleep_with_backoff(failures)

            try:
                batch = self._make_api_call(
                    current_start, current_token, deadline_epoch
                )
            except Exception as exc:
                if not self._should_retry(exc):
                    raise
                failures += 1
                applogger.warning(f"{consts.LOG_PREFIX}: API call failed, will retry")
                continue

            failures = 0
            next_token = batch.get("nextPageToken")
            next_start = batch.get("nextPageStartTime")
            applogger.info(
                "%s: batch received (token=%s start=%s)",
                consts.LOG_PREFIX,
                "yes" if next_token else "no",
                "yes" if next_start else "no",
            )

            yield batch, next_token, next_start

            if next_start:
                applogger.info("%s: window complete", consts.LOG_PREFIX)
                return
            if deadline_epoch and time.time() >= deadline_epoch:
                applogger.info("%s: time budget exhausted", consts.LOG_PREFIX)
                return

            current_token = next_token or current_token
            current_start = next_start or current_start

    def _make_api_call(
        self, page_start: str, page_token: Optional[str], deadline: Optional[float]
    ) -> dict:
        """Make single API call using streaming to avoid buffering large responses."""
        if deadline and time.time() >= deadline:
            raise ChronicleConnectorError("Time budget exhausted")

        body = {
            "detectionBatchSize": consts.DETECTION_BATCH_SIZE,
            "maxDetections": consts.MAX_DETECTIONS,
        }
        if page_token:
            body["pageToken"] = page_token
        else:
            body["pageStartTime"] = page_start

        headers = {
            "Authorization": f"Bearer {self._auth.get_access_token()}",
            "Content-Type": "application/json",
        }

        timeout = httpx.Timeout(
            connect=30.0,
            read=float(consts.API_TIMEOUT_SECONDS),
            write=30.0,
            pool=30.0,
        )

        applogger.info(
            "%s: making API call (timeout=%ds, batchSize=%d, maxDetections=%d)",
            consts.LOG_PREFIX,
            consts.API_TIMEOUT_SECONDS,
            consts.DETECTION_BATCH_SIZE,
            consts.MAX_DETECTIONS,
        )

        try:
            applogger.info("%s: opening HTTP connection with streaming", consts.LOG_PREFIX)
            # TODO: REMOVE - Response wait time tracking
            request_start = time.time()

            # Use streaming=True to avoid buffering entire response
            with httpx.Client(timeout=timeout) as client:
                applogger.info("%s: sending POST request (stream=True)", consts.LOG_PREFIX)

                with client.stream("POST", self._endpoint, headers=headers, json=body) as response:
                    request_elapsed = time.time() - request_start
                    # TODO: REMOVE - Log API response wait time
                    applogger.info(
                        "%s: HTTP response received (status=%d, wait=%.2fs)",
                        consts.LOG_PREFIX,
                        response.status_code,
                        request_elapsed,
                    )

                    if response.status_code == 401:
                        applogger.error("%s: Unauthorized (401)", consts.LOG_PREFIX)
                        raise ChronicleApiError("Unauthorized (401)", status_code=401)
                    if response.status_code >= 400:
                        applogger.error(
                            "%s: HTTP error %d", consts.LOG_PREFIX, response.status_code
                        )
                        raise ChronicleApiError(
                            f"HTTP {response.status_code}",
                            status_code=response.status_code,
                        )

                    # Read streaming response with per-message timeout (Demisto approach)
                    applogger.info(
                        "%s: reading streaming response, timeout=%ds between messages",
                        consts.LOG_PREFIX,
                        consts.API_TIMEOUT_SECONDS,
                    )

                    batch = self._read_stream_batch(response, consts.API_TIMEOUT_SECONDS)
                    return batch

        except httpx.RequestError as exc:
            applogger.error("%s: HTTP request failed: %s", consts.LOG_PREFIX, exc)
            raise ChronicleApiError(f"Network error: {exc}") from exc
        except Exception as exc:
            applogger.error(
                "%s: unexpected error in API call: %s",
                consts.LOG_PREFIX,
                exc,
            )
            raise ChronicleApiError(f"Error: {exc}") from exc

    def _read_stream_batch(self, response: "httpx.Response", timeout_seconds: int) -> dict:
        """Read and parse first complete JSON batch from never-ending streaming array.

        Chronicle sends a never-closing JSON array: [{batch1}, {batch2}, ...]
        Uses brace-depth tracking to extract individual batch objects.
        Times out if no new line arrives within timeout_seconds.

        Args:
            response: Open httpx streaming response
            timeout_seconds: Max seconds to wait between line arrivals

        Returns:
            Parsed JSON batch dict
        """
        depth = 0
        buf = []
        in_string = False
        escape_next = False
        last_line_time = time.time()
        total_bytes = 0

        try:
            for line in response.iter_lines():
                # Check for message timeout
                now = time.time()
                time_since_last = now - last_line_time
                if time_since_last > timeout_seconds and depth > 0:
                    applogger.error(
                        "%s: No data received for %d seconds, stream timeout",
                        consts.LOG_PREFIX,
                        timeout_seconds,
                    )
                    raise ChronicleApiError(
                        f"Stream timeout: no data for {timeout_seconds}s"
                    )

                if not line or line.isspace():
                    continue

                last_line_time = now
                total_bytes += len(line.encode("utf-8"))

                # Log progress every 1 MB
                if total_bytes > 0 and total_bytes % (1024 * 1024) == 0:
                    applogger.debug(
                        "%s: stream read... %.2f MB received",
                        consts.LOG_PREFIX,
                        total_bytes / (1024 * 1024),
                    )

                # Brace-depth tracking to extract individual batch objects
                for ch in line:
                    # Handle string escape sequences
                    if escape_next:
                        escape_next = False
                        if depth > 0:
                            buf.append(ch)
                        continue

                    if ch == "\\" and in_string:
                        escape_next = True
                        if depth > 0:
                            buf.append(ch)
                        continue

                    if ch == '"':
                        in_string = not in_string
                        if depth > 0:
                            buf.append(ch)
                        continue

                    if in_string:
                        if depth > 0:
                            buf.append(ch)
                        continue

                    # Brace depth tracking (outside strings)
                    if ch == "{":
                        depth += 1
                        buf.append(ch)
                    elif ch == "}":
                        if depth > 0:
                            buf.append(ch)
                            depth -= 1
                            if depth == 0:
                                # Complete batch object found
                                json_string = "".join(buf)
                                buf = []
                                try:
                                    batch = json.loads(json_string)
                                    applogger.debug(
                                        "%s: batch received (%.2f MB), keys=%s",
                                        consts.LOG_PREFIX,
                                        total_bytes / (1024 * 1024),
                                        list(batch.keys()) if isinstance(batch, dict) else "array",
                                    )

                                    # Check for heartbeat
                                    if isinstance(batch, dict) and batch.get("heartbeat"):
                                        applogger.debug(
                                            "%s: received heartbeat",
                                            consts.LOG_PREFIX,
                                        )
                                        continue

                                    # Return first non-heartbeat batch
                                    return batch

                                except json.JSONDecodeError as exc:
                                    applogger.warning(
                                        "%s: JSON decode error in batch: %s",
                                        consts.LOG_PREFIX,
                                        exc,
                                    )
                    elif depth > 0:
                        buf.append(ch)

        except httpx.TimeoutException as exc:
            applogger.error(
                "%s: HTTP read timeout: %s",
                consts.LOG_PREFIX,
                exc,
            )
            raise ChronicleApiError(f"Stream read timeout: {exc}") from exc
        except Exception as exc:
            applogger.error(
                "%s: error reading stream: %s",
                consts.LOG_PREFIX,
                exc,
            )
            raise ChronicleApiError(f"Stream read error: {exc}") from exc

    def _should_retry(self, exc: Exception) -> bool:
        """Check if exception is retryable."""
        if isinstance(exc, ChronicleApiError):
            return exc.status_code in consts.RETRYABLE_STATUS_CODES
        return isinstance(exc, (httpx.TimeoutException, httpx.RequestError))

    def _sleep_with_backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff."""
        delay = (
            consts.RETRY_BASE_DELAY_SECONDS * (2 ** attempt)
            + random.uniform(0, 1.0)
        )
        applogger.warning(
            "%s: retry %d/%d, sleeping %.1f s",
            consts.LOG_PREFIX,
            attempt,
            consts.MAX_CONSECUTIVE_FAILURES,
            delay,
        )
        time.sleep(delay)
