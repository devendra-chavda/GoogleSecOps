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
            next_start = batch.get("nextPageStartTime") or batch.get("continuationTime")

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
        """Read and parse first complete JSON batch from streaming response.

        Implements Demisto's line-based parsing with per-message timeout detection.
        Reads response line-by-line until a complete JSON object is assembled,
        timing out if no new line arrives within timeout_seconds.

        Args:
            response: Open httpx streaming response
            timeout_seconds: Max seconds to wait between line arrivals

        Returns:
            Parsed JSON batch dict
        """
        lines = []
        last_line_time = time.time()

        try:
            for line in response.iter_lines():
                # Check for message timeout: no line received for N seconds
                now = time.time()
                time_since_last = now - last_line_time
                if time_since_last > timeout_seconds:
                    applogger.error(
                        "%s: No data received for %d seconds, stream timeout",
                        consts.LOG_PREFIX,
                        timeout_seconds,
                    )
                    raise ChronicleApiError(
                        f"Stream timeout: no data for {timeout_seconds}s"
                    )

                if not line or line.isspace():
                    applogger.debug("%s: received blank line", consts.LOG_PREFIX)
                    continue

                last_line_time = now
                lines.append(line)
                bytes_received = sum(len(l.encode("utf-8")) for l in lines)

                # Log progress every 1 MB
                if bytes_received > 0 and bytes_received % (1024 * 1024) == 0:
                    applogger.info(
                        "%s: stream read... %.2f MB received (%d lines)",
                        consts.LOG_PREFIX,
                        bytes_received / (1024 * 1024),
                        len(lines),
                    )

                # Try to parse accumulated lines as a complete batch
                json_text = "".join(lines)
                try:
                    batch = json.loads(json_text)

                    # Check for heartbeat
                    if isinstance(batch, dict) and batch.get("heartbeat"):
                        applogger.debug("%s: received heartbeat, continuing", consts.LOG_PREFIX)
                        lines = []
                        continue

                    # Complete batch received
                    applogger.info(
                        "%s: batch received (%.2f MB, %d lines), keys=%s",
                        consts.LOG_PREFIX,
                        bytes_received / (1024 * 1024),
                        len(lines),
                        list(batch.keys()) if isinstance(batch, dict) else "array",
                    )
                    return batch

                except json.JSONDecodeError:
                    # Incomplete JSON, keep accumulating lines
                    continue

                except Exception as exc:
                    applogger.error(
                        "%s: error parsing batch: %s",
                        consts.LOG_PREFIX,
                        exc,
                    )
                    raise ChronicleApiError(f"Batch parse error: {exc}") from exc

        except httpx.TimeoutException as exc:
            applogger.error(
                "%s: HTTP read timeout during stream: %s",
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
