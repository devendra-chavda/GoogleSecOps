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
        """Make single API call and return batch."""
        if deadline and time.time() >= deadline:
            raise ChronicleConnectorError("Time budget exhausted")

        body = {"detectionBatchSize": consts.DETECTION_BATCH_SIZE}
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
            "%s: making API call (timeout=%ds, batchSize=%d)",
            consts.LOG_PREFIX,
            consts.API_TIMEOUT_SECONDS,
            consts.DETECTION_BATCH_SIZE,
        )

        try:
            applogger.debug("%s: opening HTTP connection", consts.LOG_PREFIX)
            # TODO: REMOVE - Response wait time tracking for debugging
            request_start = time.time()
            with httpx.Client(timeout=timeout) as client:
                applogger.debug("%s: sending POST request", consts.LOG_PREFIX)
                response = client.post(self._endpoint, headers=headers, json=body)
                request_elapsed = time.time() - request_start
                # TODO: REMOVE - Log API response wait time
                applogger.info(
                    "%s: HTTP response received (status=%d, size=%s, wait=%.2fs)",
                    consts.LOG_PREFIX,
                    response.status_code,
                    response.headers.get("content-length", "unknown"),
                    request_elapsed,
                )
        except httpx.RequestError as exc:
            applogger.error("%s: HTTP request failed: %s", consts.LOG_PREFIX, exc)
            raise ChronicleApiError(f"Network error: {exc}") from exc

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

        # FIX: Check content length before trying to read entire response
        content_length_str = response.headers.get("content-length", "0")
        try:
            content_length = int(content_length_str)
        except (ValueError, TypeError):
            content_length = 0

        MAX_RESPONSE_SIZE = 500 * 1024 * 1024  # 500 MB limit

        if content_length > MAX_RESPONSE_SIZE:
            applogger.error(
                "%s: Response too large: %.2f MB (exceeds limit of %.2f MB)",
                consts.LOG_PREFIX,
                content_length / (1024 * 1024),
                MAX_RESPONSE_SIZE / (1024 * 1024),
            )
            raise ChronicleApiError(
                f"Response too large: {content_length / (1024 * 1024):.2f} MB"
            )

        # Warn if response is very large but still acceptable
        if content_length > 100 * 1024 * 1024:
            applogger.warning(
                "%s: WARNING - Large response: %.2f MB (parsing may be slow)",
                consts.LOG_PREFIX,
                content_length / (1024 * 1024),
            )

        try:
            # TODO: REMOVE - JSON parsing time tracking
            parse_start = time.time()
            applogger.debug(
                "%s: parsing JSON response (size=%d bytes)",
                consts.LOG_PREFIX,
                content_length,
            )

            # Read with timeout to prevent hanging
            applogger.debug("%s: reading response body", consts.LOG_PREFIX)
            body_text = response.text
            applogger.debug(
                "%s: response body read (%d bytes)", consts.LOG_PREFIX, len(body_text)
            )

            applogger.debug("%s: decoding JSON", consts.LOG_PREFIX)
            batch = json.loads(body_text)

            parse_elapsed = time.time() - parse_start
            # TODO: REMOVE - Log JSON parsing time
            applogger.debug(
                "%s: JSON parsed successfully (%.2fs), keys=%s",
                consts.LOG_PREFIX,
                parse_elapsed,
                list(batch.keys()) if isinstance(batch, dict) else "array",
            )
            return batch
        except json.JSONDecodeError as exc:
            applogger.error(
                "%s: JSON decode error: %s, first 500 chars: %s",
                consts.LOG_PREFIX,
                exc,
                response.text[:500] if hasattr(response, 'text') else "N/A",
            )
            raise ChronicleApiError(f"Invalid JSON response: {exc}") from exc
        except Exception as exc:
            applogger.error(
                "%s: unexpected error parsing response: %s",
                consts.LOG_PREFIX,
                exc,
            )
            raise ChronicleApiError(f"Error parsing response: {exc}") from exc

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
