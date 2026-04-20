"""Chronicle legacyStreamDetectionAlerts streaming API client.

Uses **httpx** (not requests) because the Chronicle endpoint is a long-running
streaming connection that can remain open for many minutes.  httpx provides:
  - Fine-grained timeout control per phase (connect / read / write).
  - A clean context-manager streaming API (``client.stream()``).
  - Proper HTTP/1.1 keep-alive without manual socket management.

Stream format (per the official Demisto/XSOAR reference implementation)
-----------------------------------------------------------------------
The server sends a never-ending JSON array whose elements arrive incrementally:

    [
      {"heartbeat": true},
      {"detections": [...], "nextPageToken": "abc"},
      {"detections": [...], "nextPageStartTime": "2026-04-20T..."},
      ...
    ]

The outer ``[`` / ``]`` never fully arrives — the connection stays open.
Each element is a *detection batch* dict that may contain:

  heartbeat           keep-alive; ignore.
  error               server-side transient error; reconnect with backoff.
  detections          list of raw detection objects (may be absent).
  nextPageToken       mid-window: save token to checkpoint, keep pageStartTime.
  nextPageStartTime   window exhausted: advance checkpoint pageStartTime,
                      clear pageToken.
  continuationTime    legacy alias for nextPageStartTime (v2 API).

Checkpoint rules (no data loss, no duplication)
------------------------------------------------
  pageToken    saved  -> resume the same window mid-stream next invocation.
  pageStartTime saved -> open a fresh window from that time next invocation.

Reconnection
------------
If the connection drops the client reconnects using the most-recently received
token.  MAX_CONSECUTIVE_FAILURES limits the loop when the API is unavailable.
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


class ChronicleClient:
    """Long-running streaming client for the Chronicle Detection Alerts API."""

    def __init__(
        self,
        auth: GoogleServiceAccountAuth,
        project_id: str = consts.CHRONICLE_PROJECT_ID,
        region: str = consts.CHRONICLE_REGION,
        instance_id: str = consts.CHRONICLE_INSTANCE_ID,
    ):
        if not (project_id and region and instance_id):
            raise ValueError(
                "ChronicleProjectId, ChronicleRegion and ChronicleInstanceId are all required."
            )
        self._auth = auth
        self._endpoint = (
            f"https://{region}-chronicle.googleapis.com/v1alpha/"
            f"projects/{project_id}/locations/{region}/"
            f"instances/{instance_id}/legacy:legacyStreamDetectionAlerts"
        )

    # ── Stream line parser (mirrors Demisto reference parse_stream) ───────────

    @staticmethod
    def _parse_stream(response: httpx.Response) -> Iterator[dict]:
        """Yield one dict per detection batch from the streaming HTTP response.

        The Chronicle server sends a continuous JSON array whose top-level
        elements are delimited by newlines.  Each element is a JSON object.
        We strip the surrounding array punctuation and parse each object
        individually so we can act on it immediately without buffering the
        whole (infinite) array in memory.

        Reference: Demisto GoogleChronicleBackstoryStreamingAPI.parse_stream()
        """
        for line in response.iter_lines():
            if not line:
                continue

            line = line.strip()

            # Skip JSON array wrapper characters and bare commas.
            if line in ("[", "]", ",", "[,"):
                continue

            # Strip a trailing comma left by the array format:  {...},
            line = line.rstrip(",")

            if "{" not in line:
                continue

            # Extract the JSON object: from first '{' to last '}' (inclusive).
            # Input:  "  {\"heartbeat\": true},  "
            # Output: "{\"heartbeat\": true}"
            try:
                json_string = "{" + line.split("{", 1)[1].rsplit("}", 1)[0] + "}"
                yield json.loads(json_string)
            except (json.JSONDecodeError, IndexError) as exc:
                applogger.warning(
                    "%s: _parse_stream: unparseable line (skipping): %r — %s",
                    consts.LOG_PREFIX,
                    line[:300],
                    exc,
                )

    # ── Single streaming connection ───────────────────────────────────────────

    def _open_stream(
        self,
        body: dict,
        deadline_epoch: Optional[float],
    ) -> Tuple[bool, Optional[str], Optional[str], list]:
        """Open one httpx streaming POST and consume every batch.

        Reads batches until the window is exhausted (nextPageStartTime received),
        the time budget is hit, or the server closes the connection.

        Args:
            body:           Chronicle API request body dict.
            deadline_epoch: Unix timestamp; stop when time.time() >= this.

        Returns:
            (got_data, last_page_token, last_page_start_time, accumulated_detections)

            got_data                 True when at least one non-heartbeat
                                     batch was received.
            last_page_token          Most-recent nextPageToken (None if absent).
            last_page_start_time     Most-recent nextPageStartTime /
                                     continuationTime (None if absent).
            accumulated_detections   All detections collected from every batch
                                     in this connection; the caller buffers
                                     these to 50 MB files.
        """
        access_token = self._auth.get_access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        # Chronicle heartbeats arrive every ~15 s so a 300 s read timeout is safe.
        timeout = httpx.Timeout(
            connect=30.0,
            read=float(consts.API_TIMEOUT_SECONDS),
            write=30.0,
            pool=30.0,
        )

        got_data = False
        last_page_token: Optional[str] = None
        last_page_start_time: Optional[str] = None
        accumulated_detections: list = []

        applogger.info(
            "%s: _open_stream: POST %s  body_keys=%s",
            consts.LOG_PREFIX,
            self._endpoint,
            list(body.keys()),
        )

        with httpx.Client(timeout=timeout) as http_client:
            with http_client.stream(
                "POST", self._endpoint, headers=headers, json=body
            ) as response:

                # ── HTTP error handling ───────────────────────────────────────
                if response.status_code == 401:
                    err_body = response.read().decode()
                    raise ChronicleApiError(
                        "Unauthorized (401). Check service-account permissions.",
                        status_code=401,
                        body=err_body,
                    )
                if response.status_code >= 400:
                    err_body = response.read().decode()
                    raise ChronicleApiError(
                        f"HTTP {response.status_code}: {err_body[:500]}",
                        status_code=response.status_code,
                        body=err_body,
                    )

                applogger.info(
                    "%s: _open_stream: HTTP 200 — consuming batches",
                    consts.LOG_PREFIX,
                )

                for batch in self._parse_stream(response):

                    # ── Server-side error inside the stream ───────────────────
                    if "error" in batch:
                        err = batch["error"]
                        applogger.error(
                            "%s: server error in stream batch: code=%s  message=%s",
                            consts.LOG_PREFIX,
                            err.get("code"),
                            err.get("message", ""),
                        )
                        # Return what we have; the outer loop will reconnect.
                        return (
                            got_data,
                            last_page_token,
                            last_page_start_time,
                            accumulated_detections,
                        )

                    # ── Heartbeat ─────────────────────────────────────────────
                    if batch.get("heartbeat"):
                        applogger.debug("%s: heartbeat (keep-alive)", consts.LOG_PREFIX)
                        continue

                    # ── Real detection batch ──────────────────────────────────
                    got_data = True
                    detections: list = batch.get("detections", []) or []
                    next_page_token: Optional[str] = batch.get("nextPageToken")
                    # nextPageStartTime (v1-alpha) or continuationTime (v2)
                    # both signal that the current window is exhausted.
                    next_page_start_time: Optional[str] = (
                        batch.get("nextPageStartTime")
                        or batch.get("continuationTime")
                    )

                    applogger.info(
                        "%s: batch — detections=%d  nextPageToken=%s  nextPageStartTime=%s",
                        consts.LOG_PREFIX,
                        len(detections),
                        "present" if next_page_token else "none",
                        next_page_start_time or "none",
                    )

                    # Accumulate detections; the caller flushes to 50 MB files.
                    if detections:
                        accumulated_detections.extend(detections)

                    # Track tokens so the outer loop can resume on reconnect.
                    if next_page_token:
                        last_page_token = next_page_token
                    if next_page_start_time:
                        last_page_start_time = next_page_start_time
                        last_page_token = None  # superseded by the new start time

                    # Window exhausted — return immediately so the caller can
                    # flush the buffer and advance the checkpoint.
                    if next_page_start_time:
                        return (
                            got_data,
                            last_page_token,
                            last_page_start_time,
                            accumulated_detections,
                        )

                    # Per-batch time-budget check.
                    if deadline_epoch and time.time() >= deadline_epoch:
                        applogger.info(
                            "%s: time budget exhausted mid-stream", consts.LOG_PREFIX
                        )
                        return (
                            got_data,
                            last_page_token,
                            last_page_start_time,
                            accumulated_detections,
                        )

        applogger.info("%s: stream connection closed normally", consts.LOG_PREFIX)
        return got_data, last_page_token, last_page_start_time, accumulated_detections

    # ── Public iterator with reconnect / retry loop ───────────────────────────

    def stream_detection_batches(
        self,
        page_start_time: str = "",
        page_token: Optional[str] = None,
        deadline_epoch: Optional[float] = None,
    ) -> Iterator[Tuple[list, Optional[str], Optional[str]]]:
        """Yield *(detections, next_page_token, next_page_start_time)* per batch.

        Implements the reconnect retry loop from the Demisto reference
        (``stream_detection_alerts_in_retry_loop``).  Each iteration opens one
        httpx streaming connection.  If the connection drops before the window is
        exhausted, the method sleeps with exponential backoff and reconnects
        using the last-received token so no data is lost or re-fetched.

        Yields
        ------
        detections              All raw detections collected since the last yield.
                                May be an empty list for a heartbeat-only batch
                                (those are already filtered out internally).
        next_page_token         Non-None: mid-window; save to checkpoint.
                                Do NOT advance pageStartTime yet.
        next_page_start_time    Non-None: window exhausted; save as the new
                                checkpoint pageStartTime and clear pageToken.

        Stops when:
          - nextPageStartTime received (window fully consumed).
          - time budget (deadline_epoch) exceeded.
          - MAX_CONSECUTIVE_FAILURES consecutive failures.

        Raises
        ------
        ChronicleApiError        Non-retryable HTTP error (401, 400, etc.).
        ChronicleConnectorError  Too many consecutive stream failures.
        """
        current_page_token: Optional[str] = page_token
        current_page_start_time: str = page_start_time
        consecutive_failures = 0

        while True:

            # ── Guard ─────────────────────────────────────────────────────────
            if consecutive_failures > consts.MAX_CONSECUTIVE_FAILURES:
                raise ChronicleConnectorError(
                    f"Aborting: {consecutive_failures} consecutive stream failures."
                )

            # ── Exponential backoff ───────────────────────────────────────────
            if consecutive_failures > 0:
                delay = (
                    consts.RETRY_BASE_DELAY_SECONDS * (2 ** consecutive_failures)
                    + random.uniform(0, 1.0)
                )
                applogger.warning(
                    "%s: retry %d/%d — sleeping %.1f s",
                    consts.LOG_PREFIX,
                    consecutive_failures,
                    consts.MAX_CONSECUTIVE_FAILURES,
                    delay,
                )
                time.sleep(delay)

            # ── Build request body ────────────────────────────────────────────
            body: dict = {"detectionBatchSize": consts.DETECTION_BATCH_SIZE}
            if current_page_token:
                body["pageToken"] = current_page_token
            else:
                body["pageStartTime"] = current_page_start_time

            # ── Open one streaming connection ─────────────────────────────────
            try:
                got_data, last_token, last_start_time, pending = self._open_stream(
                    body, deadline_epoch
                )

            except ChronicleApiError as exc:
                if exc.status_code not in consts.RETRYABLE_STATUS_CODES:
                    raise  # 401, 400, 404 — caller must handle
                applogger.warning(
                    "%s: retryable HTTP %s; scheduling retry",
                    consts.LOG_PREFIX,
                    exc.status_code,
                )
                consecutive_failures += 1
                continue

            except (httpx.TimeoutException, httpx.RequestError) as exc:
                applogger.warning(
                    "%s: httpx network error: %s — scheduling retry",
                    consts.LOG_PREFIX,
                    exc,
                )
                consecutive_failures += 1
                continue

            except Exception:
                applogger.exception(
                    "%s: unexpected error in streaming; scheduling retry",
                    consts.LOG_PREFIX,
                )
                consecutive_failures += 1
                continue

            # ── Yield all detections collected from this connection ───────────
            # The caller (GoogleSecOpsToStorage) accumulates them into 50 MB
            # files and updates the checkpoint with the latest tokens.
            if pending or last_token or last_start_time:
                yield pending, last_token, last_start_time

            # ── Decide what to do next ────────────────────────────────────────
            if last_start_time:
                # Window fully consumed.
                applogger.info(
                    "%s: window exhausted (nextPageStartTime=%s); done",
                    consts.LOG_PREFIX,
                    last_start_time,
                )
                return

            if deadline_epoch and time.time() >= deadline_epoch:
                applogger.info(
                    "%s: time budget exhausted; exiting stream loop",
                    consts.LOG_PREFIX,
                )
                return

            if got_data:
                # Connection dropped after real data — reconnect with latest token.
                consecutive_failures = 0
                if last_token:
                    current_page_token = last_token
                elif last_start_time:
                    current_page_start_time = last_start_time
                    current_page_token = None
                applogger.info(
                    "%s: reconnecting after data (pageToken=%s)",
                    consts.LOG_PREFIX,
                    "present" if current_page_token else "none",
                )
            else:
                # No data received — increment failure counter.
                consecutive_failures += 1
                applogger.info(
                    "%s: no data received; consecutive_failures=%d",
                    consts.LOG_PREFIX,
                    consecutive_failures,
                )
