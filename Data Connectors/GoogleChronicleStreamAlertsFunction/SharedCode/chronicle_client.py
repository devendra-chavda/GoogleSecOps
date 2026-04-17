"""Chronicle legacyStreamDetectionAlerts API client.

Endpoint:
  POST https://{region}-chronicle.googleapis.com/v1alpha/projects/{project}/
       locations/{region}/instances/{instance}/legacy:legacyStreamDetectionAlerts

Request body:
  - First call:  { "pageStartTime": "<ISO>", "detectionBatchSize": N, "maxDetections": N }
  - Token call:  { "pageToken": "<token>", "detectionBatchSize": N, "maxDetections": N }

Response shape (2-element array):
  [
    { "heartbeat": true, "nextPageToken"?: "...", "nextPageStartTime"?: "..." },
    { "detections": [ ... ] }
  ]

Pagination rules:
  - `nextPageToken` present  -> more pages remain; next request sends ONLY
    `pageToken` (no `pageStartTime`).
  - `nextPageStartTime` present -> window fully consumed; persist this value
    as the checkpoint for the next scheduled trigger.
  - Both absent (heartbeat only, no data) -> window is empty; no checkpoint
    update needed.
"""
from typing import Iterator, Optional, Tuple

import requests

from . import consts
from .exceptions import ChronicleApiError
from .google_auth import GoogleServiceAccountAuth
from .logger import applogger
from .utils import retry_on_exception


class ChronicleClient:
    def __init__(
        self,
        auth: GoogleServiceAccountAuth,
        project_id: str = consts.CHRONICLE_PROJECT_ID,
        region: str = consts.CHRONICLE_REGION,
        instance_id: str = consts.CHRONICLE_INSTANCE_ID,
    ):
        if not (project_id and region and instance_id):
            raise ValueError(
                "ChronicleProjectId, ChronicleRegion and ChronicleInstanceId are required."
            )
        self._auth = auth
        self._endpoint = (
            f"https://{region}-chronicle.googleapis.com/v1alpha/"
            f"projects/{project_id}/locations/{region}/"
            f"instances/{instance_id}/legacy:legacyStreamDetectionAlerts"
        )

    @retry_on_exception(
        exceptions=(requests.RequestException, ChronicleApiError),
        max_retries=consts.MAX_RETRIES,
    )
    def _post(self, body: dict) -> list:
        headers = {
            "Authorization": f"Bearer {self._auth.get_access_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        resp = requests.post(
            self._endpoint,
            headers=headers,
            json=body,
            timeout=consts.API_TIMEOUT_SECONDS,
        )
        if resp.status_code == 401:
            raise ChronicleApiError(
                "Unauthorized (401). Verify service-account permissions.",
                status_code=401,
                body=resp.text,
            )
        if resp.status_code in consts.RETRYABLE_STATUS_CODES:
            raise ChronicleApiError(
                f"Retryable error {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
                body=resp.text,
            )
        if resp.status_code >= 400:
            raise ChronicleApiError(
                f"Chronicle API error {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
                body=resp.text,
            )
        data = resp.json()
        if not isinstance(data, list) or len(data) < 2:
            raise ChronicleApiError(
                f"Unexpected response shape: {str(data)[:500]}",
                status_code=resp.status_code,
                body=resp.text,
            )
        return data

    @staticmethod
    def _parse_response(data: list) -> Tuple[list, Optional[str], Optional[str]]:
        control = data[0] if isinstance(data[0], dict) else {}
        payload = data[1] if isinstance(data[1], dict) else {}
        detections = payload.get("detections", []) or []
        return (
            detections,
            control.get("nextPageToken"),
            control.get("nextPageStartTime"),
        )

    def stream_detections(
        self,
        page_start_time: str,
        detection_batch_size: int = consts.DETECTION_BATCH_SIZE,
        max_detections: int = consts.MAX_DETECTIONS,
        deadline_epoch: Optional[float] = None,
    ) -> Iterator[Tuple[list, Optional[str]]]:
        """Yield (detections, next_page_start_time) per API page.

        Pagination flow:
          1. First request uses `pageStartTime`.
          2. If response has `nextPageToken` -> build next request with ONLY
             `pageToken` (no pageStartTime). Yield detections with
             next_page_start_time=None.
          3. If response has `nextPageStartTime` -> yield detections with
             that value. Caller persists it as the new checkpoint. Stop.
          4. If neither token nor start-time -> empty window. Stop.
        """
        import time as _time

        page = 0

        # --- first request: uses pageStartTime ---
        body = {
            "pageStartTime": page_start_time,
            "detectionBatchSize": detection_batch_size,
            "maxDetections": max_detections,
        }

        while True:
            page += 1
            applogger.info(
                "%s: page=%d, request keys=%s",
                consts.LOG_PREFIX,
                page,
                list(body.keys()),
            )

            data = self._post(body)
            detections, next_page_token, next_page_start_time = self._parse_response(data)

            if next_page_start_time:
                # Window exhausted — yield with the new checkpoint and stop.
                applogger.info(
                    "%s: received nextPageStartTime=%s after %d pages",
                    consts.LOG_PREFIX,
                    next_page_start_time,
                    page,
                )
                yield detections, next_page_start_time
                return

            if next_page_token:
                # More pages — yield detections (no checkpoint yet), continue.
                yield detections, None

                if deadline_epoch and _time.time() >= deadline_epoch:
                    applogger.warning(
                        "%s: time budget reached after %d pages; stopping without advancing checkpoint",
                        consts.LOG_PREFIX,
                        page,
                    )
                    return

                # Next request uses ONLY pageToken, not pageStartTime.
                body = {
                    "pageToken": next_page_token,
                    "detectionBatchSize": detection_batch_size,
                    "maxDetections": max_detections,
                }
                continue

            # Neither token nor start-time — heartbeat-only / empty window.
            applogger.info(
                "%s: empty window (heartbeat only) after %d pages",
                consts.LOG_PREFIX,
                page,
            )
            yield detections, None
            return
