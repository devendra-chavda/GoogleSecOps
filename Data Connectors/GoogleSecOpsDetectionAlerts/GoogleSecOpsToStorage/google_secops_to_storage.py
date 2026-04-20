"""Fetch Google SecOps detection alerts and write them to Azure File Share.

Design
------
Each timer invocation of this function:

1.  Loads checkpoint from Azure File Share.
    Checkpoint format: {"pageStartTime": "<ISO>", "pageToken": "<token|null>"}

2.  Opens a long-running httpx streaming connection to the Chronicle
    legacyStreamDetectionAlerts API using ChronicleClient.stream_detection_batches().

3.  As detection batches arrive from the stream they are appended to an
    in-memory buffer.  When the buffer reaches MAX_FILE_SIZE (50 MB) it is
    flushed to a uniquely named file in the Azure File Share data share and
    the buffer is reset.  This ensures:
      - No single Azure File is larger than 50 MB.
      - Data is persisted progressively; a crash does not lose everything.
      - The companion AzureStorageToSentinel function ingests only complete,
        flushed files (it filters by file age).

4.  After each stream batch the checkpoint is updated immediately:
      nextPageToken present    → save token (keep pageStartTime unchanged)
      nextPageStartTime present → save new pageStartTime, clear token

    Writing the checkpoint BEFORE the next API call means a crash never
    silently discards a received page — the window can be retried from the
    last known-good token.

5.  After all batches are consumed (or the function time budget is exhausted)
    any remaining buffered detections are flushed to a final file.

Data-file naming
----------------
    google_secops_raw_<invocation_epoch>_<file_index>

<invocation_epoch> makes names globally unique across function invocations.
<file_index>       orders files within a single invocation.

Checkpoint / pagination guarantee
----------------------------------
nextPageToken received  → next invocation resumes mid-window (no data loss).
nextPageStartTime received → next invocation opens the next fresh window.
If the function is interrupted mid-window, the saved pageToken guarantees
that the window can be retried from the last completed page.
"""

import inspect
import json
import time

from ..SharedCode import consts
from ..SharedCode.chronicle_client import ChronicleClient
from ..SharedCode.exceptions import ChronicleConnectorError
from ..SharedCode.google_auth import GoogleServiceAccountAuth
from ..SharedCode.logger import applogger
from ..SharedCode.state_manager import StateManager


class GoogleSecOpsToStorage:
    """Orchestrate Chronicle streaming API → Azure File Share ingestion."""

    def __init__(self, start_epoch: str) -> None:
        self._fn = consts.FUNCTION_NAME_FETCHER
        self._start_epoch = start_epoch
        self._check_env_vars()

        self._auth = GoogleServiceAccountAuth()
        self._client = ChronicleClient(self._auth)

        self._checkpoint = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=consts.CHECKPOINT_FILE_NAME,
            share_name=consts.FILE_SHARE_NAME,
        )

    # ── Environment validation ────────────────────────────────────────────────

    def _check_env_vars(self) -> None:
        __method_name = inspect.currentframe().f_code.co_name
        required = [
            ("ChronicleProjectId", consts.CHRONICLE_PROJECT_ID),
            ("ChronicleRegion", consts.CHRONICLE_REGION),
            ("ChronicleInstanceId", consts.CHRONICLE_INSTANCE_ID),
            ("ChronicleServiceAccountJson", consts.SERVICE_ACCOUNT_JSON)
        ]
        missing = [name for name, val in required if not val]
        if missing:
            applogger.error(
                "%s (%s): missing env vars: %s",
                consts.LOG_PREFIX,
                __method_name,
                missing,
            )
            raise ValueError(f"Missing required environment variables: {missing}")

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self) -> None:
        """Fetch all available detection batches and persist to Azure File Share."""
        __method_name = inspect.currentframe().f_code.co_name

        page_start_time, page_token = self._checkpoint.resolve_initial_start_time(
            consts.INPUT_START_TIME
        )
        applogger.info(
            "%s (%s): starting — pageStartTime=%s  pageToken=%s",
            consts.LOG_PREFIX,
            __method_name,
            page_start_time,
            "present" if page_token else "none",
        )

        deadline = time.time() + consts.FUNCTION_BUDGET_SECONDS

        # 50 MB rolling buffer: accumulate raw detection dicts until the
        # serialised size reaches MAX_FILE_SIZE, then flush to Azure File Share.
        buffer: list = []
        buffer_bytes: int = 0
        file_index: int = 0
        total_detections: int = 0

        try:
            for detections, next_page_token, next_page_start_time in (
                self._client.stream_detection_batches(
                    page_start_time=page_start_time,
                    page_token=page_token,
                    deadline_epoch=deadline,
                )
            ):
                # ── 1. Add detections to the rolling buffer ───────────────────
                for det in detections:
                    det_bytes = len(json.dumps(det).encode("utf-8"))

                    # If adding this detection would exceed 50 MB, flush first.
                    if buffer and buffer_bytes + det_bytes > consts.MAX_FILE_SIZE:
                        file_index += 1
                        self._flush_buffer(buffer, file_index)
                        total_detections += len(buffer)
                        buffer = []
                        buffer_bytes = 0

                    buffer.append(det)
                    buffer_bytes += det_bytes

                applogger.info(
                    "%s (%s): buffer — %d dets in memory (%.2f MB)",
                    consts.LOG_PREFIX,
                    __method_name,
                    len(buffer),
                    buffer_bytes / (1024 * 1024),
                )

                # ── 2. Update checkpoint after every batch ────────────────────
                if next_page_start_time:
                    # Window exhausted — advance pageStartTime, clear token.
                    self._checkpoint.set_checkpoint(
                        page_start_time=next_page_start_time,
                        page_token=None,
                    )
                    applogger.info(
                        "%s (%s): checkpoint advanced → nextPageStartTime=%s",
                        consts.LOG_PREFIX,
                        __method_name,
                        next_page_start_time,
                    )

                elif next_page_token:
                    # Mid-window — save token; keep current pageStartTime so
                    # the window can be fully retried on failure.
                    self._checkpoint.set_checkpoint(
                        page_start_time=page_start_time,
                        page_token=next_page_token,
                    )
                    applogger.info(
                        "%s (%s): mid-window checkpoint saved (pageToken present)",
                        consts.LOG_PREFIX,
                        __method_name,
                    )

                else:
                    # Neither token — empty / heartbeat window; do not update.
                    applogger.info(
                        "%s (%s): no token in batch; checkpoint unchanged",
                        consts.LOG_PREFIX,
                        __method_name,
                    )

        except ChronicleConnectorError:
            applogger.exception(
                "%s (%s): aborting — checkpoint holds last successful position",
                consts.LOG_PREFIX,
                __method_name,
            )
            # Fall through to flush so we don't lose buffered detections.

        # ── 3. Flush the final (possibly partial) buffer ─────────────────────
        if buffer:
            file_index += 1
            self._flush_buffer(buffer, file_index)
            total_detections += len(buffer)

        applogger.info(
            "%s (%s): complete — files_written=%d  total_detections=%d",
            consts.LOG_PREFIX,
            __method_name,
            file_index,
            total_detections,
        )

    # ── Buffer flush ──────────────────────────────────────────────────────────

    def _flush_buffer(self, buffer: list, file_index: int) -> None:
        """Serialise *buffer* and write it as a JSON file to Azure File Share.

        File name: google_secops_raw_<invocation_epoch>_<file_index>

        The file contains a JSON array of raw detection dicts.
        The AzureStorageToSentinel function reads these files, transforms each
        detection, and posts them to the Log Analytics Workspace.

        Args:
            buffer:     List of raw detection dicts to persist.
            file_index: Monotonically increasing index within this invocation.
        """
        __method_name = inspect.currentframe().f_code.co_name
        file_name = f"{consts.FILE_NAME_PREFIX}_{self._start_epoch}_{file_index}"
        payload = json.dumps(buffer)
        payload_mb = len(payload.encode("utf-8")) / (1024 * 1024)

        sm = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=file_name,
            share_name=consts.FILE_SHARE_NAME_DATA,
        )
        sm.post(payload)

        applogger.info(
            "%s (%s): flushed %d detections → '%s' (%.2f MB)",
            consts.LOG_PREFIX,
            __method_name,
            len(buffer),
            file_name,
            payload_mb,
        )
