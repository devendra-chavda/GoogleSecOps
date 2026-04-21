"""Read buffered detection files from Azure File Share and ingest into Sentinel.

Design
------
This function is the second half of the two-function pipeline:

    GoogleSecOpsToStorage      →  Azure File Share  →  AzureStorageToSentinel
    (fetcher, writes raw JSON)                         (ingester, posts to LA)

Each invocation:

1. Lists all files in the data File Share whose name starts with
   FILE_NAME_PREFIX ("google_secops_raw_").

2. Skips files younger than MAX_FILE_AGE_FOR_INGESTION seconds to avoid
   a race with the fetcher that may still be writing.

3. For each eligible file (sorted oldest-first):
   a. Reads the JSON content (a list of raw detection dicts).
   b. Transforms each detection into the flat Log Analytics row schema.
   c. Posts records in batches of 500 to the Log Analytics Data Collector API
      using HMAC-SHA256 authentication (post_data).
   d. Deletes the file only after a successful POST to prevent data loss
      on partial failures.

Trigger schedule: controlled by the *IngesterSchedule* app setting
(CRON expression, e.g. "0 */5 * * * *" for every 5 minutes).
"""

import inspect
import json
import time

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.fileshare import ShareDirectoryClient

from ..SharedCode import consts
from ..SharedCode.exceptions import SentinelIngestionError
from ..SharedCode.logger import applogger
from ..SharedCode.sentinel import post_data
from ..SharedCode.state_manager import StateManager
from ..SharedCode.transform import transform_detections

_BATCH_SIZE = 500


class AzureStorageToSentinel:
    """Read raw detection files from Azure File Share and post to Sentinel."""

    def __init__(self, start_epoch: str) -> None:
        self._fn = consts.FUNCTION_NAME_INGESTER
        self._start_epoch = int(start_epoch)

        self._data_dir = ShareDirectoryClient.from_connection_string(
            conn_str=consts.CONN_STRING,
            share_name=consts.FILE_SHARE_NAME_DATA,
            directory_path="",
        )

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self) -> None:
        """Process all eligible data files and ingest into Sentinel."""
        __method_name = inspect.currentframe().f_code.co_name

        file_names = self._list_eligible_files()
        if not file_names:
            applogger.info(
                "%s (%s): no eligible data files found",
                consts.LOG_PREFIX,
                __method_name,
            )
            return

        applogger.info(
            "%s (%s): processing %d file(s)",
            consts.LOG_PREFIX,
            __method_name,
            len(file_names),
        )

        total_posted = 0
        for file_name in file_names:
            try:
                posted = self._process_file(file_name)
                total_posted += posted
            except SentinelIngestionError:
                applogger.exception(
                    "%s (%s): ingestion failed for file '%s'; skipping",
                    consts.LOG_PREFIX,
                    __method_name,
                    file_name,
                )
            except Exception:
                applogger.exception(
                    "%s (%s): unexpected error processing file '%s'; skipping",
                    consts.LOG_PREFIX,
                    __method_name,
                    file_name,
                )

        applogger.info(
            "%s (%s): complete — total events posted=%d",
            consts.LOG_PREFIX,
            __method_name,
            total_posted,
        )

    # ── File listing ──────────────────────────────────────────────────────────

    def _list_eligible_files(self) -> list:
        """Return data file names older than MAX_FILE_AGE_FOR_INGESTION, oldest first."""
        __method_name = inspect.currentframe().f_code.co_name
        try:
            entries = list(
                self._data_dir.list_directories_and_files(consts.FILE_NAME_PREFIX)
            )
            file_names = [e["name"] for e in entries if not e.get("is_directory", False)]
        except ResourceNotFoundError:
            applogger.info(
                "%s (%s): data file share or directory not found yet",
                consts.LOG_PREFIX,
                __method_name,
            )
            return []
        except Exception:
            applogger.exception(
                "%s (%s): error listing data files",
                consts.LOG_PREFIX,
                __method_name,
            )
            return []

        current_time = int(time.time())
        eligible = [
            name
            for name in file_names
            if current_time - self._epoch_from_name(name) > consts.MAX_FILE_AGE_FOR_INGESTION
        ]
        eligible.sort(key=self._epoch_from_name)

        applogger.info(
            "%s (%s): found %d file(s), %d eligible after age filter",
            consts.LOG_PREFIX,
            __method_name,
            len(file_names),
            len(eligible),
        )
        return eligible

    @staticmethod
    def _epoch_from_name(file_name: str) -> int:
        """Extract the invocation epoch from 'google_secops_raw_<epoch>_<page>'."""
        try:
            # google_secops_raw_<epoch>_<page_index>
            # parts:  [0]     [1]    [2]  [3]     [4]
            return int(file_name.split("_")[3])
        except (IndexError, ValueError):
            return 0

    # ── Per-file processing ───────────────────────────────────────────────────

    def _process_file(self, file_name: str) -> int:
        """Read, transform, post, and delete one data file.

        Args:
            file_name: Name of the file in the data File Share.

        Returns:
            Number of events successfully posted.
        """
        __method_name = inspect.currentframe().f_code.co_name

        sm = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=file_name,
            share_name=consts.FILE_SHARE_NAME_DATA,
        )
        raw = sm.get()
        if not raw:
            applogger.warning(
                "%s (%s): file '%s' is empty — skipping",
                consts.LOG_PREFIX,
                __method_name,
                file_name,
            )
            sm.delete()
            return 0

        try:
            detections = json.loads(raw)
        except json.JSONDecodeError as err:
            applogger.error(
                "%s (%s): JSON parse error in '%s': %s — skipping",
                consts.LOG_PREFIX,
                __method_name,
                file_name,
                err,
            )
            return 0

        applogger.info(
            "%s (%s): file='%s'  raw_detections=%d",
            consts.LOG_PREFIX,
            __method_name,
            file_name,
            len(detections),
        )

        transformed = list(transform_detections(detections))
        if not transformed:
            applogger.info(
                "%s (%s): no transformed records in '%s' — deleting",
                consts.LOG_PREFIX,
                __method_name,
                file_name,
            )
            sm.delete()
            return 0

        posted = self._post_in_batches(transformed, file_name)

        # Only delete after a successful post so data is never silently lost.
        sm.delete()
        applogger.info(
            "%s (%s): posted %d events from '%s' — file deleted",
            consts.LOG_PREFIX,
            __method_name,
            posted,
            file_name,
        )
        return posted

    # ── Sentinel posting ──────────────────────────────────────────────────────

    def _post_in_batches(self, events: list, file_name: str) -> int:
        """Post *events* to Sentinel in batches of _BATCH_SIZE.

        Raises:
            SentinelIngestionError: propagated from post_data on failure.
        """
        __method_name = inspect.currentframe().f_code.co_name
        posted = 0
        for i in range(0, len(events), _BATCH_SIZE):
            batch = events[i : i + _BATCH_SIZE]
            body = json.dumps(batch)
            post_data(body, consts.DCR_STREAM_NAME)
            posted += len(batch)
            applogger.info(
                "%s (%s): file='%s'  batch %d–%d posted (%d events)",
                consts.LOG_PREFIX,
                __method_name,
                file_name,
                i + 1,
                i + len(batch),
                len(batch),
            )
        return posted
