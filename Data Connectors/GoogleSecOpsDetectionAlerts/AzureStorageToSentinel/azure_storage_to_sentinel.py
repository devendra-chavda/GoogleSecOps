"""Read detection responses and ingest to Sentinel in real-time."""

import inspect
import json
import time

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.fileshare import ShareDirectoryClient

from ..SharedCode import consts
from ..SharedCode.logger import applogger
from ..SharedCode.sentinel import post_data
from ..SharedCode.state_manager import StateManager

_BATCH_SIZE = 500


class AzureStorageToSentinel:
    """Process response files and post detections to Sentinel."""

    def __init__(self, start_epoch: str) -> None:
        self._start_epoch = int(start_epoch)
        self._data_dir = ShareDirectoryClient.from_connection_string(
            conn_str=consts.CONN_STRING,
            share_name=consts.FILE_SHARE_NAME_DATA,
            directory_path="",
        )

    def run(self) -> None:
        """Process each response file and post detections."""
        method = inspect.currentframe().f_code.co_name
        file_names = self._list_eligible_files()

        if not file_names:
            applogger.info("%s (%s): no files found", consts.LOG_PREFIX, method)
            return

        applogger.info(
            "%s (%s): processing %d response files",
            consts.LOG_PREFIX,
            method,
            len(file_names),
        )

        total_posted = 0
        for filename in file_names:
            try:
                posted = self._process_response_file(filename)
                total_posted += posted
            except Exception:
                applogger.exception("%s: error processing %s", consts.LOG_PREFIX, filename)

        applogger.info(
            "%s (%s): complete (events posted=%d)",
            consts.LOG_PREFIX,
            method,
            total_posted,
        )

    def _list_eligible_files(self) -> list:
        """List response files ready for ingestion.

        Skips files younger than MAX_FILE_AGE_FOR_INGESTION to avoid
        race condition where fetcher is still writing.
        """
        try:
            entries = list(
                self._data_dir.list_directories_and_files(consts.FILE_NAME_PREFIX)
            )
            files = [e["name"] for e in entries if not e.get("is_directory")]
        except ResourceNotFoundError:
            applogger.info("%s: data share not found yet", consts.LOG_PREFIX)
            return []
        except Exception:
            applogger.exception("%s: error listing files", consts.LOG_PREFIX)
            return []

        now = int(time.time())
        eligible = [
            f
            for f in files
            if now - self._get_epoch(f) > consts.MAX_FILE_AGE_FOR_INGESTION
        ]
        eligible.sort(key=self._get_epoch)

        applogger.info(
            "%s: found %d files, %d eligible",
            consts.LOG_PREFIX,
            len(files),
            len(eligible),
        )
        return eligible

    @staticmethod
    def _get_epoch(filename: str) -> int:
        """Extract epoch from filename: google_secops_raw_<epoch>_<index>."""
        try:
            return int(filename.split("_")[3])
        except (IndexError, ValueError):
            return 0

    def _process_response_file(self, filename: str) -> int:
        """Read response file and post detections to Sentinel.

        Process: Read → Extract detections → Post → Delete
        """
        applogger.info(
            "%s: processing response file: %s", consts.LOG_PREFIX, filename
        )

        sm = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=filename,
            share_name=consts.FILE_SHARE_NAME_DATA,
        )

        # Step 1: Read response file
        raw = sm.get()
        if not raw:
            applogger.warning("%s: empty file %s", consts.LOG_PREFIX, filename)
            sm.delete()
            return 0

        # Step 2: Parse JSON response
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as err:
            applogger.error(
                "%s: JSON parse error in %s: %s", consts.LOG_PREFIX, filename, err
            )
            return 0

        # Step 3: Log full response received
        applogger.info(
            "%s: response parsed, keys=%s",
            consts.LOG_PREFIX,
            list(response.keys()) if isinstance(response, dict) else "array",
        )
        applogger.debug("%s: response content: %s", consts.LOG_PREFIX, raw)

        # Step 4: Extract detections from response
        detections = self._extract_detections(response)
        if not detections:
            applogger.info("%s: no detections in %s", consts.LOG_PREFIX, filename)
            sm.delete()
            return 0

        applogger.info(
            "%s: extracted %d detections from %s",
            consts.LOG_PREFIX,
            len(detections),
            filename,
        )

        # Step 5: Post detections to Sentinel
        posted = self._post_to_sentinel(detections, filename)

        # Step 6: Delete file after successful post
        sm.delete()
        applogger.info(
            "%s: posted %d events, file deleted: %s",
            consts.LOG_PREFIX,
            posted,
            filename,
        )

        return posted

    @staticmethod
    def _extract_detections(response):
        """Extract detections array from API response."""
        if isinstance(response, dict):
            return response.get("detections") or []
        if isinstance(response, list):
            return response
        return []

    def _post_to_sentinel(self, detections: list, filename: str) -> int:
        """Post detections to Sentinel in batches.

        Posts in chunks of 500 events at a time.
        """
        applogger.info(
            "%s: posting %d events to Sentinel (batch size=%d)",
            consts.LOG_PREFIX,
            len(detections),
            _BATCH_SIZE,
        )

        posted = 0
        for i in range(0, len(detections), _BATCH_SIZE):
            chunk = detections[i : i + _BATCH_SIZE]
            body = json.dumps(chunk)

            # Post this chunk to Sentinel
            post_data(body, consts.DCR_STREAM_NAME)
            posted += len(chunk)

            applogger.info(
                "%s: batch %d-%d posted (%d events)",
                consts.LOG_PREFIX,
                i + 1,
                i + len(chunk),
                len(chunk),
            )

        return posted
