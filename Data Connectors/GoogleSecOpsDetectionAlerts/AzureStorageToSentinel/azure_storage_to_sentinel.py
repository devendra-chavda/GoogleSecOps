"""Ingest detection responses from Azure File Share into Microsoft Sentinel.

Monitors for response files saved by GoogleSecOpsToStorage and posts
detections to Sentinel via the Log Analytics DCR API.
"""

import inspect
import json
import time

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.fileshare import ShareDirectoryClient

from ..SharedCode import consts
from ..SharedCode.logger import applogger
from ..SharedCode.sentinel import post_data
from ..SharedCode.state_manager import StateManager


class AzureStorageToSentinel:
    """Read response files from Azure File Share and post detections to Sentinel."""

    def __init__(self) -> None:
        """Initialize Azure File Share client."""
        self._data_dir = ShareDirectoryClient.from_connection_string(
            conn_str=consts.CONN_STRING,
            share_name=consts.FILE_SHARE_NAME_DATA,
            directory_path="",
        )

    def run(self) -> None:
        """Process response files from Azure File Share and post to Sentinel."""
        method = inspect.currentframe().f_code.co_name
        deadline = time.time() + consts.FUNCTION_APP_TIMEOUT_SECONDS

        # Counters for tracking pipeline flow
        total_extracted = 0
        total_posted = 0
        files_processed = 0
        last_check_time = time.time()

        applogger.info(
            "%s (%s): starting (timeout=%ds, check interval=%ds)",
            consts.LOG_PREFIX,
            method,
            consts.FUNCTION_APP_TIMEOUT_SECONDS,
            consts.FILE_CHECK_INTERVAL_SECONDS,
        )

        while time.time() < deadline:
            # Check for files at configured interval
            time_since_last_check = time.time() - last_check_time
            should_check_files = (
                time_since_last_check >= consts.FILE_CHECK_INTERVAL_SECONDS
                or last_check_time == time.time()  # First iteration
            )

            if should_check_files:
                file_names = self._list_eligible_files()
                last_check_time = time.time()

                if file_names:
                    for filename in file_names:
                        try:
                            extracted, posted = self._process_response_file(filename)
                            total_extracted += extracted
                            total_posted += posted
                            files_processed += 1
                            applogger.info(
                                "%s: progress (files=%d, extracted=%d, posted=%d)",
                                consts.LOG_PREFIX,
                                files_processed,
                                total_extracted,
                                total_posted,
                            )
                        except Exception:
                            applogger.exception(
                                "%s: error processing file %s",
                                consts.LOG_PREFIX,
                                filename,
                            )
                else:
                    remaining = deadline - time.time()
                    applogger.debug(
                        "%s: no files ready, will recheck in %ds (%.0f seconds remaining)",
                        consts.LOG_PREFIX,
                        consts.FILE_CHECK_INTERVAL_SECONDS,
                        remaining,
                    )

            # Brief sleep to avoid busy spinning
            time.sleep(consts.BUSY_WAIT_SLEEP_SECONDS)

        applogger.info(
            "%s (%s): complete (files processed=%d, extracted=%d, posted=%d)",
            consts.LOG_PREFIX,
            method,
            files_processed,
            total_extracted,
            total_posted,
        )

    def _list_eligible_files(self) -> list:
        """List response files ready for ingestion (aged files only).

        Filters out files younger than MAX_FILE_AGE_FOR_INGESTION to avoid
        race conditions where the fetcher is still writing.

        Returns:
            List of filenames sorted by creation time (oldest first).
        """
        try:
            entries = list(
                self._data_dir.list_directories_and_files(consts.FILE_NAME_PREFIX)
            )
            all_files = [e["name"] for e in entries if not e.get("is_directory")]
        except ResourceNotFoundError:
            applogger.debug("%s: data share not initialized yet", consts.LOG_PREFIX)
            return []
        except Exception:
            applogger.exception("%s: error listing files in share", consts.LOG_PREFIX)
            return []

        if not all_files:
            return []

        # Filter: only include files older than MAX_FILE_AGE_FOR_INGESTION
        now = int(time.time())
        eligible_files = [
            f
            for f in all_files
            if now - self._get_epoch(f) > consts.MAX_FILE_AGE_FOR_INGESTION
        ]
        eligible_files.sort(key=self._get_epoch)

        if eligible_files:
            applogger.info(
                "%s: found %d files (total), %d eligible (aged >%ds)",
                consts.LOG_PREFIX,
                len(all_files),
                len(eligible_files),
                consts.MAX_FILE_AGE_FOR_INGESTION,
            )

        return eligible_files

    @staticmethod
    def _get_epoch(filename: str) -> int:
        """Extract epoch timestamp from filename.

        Filename format: google_secops_raw_<epoch>_<index>
        """
        try:
            parts = filename.split("_")
            return int(parts[3])
        except (IndexError, ValueError):
            return 0

    def _process_response_file(self, filename: str) -> tuple:
        """Read response file, extract detections, post to Sentinel, and delete.

        Returns:
            Tuple of (detections_extracted, detections_posted)
        """
        sm = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=filename,
            share_name=consts.FILE_SHARE_NAME_DATA,
        )

        # Read and validate file
        raw_content = sm.get()
        if not raw_content:
            applogger.warning("%s: empty file, skipping: %s", consts.LOG_PREFIX, filename)
            sm.delete()
            return 0, 0

        # Parse JSON response
        try:
            response = json.loads(raw_content)
        except json.JSONDecodeError as err:
            applogger.error(
                "%s: invalid JSON in %s: %s",
                consts.LOG_PREFIX,
                filename,
                err,
            )
            return 0, 0

        applogger.debug(
            "%s: parsed response from %s (keys=%s)",
            consts.LOG_PREFIX,
            filename,
            list(response.keys()) if isinstance(response, dict) else "N/A",
        )

        # Extract detections
        detections = self._extract_detections(response)
        if not detections:
            applogger.info("%s: no detections found in %s", consts.LOG_PREFIX, filename)
            sm.delete()
            return 0, 0

        extracted_count = len(detections)
        applogger.info(
            "%s: extracted %d detections from %s",
            consts.LOG_PREFIX,
            extracted_count,
            filename,
        )

        # Post to Sentinel
        posted_count = self._post_to_sentinel(detections, filename)

        # Cleanup
        sm.delete()

        return extracted_count, posted_count

    @staticmethod
    def _extract_detections(response) -> list:
        """Extract detections array from API response.

        Handles both dict responses (with 'detections' key) and array responses.
        """
        if isinstance(response, dict):
            return response.get("detections") or []
        if isinstance(response, list):
            return response
        return []

    def _post_to_sentinel(self, detections: list, filename: str) -> int:
        """Post detections to Sentinel in batches.

        Posts in chunks of INGESTION_BATCH_SIZE events per API call.

        Args:
            detections: List of detection events to post
            filename: Source filename (for logging)

        Returns:
            Number of events successfully posted
        """
        total_count = len(detections)
        batch_count = (total_count + consts.INGESTION_BATCH_SIZE - 1) // consts.INGESTION_BATCH_SIZE

        applogger.info(
            "%s: posting %d events (%d batches × %d)",
            consts.LOG_PREFIX,
            total_count,
            batch_count,
            consts.INGESTION_BATCH_SIZE,
        )

        posted_count = 0
        for batch_num, start_idx in enumerate(
            range(0, total_count, consts.INGESTION_BATCH_SIZE), 1
        ):
            end_idx = min(start_idx + consts.INGESTION_BATCH_SIZE, total_count)
            batch = detections[start_idx:end_idx]
            batch_size = len(batch)

            # Post batch to Sentinel
            post_data(json.dumps(batch), consts.DCR_STREAM_NAME)
            posted_count += batch_size

            applogger.info(
                "%s: batch %d/%d posted (events %d-%d, %d events)",
                consts.LOG_PREFIX,
                batch_num,
                batch_count,
                start_idx + 1,
                end_idx,
                batch_size,
            )

        applogger.info(
            "%s: completed posting from %s (all %d batches)",
            consts.LOG_PREFIX,
            filename,
            batch_count,
        )

        return posted_count
