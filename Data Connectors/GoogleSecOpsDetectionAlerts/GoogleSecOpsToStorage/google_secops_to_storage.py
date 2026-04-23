"""Fetch detection alerts from Google SecOps (Chronicle) and save to Azure File Share.

Polls the Chronicle API for detection alerts and saves each response batch
to Azure File Share for durable buffering. The companion AzureStorageToSentinel
function monitors and ingests the files into Microsoft Sentinel.
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
    """Fetch detection batches from Chronicle and save to Azure File Share."""

    def __init__(self) -> None:
        """Initialize Chronicle client, checkpoint manager, and validate configuration."""
        self._validate_env_vars()
        self._auth = GoogleServiceAccountAuth()
        self._client = ChronicleClient(self._auth)
        self._checkpoint = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=consts.CHECKPOINT_FILE_NAME,
            share_name=consts.FILE_SHARE_NAME,
        )
        self._start_time = int(time.time())

    def _validate_env_vars(self) -> None:
        """Verify all required environment variables are configured.

        Raises:
            ValueError: If any required environment variables are missing
        """
        required_vars = [
            ("AzureWebJobsStorage", consts.CONN_STRING),
            ("ChronicleProjectId", consts.CHRONICLE_PROJECT_ID),
            ("ChronicleRegion", consts.CHRONICLE_REGION),
            ("ChronicleInstanceId", consts.CHRONICLE_INSTANCE_ID),
            ("ChronicleServiceAccountJson", consts.SERVICE_ACCOUNT_JSON),
            ("AZURE_DATA_COLLECTION_ENDPOINT", consts.DCE_ENDPOINT),
            ("DCR_RULE_ID", consts.DCR_IMMUTABLE_ID),
            ("DcrStreamName", consts.DCR_STREAM_NAME),
        ]
        missing = [name for name, val in required_vars if not val]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")

    def run(self) -> None:
        """Fetch detection batches from Chronicle API and save to Azure File Share."""
        method = inspect.currentframe().f_code.co_name
        page_start, page_token = self._checkpoint.resolve_initial_start_time()

        applogger.info(
            "%s (%s): starting (checkpoint: start=%s token=%s, timeout=%ds)",
            consts.LOG_PREFIX,
            method,
            page_start,
            "yes" if page_token else "no",
            consts.FUNCTION_APP_TIMEOUT_SECONDS,
        )

        deadline = time.time() + consts.FUNCTION_APP_TIMEOUT_SECONDS
        batch_count = 0
        total_detections = 0

        applogger.debug(
            "%s: deadline set to %s (%.0f seconds from now)",
            consts.LOG_PREFIX,
            time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(deadline)),
            deadline - time.time(),
        )

        try:
            applogger.debug("%s: beginning API polling loop", consts.LOG_PREFIX)
            for batch, next_token, next_start in self._client.poll_detection_batches(
                page_start_time=page_start,
                page_token=page_token,
                deadline_epoch=deadline,
            ):
                batch_count += 1

                # Save batch to file and track detection count
                batch_detection_count = self._write_response_to_file(batch, batch_count)
                total_detections += batch_detection_count

                # Update checkpoint after successful save
                self._update_checkpoint(page_start, next_token, next_start)

                # Check if time budget is exhausted
                remaining = deadline - time.time()
                if remaining <= 0:
                    applogger.warning(
                        "%s: time budget exhausted after batch #%d, stopping",
                        consts.LOG_PREFIX,
                        batch_count,
                    )
                    break

                applogger.debug(
                    "%s: batch #%d complete (%.0f seconds remaining)",
                    consts.LOG_PREFIX,
                    batch_count,
                    remaining,
                )

            applogger.info(
                "%s: polling loop completed normally",
                consts.LOG_PREFIX,
            )

        except ChronicleConnectorError as exc:
            applogger.exception(
                "%s: Chronicle API error after %d batches: %s",
                consts.LOG_PREFIX,
                batch_count,
                exc,
            )
        except Exception as exc:
            applogger.exception(
                "%s: unexpected error after %d batches: %s",
                consts.LOG_PREFIX,
                batch_count,
                exc,
            )

        runtime = time.time() - self._start_time
        applogger.info(
            "%s (%s): complete (batches=%d, detections fetched and saved=%d, runtime=%.1fs)",
            consts.LOG_PREFIX,
            method,
            batch_count,
            total_detections,
            runtime,
        )

    def _write_response_to_file(self, response: dict, index: int) -> int:
        """Save full API response to Azure File Share.

        Writes the complete response as a JSON file and tracks detection count.

        Args:
            response: Complete API response dict
            index: Batch number in this invocation

        Returns:
            Number of detections in this batch
        """
        current_epoch = int(time.time())
        filename = f"{consts.FILE_NAME_PREFIX}_{current_epoch}_{index}"

        # Extract detection count
        detections = response.get("detections", []) if isinstance(response, dict) else []
        detection_count = len(detections) if isinstance(detections, list) else 0

        # Log response summary
        applogger.info(
            "%s: API response #%d has %d detections (keys=%s)",
            consts.LOG_PREFIX,
            index,
            detection_count,
            list(response.keys()) if isinstance(response, dict) else "N/A",
        )
        applogger.debug(
            "%s: response #%d content: %s",
            consts.LOG_PREFIX,
            index,
            json.dumps(response),
        )

        # Write to file share
        content = json.dumps(response, indent=2)
        size_kb = len(content.encode("utf-8")) / 1024

        write_start = time.time()
        sm = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=filename,
            share_name=consts.FILE_SHARE_NAME_DATA,
        )
        sm.post(content)
        write_elapsed = time.time() - write_start

        applogger.info(
            "%s: response #%d saved (file=%s, detections=%d, size=%.1f KB, time=%.2fs)",
            consts.LOG_PREFIX,
            index,
            filename,
            detection_count,
            size_kb,
            write_elapsed,
        )

        return detection_count

    def _update_checkpoint(
        self, page_start: str, next_token: str, next_start: str
    ) -> None:
        """Update checkpoint after successful file write.

        Handles two scenarios:
        1. Window complete: Save new start time and clear token
        2. Mid-window: Save pagination token and keep start time

        Args:
            page_start: Current window start time
            next_token: Pagination token from response (if any)
            next_start: Next window start time (if any)
        """
        checkpoint_start = time.time()

        if next_start:
            # Window complete: advance to next time window
            self._checkpoint.set_checkpoint(next_start, None)
            elapsed = time.time() - checkpoint_start
            applogger.info(
                "%s: window complete, checkpoint advanced to %s (update=%.2fs)",
                consts.LOG_PREFIX,
                next_start,
                elapsed,
            )
        elif next_token:
            # Mid-window: pagination needed
            self._checkpoint.set_checkpoint(page_start, next_token)
            elapsed = time.time() - checkpoint_start
            applogger.debug(
                "%s: mid-window checkpoint saved with token (update=%.2fs)",
                consts.LOG_PREFIX,
                elapsed,
            )
