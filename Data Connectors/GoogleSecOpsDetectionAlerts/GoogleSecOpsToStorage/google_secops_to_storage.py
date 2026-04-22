"""Fetch Google SecOps detection alerts and save each response to a file immediately."""

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
    """Fetch batches from Chronicle API and save each response immediately."""

    def __init__(self, start_epoch: str) -> None:
        self._start_epoch = start_epoch
        self._validate_env_vars()
        self._auth = GoogleServiceAccountAuth()
        self._client = ChronicleClient(self._auth)
        self._checkpoint = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=consts.CHECKPOINT_FILE_NAME,
            share_name=consts.FILE_SHARE_NAME,
        )

    def _validate_env_vars(self) -> None:
        required = [
            ("AzureWebJobsStorage", consts.CONN_STRING),
            ("ChronicleProjectId", consts.CHRONICLE_PROJECT_ID),
            ("ChronicleRegion", consts.CHRONICLE_REGION),
            ("ChronicleInstanceId", consts.CHRONICLE_INSTANCE_ID),
            ("ChronicleServiceAccountJson", consts.SERVICE_ACCOUNT_JSON),
            ("AZURE_DATA_COLLECTION_ENDPOINT", consts.DCE_ENDPOINT),
            ("DCR_RULE_ID", consts.DCR_IMMUTABLE_ID),
            ("DcrStreamName", consts.DCR_STREAM_NAME),
        ]
        missing = [name for name, val in required if not val]
        if missing:
            raise ValueError(f"Missing env vars: {missing}")

    def run(self) -> None:
        """Fetch and save each API response immediately."""
        method = inspect.currentframe().f_code.co_name
        page_start, page_token = self._checkpoint.resolve_initial_start_time(
            consts.INPUT_START_TIME, consts.LOOKBACK_DAYS
        )
        applogger.info(
            "%s (%s): starting (start=%s token=%s timeout=%ds)",
            consts.LOG_PREFIX,
            method,
            page_start,
            "yes" if page_token else "no",
            consts.FUNCTION_APP_TIMEOUT_SECONDS,
        )

        deadline = time.time() + consts.FUNCTION_APP_TIMEOUT_SECONDS
        batch_count = 0
        applogger.debug(
            "%s: deadline set to %s (%.0f seconds from now)",
            consts.LOG_PREFIX,
            time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(deadline)),
            deadline - time.time(),
        )

        try:
            applogger.debug("%s: starting API polling loop", consts.LOG_PREFIX)
            for batch, next_token, next_start in self._client.poll_detection_batches(
                page_start_time=page_start,
                page_token=page_token,
                deadline_epoch=deadline,
            ):
                # Step 1: Save full API response to file immediately
                batch_count += 1
                applogger.debug(
                    "%s: received batch #%d, saving to file",
                    consts.LOG_PREFIX,
                    batch_count,
                )
                self._write_response_to_file(batch, batch_count)

                # Step 2: Update checkpoint after save
                applogger.debug(
                    "%s: updating checkpoint after batch #%d",
                    consts.LOG_PREFIX,
                    batch_count,
                )
                self._update_checkpoint(page_start, next_token, next_start)

                # Check time budget
                remaining = deadline - time.time()
                applogger.debug(
                    "%s: batch #%d complete, %.0f seconds remaining",
                    consts.LOG_PREFIX,
                    batch_count,
                    remaining,
                )
                if remaining <= 0:
                    applogger.warning(
                        "%s: time budget exhausted, stopping",
                        consts.LOG_PREFIX,
                    )
                    break

            applogger.info(
                "%s: polling loop completed normally",
                consts.LOG_PREFIX,
            )

        except ChronicleConnectorError as exc:
            applogger.exception(
                "%s: API error after %d batches: %s",
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

        applogger.info(
            "%s (%s): complete (responses saved=%d, runtime=%.1f seconds)",
            consts.LOG_PREFIX,
            method,
            batch_count,
            time.time() - (deadline - consts.FUNCTION_APP_TIMEOUT_SECONDS),
        )

    def _write_response_to_file(self, response: dict, index: int) -> None:
        """Write full API response to file immediately.

        Args:
            response: Complete API response dict (unmodified)
            index: Response number in this invocation
        """
        filename = f"{consts.FILE_NAME_PREFIX}_{self._start_epoch}_{index}"
        content = json.dumps(response, indent=2)
        size_kb = len(content.encode("utf-8")) / 1024

        # Log the full response being saved
        applogger.info(
            "%s: API response #%d: keys=%s",
            consts.LOG_PREFIX,
            index,
            list(response.keys()) if isinstance(response, dict) else "array",
        )
        applogger.debug(
            "%s: full response: %s",
            consts.LOG_PREFIX,
            json.dumps(response),
        )

        # TODO: REMOVE - File write time tracking
        write_start = time.time()
        # Write to file immediately
        sm = StateManager(
            connection_string=consts.CONN_STRING,
            file_path=filename,
            share_name=consts.FILE_SHARE_NAME_DATA,
        )
        sm.post(content)
        write_elapsed = time.time() - write_start

        # TODO: REMOVE - Log file write time
        applogger.info(
            "%s: response saved → file=%s size=%.2f KB write_time=%.2fs",
            consts.LOG_PREFIX,
            filename,
            size_kb,
            write_elapsed,
        )

    def _update_checkpoint(
        self, page_start: str, next_token: str, next_start: str
    ) -> None:
        """Update checkpoint after successful file write.

        Args:
            page_start: Current window start time
            next_token: Pagination token from response (if any)
            next_start: Next window start time (if any)
        """
        # TODO: REMOVE - Checkpoint update time tracking
        checkpoint_start = time.time()
        if next_start:
            # Window complete: save new start time, clear token
            self._checkpoint.set_checkpoint(next_start, None)
            checkpoint_elapsed = time.time() - checkpoint_start
            # TODO: REMOVE - Log checkpoint update time
            applogger.info(
                "%s: window complete, checkpoint advanced to %s (update_time=%.2fs)",
                consts.LOG_PREFIX,
                next_start,
                checkpoint_elapsed,
            )
        elif next_token:
            # Mid-window: save token, keep current start time
            self._checkpoint.set_checkpoint(page_start, next_token)
            checkpoint_elapsed = time.time() - checkpoint_start
            # TODO: REMOVE - Log checkpoint update time
            applogger.info(
                "%s: mid-window, checkpoint saved with token (update_time=%.2fs)",
                consts.LOG_PREFIX,
                checkpoint_elapsed,
            )
