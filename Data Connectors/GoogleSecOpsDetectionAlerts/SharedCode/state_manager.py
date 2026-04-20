"""Checkpoint state stored in Azure File Share.

A single JSON file holds the cursor for the next poll:

    {
        "pageStartTime": "<ISO-8601 UTC>",   // start of the next detection window
        "pageToken":     "<opaque string>"   // mid-window resume token (null when absent)
    }

Pagination rules
----------------
pageToken present  → resume mid-window: next API call sends ONLY pageToken.
pageToken absent   → fresh window:       next API call sends pageStartTime.
pageStartTime is ALWAYS persisted, even while paginating with pageToken, so that
if the function is interrupted we can restart the window from the beginning rather
than losing data.
"""

import json
from typing import Optional, Tuple

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.fileshare import ShareClient, ShareFileClient

from . import consts
from .logger import applogger


class StateManager:
    """Read/write a file on Azure File Share as a plain string.

    Can be used both for the single checkpoint file and for any raw data file
    stored in the data file share.
    """

    def __init__(
        self,
        connection_string: str = consts.CONN_STRING,
        file_path: str = consts.CHECKPOINT_FILE_NAME,
        share_name: str = consts.FILE_SHARE_NAME,
    ):
        if not connection_string:
            raise ValueError("AzureWebJobsStorage connection string is required.")
        self._share_cli = ShareClient.from_connection_string(
            conn_str=connection_string, share_name=share_name
        )
        self._file_cli = ShareFileClient.from_connection_string(
            conn_str=connection_string, share_name=share_name, file_path=file_path
        )

    # ── Low-level file I/O ────────────────────────────────────────────────────

    def post(self, text: str) -> None:
        """Upload *text* to the file, creating the share/file if needed."""
        try:
            self._file_cli.upload_file(text)
        except ResourceNotFoundError:
            try:
                self._share_cli.create_share()
                self._file_cli.upload_file(text)
            except ResourceExistsError:
                self._file_cli.upload_file(text)

    def get(self) -> Optional[str]:
        """Return file contents as a string, or *None* if the file does not exist."""
        try:
            return self._file_cli.download_file().readall().decode()
        except ResourceNotFoundError:
            return None

    def delete(self) -> None:
        """Delete the file (silently ignores 'not found')."""
        try:
            self._file_cli.delete_file()
        except ResourceNotFoundError:
            pass

    # ── High-level checkpoint helpers (checkpoint file only) ──────────────────

    def get_checkpoint(self) -> Optional[dict]:
        """Return the parsed checkpoint dict, or *None* if not yet written."""
        raw = self.get()
        if raw:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                applogger.warning(
                    "%s: corrupt checkpoint JSON; discarding", consts.LOG_PREFIX
                )
        return None

    def set_checkpoint(
        self,
        page_start_time: str,
        page_token: Optional[str] = None,
    ) -> None:
        """Persist the checkpoint.

        Args:
            page_start_time: ISO-8601 UTC string for the start of the detection window.
            page_token:       Mid-window pagination token (pass *None* when the window
                              is exhausted and pageStartTime has been advanced).
        """
        data = {"pageStartTime": page_start_time, "pageToken": page_token}
        self.post(json.dumps(data))
        applogger.info(
            "%s: checkpoint saved — pageStartTime=%s  pageToken=%s",
            consts.LOG_PREFIX,
            page_start_time,
            "present" if page_token else "none",
        )

    def resolve_initial_start_time(self, input_start_time: str) -> Tuple[str, Optional[str]]:
        """Return *(pageStartTime, pageToken)* for the next API request.

        - If a saved checkpoint exists, return its values (subsequent invocations).
        - Otherwise seed from *input_start_time* (very first invocation).

        Returns:
            Tuple of (page_start_time, page_token).  page_token may be None.

        Raises:
            ValueError: when no checkpoint exists AND input_start_time is empty.
        """
        cp = self.get_checkpoint()
        if cp:
            page_start_time = cp.get("pageStartTime", "")
            page_token = cp.get("pageToken")
            if page_start_time or page_token:
                applogger.info(
                    "%s: loaded checkpoint — pageStartTime=%s  pageToken=%s",
                    consts.LOG_PREFIX,
                    page_start_time,
                    "present" if page_token else "none",
                )
                return page_start_time, page_token

        if not input_start_time:
            raise ValueError(
                "No checkpoint found and InputStartTime is not configured. "
                "Set the InputStartTime app setting (ISO-8601 UTC, e.g. 2026-04-14T00:00:00Z)."
            )
        applogger.info(
            "%s: no checkpoint — seeding from InputStartTime=%s",
            consts.LOG_PREFIX,
            input_start_time,
        )
        return input_start_time, None
