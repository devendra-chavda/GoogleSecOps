"""Azure File Share checkpoint and data file manager."""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.fileshare import ShareClient, ShareFileClient

from . import consts
from .logger import applogger


class StateManager:
    """Read/write checkpoint and data files from Azure File Share."""

    def __init__(
        self,
        connection_string: str = consts.CONN_STRING,
        file_path: str = consts.CHECKPOINT_FILE_NAME,
        share_name: str = consts.FILE_SHARE_NAME,
    ):
        if not connection_string:
            raise ValueError("AzureWebJobsStorage connection string required")
        self._file_cli = ShareFileClient.from_connection_string(
            conn_str=connection_string, share_name=share_name, file_path=file_path
        )
        self._share_cli = ShareClient.from_connection_string(
            conn_str=connection_string, share_name=share_name
        )

    def get(self) -> Optional[str]:
        """Read file contents."""
        try:
            return self._file_cli.download_file().readall().decode()
        except ResourceNotFoundError:
            return None

    def post(self, text: str) -> None:
        """Write file contents, creating share if needed."""
        try:
            self._file_cli.upload_file(text)
        except ResourceNotFoundError:
            try:
                self._share_cli.create_share()
            except ResourceExistsError:
                pass
            self._file_cli.upload_file(text)

    def delete(self) -> None:
        """Delete file (ignores if not found)."""
        try:
            self._file_cli.delete_file()
        except ResourceNotFoundError:
            pass

    def get_checkpoint(self) -> Optional[dict]:
        """Load checkpoint dict from file."""
        raw = self.get()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            applogger.warning("%s: corrupt checkpoint, discarding", consts.LOG_PREFIX)
            return None

    def set_checkpoint(
        self, page_start_time: str, page_token: Optional[str] = None
    ) -> None:
        """Save checkpoint to file."""
        data = {"pageStartTime": page_start_time, "pageToken": page_token}
        self.post(json.dumps(data))
        applogger.info(
            "%s: checkpoint saved (token=%s)",
            consts.LOG_PREFIX,
            "yes" if page_token else "no",
        )

    def resolve_initial_start_time(
        self, input_start_time: str, lookback_days: int = consts.LOOKBACK_DAYS
    ) -> Tuple[str, Optional[str]]:
        """Get start time and token for next API call.

        Logic:
        1. Load checkpoint if exists and valid
        2. Reset if older than 7 days
        3. Fall back to InputStartTime or LookbackDays
        """
        cp = self.get_checkpoint()
        if cp:
            page_start = cp.get("pageStartTime", "")
            page_token = cp.get("pageToken")
            if page_start or page_token:
                if self._is_stale(page_start):
                    new_start = self._compute_start_time(consts.MAX_LOOKBACK_DAYS)
                    applogger.warning(
                        "%s: checkpoint stale, resetting to %s",
                        consts.LOG_PREFIX,
                        new_start,
                    )
                    return new_start, None
                applogger.info("%s: loaded checkpoint", consts.LOG_PREFIX)
                return page_start, page_token

        # No checkpoint: use provided start time or compute from lookback
        lookback = min(lookback_days, consts.MAX_LOOKBACK_DAYS)
        if input_start_time:
            applogger.info(
                "%s: using InputStartTime=%s", consts.LOG_PREFIX, input_start_time
            )
            return input_start_time, None

        start_time = self._compute_start_time(lookback)
        applogger.info(
            "%s: computed start from LookbackDays=%d", consts.LOG_PREFIX, lookback
        )
        return start_time, None

    def _is_stale(self, iso_time: str) -> bool:
        """Check if time is older than MAX_LOOKBACK_DAYS."""
        try:
            dt = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
            cutoff = datetime.now(timezone.utc) - timedelta(days=consts.MAX_LOOKBACK_DAYS)
            return dt < cutoff
        except (ValueError, AttributeError):
            return False

    def _compute_start_time(self, days_ago: int) -> str:
        """Compute ISO timestamp for N days ago."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return cutoff.isoformat().replace("+00:00", "Z")
