"""Checkpoint state stored in Azure Table Storage.

Schema: a single entity keyed by (STATE_PARTITION_KEY, STATE_ROW_KEY) with
`pageStartTime` (ISO-8601 UTC string) holding the cursor for the next poll.
"""
import json
from typing import Optional

from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError
from azure.data.tables import TableServiceClient, UpdateMode

from . import consts
from .logger import applogger


class StateManager:
    """Persist Chronicle stream-detection-alerts checkpoint across invocations."""

    def __init__(
        self,
        connection_string: str = consts.AZURE_STORAGE_CONNECTION_STRING,
        table_name: str = consts.STATE_TABLE_NAME,
        partition_key: str = consts.STATE_PARTITION_KEY,
        row_key: str = consts.STATE_ROW_KEY,
    ):
        if not connection_string:
            raise ValueError("AzureWebJobsStorage connection string is required.")
        self._service = TableServiceClient.from_connection_string(connection_string)
        self._table_name = table_name
        self._partition_key = partition_key
        self._row_key = row_key
        self._table = self._service.get_table_client(table_name)
        self._ensure_table()

    def _ensure_table(self) -> None:
        try:
            self._service.create_table(self._table_name)
        except ResourceExistsError:
            pass

    def get_checkpoint(self) -> Optional[dict]:
        try:
            entity = self._table.get_entity(self._partition_key, self._row_key)
            return {
                "pageStartTime": entity.get("pageStartTime"),
                "updatedAt": entity.get("updatedAt"),
                "extra": json.loads(entity.get("extra", "{}")),
            }
        except ResourceNotFoundError:
            return None

    def set_checkpoint(self, page_start_time: str, extra: Optional[dict] = None) -> None:
        from datetime import datetime, timezone
        entity = {
            "PartitionKey": self._partition_key,
            "RowKey": self._row_key,
            "pageStartTime": page_start_time,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "extra": json.dumps(extra or {}),
        }
        self._table.upsert_entity(entity, mode=UpdateMode.REPLACE)
        applogger.info(
            "%s: checkpoint updated to pageStartTime=%s",
            consts.LOG_PREFIX,
            page_start_time,
        )

    def resolve_initial_start_time(self, input_start_time: str) -> str:
        """Return the pageStartTime to use for the next request.

        - If a checkpoint exists, use it (subsequent schedules).
        - Otherwise seed from `input_start_time` (first run).
        """
        cp = self.get_checkpoint()
        if cp and cp.get("pageStartTime"):
            return cp["pageStartTime"]
        if not input_start_time:
            raise ValueError(
                "No checkpoint found and InputStartTime is not configured."
            )
        return input_start_time
