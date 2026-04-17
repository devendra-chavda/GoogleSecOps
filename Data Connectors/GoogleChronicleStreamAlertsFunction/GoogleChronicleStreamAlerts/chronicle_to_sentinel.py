"""Orchestrator: Chronicle stream-detection-alerts -> Azure Sentinel DCR.

Lifecycle of a single timer invocation:

1. Resolve `pageStartTime`:
   - Use checkpoint from Azure Table Storage if present (subsequent runs).
   - Otherwise seed from `InputStartTime` app setting (first run).
2. Paginate through `legacy:legacyStreamDetectionAlerts`:
   - Response has `nextPageToken` -> fetch next page (pass only `pageToken`).
   - Response has `nextPageStartTime` -> window done; save as checkpoint.
3. Post detections to Sentinel DCR after each page (partial progress is durable).
4. Update checkpoint ONLY when `nextPageStartTime` is received — never on
   a token-paginated mid-window page.
"""
import time
from typing import Optional

from ..SharedCode import consts
from ..SharedCode.chronicle_client import ChronicleClient
from ..SharedCode.exceptions import ChronicleConnectorError
from ..SharedCode.google_auth import GoogleServiceAccountAuth
from ..SharedCode.logger import applogger
from ..SharedCode.sentinel import SentinelPoster
from ..SharedCode.state_manager import StateManager
from ..SharedCode.transform import transform_detections


class ChronicleToSentinel:
    def __init__(self):
        self._state = StateManager()
        self._auth = GoogleServiceAccountAuth()
        self._client = ChronicleClient(self._auth)
        self._sentinel = SentinelPoster()

    def run(self) -> None:
        page_start_time = self._state.resolve_initial_start_time(consts.INPUT_START_TIME)
        applogger.info(
            "%s: starting with pageStartTime=%s", consts.LOG_PREFIX, page_start_time
        )

        deadline = time.time() + consts.FUNCTION_BUDGET_SECONDS
        total_posted = 0
        new_checkpoint: Optional[str] = None

        try:
            for detections, next_page_start_time in self._client.stream_detections(
                page_start_time=page_start_time,
                deadline_epoch=deadline,
            ):
                if detections:
                    transformed = list(transform_detections(detections))
                    if transformed:
                        total_posted += self._sentinel.post(transformed)

                if next_page_start_time:
                    new_checkpoint = next_page_start_time
        except ChronicleConnectorError:
            applogger.exception(
                "%s: aborting run; checkpoint NOT advanced", consts.LOG_PREFIX
            )
            raise

        if new_checkpoint:
            self._state.set_checkpoint(new_checkpoint)
            applogger.info(
                "%s: checkpoint advanced to %s", consts.LOG_PREFIX, new_checkpoint
            )
        else:
            applogger.info(
                "%s: no nextPageStartTime received; checkpoint unchanged",
                consts.LOG_PREFIX,
            )

        applogger.info(
            "%s: run complete; total detections posted=%d",
            consts.LOG_PREFIX,
            total_posted,
        )
