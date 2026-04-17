"""Timer-trigger entry point for the Chronicle stream-detection-alerts connector."""
import datetime
import logging

import azure.functions as func

from ..SharedCode import consts
from ..SharedCode.logger import applogger
from .chronicle_to_sentinel import ChronicleToSentinel


def main(mytimer: func.TimerRequest) -> None:
    start = datetime.datetime.now(datetime.timezone.utc)
    applogger.info("%s: function start at %s", consts.LOG_PREFIX, start.isoformat())
    if mytimer.past_due:
        logging.info("%s: timer is past due", consts.LOG_PREFIX)
    try:
        runner = ChronicleToSentinel()
        runner.run()
    except Exception:  # noqa: BLE001
        applogger.exception("%s: unhandled error during run", consts.LOG_PREFIX)
        raise
    finally:
        end = datetime.datetime.now(datetime.timezone.utc)
        applogger.info(
            "%s: function end at %s (duration=%ss)",
            consts.LOG_PREFIX,
            end.isoformat(),
            (end - start).total_seconds(),
        )
