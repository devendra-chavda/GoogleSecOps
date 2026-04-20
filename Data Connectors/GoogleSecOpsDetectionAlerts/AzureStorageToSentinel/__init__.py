"""Timer-trigger entry point for the AzureStorageToSentinel function.

Reads raw detection JSON files written by GoogleSecOpsToStorage from
Azure File Share, transforms each record, and ingests them into the
Azure Log Analytics Workspace table via the Data Collector API.

Trigger schedule: controlled by the *IngesterSchedule* app setting
(CRON expression, e.g. "0 */5 * * * *" for every 5 minutes).
"""
import datetime
import logging
import time

import azure.functions as func

from ..SharedCode import consts
from ..SharedCode.logger import applogger
from .azure_storage_to_sentinel import AzureStorageToSentinel


def main(mytimer: func.TimerRequest) -> None:
    start = datetime.datetime.now(datetime.timezone.utc)
    start_epoch = str(int(time.time()))

    applogger.info(
        "%s: %s started at %s",
        consts.LOG_PREFIX,
        consts.FUNCTION_NAME_INGESTER,
        start.isoformat(),
    )

    if mytimer.past_due:
        logging.info("%s: timer is past due", consts.LOG_PREFIX)

    try:
        runner = AzureStorageToSentinel(start_epoch)
        runner.run()
    except Exception:
        applogger.exception(
            "%s: unhandled error in %s",
            consts.LOG_PREFIX,
            consts.FUNCTION_NAME_INGESTER,
        )
        raise
    finally:
        end = datetime.datetime.now(datetime.timezone.utc)
        applogger.info(
            "%s: %s ended at %s (duration=%.2fs)",
            consts.LOG_PREFIX,
            consts.FUNCTION_NAME_INGESTER,
            end.isoformat(),
            (end - start).total_seconds(),
        )
