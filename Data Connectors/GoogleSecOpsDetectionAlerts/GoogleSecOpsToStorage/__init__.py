"""Timer-trigger entry point for the GoogleSecOpsToStorage function.

Fetches detection alerts from the Google SecOps (Chronicle) streaming API
and writes them page-by-page into Azure File Share for durable buffering.

The companion AzureStorageToSentinel function then reads those files and
ingests the records into the Azure Log Analytics Workspace table.

Trigger schedule: controlled by the *FetcherSchedule* app setting
(CRON expression, e.g. "0 */5 * * * *" for every 5 minutes).
"""
import datetime
import logging
import time

import azure.functions as func

from ..SharedCode import consts
from ..SharedCode.logger import applogger
from .google_secops_to_storage import GoogleSecOpsToStorage


def main(mytimer: func.TimerRequest) -> None:
    start = datetime.datetime.now(datetime.timezone.utc)
    start_epoch = str(int(time.time()))

    applogger.info(
        "%s: %s started at %s",
        consts.LOG_PREFIX,
        consts.FUNCTION_NAME_FETCHER,
        start.isoformat(),
    )

    if mytimer.past_due:
        logging.info("%s: timer is past due", consts.LOG_PREFIX)

    try:
        runner = GoogleSecOpsToStorage(start_epoch)
        runner.run()
    except Exception:
        applogger.exception(
            "%s: unhandled error in %s",
            consts.LOG_PREFIX,
            consts.FUNCTION_NAME_FETCHER,
        )
        raise
    finally:
        end = datetime.datetime.now(datetime.timezone.utc)
        applogger.info(
            "%s: %s ended at %s (duration=%.2fs)",
            consts.LOG_PREFIX,
            consts.FUNCTION_NAME_FETCHER,
            end.isoformat(),
            (end - start).total_seconds(),
        )
