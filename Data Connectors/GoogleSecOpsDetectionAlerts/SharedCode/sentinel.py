"""Post events to Azure Log Analytics via the Azure Monitor Ingestion SDK.

Uses LogsIngestionClient (DCR-based ingestion) with DefaultAzureCredential.
Requires a Data Collection Endpoint, Data Collection Rule immutable ID, and
stream name configured as environment variables.
"""

import inspect
import json

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

from . import consts
from .exceptions import SentinelIngestionError
from .logger import applogger


def post_data(body: str, stream_name: str = consts.DCR_STREAM_NAME) -> None:
    """Upload a JSON array *body* to Log Analytics via DCR ingestion.

    Args:
        body:        JSON string containing a list of records.
        stream_name: DCR stream name (defaults to DCRStreamName env var).

    Raises:
        SentinelIngestionError: on missing config or ingestion failure.
    """
    __method_name = inspect.currentframe().f_code.co_name

    endpoint = consts.DCE_ENDPOINT.strip()
    rule_id = consts.DCR_IMMUTABLE_ID.strip()
    stream = stream_name.strip() if stream_name else ""

    missing = [
        name for name, val in [
            ("DCEEndpoint", endpoint),
            ("DCRImmutableId", rule_id),
            ("DCRStreamName", stream),
        ] if not val
    ]
    if missing:
        raise SentinelIngestionError(
            f"Missing env vars for Monitor ingestion: {missing}"
        )

    try:
        records = json.loads(body)
    except json.JSONDecodeError as err:
        raise SentinelIngestionError(f"Invalid JSON body: {err}") from err

    if not records:
        applogger.debug(
            "{}(method={}) : empty batch, skip".format(
                consts.LOGS_STARTS_WITH, __method_name
            )
        )
        return

    try:
        credential = DefaultAzureCredential()
        client = LogsIngestionClient(endpoint=endpoint, credential=credential)
        client.upload(rule_id=rule_id, stream_name=stream, logs=records)
        applogger.info(
            "{}(method={}) : uploaded {} records → stream={}".format(
                consts.LOGS_STARTS_WITH, __method_name, len(records), stream
            )
        )
    except HttpResponseError as err:
        applogger.error(
            "{}(method={}) : HTTP error: {}".format(
                consts.LOGS_STARTS_WITH, __method_name, err
            )
        )
        raise SentinelIngestionError(f"HTTP error: {err}") from err
    except Exception as err:
        applogger.error(
            "{}(method={}) : unexpected error: {}".format(
                consts.LOGS_STARTS_WITH, __method_name, err
            )
        )
        raise SentinelIngestionError(f"Unexpected error: {err}") from err
