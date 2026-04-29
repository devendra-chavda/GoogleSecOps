"""Post events to Azure Log Analytics via the Azure Monitor Ingestion SDK.

Uses LogsIngestionClient (DCR-based ingestion) with either:
- ClientSecretCredential (if AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID provided)
- DefaultAzureCredential (fallback for managed identity, MSI, etc.)

Requires a Data Collection Endpoint, Data Collection Rule immutable ID, and
stream name configured as environment variables.
"""

import inspect
import json
import os

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

from . import consts
from .exceptions import SentinelIngestionError
from .logger import applogger


def _get_credential():
    """Get Azure credential (ClientSecretCredential if configured, otherwise DefaultAzureCredential).

    Returns:
        Azure credential object

    Raises:
        ValueError: If ClientSecretCredential is partially configured
    """
    __method_name = inspect.currentframe().f_code.co_name

    client_id = consts.AZURE_CLIENT_ID
    client_secret = consts.AZURE_CLIENT_SECRET
    tenant_id = consts.AZURE_TENANT_ID
    try:
        credential = ClientSecretCredential(
            client_id=client_id, client_secret=client_secret, tenant_id=tenant_id
        )
        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                "SentinelAuth",
                f"Using ClientSecretCredential (client_id={client_id[:20]}...)",
            )
        )
        return credential
    except Exception as exc:
        error_msg = consts.LOG_FORMAT.format(
            consts.LOG_PREFIX,
            __method_name,
            "SentinelAuth",
            f"Failed to create ClientSecretCredential: type={type(exc).__name__}, reason={str(exc)[:150]}",
        )
        applogger.error(error_msg)
        raise ValueError(error_msg) from exc


def post_data(body: str, stream_name: str = consts.DCR_STREAM_NAME) -> None:
    """Upload a JSON array *body* to Log Analytics via DCR ingestion.

    Args:
        body:        JSON string containing a list of records.
        stream_name: DCR stream name (defaults to DCRStreamName env var).

    Raises:
        SentinelIngestionError: on missing config or ingestion failure.
    """
    __method_name = inspect.currentframe().f_code.co_name
    azure_function_name = consts.FUNCTION_NAME_INGESTER

    applogger.debug(
        consts.LOG_FORMAT.format(
            consts.LOG_PREFIX,
            __method_name,
            azure_function_name,
            "Starting Sentinel data ingestion",
        )
    )

    endpoint = consts.DCE_ENDPOINT.strip()
    rule_id = consts.DCR_IMMUTABLE_ID.strip()
    stream = stream_name.strip() if stream_name else ""

    try:
        records = json.loads(body)
        body_size_kb = len(body.encode("utf-8")) / 1024
        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                azure_function_name,
                f"JSON parsed: {len(records)} records, payload_size={body_size_kb:.1f}KB",
            )
        )
    except json.JSONDecodeError as err:
        error_msg = consts.LOG_FORMAT.format(
            consts.LOG_PREFIX,
            __method_name,
            azure_function_name,
            f"Invalid JSON body: char={err.pos}, line={err.lineno}, reason={err.msg}",
        )
        applogger.error(error_msg)
        raise SentinelIngestionError(error_msg) from err

    if not records:
        applogger.debug(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                azure_function_name,
                "Empty batch received, skipping ingestion",
            )
        )
        return

    try:
        # Get Azure credential (explicit or managed identity)
        credential = _get_credential()
        client = LogsIngestionClient(endpoint=endpoint, credential=credential)
        client.upload(rule_id=rule_id, stream_name=stream, logs=records)

        applogger.info(
            consts.LOG_FORMAT.format(
                consts.LOG_PREFIX,
                __method_name,
                azure_function_name,
                f"Posted: {len(records)} records to DCR stream={stream}, endpoint={consts.DCE_ENDPOINT[:30]}...",
            )
        )
    except HttpResponseError as err:
        error_msg = consts.LOG_FORMAT.format(
            consts.LOG_PREFIX,
            __method_name,
            azure_function_name,
            f"HTTP error during ingestion: status={err.status_code}, stream={stream}, reason={str(err)[:150]}",
        )
        applogger.error(error_msg)
        raise SentinelIngestionError(error_msg) from err
    except Exception as err:
        error_msg = consts.LOG_FORMAT.format(
            consts.LOG_PREFIX,
            __method_name,
            azure_function_name,
            f"Unexpected error during ingestion: type={type(err).__name__}, stream={stream}, reason={str(err)[:150]}",
        )
        applogger.error(error_msg)
        raise SentinelIngestionError(error_msg) from err
