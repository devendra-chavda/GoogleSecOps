"""Post events to Azure Log Analytics Workspace via the Data Collector API.

Uses the HMAC-SHA256 shared-key authentication (older but widely supported).
The workspace table name is  <log_type>_CL  (Azure appends the _CL suffix).

Reference:
  https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api
"""

import base64
import datetime
import hashlib
import hmac
import inspect

import requests

from . import consts
from .exceptions import SentinelIngestionError
from .logger import applogger

# Maximum number of records in a single POST body.
_MAX_BATCH = 500


def _build_signature(
    date: str,
    content_length: int,
    method: str,
    content_type: str,
    resource: str,
) -> str:
    """Return the SharedKey authorization header value."""
    x_headers = "x-ms-date:" + date
    string_to_hash = (
        method
        + "\n"
        + str(content_length)
        + "\n"
        + content_type
        + "\n"
        + x_headers
        + "\n"
        + resource
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(consts.WORKSPACE_KEY)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return "SharedKey {}:{}".format(consts.WORKSPACE_ID, encoded_hash)


def post_data(body: str, log_type: str = consts.LOG_TYPE) -> int:
    """POST a JSON array *body* to a Log Analytics custom table.

    Args:
        body:     JSON string containing a list of records.
        log_type: Table name prefix (Azure appends *_CL* automatically).

    Returns:
        HTTP status code (2xx on success).

    Raises:
        SentinelIngestionError: on authentication error or non-2xx response.
    """
    __method_name = inspect.currentframe().f_code.co_name
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)

    try:
        signature = _build_signature(
            rfc1123date, content_length, method, content_type, resource
        )
    except Exception as err:
        applogger.error(
            "{}(method={}) : Error building signature: {}".format(
                consts.LOGS_STARTS_WITH, __method_name, err
            )
        )
        raise SentinelIngestionError(f"Signature error: {err}") from err

    uri = (
        "https://"
        + consts.WORKSPACE_ID
        + ".ods.opinsights.azure.com"
        + resource
        + "?api-version=2016-04-01"
    )
    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }

    try:
        response = requests.post(uri, data=body, headers=headers, timeout=120)
        if 200 <= response.status_code <= 299:
            applogger.debug(
                "{}(method={}) : Data posted — status_code={}".format(
                    consts.LOGS_STARTS_WITH, __method_name, response.status_code
                )
            )
            return response.status_code
        raise SentinelIngestionError(
            f"Non-success response {response.status_code}: {response.text[:500]}"
        )
    except requests.RequestException as err:
        applogger.error(
            "{}(method={}) : Request error: {}".format(
                consts.LOGS_STARTS_WITH, __method_name, err
            )
        )
        raise SentinelIngestionError(f"Request error: {err}") from err
