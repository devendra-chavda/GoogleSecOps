"""Post events to a Sentinel Data Collection Rule (Logs Ingestion API)."""

import inspect
from typing import Iterable, List

from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
from azure.identity import AzureAuthorityHosts, ClientSecretCredential
from azure.monitor.ingestion import LogsIngestionClient

from . import consts
from .exceptions import SentinelIngestionError
from .logger import applogger

_MAX_BATCH = 500


class SentinelPoster:
    """Ingest events into Microsoft Sentinel via the Logs Ingestion API (DCR)."""

    def __init__(
        self,
        endpoint: str = consts.AZURE_DATA_COLLECTION_ENDPOINT,
        rule_id: str = consts.DCR_RULE_ID,
        stream_name: str = consts.DCR_STREAM_NAME,
    ):
        __method_name = inspect.currentframe().f_code.co_name
        if not (endpoint and rule_id and stream_name):
            raise ValueError(
                "AZURE_DATA_COLLECTION_ENDPOINT, DCR_RULE_ID and "
                "DcrStreamName are required."
            )
        self._endpoint = endpoint
        self._rule_id = rule_id
        self._stream_name = stream_name

        if ".us" in consts.SCOPE:
            creds = ClientSecretCredential(
                client_id=consts.AZURE_CLIENT_ID,
                client_secret=consts.AZURE_CLIENT_SECRET,
                tenant_id=consts.AZURE_TENANT_ID,
                authority=AzureAuthorityHosts.AZURE_GOVERNMENT,
            )
        else:
            creds = ClientSecretCredential(
                client_id=consts.AZURE_CLIENT_ID,
                client_secret=consts.AZURE_CLIENT_SECRET,
                tenant_id=consts.AZURE_TENANT_ID,
            )

        self._client = LogsIngestionClient(
            endpoint=endpoint,
            credential=creds,
            credential_scopes=[consts.SCOPE],
            logging_enable=False,
        )
        applogger.info(
            consts.LOG_FORMAT.format(
                consts.LOGS_STARTS_WITH,
                __method_name,
                "SentinelPoster initialized successfully.",
            )
        )

    def _upload(self, batch: List[dict]) -> None:
        """Upload a single batch to the DCR stream."""
        self._client.upload(
            rule_id=self._rule_id,
            stream_name=self._stream_name,
            logs=batch,
        )

    def post(self, events: Iterable[dict]) -> int:
        """Post events in batches. Returns total count of events posted."""
        __method_name = inspect.currentframe().f_code.co_name
        batch: List[dict] = []
        posted = 0

        for ev in events:
            batch.append(ev)
            if len(batch) >= _MAX_BATCH:
                try:
                    self._upload(batch)
                except ClientAuthenticationError as exc:
                    applogger.error(
                        consts.LOG_FORMAT.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            f"Authentication error while uploading data to Sentinel: {exc}",
                        )
                    )
                    raise SentinelIngestionError(
                        f"Authentication error: {exc}"
                    ) from exc
                except HttpResponseError as exc:
                    applogger.error(
                        consts.LOG_FORMAT.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            f"HTTP response error while uploading data to Sentinel: {exc}",
                        )
                    )
                    raise SentinelIngestionError(
                        f"DCR ingestion failed: {exc}"
                    ) from exc
                posted += len(batch)
                batch = []

        if batch:
            try:
                self._upload(batch)
            except ClientAuthenticationError as exc:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        f"Authentication error while uploading data to Sentinel: {exc}",
                    )
                )
                raise SentinelIngestionError(
                    f"Authentication error: {exc}"
                ) from exc
            except HttpResponseError as exc:
                applogger.error(
                    consts.LOG_FORMAT.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        f"HTTP response error while uploading data to Sentinel: {exc}",
                    )
                )
                raise SentinelIngestionError(
                    f"DCR ingestion failed: {exc}"
                ) from exc
            posted += len(batch)

        applogger.info(
            consts.LOG_FORMAT.format(
                consts.LOGS_STARTS_WITH,
                __method_name,
                f"Posted {posted} events to Sentinel.",
            )
        )
        return posted
