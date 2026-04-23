"""Constants and configurations for the Google SecOps Detection Alerts connector."""

import os
from .utils import parse_cron_timeout

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LogLevel", "INFO")
LOGS_STARTS_WITH = "GoogleSecOpsDetectionAlerts"
LOG_PREFIX = LOGS_STARTS_WITH
FUNCTION_NAME_FETCHER = "GoogleSecOpsToStorage"
FUNCTION_NAME_INGESTER = "AzureStorageToSentinel"
LOG_FORMAT = "{}(method = {}) : {} : {}"

# ── Azure Monitor Ingestion (DCR-based) ──────────────────────────────────────
DCE_ENDPOINT = os.environ.get(
    "AZURE_DATA_COLLECTION_ENDPOINT", ""
)  # set by ARM template
DCR_IMMUTABLE_ID = os.environ.get("DCR_RULE_ID", "")  # set by ARM template
DCR_STREAM_NAME = os.environ.get("DcrStreamName", "")  # set by ARM template

# ── Chronicle API ─────────────────────────────────────────────────────────────
CHRONICLE_PROJECT_ID = os.environ.get("ChronicleProjectId", "")
CHRONICLE_REGION = os.environ.get("ChronicleRegion", "us")
CHRONICLE_INSTANCE_ID = os.environ.get("ChronicleInstanceId", "")
SERVICE_ACCOUNT_JSON = os.environ.get("ChronicleServiceAccountJson", "")

# ── Chronicle pagination parameters ───────────────────────────────────────────
DETECTION_BATCH_SIZE = int(os.environ.get("DetectionBatchSize", "1000"))
MAX_DETECTIONS = int(os.environ.get("MaxDetections", "100"))
LOOKBACK_DAYS = int(os.environ.get("LookbackDays", "1"))
MAX_LOOKBACK_DAYS = 7

# ── Checkpoint / state (Azure File Share) ─────────────────────────────────────
# AzureWebJobsStorage is the standard connection string env-var for Azure Functions.
CONN_STRING = os.environ.get("AzureWebJobsStorage", "")
FILE_SHARE_NAME = os.environ.get("FileShareName", "google-secops-state")
FILE_SHARE_NAME_DATA = os.environ.get("FileShareNameData", "google-secops-data")
CHECKPOINT_FILE_NAME = os.environ.get("CheckpointFileName", "google_secops_checkpoint")

# ── Google OAuth ──────────────────────────────────────────────────────────────
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TOKEN_EXPIRY_BUFFER_SECONDS = 60

# ── Retry / timeout ───────────────────────────────────────────────────────────
# Chronicle server sends a heartbeat every ~15 s; 300 s read timeout is safe.
API_TIMEOUT_SECONDS = 300
RETRY_BASE_DELAY_SECONDS = 2
# After this many consecutive stream failures the fetcher gives up for this run.
MAX_CONSECUTIVE_FAILURES = 7
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
# Function app timeout computed from Schedule CRON expression (e.g., "0 */10 * * * *" → 570 seconds)
FUNCTION_APP_TIMEOUT_SECONDS = int(parse_cron_timeout())

# ── Data file settings ────────────────────────────────────────────────────────
# Raw detection files are named:  google_secops_raw_<epoch>_<file_index>
# The epoch is the start_time of the function invocation (not the detection time).
FILE_NAME_PREFIX = "google_secops_raw"
# Minimum age (seconds) a data file must have before the ingester picks it up,
# giving the fetcher time to finish writing the file.
MAX_FILE_AGE_FOR_INGESTION = 300
# Maximum byte size of a single Azure File Share data file before rolling over.
# Detections are accumulated until this limit is hit, then flushed to a new file.
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# ── Error messages ─────────────────────────────────────────────────────────────
UNEXPECTED_ERROR_MSG = "Unexpected error : Error-{}"
HTTP_ERROR_MSG = "HTTP error : Error-{}"
REQUEST_ERROR_MSG = "Request error : Error-{}"
CONNECTION_ERROR_MSG = "Connection error : Error-{}"
