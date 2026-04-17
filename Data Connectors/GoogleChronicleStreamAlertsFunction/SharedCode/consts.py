"""Constants and configurations for the Google Chronicle Stream Detection Alerts connector."""

import os

# Logging
LOG_LEVEL = os.environ.get("LogLevel", "INFO")
LOGS_STARTS_WITH = "GoogleChronicleStreamAlerts"
LOG_PREFIX = LOGS_STARTS_WITH
FUNCTION_NAME = "GoogleChronicleStreamAlerts"
LOG_FORMAT = "{}(method = {}) : {}"

# Azure Sentinel - Log Ingestion API
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
SCOPE = os.environ.get("SCOPE", "https://monitor.azure.com/.default")
AZURE_DATA_COLLECTION_ENDPOINT = os.environ.get("AZURE_DATA_COLLECTION_ENDPOINT", "")
DCR_RULE_ID = os.environ.get("DCR_RULE_ID", "")
DCR_STREAM_NAME = os.environ.get("DcrStreamName", "Custom-GCSDetectionAlerts")

# Chronicle API
CHRONICLE_PROJECT_ID = os.environ.get("ChronicleProjectId", "")
CHRONICLE_REGION = os.environ.get("ChronicleRegion", "us")
CHRONICLE_INSTANCE_ID = os.environ.get("ChronicleInstanceId", "")
SERVICE_ACCOUNT_JSON = os.environ.get("ChronicleServiceAccountJson", "")

# Checkpoint
INPUT_START_TIME = os.environ.get("InputStartTime", "")
AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AzureWebJobsStorage", "")
STATE_TABLE_NAME = os.environ.get("StateTableName", "GoogleChronicleState")
STATE_PARTITION_KEY = "chronicle"
STATE_ROW_KEY = "streamDetectionAlerts"

# Chronicle API parameters
DETECTION_BATCH_SIZE = int(os.environ.get("DetectionBatchSize", "1000"))
MAX_DETECTIONS = int(os.environ.get("MaxDetections", "1000"))

# Google OAuth
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TOKEN_EXPIRY_BUFFER_SECONDS = 60

# Retry and timeout
API_TIMEOUT_SECONDS = 120
MAX_RETRIES = 4
RETRY_BASE_DELAY_SECONDS = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
FUNCTION_APP_TIMEOUT_SECONDS = 570
FUNCTION_BUDGET_SECONDS = FUNCTION_APP_TIMEOUT_SECONDS
SENTINEL_RETRY_COUNT = 3
MAX_TIMEOUT_SENTINEL = 120

# Error messages
UNEXPECTED_ERROR_MSG = "Unexpected error : Error-{}"
HTTP_ERROR_MSG = "HTTP error : Error-{}"
REQUEST_ERROR_MSG = "Request error : Error-{}"
CONNECTION_ERROR_MSG = "Connection error : Error-{}"
