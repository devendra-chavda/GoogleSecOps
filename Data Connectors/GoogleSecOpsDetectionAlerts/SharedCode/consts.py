"""Configuration constants for Google SecOps Detection Alerts connector.

This module defines all environment variables, defaults, and tuning parameters
for the two-function pipeline that fetches detections from Google Chronicle
and ingests them into Microsoft Sentinel.

Pipeline Overview:
  1. GoogleSecOpsToStorage: Polls Chronicle API → saves to Azure File Share
  2. AzureStorageToSentinel: Monitors share → posts to Sentinel via DCR API
"""

import os
from .utils import parse_cron_timeout


# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION METADATA
# ═══════════════════════════════════════════════════════════════════════════════
# Used for logging and identification across both functions

LOG_PREFIX = "GoogleSecOpsDetectionAlerts"  # Prefix for all log messages
LOG_LEVEL = os.environ.get("LogLevel", "INFO")  # DEBUG, INFO, WARNING, ERROR

FUNCTION_NAME_FETCHER = "GoogleSecOpsToStorage"  # First function (Chronicle → Storage)
FUNCTION_NAME_INGESTER = "AzureStorageToSentinel"  # Second function (Storage → Sentinel)


# ═══════════════════════════════════════════════════════════════════════════════
# CHRONICLE API CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
# Required: Set via ARM template or environment variables
# These connect to your Google SecOps (Chronicle) instance

CHRONICLE_PROJECT_ID = os.environ.get("ChronicleProjectId", "")
CHRONICLE_REGION = os.environ.get("ChronicleRegion", "us")  # us, europe, asia-southeast1
CHRONICLE_INSTANCE_ID = os.environ.get("ChronicleInstanceId", "")
SERVICE_ACCOUNT_JSON = os.environ.get("ChronicleServiceAccountJson", "")

# Google OAuth configuration for Chronicle API authentication
OAUTH_SCOPE = os.environ.get("OAuthScope", "https://www.googleapis.com/auth/cloud-platform")
TOKEN_EXPIRY_BUFFER_SECONDS = 60  # Refresh token 60s before expiry


# ═══════════════════════════════════════════════════════════════════════════════
# AZURE STORAGE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
# File shares for checkpoint tracking and raw data storage

CONN_STRING = os.environ.get("AzureWebJobsStorage", "")  # Storage account connection string

# State management (checkpoint tracking)
FILE_SHARE_NAME = os.environ.get("FileShareName", "google-secops-state")
CHECKPOINT_FILE_NAME = os.environ.get("CheckpointFileName", "google_secops_checkpoint")

# Raw detection data (buffering between functions)
FILE_SHARE_NAME_DATA = os.environ.get("FileShareNameData", "google-secops-data")
FILE_NAME_PREFIX = "google_secops_raw"  # Files named: {PREFIX}_{epoch}_{index}


# ═══════════════════════════════════════════════════════════════════════════════
# AZURE MONITOR INGESTION (SENTINEL DCR)
# ═══════════════════════════════════════════════════════════════════════════════
# Data Collection Rule (DCR) endpoint for posting detections to Sentinel
# Required: Set via ARM template

DCE_ENDPOINT = os.environ.get("AZURE_DATA_COLLECTION_ENDPOINT", "")
DCR_IMMUTABLE_ID = os.environ.get("DCR_RULE_ID", "")
DCR_STREAM_NAME = os.environ.get("DcrStreamName", "")


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION FETCHING PARAMETERS
# ═══════════════════════════════════════════════════════════════════════════════
# Control how many detections are fetched from Chronicle in each operation

LOOKBACK_DAYS = int(os.environ.get("LookbackDays", "1"))  # Default: 1 day back
MAX_LOOKBACK_DAYS = 7  # Safety limit: never go back more than 7 days

DETECTION_BATCH_SIZE = int(os.environ.get("DetectionBatchSize", "1000"))
# How many detections per Chronicle API page (Chronicle's pagination)

MAX_DETECTIONS = int(os.environ.get("MaxDetections", "1000"))
# How many detections to fetch before stopping (per run)
# Prevents runaway fetches; use smaller values in testing


# ═══════════════════════════════════════════════════════════════════════════════
# DATA PIPELINE SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════
# Control file handling and batching through the pipeline

# Ingestion: Post to Sentinel in chunks (500 events per API call)
INGESTION_BATCH_SIZE = 500

# File age before ingester picks it up (seconds)
# Prevents race condition: gives fetcher time to finish writing before ingester reads
MAX_FILE_AGE_FOR_INGESTION = 300  # 5 minutes


# ═══════════════════════════════════════════════════════════════════════════════
# POLLING & MONITORING SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════
# How often the ingester checks for new files

FILE_CHECK_INTERVAL_SECONDS = 300  # 5 minutes: check for new files
BUSY_WAIT_SLEEP_SECONDS = 10  # Sleep between checks (avoids CPU spinning)


# ═══════════════════════════════════════════════════════════════════════════════
# RESILIENCE & TIMEOUT SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════
# Error handling and timeouts for API calls

# Chronicle API streaming timeout
API_TIMEOUT_SECONDS = 300  # 5 minutes
# Chronicle server sends heartbeat every ~15 seconds
# 300s timeout is safe for detecting truly dead connections

# Retry behavior for transient errors
RETRY_BASE_DELAY_SECONDS = 2  # Initial backoff delay: 2 seconds
MAX_CONSECUTIVE_FAILURES = 7  # Give up after 7 consecutive errors
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}  # HTTP codes to retry on

# Function timeout calculated from Azure schedule (CRON expression)
# Example: "0 */10 * * * *" (every 10 min) → 570 seconds
FUNCTION_APP_TIMEOUT_SECONDS = int(parse_cron_timeout())
