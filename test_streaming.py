"""Test script to verify streaming data reception and chunk reading locally."""

import json
import os
import google.auth
import google.auth.transport.requests
import httpx
from .google_auth import GoogleServiceAccountAuth


class GoogleAuthTransport(httpx.BaseTransport):
    """Custom HTTPX transport that adds Google auth headers."""

    def __init__(self, transport: httpx.BaseTransport = None):
        self.transport = transport or httpx.HTTPTransport()
        self.auth_request = google.auth.transport.requests.Request()
        self.credentials = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Add Google auth headers to HTTPX request."""
        if not self.credentials:
            self.credentials, _ = google.auth.default()
        self.credentials.before_request(
            self.auth_request, request.method, str(request.url), request.headers
        )
        return self.transport.handle_request(request)



def test_streaming():
    """Test streaming with hardcoded or env-based service account JSON."""
    
    # Hardcoded service account JSON or from environment
    service_account_json = {}

    
    if not service_account_json:
        print("ERROR: Set SecOpsServiceAccountJson environment variable")
        return

    # Auth setup with HTTPX and custom Google auth transport
    auth = GoogleServiceAccountAuth(json.dumps(service_account_json))
    # Set credentials for the transport
    transport = GoogleAuthTransport()
    transport.credentials = auth.get_credentials()
    http_client = httpx.Client(transport=transport)
    
    # API endpoint
    project_id = os.environ.get("SecOpsProjectId", "chronicle-272")
    region = os.environ.get("SecOpsRegion", "us")
    instance_id = os.environ.get("SecOpsInstanceId", "ed19f037-2354-43df-bfbf-350362b45844")
    
    endpoint = (
        f"https://{region}-chronicle.googleapis.com/v1alpha/"
        f"projects/{project_id}/locations/{region}/"
        f"instances/{instance_id}/legacy:legacyStreamDetectionAlerts"
    )
    
    print(f"Testing streaming from: {endpoint}")
    payload = {
        "detectionBatchSize": 1000,
        "maxDetections": 10,
        "pageStartTime": "2026-04-24T06:20:00.282192142Z"
    }
    batch = ""

    
    # Make streaming request with HTTPX
    with http_client.stream(
        "POST",
        url=endpoint,
        content=json.dumps(payload),
        timeout=300.0,
    ) as response:
        response.raise_for_status()

        # Parse stream (same as secops_client.parse_stream)
        lines_received = 0
        batches_found = 0

        try:
            for line in response.iter_lines():
                if not line:
                    continue
                lines_received += 1

                batches_found += 1

                batch += line

        finally:
            print(
                f"Stream complete: lines_received={lines_received}, batches_found={batches_found}"
            )
            
    parsed = json.loads(batch)
    print(parsed)

    # with open("./test.txt", "w", encoding="utf-8") as f:
    #     f.write(batch)


if __name__ == "__main__":
    test_streaming()

    # with open("./test.txt", "r", encoding="utf-8") as f:
    #     data = f.read()

    # batches = json.loads(data)
    # print(len(batches))
    # print(len(batches[1]), len(batches[0]))
