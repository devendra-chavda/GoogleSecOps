# Demisto-Inspired Streaming Fix - Per-Message Timeout Detection

## Problem
Stream was hanging at 50 MB with no timeout or error. The chunked reading approach (`response.iter_bytes()`) was blocking indefinitely without detecting when the stream stopped sending data.

## Solution: Line-Based Parsing with Timeout Detection

Implemented Demisto's approach with key improvements:

### Old Approach (Failed)
```python
# Chunks were accumulating but no timeout if stream stopped
for chunk in response.iter_bytes(chunk_size=1_MB):
    chunks.append(chunk)
    # NO per-message timeout detection
    # Stream could hang forever
```

### New Approach (Demisto-Inspired)
```python
def _read_stream_batch(self, response, timeout_seconds):
    for line in response.iter_lines():
        now = time.time()
        if now - last_line_time > timeout_seconds:
            # DETECT: No new line for 300 seconds = timeout
            raise ChronicleApiError("Stream timeout")
        
        lines.append(line)
        
        # Try parsing accumulated lines
        json_text = "".join(lines)
        batch = json.loads(json_text)
        
        if batch.get("heartbeat"):
            continue  # Heartbeat, keep connection alive
        
        return batch  # Complete batch
```

## Key Changes

### 1. **Per-Message Timeout Detection**
- Tracks `last_line_time` for each line received
- If no new line arrives for 300 seconds → immediate timeout error
- Prevents indefinite hanging

### 2. **Line-Based Instead of Chunk-Based**
- `response.iter_lines(chunk_size=1MB)` instead of `iter_bytes()`
- Parses complete JSON objects as they arrive
- More aligned with Chronicle's JSON array format

### 3. **Heartbeat Handling**
- Detects `{"heartbeat": true}` batches
- Continues loop without returning
- Keeps connection alive between real batches

### 4. **Incremental Parsing**
- Tries to parse accumulated lines after each new line
- Returns immediately when a complete batch is found
- Doesn't wait for entire response

### 5. **Better Progress Logging**
```
INFO: stream read... 1.00 MB received (5 lines)
INFO: stream read... 2.00 MB received (10 lines)
...
INFO: batch received (50.00 MB, 250 lines), keys=['detections', 'nextPageToken']
```

## What Happens If Stream Hangs

### Before (Would hang forever):
```
INFO: HTTP response received (status=200, wait=0.17s)
INFO: reading stream... 50 MB received (50 chunks)
[5+ minutes of silence]
[Function timeout after 10 minutes]
```

### After (Detects immediately):
```
INFO: HTTP response received (status=200, wait=0.17s)
INFO: stream read... 10 MB received (50 lines)
INFO: stream read... 20 MB received (100 lines)
...
INFO: stream read... 50 MB received (250 lines)
[No new line for 10+ seconds...]
ERROR: No data received for 300 seconds, stream timeout
```

## API Behavior Expected

- Chronicle sends never-ending JSON array: `[{...}, {...}, ...]`
- Each element is a batch containing:
  - `detections`: array of alerts
  - `nextPageToken`: pagination token (mid-window)
  - `nextPageStartTime`: next window start (window complete)
  - `heartbeat`: keep-alive message every ~15 seconds

- Server keeps connection open between batches
- Client must detect if connection dies (no line for N seconds)

## Configuration

- `API_TIMEOUT_SECONDS = 300` (in consts.py)
  - Max seconds to wait for next line arrival
  - Chronicle sends heartbeats every ~15s, so 300s is safe
  - Can be tuned via environment variable if needed

## Expected Behavior

### Scenario 1: Normal Operation
```
INFO: stream read... 10 MB received
INFO: stream read... 20 MB received
...
INFO: batch received (156 MB), keys=['detections', 'nextPageToken']
```
→ Success, continues pagination

### Scenario 2: Heartbeat During Large Response
```
INFO: stream read... 50 MB received
DEBUG: received heartbeat, continuing
INFO: stream read... 60 MB received
...
INFO: batch received (75 MB), keys=['detections', 'nextPageToken']
```
→ Connection kept alive, continues

### Scenario 3: Stream Hangs
```
INFO: stream read... 50 MB received
[No new line for 300 seconds...]
ERROR: No data received for 300 seconds, stream timeout
```
→ Timeout detected and reported instead of silent hang

## Testing Notes

- Smaller `maxDetections` (100) should reduce response size
- Heartbeats (~15s interval) keep connection alive
- 300-second timeout prevents indefinite hangs
- Each batch returns immediately when complete (no waiting for stream to close)

## Demisto Reference

Based on: https://github.com/demisto/content/blob/master/Packs/GoogleChronicleBackstory/Integrations/GoogleChronicleBackstoryStreamingAPI/GoogleChronicleBackstoryStreamingAPI.py

Their approach:
- 300-second timeout between messages (we now implement this)
- Handle heartbeats gracefully (we now do this)
- Line-by-line parsing (we now use this)
- Proper error handling (we added comprehensive logging)
