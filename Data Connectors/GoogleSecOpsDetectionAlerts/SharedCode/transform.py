"""Transform raw Chronicle detection objects into the DCR table schema.

Raw API shape (each element of the `detections` array):
{
  "type": "RULE_DETECTION",
  "detection": [
    {
      "ruleName": "...",
      "ruleId": "ru_...",
      "ruleVersion": "ru_...@v_...",
      "ruleLabels": [ {"key": "...", "value": "..."} ],
      "severity": "HIGH",
      "description": "...",
      "urlBackToProduct": "https://...",
      "alertState": "ALERTING",
      "ruleType": "MULTI_EVENT",
      "detectionFields": [ {"key": "...", "value": "..."} ],
      "outcomes": [ {"key": "...", "value": "...", "source": "..."} ],
      "riskScore": 40,
      "variables": { ... }
    }
  ],
  "createdTime": "2026-04-15T00:01:23Z",
  "id": "de_...",
  "detectorId": "..."
}

Target schema (GCSDetectionAlerts_CL):
  detection_id, type, detection_time, rule_id, rule_name, rule_version,
  rule_labels (dynamic), severity, summary, url_back_to_product,
  collection_elements (dynamic), alert_state, detector_id
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List

from .logger import applogger
from . import consts


def _safe_str(obj: Any, key: str, default: str = "") -> str:
    if isinstance(obj, dict):
        return str(obj.get(key, default) or default)
    return default


def _build_collection_elements(det: dict) -> list:
    """Combine detectionFields, outcomes, and variables into a single dynamic array."""
    elements = []
    for field in det.get("detectionFields", []) or []:
        elements.append(
            {
                "source": "detectionField",
                "key": field.get("key", ""),
                "value": field.get("value", ""),
            }
        )
    for outcome in det.get("outcomes", []) or []:
        elements.append(
            {
                "source": outcome.get("source", "outcome"),
                "key": outcome.get("key", ""),
                "value": outcome.get("value", ""),
            }
        )
    variables = det.get("variables", {}) or {}
    for var_name, var_obj in variables.items():
        if isinstance(var_obj, dict):
            elements.append(
                {
                    "source": "variable",
                    "key": var_name,
                    "value": var_obj.get("value", ""),
                }
            )
    return elements


def transform_detection(raw: dict) -> Dict[str, Any]:
    """Flatten a single raw detection into the DCR row schema."""
    det = {}
    detection_list = raw.get("detection", []) or []
    if detection_list and isinstance(detection_list, list):
        det = detection_list[0] if isinstance(detection_list[0], dict) else {}

    return {
        "detection_id": _safe_str(raw, "id"),
        "type": _safe_str(raw, "type"),
        "detection_time": raw.get("createdTime")
        or datetime.now(timezone.utc).isoformat(),
        "rule_id": _safe_str(det, "ruleId"),
        "rule_name": _safe_str(det, "ruleName"),
        "rule_version": _safe_str(det, "ruleVersion"),
        "rule_labels": det.get("ruleLabels", []) or [],
        "severity": _safe_str(det, "severity"),
        "summary": _safe_str(det, "description"),
        "url_back_to_product": _safe_str(det, "urlBackToProduct"),
        "collection_elements": _build_collection_elements(det),
        "alert_state": _safe_str(det, "alertState"),
        "detector_id": _safe_str(raw, "detectorId"),
    }


def transform_detections(raw_detections: List[dict]) -> Iterator[Dict[str, Any]]:
    """Transform a batch of raw detections, skipping any that fail."""
    for i, raw in enumerate(raw_detections):
        try:
            yield transform_detection(raw)
        except Exception:
            applogger.warning(
                "%s: failed to transform detection index=%d, skipping",
                consts.LOG_PREFIX,
                i,
                exc_info=True,
            )
