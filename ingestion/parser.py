from __future__ import annotations
import json
import logging
from datetime import datetime, timezone

from models import LogEntry

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = frozenset([
    "timestamp", "method", "path", "status",
    "ip", "body", "response_time_ms", "user_agent",
])


def parse_entry(raw: str) -> LogEntry | None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Malformed JSON (%.10000s): %s", raw, exc)
        return None

    if not isinstance(data, dict):
        logger.error("Log entry is not a JSON object: %.10000s", raw)
        return None

    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        logger.error("Log entry missing fields %s: %.10000s", sorted(missing), raw)
        return None

    try:
        ts_raw = data["timestamp"]
        if isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        else:
            ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
    except (ValueError, TypeError, OSError) as exc:
        logger.error("Invalid timestamp in entry: %s", exc)
        return None

    try:
        return LogEntry(
            timestamp=ts,
            method=str(data["method"]),
            path=str(data["path"]),
            status=int(data["status"]),
            ip=str(data["ip"]),
            body=str(data["body"]),
            response_time_ms=int(data["response_time_ms"]),
            user_agent=str(data["user_agent"]),
            raw=raw,
        )
    except (ValueError, TypeError) as exc:
        logger.error("Type coercion failed for log entry: %s", exc)
        return None
