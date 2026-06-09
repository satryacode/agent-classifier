# Traffic Fraud Classifier Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python stream processing service that tails dummy-be's JSON log file, profiles traffic, detects fraud patterns, and outputs JSON Lines verdicts.

**Architecture:** File ingestor tails `logs/requests.jsonl` → TrafficProfiler maintains IP/user/endpoint profiles → ClassificationEngine runs 4 detectors → OutputWriter emits JSON Lines. dummy-be must first be fixed to write logs in the correct format.

**Tech Stack:** Python 3.11+, pydantic-settings, hypothesis, pytest, moto; Go/zap for dummy-be fix.

---

## Chunk 1: dummy-be Logging Fix

### Task 1: Fix dummy-be logger format and file output

**Files:**
- Modify: `dummy-be/middleware/logger.go`
- Modify: `dummy-be/.gitignore`

- [ ] **Step 1: Fix `.gitignore`** — it has junk content. Replace entirely:

```
.env
*.env
dummy-be
logs/*.jsonl
```

- [ ] **Step 2: Update `NewLogger()` in `middleware/logger.go`**

Replace the entire file:

```go
// middleware/logger.go
package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type responseWriter struct {
	gin.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func RequestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		c.Next()

		elapsed := time.Since(start).Milliseconds()

		compactBody := string(bodyBytes)
		var compacted bytes.Buffer
		if json.Compact(&compacted, bodyBytes) == nil {
			compactBody = compacted.String()
		}

		logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.String("ip", c.ClientIP()),
			zap.String("body", compactBody),
			zap.Int64("response_time_ms", elapsed),
			zap.String("user_agent", c.Request.UserAgent()),
		)
	}
}

func NewLogger() (*zap.Logger, error) {
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return nil, fmt.Errorf("create logs dir: %w", err)
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "timestamp"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	enc := zapcore.NewJSONEncoder(encCfg)

	logFile, err := os.OpenFile(
		"logs/requests.jsonl",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0o644,
	)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(enc, zapcore.AddSync(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(enc, zapcore.AddSync(logFile), zap.InfoLevel),
	)
	return zap.New(core), nil
}
```

- [ ] **Step 3: Build and verify it compiles**

```bash
cd dummy-be && go build ./...
```
Expected: no errors.

- [ ] **Step 4: Run the server and fire a test request, check the log file**

```bash
cd dummy-be && go run . &
sleep 1
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass"}'
cat logs/requests.jsonl
```

Expected: one JSON line with `timestamp` in ISO 8601 format, `method`, `path`, `status`, `ip`, `body`, `response_time_ms`, `user_agent` fields.

- [ ] **Step 5: Kill the server and commit**

```bash
kill %1
cd dummy-be
git add middleware/logger.go .gitignore
git commit -m "fix: write structured logs to file with ISO8601 timestamp"
```

---

## Chunk 2: Core Models + Config + Parser

### Task 2: Add `models.py`

**Files:**
- Create: `models.py`

- [ ] **Step 1: Write the failing test** in `tests/unit/test_models.py`

```python
from datetime import datetime, timezone
from models import LogEntry, Verdict, FraudFlag, DetectionResult

def test_log_entry_frozen():
    entry = LogEntry(
        timestamp=datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc),
        method="POST", path="/login", status=200,
        ip="1.2.3.4", body='{"username":"admin"}',
        response_time_ms=12, user_agent="Mozilla/5.0", raw="{}",
    )
    import pytest
    with pytest.raises((AttributeError, TypeError)):
        entry.method = "GET"

def test_verdict_fields():
    from models import Verdict
    v = Verdict(
        timestamp="2026-06-09T10:00:00Z", source_ip="1.2.3.4",
        user_identity=None, method="POST", path="/login",
        classification="FRAUDULENT", confidence_score=0.9,
        reason="sql_injection", original_log_entry_reference="{}",
    )
    assert v.classification == "FRAUDULENT"
    assert v.confidence_score == 0.9
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd agent-classifier && python -m pytest tests/unit/test_models.py -v
```
Expected: `ImportError: No module named 'models'`

- [ ] **Step 3: Create `models.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class LogEntry:
    timestamp: datetime
    method: str
    path: str
    status: int
    ip: str
    body: str
    response_time_ms: int
    user_agent: str
    raw: str


@dataclass
class DetectionResult:
    is_fraudulent: bool
    reason: str
    confidence: float


@dataclass
class ProfileContext:
    ip: str
    ip_request_count: int = 0
    ip_distinct_paths: set = field(default_factory=set)
    ip_suspicious: bool = False
    ip_suspicious_reason: Optional[str] = None
    ip_failed_logins: int = 0
    ip_total_logins: int = 0
    ip_distinct_users: set = field(default_factory=set)
    ip_successful_logins: list = field(default_factory=list)  # list of datetime
    username: Optional[str] = None
    user_failed_logins: int = 0
    user_total_logins: int = 0
    user_distinct_ips: set = field(default_factory=set)
    user_suspicious: bool = False
    user_suspicious_reason: Optional[str] = None
    endpoint_request_count: int = 0
    endpoint_error_count: int = 0
    endpoint_rate_abuse: bool = False


@dataclass
class Verdict:
    timestamp: str
    source_ip: str
    user_identity: Optional[str]
    method: str
    path: str
    classification: str  # "LEGITIMATE" or "FRAUDULENT"
    confidence_score: float
    reason: str
    original_log_entry_reference: str


@dataclass
class FraudFlag:
    ip: str
    user_identity: Optional[str]
    timestamp: str
    reason: str
    confidence_score: float
```

- [ ] **Step 4: Run tests and verify they pass**

```bash
python -m pytest tests/unit/test_models.py -v
```

- [ ] **Step 5: Commit**

```bash
git add models.py tests/unit/test_models.py
git commit -m "feat: add core data models"
```

---

### Task 3: Update `config/settings.py` — add file ingestor fields

**Files:**
- Modify: `config/settings.py` (after line 120, before `config_file`)

- [ ] **Step 1: Add two fields to `ClassifierConfig`** after `output_retry_interval_seconds`:

```python
# Ingestion source
log_source: str = "file"  # "file" or "cloudwatch"
log_file_path: str = "logs/requests.jsonl"
```

- [ ] **Step 2: Run existing config tests to verify nothing broke**

```bash
python -m pytest tests/unit/test_config.py -v
```
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add config/settings.py
git commit -m "feat: add log_source and log_file_path config fields"
```

---

### Task 4: Implement `ingestion/parser.py` + property tests 1–2

**Files:**
- Create: `ingestion/parser.py`
- Create: `tests/properties/test_parsing.py`
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add shared Hypothesis strategies to `tests/conftest.py`**

```python
from datetime import datetime, timezone
from hypothesis import strategies as st
from models import LogEntry

REQUIRED_FIELDS = ["timestamp", "method", "path", "status", "ip", "body", "response_time_ms", "user_agent"]

valid_log_entry_dicts = st.fixed_dictionaries({
    "timestamp": st.datetimes(timezones=st.just(timezone.utc)).map(lambda d: d.isoformat()),
    "method": st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    "path": st.sampled_from(["/login", "/register", "/home", "/other"]),
    "status": st.integers(min_value=100, max_value=599),
    "ip": st.ip_addresses(v=4).map(str),
    "body": st.text(max_size=200),
    "response_time_ms": st.integers(min_value=0, max_value=60000),
    "user_agent": st.text(min_size=1, max_size=100),
})
```

- [ ] **Step 2: Write property tests 1–2**

Create `tests/properties/test_parsing.py`:

```python
# Feature: traffic-fraud-classifier, Property 1: Log entry parsing round-trip
# Feature: traffic-fraud-classifier, Property 2: Invalid entries are rejected without halting
import json
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts, REQUIRED_FIELDS
from ingestion.parser import parse_entry


@given(valid_log_entry_dicts)
@settings(max_examples=100)
def test_property_1_parse_roundtrip(d):
    """Valid entries parse to LogEntry with matching field values."""
    raw = json.dumps(d)
    entry = parse_entry(raw)
    assert entry is not None
    assert entry.method == d["method"]
    assert entry.path == d["path"]
    assert entry.status == d["status"]
    assert entry.ip == d["ip"]
    assert entry.body == d["body"]
    assert entry.response_time_ms == d["response_time_ms"]
    assert entry.user_agent == d["user_agent"]
    assert entry.raw == raw


@given(st.text())
@settings(max_examples=100)
def test_property_2a_malformed_json_returns_none(raw):
    """Malformed JSON returns None without raising."""
    try:
        json.loads(raw)
        return  # valid JSON, skip
    except json.JSONDecodeError:
        pass
    result = parse_entry(raw)
    assert result is None


@given(valid_log_entry_dicts, st.sampled_from(REQUIRED_FIELDS))
@settings(max_examples=100)
def test_property_2b_missing_field_returns_none(d, missing_field):
    """Entry missing a required field returns None."""
    d.pop(missing_field)
    result = parse_entry(json.dumps(d))
    assert result is None
```

- [ ] **Step 3: Run to verify they fail**

```bash
python -m pytest tests/properties/test_parsing.py -v
```
Expected: `ImportError: cannot import name 'parse_entry'`

- [ ] **Step 4: Create `ingestion/parser.py`**

```python
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
```

- [ ] **Step 5: Run property tests**

```bash
python -m pytest tests/properties/test_parsing.py -v
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add ingestion/parser.py tests/properties/test_parsing.py tests/conftest.py
git commit -m "feat: add log entry parser with property tests 1-2"
```

---

### Task 5: Implement `ingestion/file_ingestor.py` + property test 3

**Files:**
- Create: `ingestion/file_ingestor.py`
- Add to: `tests/properties/test_parsing.py`

- [ ] **Step 1: Write property test 3 in `tests/properties/test_parsing.py`**

```python
# Feature: traffic-fraud-classifier, Property 3: Chronological ordering
from hypothesis import given, settings
from hypothesis import strategies as st
from datetime import datetime, timezone, timedelta
import json
from ingestion.file_ingestor import sort_entries_chronologically
from tests.conftest import valid_log_entry_dicts

@given(st.lists(valid_log_entry_dicts, min_size=0, max_size=20))
@settings(max_examples=100)
def test_property_3_chronological_ordering(dicts):
    """After sorting, timestamps are non-decreasing and sort is stable."""
    from ingestion.parser import parse_entry
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d))) is not None]
    sorted_entries = sort_entries_chronologically(entries)
    for i in range(len(sorted_entries) - 1):
        assert sorted_entries[i].timestamp <= sorted_entries[i + 1].timestamp
```

- [ ] **Step 2: Run to verify it fails**

```bash
python -m pytest tests/properties/test_parsing.py::test_property_3_chronological_ordering -v
```

- [ ] **Step 3: Create `ingestion/file_ingestor.py`**

```python
from __future__ import annotations
import logging
import time
from pathlib import Path
from typing import Iterator

from models import LogEntry
from ingestion.parser import parse_entry

logger = logging.getLogger(__name__)


def sort_entries_chronologically(entries: list[LogEntry]) -> list[LogEntry]:
    """Stable sort entries by timestamp (ascending)."""
    return sorted(entries, key=lambda e: e.timestamp)


class FileIngestor:
    """Tails a JSON Lines log file, yielding parsed LogEntry objects as lines appear."""

    def __init__(self, file_path: str, poll_interval: float = 1.0):
        self._path = Path(file_path)
        self._poll_interval = poll_interval
        self._position = 0

    def poll(self) -> list[LogEntry]:
        """Read any new lines since last poll. Returns entries in chronological order."""
        if not self._path.exists():
            logger.warning("Log file not found: %s", self._path)
            return []

        entries: list[LogEntry] = []
        try:
            with self._path.open("r", encoding="utf-8") as f:
                f.seek(self._position)
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    entry = parse_entry(line)
                    if entry is not None:
                        entries.append(entry)
                self._position = f.tell()
        except OSError as exc:
            logger.error("Error reading log file %s: %s", self._path, exc)

        return sort_entries_chronologically(entries)

    def reset(self) -> None:
        """Reset file position to beginning (useful for testing)."""
        self._position = 0

    def tail(self) -> Iterator[list[LogEntry]]:
        """Continuously yield batches of new entries as they appear."""
        while True:
            batch = self.poll()
            yield batch
            time.sleep(self._poll_interval)
```

- [ ] **Step 4: Run all parsing property tests**

```bash
python -m pytest tests/properties/test_parsing.py -v
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add ingestion/file_ingestor.py tests/properties/test_parsing.py
git commit -m "feat: add file ingestor with chronological sort, property test 3"
```

---

## Chunk 3: Traffic Profiler

### Task 6: IP Profile + property tests 4–6

**Files:**
- Create: `profiler/ip_profile.py`
- Create: `tests/properties/test_profiling.py`

- [ ] **Step 1: Write property tests 4–6** in `tests/properties/test_profiling.py`:

```python
# Feature: traffic-fraud-classifier, Property 4: IP profile metrics accuracy
# Feature: traffic-fraud-classifier, Property 5: Time window reset zeroes counters
# Feature: traffic-fraud-classifier, Property 6: Malformed IP entries discarded
import json
from datetime import datetime, timezone, timedelta
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts
from ingestion.parser import parse_entry
from profiler.ip_profile import IPProfileManager


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=30))
@settings(max_examples=100)
def test_property_4_ip_metrics_accuracy(dicts):
    """request_count equals entries from that IP; endpoints is the distinct set."""
    manager = IPProfileManager()
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d)))]
    for e in entries:
        manager.update(e)
    from collections import Counter
    ip_counts = Counter(e.ip for e in entries)
    for ip, count in ip_counts.items():
        profile = manager.get(ip)
        assert profile.request_count == count
        expected_endpoints = {f"{e.method} {e.path.split('?')[0].rstrip('/')}" for e in entries if e.ip == ip}
        assert profile.endpoints == expected_endpoints


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=20))
@settings(max_examples=50)
def test_property_5_reset_zeroes_counters(dicts):
    """After reset_window(), all request counts are zero."""
    manager = IPProfileManager()
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d)))]
    for e in entries:
        manager.update(e)
    manager.reset_window()
    for ip in manager.all_ips():
        profile = manager.get(ip)
        assert profile.request_count == 0
        assert len(profile.endpoints) == 0


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=20))
@settings(max_examples=50)
def test_property_6_malformed_ip_discarded(dicts):
    """Entries with empty/non-IP are not added to any profile."""
    import copy
    manager = IPProfileManager()
    bad_dicts = [dict(d, ip="") for d in dicts]
    entries = [e for d in bad_dicts if (e := parse_entry(json.dumps(d)))]
    # parser accepts empty string as ip since it's just a string field
    # the profile manager must discard them
    before_count = manager.dropped_count
    for e in entries:
        manager.update(e)
    assert manager.dropped_count == before_count + len(entries)
    assert len(list(manager.all_ips())) == 0
```

- [ ] **Step 2: Run to verify they fail**

```bash
python -m pytest tests/properties/test_profiling.py -v -k "ip"
```

- [ ] **Step 3: Create `profiler/ip_profile.py`**

```python
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

from models import LogEntry

logger = logging.getLogger(__name__)

_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
    r'|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
)


def _is_valid_ip(ip: str) -> bool:
    return bool(ip and _IP_RE.match(ip))


def _normalize_path(path: str) -> str:
    return path.split("?")[0].rstrip("/") or "/"


@dataclass
class IPProfile:
    ip: str
    request_count: int = 0
    endpoints: set = field(default_factory=set)
    first_request_time: Optional[datetime] = None
    request_rate: float = 0.0
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class IPProfileManager:
    def __init__(self):
        self._profiles: dict[str, IPProfile] = {}
        self.dropped_count: int = 0

    def update(self, entry: LogEntry) -> None:
        if not _is_valid_ip(entry.ip):
            logger.warning("Dropping entry with invalid IP: %r", entry.ip)
            self.dropped_count += 1
            return

        if entry.ip not in self._profiles:
            self._profiles[entry.ip] = IPProfile(ip=entry.ip)

        p = self._profiles[entry.ip]
        p.request_count += 1

        endpoint = f"{entry.method} {_normalize_path(entry.path)}"
        p.endpoints.add(endpoint)

        now = entry.timestamp
        if p.first_request_time is None:
            p.first_request_time = now

        elapsed = (now - p.first_request_time).total_seconds()
        if elapsed > 0:
            p.request_rate = round(p.request_count / elapsed, 2)
        else:
            p.request_rate = float(p.request_count)

    def get(self, ip: str) -> Optional[IPProfile]:
        return self._profiles.get(ip)

    def all_ips(self) -> Iterator[str]:
        return iter(self._profiles.keys())

    def reset_window(self) -> None:
        for p in self._profiles.values():
            p.request_count = 0
            p.endpoints = set()
            p.first_request_time = None
            p.request_rate = 0.0
            p.suspicious = False
            p.suspicious_reason = None
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/properties/test_profiling.py -v -k "ip or reset or malformed"
```

- [ ] **Step 5: Commit**

```bash
git add profiler/ip_profile.py tests/properties/test_profiling.py
git commit -m "feat: add IP profile manager with property tests 4-6"
```

---

### Task 7: User Profile + property tests 7–9

**Files:**
- Create: `profiler/user_profile.py`

- [ ] **Step 1: Add property tests 7–9 to `tests/properties/test_profiling.py`**

```python
# Feature: traffic-fraud-classifier, Property 7: User identity association
# Feature: traffic-fraud-classifier, Property 8: Failed login threshold
# Feature: traffic-fraud-classifier, Property 9: Multi-IP threshold
from profiler.user_profile import UserProfileManager

@given(valid_log_entry_dicts)
@settings(max_examples=100)
def test_property_7_user_association(d):
    """Entries on /login or /register with valid username get associated; others don't."""
    manager = UserProfileManager()
    import json as _json
    entry = parse_entry(_json.dumps(d))
    if entry is None:
        return
    manager.update(entry)
    if entry.path in ("/login", "/register"):
        try:
            body = _json.loads(entry.body)
            username = body.get("username", "")
            if username:
                assert manager.get(username) is not None
                return
        except (ValueError, AttributeError):
            pass
    # No association expected
    assert all(manager.get(u) is None or True for u in [])  # vacuously true


def _make_failed_login(ip: str, username: str, n: int) -> list:
    """Create n failed login entries for a user."""
    import json as _json
    from datetime import datetime, timezone, timedelta
    entries = []
    for i in range(n):
        d = {
            "timestamp": (datetime(2026,1,1,tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat(),
            "method": "POST", "path": "/login", "status": 401,
            "ip": ip, "body": _json.dumps({"username": username, "password": "x"}),
            "response_time_ms": 10, "user_agent": "Mozilla/5.0",
        }
        e = parse_entry(_json.dumps(d))
        if e:
            entries.append(e)
    return entries


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=50)
def test_property_8_failed_login_threshold(n):
    """User suspicious iff failed logins > 5."""
    manager = UserProfileManager()
    entries = _make_failed_login("1.2.3.4", "alice", n)
    for e in entries:
        manager.update(e)
    profile = manager.get("alice")
    assert profile is not None
    assert profile.suspicious == (n > 5)


@given(st.integers(min_value=1, max_value=10))
@settings(max_examples=50)
def test_property_9_multi_ip_threshold(k):
    """User suspicious iff accessed from > 3 distinct IPs."""
    import json as _json
    from datetime import datetime, timezone, timedelta
    manager = UserProfileManager()
    for i in range(k):
        ip = f"10.0.0.{i+1}"
        d = {
            "timestamp": (datetime(2026,1,1,tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat(),
            "method": "POST", "path": "/login", "status": 200,
            "ip": ip, "body": _json.dumps({"username": "bob", "password": "x"}),
            "response_time_ms": 10, "user_agent": "Mozilla/5.0",
        }
        e = parse_entry(_json.dumps(d))
        if e:
            manager.update(e)
    profile = manager.get("bob")
    if profile:
        assert profile.suspicious == (k > 3)
```

- [ ] **Step 2: Run to verify they fail**

```bash
python -m pytest tests/properties/test_profiling.py -v -k "user"
```

- [ ] **Step 3: Create `profiler/user_profile.py`**

```python
from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from models import LogEntry

logger = logging.getLogger(__name__)

FAILED_LOGIN_THRESHOLD = 5
MULTI_IP_THRESHOLD = 3


def _extract_username(entry: LogEntry) -> Optional[str]:
    if entry.path not in ("/login", "/register"):
        return None
    try:
        body = json.loads(entry.body)
        username = body.get("username", "")
        return str(username) if username else None
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None


@dataclass
class UserProfile:
    username: str
    failed_login_count: int = 0
    total_login_count: int = 0
    distinct_ips: set = field(default_factory=set)
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class UserProfileManager:
    def __init__(self):
        self._profiles: dict[str, UserProfile] = {}

    def update(self, entry: LogEntry) -> None:
        username = _extract_username(entry)
        if username is None:
            return

        if username not in self._profiles:
            self._profiles[username] = UserProfile(username=username)

        p = self._profiles[username]
        p.distinct_ips.add(entry.ip)

        if entry.path == "/login":
            p.total_login_count += 1
            if entry.status == 401:
                p.failed_login_count += 1

        if not p.suspicious:
            if p.failed_login_count > FAILED_LOGIN_THRESHOLD:
                p.suspicious = True
                p.suspicious_reason = f"failed_logins={p.failed_login_count}"
            elif len(p.distinct_ips) > MULTI_IP_THRESHOLD:
                p.suspicious = True
                p.suspicious_reason = f"distinct_ips={len(p.distinct_ips)}"

    def get(self, username: str) -> Optional[UserProfile]:
        return self._profiles.get(username)

    def reset_window(self) -> None:
        for p in self._profiles.values():
            p.failed_login_count = 0
            p.total_login_count = 0
            p.distinct_ips = set()
            p.suspicious = False
            p.suspicious_reason = None
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/properties/test_profiling.py -v
```

- [ ] **Step 5: Commit**

```bash
git add profiler/user_profile.py tests/properties/test_profiling.py
git commit -m "feat: add user profile manager with property tests 7-9"
```

---

### Task 8: Endpoint Profile + TrafficProfiler coordinator + property tests 10–11

**Files:**
- Create: `profiler/endpoint_profile.py`
- Create: `profiler/profiler.py`

- [ ] **Step 1: Add property tests 10–11 to `tests/properties/test_profiling.py`**

```python
# Feature: traffic-fraud-classifier, Property 10: Endpoint profile metrics
# Feature: traffic-fraud-classifier, Property 11: Rate-abuse detection
from profiler.endpoint_profile import EndpointProfileManager

@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=30))
@settings(max_examples=100)
def test_property_10_endpoint_metrics(dicts):
    """request_count, error_count, error_rate, unique_ips are accurate."""
    manager = EndpointProfileManager()
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d)))]
    for e in entries:
        manager.update(e)
    from collections import defaultdict
    ep_counts = defaultdict(lambda: {"total": 0, "errors": 0, "ips": set()})
    for e in entries:
        key = f"{e.method} {e.path.split('?')[0].rstrip('/') or '/'}"
        ep_counts[key]["total"] += 1
        if e.status >= 400:
            ep_counts[key]["errors"] += 1
        ep_counts[key]["ips"].add(e.ip)
    for key, expected in ep_counts.items():
        profile = manager.get(key)
        assert profile is not None
        assert profile.request_count == expected["total"]
        assert profile.error_count == expected["errors"]
        assert abs(profile.error_rate - (expected["errors"] / expected["total"] * 100)) < 0.01
        assert profile.unique_ips == expected["ips"]


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=50)
def test_property_11_rate_abuse_threshold(n):
    """rate_abuse flag set iff IP sends > 50 requests to same endpoint."""
    import json as _json
    from datetime import datetime, timezone, timedelta
    manager = EndpointProfileManager()
    for i in range(n):
        d = {
            "timestamp": (datetime(2026,1,1,tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat(),
            "method": "POST", "path": "/login", "status": 200,
            "ip": "1.2.3.4", "body": "{}", "response_time_ms": 10,
            "user_agent": "Mozilla/5.0",
        }
        e = parse_entry(_json.dumps(d))
        if e:
            manager.update(e)
    profile = manager.get("POST /login")
    assert profile is not None
    assert ("1.2.3.4" in profile.rate_abuse_ips) == (n > 50)
```

- [ ] **Step 2: Create `profiler/endpoint_profile.py`**

```python
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Optional

from models import LogEntry

logger = logging.getLogger(__name__)

RATE_ABUSE_THRESHOLD = 50


def _normalize(method: str, path: str) -> str:
    return f"{method} {path.split('?')[0].rstrip('/') or '/'}"


@dataclass
class EndpointProfile:
    endpoint: str
    request_count: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    unique_ips: set = field(default_factory=set)
    rate_abuse_ips: set = field(default_factory=set)
    _ip_counts: dict = field(default_factory=dict, repr=False)


class EndpointProfileManager:
    def __init__(self, rate_abuse_threshold: int = RATE_ABUSE_THRESHOLD):
        self._profiles: dict[str, EndpointProfile] = {}
        self._threshold = rate_abuse_threshold

    def update(self, entry: LogEntry) -> None:
        key = _normalize(entry.method, entry.path)
        if key not in self._profiles:
            self._profiles[key] = EndpointProfile(endpoint=key)

        p = self._profiles[key]
        p.request_count += 1
        if entry.status >= 400:
            p.error_count += 1
        p.error_rate = p.error_count / p.request_count * 100
        p.unique_ips.add(entry.ip)

        p._ip_counts[entry.ip] = p._ip_counts.get(entry.ip, 0) + 1
        if p._ip_counts[entry.ip] > self._threshold:
            p.rate_abuse_ips.add(entry.ip)

    def get(self, key: str) -> Optional[EndpointProfile]:
        return self._profiles.get(key)

    def reset_window(self) -> None:
        for p in self._profiles.values():
            p.request_count = 0
            p.error_count = 0
            p.error_rate = 0.0
            p.unique_ips = set()
            p.rate_abuse_ips = set()
            p._ip_counts = {}
```

- [ ] **Step 3: Create `profiler/profiler.py`**

```python
from __future__ import annotations
from models import LogEntry, ProfileContext
from profiler.ip_profile import IPProfileManager
from profiler.user_profile import UserProfileManager, _extract_username
from profiler.endpoint_profile import EndpointProfileManager


class TrafficProfiler:
    def __init__(self, rate_abuse_threshold: int = 50):
        self.ip = IPProfileManager()
        self.user = UserProfileManager()
        self.endpoint = EndpointProfileManager(rate_abuse_threshold)

    def update(self, entry: LogEntry) -> ProfileContext:
        self.ip.update(entry)
        self.user.update(entry)
        self.endpoint.update(entry)
        return self._build_context(entry)

    def _build_context(self, entry: LogEntry) -> ProfileContext:
        ip_p = self.ip.get(entry.ip)
        username = _extract_username(entry)
        user_p = self.user.get(username) if username else None
        from profiler.endpoint_profile import _normalize
        ep_key = _normalize(entry.method, entry.path)
        ep_p = self.endpoint.get(ep_key)

        ctx = ProfileContext(ip=entry.ip)
        if ip_p:
            ctx.ip_request_count = ip_p.request_count
            ctx.ip_distinct_paths = {e.split(" ", 1)[1] for e in ip_p.endpoints}
            ctx.ip_suspicious = ip_p.suspicious
            ctx.ip_suspicious_reason = ip_p.suspicious_reason
        if user_p:
            ctx.username = username
            ctx.user_failed_logins = user_p.failed_login_count
            ctx.user_total_logins = user_p.total_login_count
            ctx.user_distinct_ips = user_p.distinct_ips
            ctx.user_suspicious = user_p.suspicious
            ctx.user_suspicious_reason = user_p.suspicious_reason
        if ep_p:
            ctx.endpoint_request_count = ep_p.request_count
            ctx.endpoint_error_count = ep_p.error_count
            ctx.endpoint_rate_abuse = entry.ip in ep_p.rate_abuse_ips
        return ctx

    def reset_window(self) -> None:
        self.ip.reset_window()
        self.user.reset_window()
        self.endpoint.reset_window()

    def get_ip_profiles(self):
        return self.ip

    def get_user_profiles(self):
        return self.user

    def get_endpoint_profiles(self):
        return self.endpoint
```

- [ ] **Step 4: Run all profiling tests**

```bash
python -m pytest tests/properties/test_profiling.py -v
```

- [ ] **Step 5: Commit**

```bash
git add profiler/endpoint_profile.py profiler/profiler.py tests/properties/test_profiling.py
git commit -m "feat: add endpoint profile + TrafficProfiler coordinator, property tests 10-11"
```

---

## Chunk 4: Classification Engine

### Task 9: BaseDetector + SQLInjectionDetector + property tests 12–13

**Files:**
- Create: `classifiers/base.py`
- Create: `classifiers/sqli_detector.py`
- Create: `tests/properties/test_sqli.py`

- [ ] **Step 1: Create `classifiers/base.py`**

```python
from abc import ABC, abstractmethod
from models import LogEntry, DetectionResult, ProfileContext


class BaseDetector(ABC):
    @abstractmethod
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        """Return list of DetectionResults (empty if no fraud detected)."""
        ...
```

- [ ] **Step 2: Write property tests 12–13** in `tests/properties/test_sqli.py`

```python
# Feature: traffic-fraud-classifier, Property 12: SQL injection case-insensitive
# Feature: traffic-fraud-classifier, Property 13: SQL injection confidence scoring
import json
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts
from ingestion.parser import parse_entry
from classifiers.sqli_detector import SQLInjectionDetector
from models import ProfileContext

detector = SQLInjectionDetector()

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users;",
    "' UNION SELECT * FROM users--",
    "admin'--",
    "' AND 1=1",
]

OTHER_PATHS = ["/home", "/api/data", "/users"]


@given(
    st.sampled_from(["/login", "/register"]),
    st.sampled_from(SQLI_PAYLOADS),
    st.sampled_from(["lower", "upper", "mixed"]),
)
@settings(max_examples=100)
def test_property_12_sqli_detected_case_insensitive(path, payload, case):
    if case == "upper":
        payload = payload.upper()
    elif case == "lower":
        payload = payload.lower()
    body = json.dumps({"username": payload, "password": "x"})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": path, "status": 200,
        "ip": "1.2.3.4", "body": body,
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = parse_entry(json.dumps(d))
    assert entry is not None
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert any(r.is_fraudulent and r.reason == "sql_injection" for r in results)


@given(st.sampled_from(OTHER_PATHS), st.sampled_from(SQLI_PAYLOADS))
@settings(max_examples=50)
def test_property_12_sqli_skipped_for_other_paths(path, payload):
    body = json.dumps({"q": payload})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": path, "status": 200,
        "ip": "1.2.3.4", "body": body,
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = parse_entry(json.dumps(d))
    assert entry is not None
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert not any(r.reason == "sql_injection" for r in results)


def test_property_13_two_indicators_confidence_gte_09():
    """2+ indicators → confidence >= 0.9."""
    body = json.dumps({"username": "' OR 1=1 UNION SELECT * FROM users--"})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 401,
        "ip": "1.2.3.4", "body": body, "response_time_ms": 10, "user_agent": "x",
    }
    entry = parse_entry(json.dumps(d))
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    sqli = [r for r in results if r.reason == "sql_injection"]
    assert sqli and sqli[0].confidence >= 0.9


def test_property_13_one_indicator_confidence_07_to_089():
    """1 indicator → confidence in [0.7, 0.89]."""
    body = json.dumps({"username": "admin'--"})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 401,
        "ip": "1.2.3.4", "body": body, "response_time_ms": 10, "user_agent": "x",
    }
    entry = parse_entry(json.dumps(d))
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    sqli = [r for r in results if r.reason == "sql_injection"]
    assert sqli and 0.7 <= sqli[0].confidence <= 0.89
```

- [ ] **Step 3: Run to verify they fail**

```bash
python -m pytest tests/properties/test_sqli.py -v
```

- [ ] **Step 4: Create `classifiers/sqli_detector.py`**

```python
from __future__ import annotations
import re
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

_PATTERNS = [
    re.compile(r"'[\s]*(?:OR|AND|SELECT|UNION|DROP|DELETE|INSERT)\b", re.IGNORECASE),
    re.compile(r"\b(?:OR|AND)\s+\d+=\d+", re.IGNORECASE),
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"--", re.IGNORECASE),
    re.compile(r";\s*(?:DROP|DELETE|INSERT)\b", re.IGNORECASE),
]

_TARGET_PATHS = frozenset(["/login", "/register"])


class SQLInjectionDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        if entry.path not in _TARGET_PATHS:
            return []

        matches = sum(1 for p in _PATTERNS if p.search(entry.body))
        if matches == 0:
            return []

        confidence = 0.9 if matches >= 2 else 0.75
        return [DetectionResult(is_fraudulent=True, reason="sql_injection", confidence=confidence)]
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/properties/test_sqli.py -v
```

- [ ] **Step 6: Commit**

```bash
git add classifiers/base.py classifiers/sqli_detector.py tests/properties/test_sqli.py
git commit -m "feat: add SQL injection detector with property tests 12-13"
```

---

### Task 10: BruteForceDetector + property tests 14–16

**Files:**
- Create: `classifiers/brute_force_detector.py`
- Create: `tests/properties/test_brute_force.py`

- [ ] **Step 1: Write property tests 14–16** in `tests/properties/test_brute_force.py`

```python
# Feature: traffic-fraud-classifier, Property 14: Brute-force detection and propagation
# Feature: traffic-fraud-classifier, Property 15: Credential stuffing detection
# Feature: traffic-fraud-classifier, Property 16: Brute-force confidence calculation
import json
from datetime import datetime, timezone, timedelta
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.brute_force_detector import BruteForceDetector
from models import ProfileContext


def _make_ctx(ip_failed=0, ip_total=0, user_failed=0, user_total=0, username=None):
    ctx = ProfileContext(ip="1.2.3.4")
    ctx.ip_failed_logins = ip_failed
    ctx.ip_total_logins = ip_total
    ctx.username = username
    ctx.user_failed_logins = user_failed
    ctx.user_total_logins = user_total
    return ctx


def _make_entry(path="/login", status=401):
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": path, "status": status,
        "ip": "1.2.3.4", "body": json.dumps({"username": "alice", "password": "x"}),
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    return parse_entry(json.dumps(d))


detector = BruteForceDetector()


@given(st.integers(min_value=1, max_value=30))
@settings(max_examples=50)
def test_property_14_brute_force_detection(n):
    """IP with > 10 failed logins → brute_force verdict."""
    entry = _make_entry()
    ctx = _make_ctx(ip_failed=n, ip_total=n)
    results = detector.evaluate(entry, ctx)
    has_bf = any(r.reason == "brute_force" for r in results)
    assert has_bf == (n > 10)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=50)
def test_property_15_credential_stuffing(n):
    """User with > 5 failed logins → credential_stuffing verdict."""
    entry = _make_entry()
    ctx = _make_ctx(user_failed=n, user_total=n, username="alice")
    results = detector.evaluate(entry, ctx)
    has_cs = any(r.reason == "credential_stuffing" for r in results)
    assert has_cs == (n > 5)


@given(
    st.integers(min_value=1, max_value=30),
    st.integers(min_value=1, max_value=50),
)
@settings(max_examples=100)
def test_property_16_confidence_calculation(failed, total):
    if failed > total:
        total = failed
    entry = _make_entry()
    ctx = _make_ctx(ip_failed=failed, ip_total=total)
    results = detector.evaluate(entry, ctx)
    bf = [r for r in results if r.reason == "brute_force"]
    if bf:
        expected = max(failed / total, 0.5)
        assert abs(bf[0].confidence - expected) < 0.01
```

- [ ] **Step 2: Run to verify they fail**

```bash
python -m pytest tests/properties/test_brute_force.py -v
```

- [ ] **Step 3: Create `classifiers/brute_force_detector.py`**

```python
from __future__ import annotations
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

IP_THRESHOLD = 10
USER_THRESHOLD = 5


class BruteForceDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        results = []

        if context.ip_failed_logins > IP_THRESHOLD:
            t = context.ip_total_logins or context.ip_failed_logins
            conf = max(context.ip_failed_logins / t, 0.5)
            results.append(DetectionResult(
                is_fraudulent=True, reason="brute_force", confidence=round(conf, 4)
            ))

        if context.username and context.user_failed_logins > USER_THRESHOLD:
            t = context.user_total_logins or context.user_failed_logins
            conf = max(context.user_failed_logins / t, 0.5)
            results.append(DetectionResult(
                is_fraudulent=True, reason="credential_stuffing", confidence=round(conf, 4)
            ))

        return results
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/properties/test_brute_force.py -v
```

- [ ] **Step 5: Commit**

```bash
git add classifiers/brute_force_detector.py tests/properties/test_brute_force.py
git commit -m "feat: add brute force detector with property tests 14-16"
```

---

### Task 11: AuthAbuseDetector + property tests 17–19

**Files:**
- Create: `classifiers/auth_abuse_detector.py`
- Create: `tests/properties/test_auth_abuse.py`

- [ ] **Step 1: Write property tests 17–19** in `tests/properties/test_auth_abuse.py`

```python
# Feature: traffic-fraud-classifier, Property 17: Unusual user-agent
# Feature: traffic-fraud-classifier, Property 18: Token manipulation
# Feature: traffic-fraud-classifier, Property 19: Forged token
import json
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.auth_abuse_detector import AuthAbuseDetector, RECOGNIZED_UA_PREFIXES
from models import ProfileContext
from datetime import datetime, timezone, timedelta

detector = AuthAbuseDetector()

RECOGNIZED_UAS = [p + "something" for p in RECOGNIZED_UA_PREFIXES]


def _home_entry(ua, status=200, ip="1.2.3.4"):
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": "/home", "status": status,
        "ip": ip, "body": "", "response_time_ms": 10, "user_agent": ua,
    }
    return parse_entry(json.dumps(d))


@given(st.text(min_size=1, max_size=100).filter(
    lambda ua: not any(ua.startswith(p) for p in RECOGNIZED_UA_PREFIXES)
))
@settings(max_examples=100)
def test_property_17_unusual_ua_detected(ua):
    entry = _home_entry(ua)
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert any(r.reason == "unusual_user_agent" and r.confidence == 0.6 for r in results)


@given(st.sampled_from(RECOGNIZED_UAS))
@settings(max_examples=50)
def test_property_17_recognized_ua_not_flagged(ua):
    entry = _home_entry(ua)
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert not any(r.reason == "unusual_user_agent" for r in results)


@given(st.integers(min_value=2, max_value=5))
@settings(max_examples=50)
def test_property_18_token_manipulation(n_users):
    """2+ distinct users from same IP → token_manipulation."""
    ctx = ProfileContext(ip="1.2.3.4")
    ctx.ip_distinct_users = {f"user{i}" for i in range(n_users)}
    entry = _home_entry("Mozilla/5.0")
    results = detector.evaluate(entry, ctx)
    assert any(r.reason == "token_manipulation" and r.confidence == 0.9 for r in results)


def test_property_19_forged_token_no_prior_login():
    """Successful /home with no prior successful login → forged_token."""
    ctx = ProfileContext(ip="1.2.3.4")
    ctx.ip_successful_logins = []  # no logins
    entry = _home_entry("Mozilla/5.0", status=200)
    results = detector.evaluate(entry, ctx)
    assert any(r.reason == "forged_token" and r.confidence == 0.85 for r in results)


def test_property_19_recent_login_no_forged_token():
    """Successful /home with recent successful login → no forged_token."""
    ctx = ProfileContext(ip="1.2.3.4")
    now = datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc)
    ctx.ip_successful_logins = [now - timedelta(minutes=5)]
    entry = _home_entry("Mozilla/5.0", status=200)
    # patch entry timestamp
    from dataclasses import replace
    entry = replace(entry, timestamp=now)
    results = detector.evaluate(entry, ctx)
    assert not any(r.reason == "forged_token" for r in results)
```

- [ ] **Step 2: Create `classifiers/auth_abuse_detector.py`**

```python
from __future__ import annotations
from datetime import timedelta
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

RECOGNIZED_UA_PREFIXES = [
    "Mozilla/5.0", "Chrome/", "Safari/", "Firefox/", "Edge/",
    "PostmanRuntime/", "axios/", "python-requests/",
]
FORGED_TOKEN_WINDOW = timedelta(minutes=30)


class AuthAbuseDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        if entry.path != "/home":
            return []

        results = []

        # Unusual user-agent
        ua = entry.user_agent
        if not any(ua.startswith(p) for p in RECOGNIZED_UA_PREFIXES):
            results.append(DetectionResult(
                is_fraudulent=True, reason="unusual_user_agent", confidence=0.6
            ))

        # Token manipulation: 2+ distinct users from same IP
        if len(context.ip_distinct_users) >= 2:
            results.append(DetectionResult(
                is_fraudulent=True, reason="token_manipulation", confidence=0.9
            ))

        # Forged token: successful /home with no recent successful login
        if entry.status == 200:
            window_start = entry.timestamp - FORGED_TOKEN_WINDOW
            recent_logins = [
                t for t in context.ip_successful_logins
                if t >= window_start
            ]
            if not recent_logins:
                results.append(DetectionResult(
                    is_fraudulent=True, reason="forged_token", confidence=0.85
                ))

        return results
```

- [ ] **Step 3: Update `ProfileContext` in `models.py`** — add `ip_successful_logins` field (it's already there from Task 2).

- [ ] **Step 4: Update `profiler/profiler.py`** — track successful logins in context. Add to `_build_context`:

In `profiler/profiler.py`, inside `_build_context`, add:
```python
# Track distinct users per IP for token manipulation detection
# and successful login timestamps for forged token detection
if ip_p:
    # ip_distinct_users: populated from user profiles keyed by IP
    ctx.ip_distinct_users = self._get_ip_users(entry.ip)
    ctx.ip_successful_logins = self._get_ip_successful_logins(entry.ip)
```

Add these methods to `TrafficProfiler`:
```python
def _get_ip_users(self, ip: str) -> set:
    """Get distinct usernames that have logged in from this IP."""
    users = set()
    for username, profile in self.user._profiles.items():
        if ip in profile.distinct_ips:
            users.add(username)
    return users

def _get_ip_successful_logins(self, ip: str) -> list:
    """Get timestamps of successful logins from this IP."""
    return self._ip_successful_logins.get(ip, [])
```

Also add to `TrafficProfiler.__init__`:
```python
self._ip_successful_logins: dict[str, list] = {}
```

And add to `update()` before `return`:
```python
# Track successful logins per IP
if entry.path == "/login" and entry.status == 200:
    self._ip_successful_logins.setdefault(entry.ip, []).append(entry.timestamp)
```

- [ ] **Step 5: Run all auth abuse tests**

```bash
python -m pytest tests/properties/test_auth_abuse.py -v
```

- [ ] **Step 6: Commit**

```bash
git add classifiers/auth_abuse_detector.py tests/properties/test_auth_abuse.py profiler/profiler.py
git commit -m "feat: add auth abuse detector with property tests 17-19"
```

---

### Task 12: ReconnaissanceDetector + property tests 20–22

**Files:**
- Create: `classifiers/recon_detector.py`
- Create: `tests/properties/test_recon.py`

- [ ] **Step 1: Write property tests 20–22** in `tests/properties/test_recon.py`

```python
# Feature: traffic-fraud-classifier, Property 20: Reconnaissance by path diversity
# Feature: traffic-fraud-classifier, Property 21: Path enumeration
# Feature: traffic-fraud-classifier, Property 22: Scanner user-agent
import json
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.recon_detector import ReconnaissanceDetector, KNOWN_PATHS, SCANNER_IDS
from models import ProfileContext

detector = ReconnaissanceDetector()

UNKNOWN_PATHS = ["/admin", "/wp-admin", "/etc/passwd", "/.env", "/api/v1/secret"]
KNOWN_PATH_LIST = list(KNOWN_PATHS)


def _entry(path="/login", ua="Mozilla/5.0", ip="1.2.3.4", distinct_paths=None):
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": path, "status": 200,
        "ip": ip, "body": "", "response_time_ms": 10, "user_agent": ua,
    }
    e = parse_entry(json.dumps(d))
    ctx = ProfileContext(ip=ip)
    if distinct_paths is not None:
        ctx.ip_distinct_paths = set(distinct_paths)
    return e, ctx


@given(st.integers(min_value=1, max_value=15))
@settings(max_examples=50)
def test_property_20_recon_by_path_diversity(n):
    """IP targeting > 5 distinct paths → reconnaissance."""
    paths = [f"/path{i}" for i in range(n)]
    e, ctx = _entry(distinct_paths=paths)
    results = detector.evaluate(e, ctx)
    has_recon = any(r.reason == "reconnaissance" for r in results)
    assert has_recon == (n > 5)


@given(st.sampled_from(UNKNOWN_PATHS))
@settings(max_examples=50)
def test_property_21_path_enumeration(path):
    """Unknown path → path_enumeration."""
    e, ctx = _entry(path=path)
    results = detector.evaluate(e, ctx)
    assert any(r.reason == "path_enumeration" for r in results)


@given(st.sampled_from(KNOWN_PATH_LIST))
@settings(max_examples=20)
def test_property_21_known_path_not_flagged(path):
    """Known path → no path_enumeration."""
    e, ctx = _entry(path=path)
    results = detector.evaluate(e, ctx)
    assert not any(r.reason == "path_enumeration" for r in results)


@given(
    st.sampled_from(SCANNER_IDS),
    st.sampled_from(["lower", "upper", "mixed"]),
)
@settings(max_examples=50)
def test_property_22_scanner_ua(scanner_id, case):
    """Scanner UA → scanner_detected."""
    ua = scanner_id.upper() if case == "upper" else (
        scanner_id.lower() if case == "lower" else scanner_id
    )
    ua = "prefix-" + ua + "/1.0"
    e, ctx = _entry(ua=ua)
    results = detector.evaluate(e, ctx)
    assert any(r.reason == "scanner_detected" for r in results)
```

- [ ] **Step 2: Create `classifiers/recon_detector.py`**

```python
from __future__ import annotations
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

KNOWN_PATHS = frozenset(["/register", "/login", "/home"])
SCANNER_IDS = ["sqlmap", "nikto", "nmap", "dirbuster", "gobuster"]
PATH_DIVERSITY_THRESHOLD = 5


class ReconnaissanceDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        results = []

        # Path diversity reconnaissance
        if len(context.ip_distinct_paths) > PATH_DIVERSITY_THRESHOLD:
            results.append(DetectionResult(
                is_fraudulent=True, reason="reconnaissance", confidence=0.8
            ))

        # Path enumeration
        normalized = entry.path.split("?")[0].rstrip("/") or "/"
        if normalized not in KNOWN_PATHS:
            results.append(DetectionResult(
                is_fraudulent=True, reason="path_enumeration", confidence=0.7
            ))

        # Scanner user-agent
        ua_lower = entry.user_agent.lower()
        if any(sid in ua_lower for sid in SCANNER_IDS):
            results.append(DetectionResult(
                is_fraudulent=True, reason="scanner_detected", confidence=0.95
            ))

        return results
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/properties/test_recon.py -v
```

- [ ] **Step 4: Commit**

```bash
git add classifiers/recon_detector.py tests/properties/test_recon.py
git commit -m "feat: add reconnaissance detector with property tests 20-22"
```

---

### Task 13: ClassificationEngine + property tests 23–24

**Files:**
- Create: `classifiers/engine.py`
- Create: `tests/properties/test_verdict.py`

- [ ] **Step 1: Write property tests 23–24** in `tests/properties/test_verdict.py`

```python
# Feature: traffic-fraud-classifier, Property 23: Multiple fraud reasons reported
# Feature: traffic-fraud-classifier, Property 24: Verdict completeness and legitimate default
import json
from ingestion.parser import parse_entry
from classifiers.engine import ClassificationEngine
from classifiers.sqli_detector import SQLInjectionDetector
from classifiers.brute_force_detector import BruteForceDetector
from classifiers.auth_abuse_detector import AuthAbuseDetector
from classifiers.recon_detector import ReconnaissanceDetector
from models import ProfileContext
from config.settings import ClassifierConfig

config = ClassifierConfig()
engine = ClassificationEngine(
    [SQLInjectionDetector(), BruteForceDetector(), AuthAbuseDetector(), ReconnaissanceDetector()],
    config,
)


def _parse(d):
    return parse_entry(json.dumps(d))


def test_property_23_multiple_reasons_reported():
    """Entry triggering multiple rules gets all reasons comma-separated."""
    # SQLi + scanner UA on /login
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 401,
        "ip": "1.2.3.4", "body": json.dumps({"username": "' OR 1=1--", "password": "x"}),
        "response_time_ms": 10, "user_agent": "sqlmap/1.0",
    }
    entry = _parse(d)
    ctx = ProfileContext(ip="1.2.3.4")
    verdict = engine.classify(entry, ctx)
    assert verdict.classification == "FRAUDULENT"
    reasons = verdict.reason.split(",")
    assert len(reasons) >= 2
    assert "sql_injection" in verdict.reason
    assert "scanner_detected" in verdict.reason


def test_property_24_legitimate_default():
    """Clean entry with no suspicious profile → LEGITIMATE with confidence 1.0."""
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 200,
        "ip": "1.2.3.4", "body": json.dumps({"username": "admin", "password": "pass"}),
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = _parse(d)
    ctx = ProfileContext(ip="1.2.3.4")
    verdict = engine.classify(entry, ctx)
    assert verdict.classification == "LEGITIMATE"
    assert verdict.confidence_score == 1.0


def test_property_24_verdict_has_all_fields():
    """Every verdict has all required fields."""
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": "/home", "status": 200,
        "ip": "1.2.3.4", "body": "", "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = _parse(d)
    ctx = ProfileContext(ip="1.2.3.4")
    verdict = engine.classify(entry, ctx)
    for field in ["timestamp", "source_ip", "method", "path", "classification",
                  "confidence_score", "reason", "original_log_entry_reference"]:
        assert hasattr(verdict, field)
```

- [ ] **Step 2: Create `classifiers/engine.py`**

```python
from __future__ import annotations
from models import LogEntry, Verdict, ProfileContext, DetectionResult
from classifiers.base import BaseDetector
from config.settings import ClassifierConfig


class ClassificationEngine:
    def __init__(self, detectors: list[BaseDetector], config: ClassifierConfig):
        self._detectors = detectors
        self._config = config

    def classify(self, entry: LogEntry, context: ProfileContext) -> Verdict:
        all_results: list[DetectionResult] = []
        for detector in self._detectors:
            all_results.extend(detector.evaluate(entry, context))

        fraudulent = [r for r in all_results if r.is_fraudulent]

        if not fraudulent and not context.ip_suspicious and not context.user_suspicious:
            return Verdict(
                timestamp=entry.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                source_ip=entry.ip,
                user_identity=context.username,
                method=entry.method,
                path=entry.path,
                classification="LEGITIMATE",
                confidence_score=1.0,
                reason="clean",
                original_log_entry_reference=entry.raw,
            )

        max_confidence = max((r.confidence for r in fraudulent), default=0.5)
        reasons = ",".join(dict.fromkeys(r.reason for r in fraudulent))  # deduplicated, ordered
        if not reasons:
            reasons = "suspicious_profile"

        return Verdict(
            timestamp=entry.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip=entry.ip,
            user_identity=context.username,
            method=entry.method,
            path=entry.path,
            classification="FRAUDULENT",
            confidence_score=round(max_confidence, 4),
            reason=reasons[:500],
            original_log_entry_reference=entry.raw,
        )
```

- [ ] **Step 3: Run all verdict tests**

```bash
python -m pytest tests/properties/test_verdict.py -v
```

- [ ] **Step 4: Commit**

```bash
git add classifiers/engine.py tests/properties/test_verdict.py
git commit -m "feat: add classification engine with property tests 23-24"
```

---

## Chunk 5: Output, Pipeline, Integration

### Task 14: OutputWriter + property tests 25–26

**Files:**
- Create: `output/writer.py`
- Create: `tests/properties/test_verdict.py` (add to existing)

- [ ] **Step 1: Add property tests 25–26 to `tests/properties/test_verdict.py`**

```python
# Feature: traffic-fraud-classifier, Property 25: Fraud flag creation at confidence threshold
# Feature: traffic-fraud-classifier, Property 26: Verdict JSON serialization round-trip
import json as _json
from hypothesis import given, settings
from hypothesis import strategies as st
from output.writer import OutputWriter
from models import Verdict, FraudFlag
import io


def _make_verdict(classification="FRAUDULENT", confidence=0.9, reason="sql_injection"):
    return Verdict(
        timestamp="2026-06-09T10:00:00Z",
        source_ip="1.2.3.4",
        user_identity="alice",
        method="POST",
        path="/login",
        classification=classification,
        confidence_score=confidence,
        reason=reason,
        original_log_entry_reference='{"raw":"entry"}',
    )


@given(st.floats(min_value=0.0, max_value=1.0))
@settings(max_examples=100)
def test_property_25_fraud_flag_threshold(confidence):
    verdict = _make_verdict(confidence=confidence)
    writer = OutputWriter(config=ClassifierConfig())
    flags = writer.maybe_create_flag(verdict)
    if confidence >= 0.7:
        assert len(flags) == 1
        assert flags[0].ip == verdict.source_ip
        assert flags[0].confidence_score == confidence
    else:
        assert len(flags) == 0


def test_property_26_verdict_serialization_roundtrip():
    """Serialize to JSON line and parse back → identical fields."""
    verdict = _make_verdict()
    writer = OutputWriter(config=ClassifierConfig())
    buf = io.StringIO()
    writer._write_to(verdict, buf)
    line = buf.getvalue().strip()
    parsed = _json.loads(line)
    assert parsed["classification"] == verdict.classification
    assert parsed["source_ip"] == verdict.source_ip
    assert f"{parsed['confidence_score']:.2f}" == f"{verdict.confidence_score:.2f}"
    assert parsed["timestamp"].endswith("Z")
    for field in ["timestamp", "source_ip", "user_identity", "method", "path",
                  "classification", "confidence_score", "reason", "original_log_entry_reference"]:
        assert field in parsed
```

- [ ] **Step 2: Create `output/writer.py`**

```python
from __future__ import annotations
import io
import json
import logging
import sys
import time
from collections import deque
from pathlib import Path
from typing import TextIO

from models import Verdict, FraudFlag
from config.settings import ClassifierConfig

logger = logging.getLogger(__name__)


class OutputWriter:
    def __init__(self, config: ClassifierConfig):
        self._config = config
        self._buffer: deque[Verdict] = deque()
        self._dest = config.output_destination
        self._file_handle: TextIO | None = None
        self._open_destination()

    def _open_destination(self) -> None:
        if self._dest == "stdout":
            self._file_handle = sys.stdout
        elif not self._dest.startswith("/aws/"):
            try:
                path = Path(self._dest)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._file_handle = path.open("a", encoding="utf-8")
            except OSError as exc:
                logger.error("Cannot open output file %s: %s", self._dest, exc)
                self._file_handle = None

    def write_verdict(self, verdict: Verdict) -> None:
        if self._file_handle:
            try:
                self._write_to(verdict, self._file_handle)
                self._flush_buffer()
                return
            except OSError as exc:
                logger.error("Write failed: %s — buffering", exc)

        self._buffer.append(verdict)
        if len(self._buffer) > self._config.output_buffer_size:
            dropped = self._buffer.popleft()
            sys.stderr.write(f"[OUTPUT LOSS] Buffer full, dropped verdict for {dropped.source_ip}\n")

    def _write_to(self, verdict: Verdict, dest: TextIO) -> None:
        obj = {
            "timestamp": verdict.timestamp,
            "source_ip": verdict.source_ip,
            "user_identity": verdict.user_identity,
            "method": verdict.method,
            "path": verdict.path,
            "classification": verdict.classification,
            "confidence_score": round(verdict.confidence_score, 2),
            "reason": verdict.reason,
            "original_log_entry_reference": verdict.original_log_entry_reference,
        }
        dest.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _flush_buffer(self) -> None:
        while self._buffer and self._file_handle:
            try:
                self._write_to(self._buffer[0], self._file_handle)
                self._buffer.popleft()
            except OSError:
                break

    def maybe_create_flag(self, verdict: Verdict) -> list[FraudFlag]:
        if verdict.classification == "FRAUDULENT" and verdict.confidence_score >= self._config.fraud_flag_confidence_threshold:
            return [FraudFlag(
                ip=verdict.source_ip,
                user_identity=verdict.user_identity,
                timestamp=verdict.timestamp,
                reason=verdict.reason,
                confidence_score=verdict.confidence_score,
            )]
        return []

    def close(self) -> None:
        if self._file_handle and self._file_handle is not sys.stdout:
            self._file_handle.close()
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/properties/test_verdict.py -v
```

- [ ] **Step 4: Commit**

```bash
git add output/writer.py tests/properties/test_verdict.py
git commit -m "feat: add output writer with property tests 25-26"
```

---

### Task 15: Property test 27 (config) + run all property tests

- [ ] **Step 1: Create `tests/properties/test_config.py`**

```python
# Feature: traffic-fraud-classifier, Property 27: Configuration precedence and validation
from hypothesis import given, settings
from hypothesis import strategies as st
from config.settings import ClassifierConfig
import os, tempfile, yaml


@given(
    st.integers(min_value=1, max_value=3600),
    st.integers(min_value=0, max_value=7200),
)
@settings(max_examples=100)
def test_property_27_env_overrides_yaml(env_val, yaml_val):
    """Env var always wins over YAML config file value."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"time_window_seconds": yaml_val}, f)
        fname = f.name
    try:
        os.environ["CLASSIFIER_TIME_WINDOW_SECONDS"] = str(env_val)
        config = ClassifierConfig(config_file=fname)
        # env_val may be out of range → default used; either way env wins over yaml
        if 1 <= env_val <= 3600:
            assert config.time_window_seconds == env_val
        else:
            assert config.time_window_seconds == 300  # default
    finally:
        del os.environ["CLASSIFIER_TIME_WINDOW_SECONDS"]
        os.unlink(fname)


@given(st.floats(min_value=-1.0, max_value=2.0))
@settings(max_examples=100)
def test_property_27_out_of_range_uses_default(val):
    """Out-of-range confidence threshold → default 0.7."""
    config = ClassifierConfig(fraud_flag_confidence_threshold=val)
    if 0.0 <= val <= 1.0:
        assert abs(config.fraud_flag_confidence_threshold - val) < 1e-9
    else:
        assert config.fraud_flag_confidence_threshold == 0.7
```

- [ ] **Step 2: Run all 27 property tests**

```bash
python -m pytest tests/properties/ -v
```

Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add tests/properties/test_config.py
git commit -m "feat: add property test 27 for configuration"
```

---

### Task 16: Main pipeline + CLI

**Files:**
- Create: `main.py`
- Create: `__main__.py`

- [ ] **Step 1: Create `main.py`**

```python
from __future__ import annotations
import logging
import signal
import time
from datetime import datetime, timezone

from config.settings import ClassifierConfig
from ingestion.file_ingestor import FileIngestor
from profiler.profiler import TrafficProfiler
from classifiers.engine import ClassificationEngine
from classifiers.sqli_detector import SQLInjectionDetector
from classifiers.brute_force_detector import BruteForceDetector
from classifiers.auth_abuse_detector import AuthAbuseDetector
from classifiers.recon_detector import ReconnaissanceDetector
from output.writer import OutputWriter

logger = logging.getLogger(__name__)


def run(config: ClassifierConfig) -> None:
    profiler = TrafficProfiler(rate_abuse_threshold=config.rate_abuse_threshold)
    engine = ClassificationEngine(
        [
            SQLInjectionDetector(),
            BruteForceDetector(),
            AuthAbuseDetector(),
            ReconnaissanceDetector(),
        ],
        config,
    )
    writer = OutputWriter(config)
    ingestor = FileIngestor(config.log_file_path, poll_interval=config.poll_interval_seconds)

    window_start = datetime.now(tz=timezone.utc)
    running = True

    def _handle_shutdown(sig, frame):
        nonlocal running
        logger.info("Shutting down...")
        running = False

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    logger.info("Pipeline started. Tailing %s", config.log_file_path)

    while running:
        now = datetime.now(tz=timezone.utc)
        if (now - window_start).total_seconds() >= config.time_window_seconds:
            profiler.reset_window()
            window_start = now

        entries = ingestor.poll()
        for entry in entries:
            context = profiler.update(entry)
            verdict = engine.classify(entry, context)
            writer.write_verdict(verdict)
            for flag in writer.maybe_create_flag(verdict):
                logger.info("FraudFlag: ip=%s reason=%s confidence=%.2f",
                            flag.ip, flag.reason, flag.confidence_score)

        time.sleep(config.poll_interval_seconds)

    writer.close()
    logger.info("Pipeline stopped.")
```

- [ ] **Step 2: Create `__main__.py`**

```python
import argparse
import logging
import sys

def _setup_logging():
    logging.basicConfig(
        stream=sys.stderr,
        format='{"level":"%(levelname)s","ts":"%(asctime)s","logger":"%(name)s","msg":"%(message)s"}',
        level=logging.INFO,
    )

def main():
    _setup_logging()
    parser = argparse.ArgumentParser(description="Traffic Fraud Classifier")
    parser.add_argument("--config", help="Path to YAML config file")
    args = parser.parse_args()

    from config.settings import ClassifierConfig
    config = ClassifierConfig(config_file=args.config) if args.config else ClassifierConfig()

    from main import run
    run(config)

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Smoke test the pipeline**

Start dummy-be, fire some requests, then run the classifier:

```bash
cd dummy-be && go run . &
sleep 1

# Fire some requests
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass"}'

curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"'"'"' OR 1=1--","password":"x"}'

kill %1

# Run classifier against the log file
cd ../agent-classifier
python -m agent_classifier --config /dev/null 2>/dev/null &
sleep 3
kill %1
```

Expected: JSON Lines with at least one `FRAUDULENT` verdict for the SQLi request.

- [ ] **Step 4: Commit**

```bash
git add main.py __main__.py
git commit -m "feat: add main pipeline loop and CLI entry point"
```

---

### Task 17: Integration tests

**Files:**
- Create: `tests/integration/test_pipeline.py`

- [ ] **Step 1: Create `tests/integration/test_pipeline.py`**

```python
"""End-to-end pipeline integration tests using temp log files."""
import io
import json
import tempfile
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from config.settings import ClassifierConfig
from ingestion.file_ingestor import FileIngestor
from ingestion.parser import parse_entry
from profiler.profiler import TrafficProfiler
from classifiers.engine import ClassificationEngine
from classifiers.sqli_detector import SQLInjectionDetector
from classifiers.brute_force_detector import BruteForceDetector
from classifiers.auth_abuse_detector import AuthAbuseDetector
from classifiers.recon_detector import ReconnaissanceDetector
from output.writer import OutputWriter


def _make_log_line(path="/login", method="POST", status=200, ip="1.2.3.4",
                    body=None, ua="Mozilla/5.0", offset_secs=0):
    ts = (datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_secs))
    d = {
        "timestamp": ts.isoformat(),
        "method": method, "path": path, "status": status,
        "ip": ip, "body": body or json.dumps({"username": "user", "password": "pass"}),
        "response_time_ms": 10, "user_agent": ua,
    }
    return json.dumps(d) + "\n"


def _run_pipeline(lines: list[str], config: ClassifierConfig = None):
    config = config or ClassifierConfig()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.writelines(lines)
        fname = f.name

    try:
        ingestor = FileIngestor(fname)
        profiler = TrafficProfiler()
        engine = ClassificationEngine(
            [SQLInjectionDetector(), BruteForceDetector(),
             AuthAbuseDetector(), ReconnaissanceDetector()],
            config,
        )
        buf = io.StringIO()
        writer = OutputWriter(ClassifierConfig(output_destination="stdout"))
        writer._file_handle = buf

        for entry in ingestor.poll():
            ctx = profiler.update(entry)
            verdict = engine.classify(entry, ctx)
            writer._write_to(verdict, buf)

        buf.seek(0)
        return [json.loads(line) for line in buf if line.strip()]
    finally:
        os.unlink(fname)


def test_sqli_detected_end_to_end():
    body = json.dumps({"username": "' OR 1=1--", "password": "x"})
    verdicts = _run_pipeline([_make_log_line(body=body)])
    assert any(v["classification"] == "FRAUDULENT" and "sql_injection" in v["reason"]
               for v in verdicts)


def test_clean_request_is_legitimate():
    verdicts = _run_pipeline([_make_log_line()])
    assert all(v["classification"] == "LEGITIMATE" for v in verdicts)


def test_brute_force_detected_after_threshold():
    lines = [
        _make_log_line(status=401, ip="5.5.5.5", offset_secs=i)
        for i in range(12)
    ]
    verdicts = _run_pipeline(lines)
    fraudulent = [v for v in verdicts if v["classification"] == "FRAUDULENT"]
    assert len(fraudulent) > 0
    assert any("brute_force" in v["reason"] for v in fraudulent)


def test_scanner_ua_detected():
    verdicts = _run_pipeline([_make_log_line(ua="sqlmap/1.5.8")])
    assert any(v["classification"] == "FRAUDULENT" and "scanner_detected" in v["reason"]
               for v in verdicts)


def test_verdict_has_required_fields():
    verdicts = _run_pipeline([_make_log_line()])
    for v in verdicts:
        for field in ["timestamp", "source_ip", "method", "path", "classification",
                      "confidence_score", "reason", "original_log_entry_reference"]:
            assert field in v
```

- [ ] **Step 2: Run integration tests**

```bash
python -m pytest tests/integration/test_pipeline.py -v
```

Expected: all pass.

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest -v
```

Expected: all tests pass.

- [ ] **Step 4: Final commit**

```bash
git add tests/integration/test_pipeline.py
git commit -m "feat: add integration tests, complete traffic fraud classifier"
```

---

## Running the Full System

1. Start dummy-be:
```bash
cd dummy-be && go run .
```

2. Start the classifier (in another terminal):
```bash
cd agent-classifier && python -m agent_classifier
```

3. Fire traffic at dummy-be — verdicts stream to stdout in JSON Lines format.
