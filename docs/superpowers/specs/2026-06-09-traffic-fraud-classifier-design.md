# Design: Traffic Fraud Classifier

## Overview

A Python 3.11+ stream processing service that reads structured JSON logs from the dummy-be backend, profiles traffic by IP/user/endpoint, applies rule-based fraud detection, and outputs JSON Lines verdicts.

Initial mode: file-based ingestion (tail `logs/requests.jsonl`). CloudWatch ingestion is available for production use.

## Part 1: dummy-be Logging Fix

**Problem:** The zap logger writes to stdout only, uses `ts` (Unix epoch) instead of `timestamp` (ISO 8601), which doesn't match the classifier's expected `LogEntry` format.

**Change:** Update `middleware/logger.go` — `NewLogger()`:
- Custom `zapcore.EncoderConfig` with `TimeKey: "timestamp"`, `EncodeTime: zapcore.ISO8601TimeEncoder`
- Write to both stdout and `logs/requests.jsonl` via `zapcore.NewTee`
- `logs/` added to `.gitignore`

Output format per request:
```json
{"level":"info","timestamp":"2026-06-09T10:00:00.000Z","msg":"request","method":"POST","path":"/login","status":200,"ip":"1.2.3.4","body":"{...}","response_time_ms":12,"user_agent":"Mozilla/5.0"}
```

## Part 2: agent-classifier Full Build

### Architecture

Three-stage pipeline: **Ingestion → Profiling → Classification → Output**

```
logs/requests.jsonl
        │
   FileIngestor (tails file, yields LogEntry)
        │
   TrafficProfiler (IP / User / Endpoint profiles)
        │
   ClassificationEngine
   ├── SQLInjectionDetector
   ├── BruteForceDetector
   ├── AuthAbuseDetector
   └── ReconnaissanceDetector
        │
   OutputWriter (JSON Lines → stdout / file / CloudWatch)
```

### Ingestion

**`ingestion/file_ingestor.py`** — tails `requests.jsonl`, polls every second for new lines, parses each line via `parse_entry()`, returns `LogEntry` objects in chronological order.

**`ingestion/parser.py`** — `parse_entry(raw: str) -> LogEntry | None`. Parses JSON, validates all 8 required fields, returns `None` on malformed input (logs error, never halts).

**`ingestion/ingestor.py`** — `LogIngester` for CloudWatch (boto3 `filter_log_events`, exponential backoff).

### Data Models (`models.py`)

- `LogEntry` — frozen dataclass, 8 required fields + raw string
- `Verdict` — classification output (LEGITIMATE/FRAUDULENT, confidence, reason, original ref)
- `FraudFlag` — ip, user_identity, timestamp, reason, confidence_score
- `DetectionResult` — is_fraudulent, reason, confidence
- `ProfileContext` — aggregated profiles for one entry

### Configuration additions

```python
log_source: str = "file"          # "file" or "cloudwatch"
log_file_path: str = "logs/requests.jsonl"
```

All existing fields retained. Env prefix: `CLASSIFIER_`.

### Profiling (`profiler/`)

- **`ip_profile.py`** — request count, distinct endpoints, request rate, suspicious flag
- **`user_profile.py`** — extract username from /login and /register bodies, track failed logins, distinct IPs, suspicious flag
- **`endpoint_profile.py`** — request count, error count/rate, unique IPs, rate-abuse flag
- **`profiler.py`** — `TrafficProfiler` coordinator; `update(entry) -> ProfileContext`, `reset_window()`

### Classification (`classifiers/`)

- **`base.py`** — `BaseDetector(ABC)` with `evaluate(entry, context) -> DetectionResult | None`
- **`sqli_detector.py`** — compiled regex patterns, /login + /register only, confidence 0.7-0.89 (1 indicator) or ≥0.9 (2+)
- **`brute_force_detector.py`** — >10 failed/IP → brute_force, >5 failed/user → credential_stuffing, confidence = max(F/T, 0.5)
- **`auth_abuse_detector.py`** — unusual UA (confidence 0.6), token manipulation (0.9), forged token (0.85)
- **`recon_detector.py`** — path diversity >5 (reconnaissance), unknown paths (path_enumeration), scanner UA (scanner_detected)
- **`engine.py`** — `ClassificationEngine`, runs all detectors, merges highest confidence + all reasons comma-separated

### Output (`output/`)

- **`writer.py`** — `OutputWriter`, serializes `Verdict` to JSON Lines (UTF-8), confidence_score to 2dp, timestamp as ISO 8601 UTC
- Buffers up to 1000 records when destination unavailable, retries every 5s, discards oldest on buffer full
- Creates `FraudFlag` records for FRAUDULENT verdicts with confidence ≥ 0.7

### Testing

27 property-based tests (Hypothesis) covering all correctness properties from design.md. Unit tests for specific examples and edge cases. Integration tests with moto-mocked CloudWatch.

### Main Pipeline (`main.py`, `__main__.py`)

Poll loop: ingest → profile → classify → output. Time window resets at configured intervals. Graceful shutdown. CLI with optional `--config` flag.

## Build Order (from tasks.md)

1. Core data models
2. Parser + property tests (Properties 1-3)
3. File ingestor + profilers + property tests (Properties 4-11)
4. Classifiers + property tests (Properties 12-26)
5. Output writer + fraud flags + property tests
6. Main pipeline + CLI + integration tests
