# agent-classifier

Traffic fraud classification pipeline for [dummy-be](https://github.com/satryacode/nexth-dummy-be). Tails the backend's request log, profiles traffic, detects fraud patterns, and persists verdicts to PostgreSQL.

## How It Works

```
dummy-be logs/requests.jsonl
        │
        ▼
  FileIngestor (tail)
        │
        ▼
  TrafficProfiler
  ├── IPProfileManager    — per-IP request count, failure rate, path diversity
  ├── UserProfileManager  — per-user failed logins, multi-IP usage
  └── EndpointProfileManager — per-endpoint error rate, rate abuse
        │
        ▼
  ClassificationEngine
  ├── SQLInjectionDetector   — pattern match on /login, /register bodies
  ├── BruteForceDetector     — IP/user failed login thresholds
  ├── AuthAbuseDetector      — unusual UA, token manipulation, forged token
  └── ReconnaissanceDetector — path diversity, path enumeration, scanner UA
        │
        ▼
  OutputWriter  →  stdout (JSON Lines)
  DBWriter      →  PostgreSQL fraud_verdicts table (remediated=0)
```

## Prerequisites

- Python 3.11+
- PostgreSQL (same instance as dummy-be)
- dummy-be running and writing to `logs/requests.jsonl`

## Setup

### 1. Install dependencies

```bash
pip install -e ".[dev]"
```

### 2. Configure environment

The classifier reads DB connection from the same env vars as dummy-be:

```env
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=myapp_db
DB_USER=myapp_user
DB_PASS=your_password
```

Optional classifier config (all have defaults):

```env
CLASSIFIER_TIME_WINDOW_SECONDS=300       # rolling window for profiling
CLASSIFIER_BRUTE_FORCE_IP_THRESHOLD=10   # failed logins per IP before flagging
CLASSIFIER_BRUTE_FORCE_USER_THRESHOLD=5  # failed logins per user before flagging
CLASSIFIER_RATE_ABUSE_THRESHOLD=50       # requests per IP per endpoint
CLASSIFIER_FRAUD_FLAG_CONFIDENCE_THRESHOLD=0.7
```

Or pass a YAML config file:

```yaml
# config.yaml
time_window_seconds: 300
brute_force_ip_threshold: 10
fraud_flag_confidence_threshold: 0.7
```

```bash
python3 -m agent_classifier --config config.yaml
```

### 3. Apply DB schema (first run only)

```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db -f ../dummy-be/db/schema.sql
```

This creates the `fraud_verdicts` table and adds the `blocked` column to `users`.

### 4. Run

```bash
DB_HOST=127.0.0.1 DB_PASS=your_password python3 -m agent_classifier
```

## Endpoints Monitored

| Method | Path        | Detectors active                          |
|--------|-------------|-------------------------------------------|
| POST   | `/login`    | SQLi, BruteForce, ReconDetector           |
| POST   | `/register` | SQLi, ReconDetector                       |
| GET    | `/home`     | AuthAbuse (forged token, unusual UA)      |
| Any    | unknown     | ReconDetector (path enumeration)          |

## Verdict Output

Each request produces a JSON Lines verdict on stdout:

```json
{
  "timestamp": "2026-06-09T10:00:00Z",
  "source_ip": "1.2.3.4",
  "user_identity": "alice",
  "method": "POST",
  "path": "/login",
  "classification": "FRAUDULENT",
  "confidence_score": 0.9,
  "reason": "sql_injection,scanner_detected",
  "original_log_entry_reference": "{...}"
}
```

`classification` is always `LEGITIMATE` or `FRAUDULENT`.

## DB Schema

```sql
-- fraud verdicts (written by this service)
fraud_verdicts (
    id, source_ip, user_identity, method, path,
    confidence_score, reason, original_log_entry_reference,
    detected_at,        -- auto
    remediated          -- 0 = unreviewed, 1 = confirmed by agent-analyzer
)

-- users (updated by agent-analyzer after review)
users.blocked           -- 0 = active, 1 = blocked
```

Query all unreviewed verdicts:

```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "SELECT source_ip, reason, confidence_score, detected_at FROM fraud_verdicts WHERE remediated=0;"
```

## Tests

```bash
# All tests (79)
python3 -m pytest -v

# Property tests only (35)
python3 -m pytest tests/properties/ -v

# Integration tests only
python3 -m pytest tests/integration/ -v
```

## Project Structure

```
agent-classifier/
├── config/
│   └── settings.py          # pydantic-settings config with CLASSIFIER_ prefix
├── ingestion/
│   ├── parser.py             # parse JSON log lines → LogEntry
│   └── file_ingestor.py      # tail log file, incremental polling
├── profiler/
│   ├── ip_profile.py         # per-IP metrics
│   ├── user_profile.py       # per-user metrics
│   ├── endpoint_profile.py   # per-endpoint metrics
│   └── profiler.py           # TrafficProfiler coordinator
├── classifiers/
│   ├── base.py               # BaseDetector ABC
│   ├── sqli_detector.py
│   ├── brute_force_detector.py
│   ├── auth_abuse_detector.py
│   ├── recon_detector.py
│   └── engine.py             # ClassificationEngine
├── output/
│   ├── writer.py             # JSON Lines to stdout/file
│   └── db_writer.py          # INSERT to fraud_verdicts
├── models.py                 # LogEntry, Verdict, ProfileContext, FraudFlag
├── main.py                   # pipeline loop
└── __main__.py               # CLI entry point
```
