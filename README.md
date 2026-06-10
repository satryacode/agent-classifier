# agent-classifier

Traffic fraud classification pipeline for [dummy-be](https://github.com/satryacode/nexth-dummy-be). Bridges dummy-be container logs, profiles traffic per IP/user/endpoint, classifies each request, and persists `FRAUDULENT` verdicts to PostgreSQL for review by an agent-analyzer.

## How It Works

```
dummy-be container stdout
        │  (docker logs -f bridge → host file)
        ▼
  logs/requests.jsonl  (JSON Lines, one entry per request)
        │
        ▼
  FileIngestor (tail + poll)
        │
        ▼
  TrafficProfiler
  ├── IPProfileManager    — per-IP request count, failure rate, path diversity
  ├── UserProfileManager  — per-user failed logins, multi-IP usage
  └── EndpointProfileManager — per-endpoint error rate, rate abuse
        │
        ▼
  ClassificationEngine
  ├── SQLInjectionDetector   — regex pattern match on /login, /register bodies
  ├── BruteForceDetector     — IP/user failed login threshold checks
  ├── AuthAbuseDetector      — unusual UA, token manipulation, forged token
  └── ReconnaissanceDetector — path diversity, path enumeration, scanner UA
        │
        ▼
  OutputWriter  →  stdout (JSON Lines verdict per request)
  DBWriter      →  PostgreSQL fraud_verdicts (remediated=0, pending review)
```

## Prerequisites

- Python 3.9+
- PostgreSQL (same instance as dummy-be)
- dummy-be running as a Docker container named `dummy-be`

## Quickstart (recommended)

Use `start.sh` from the repo root — it handles everything:

```bash
# Full startup: schema + dummy-be + classifier
./start.sh

# Classifier only (dummy-be already running)
./start.sh --classifier-only

# Schema only
./start.sh --schema

# Fire demo attack requests
./start.sh --demo
```

`start.sh` automatically:
- Reads `DB_PASS` from `~/nexth-dummy-be/.env`
- Bridges `docker logs -f dummy-be` → `logs/requests.jsonl`
- Installs Python dependencies via `pip`
- Passes `CLASSIFIER_LOG_FILE_PATH` to the classifier

## Manual Setup

### 1. Install dependencies

```bash
cd ~/agent-classifier
python3 -m pip install -e .
```

### 2. Configure environment

DB connection (same vars as dummy-be):

```env
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=myapp_db
DB_USER=myapp_user
DB_PASS=your_password
```

Log file path (where docker logs bridge writes):

```env
CLASSIFIER_LOG_FILE_PATH=/home/ssm-user/nexth-dummy-be/logs/requests.jsonl
```

Optional tuning (all have defaults):

```env
CLASSIFIER_TIME_WINDOW_SECONDS=300
CLASSIFIER_BRUTE_FORCE_IP_THRESHOLD=10
CLASSIFIER_BRUTE_FORCE_USER_THRESHOLD=5
CLASSIFIER_RATE_ABUSE_THRESHOLD=50
CLASSIFIER_FRAUD_FLAG_CONFIDENCE_THRESHOLD=0.7
```

Or use a YAML config file:

```yaml
# config.yaml
time_window_seconds: 300
brute_force_ip_threshold: 10
fraud_flag_confidence_threshold: 0.7
```

```bash
python3 __main__.py --config config.yaml
```

### 3. Apply DB schema (first run only)

```bash
PGPASSWORD=your_password psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -f ~/nexth-dummy-be/db/schema.sql
```

Creates `fraud_verdicts` table and adds `blocked` column to `users`.

### 4. Bridge logs + run

```bash
# Bridge docker logs to a file
mkdir -p ~/nexth-dummy-be/logs
sudo docker logs -f --tail 0 dummy-be 2>/dev/null \
  >> ~/nexth-dummy-be/logs/requests.jsonl &

# Start classifier
cd ~/agent-classifier
DB_HOST=127.0.0.1 DB_PASS=your_password \
CLASSIFIER_LOG_FILE_PATH=~/nexth-dummy-be/logs/requests.jsonl \
  python3 __main__.py
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

`classification` is always `LEGITIMATE` or `FRAUDULENT`. Only `FRAUDULENT` verdicts are written to the DB.

## DB Schema

```sql
-- Fraud verdicts written by this service (remediated=0 = pending agent-analyzer review)
fraud_verdicts (
    id, source_ip, user_identity, method, path,
    confidence_score, reason, original_log_entry_reference,
    detected_at,   -- auto-set on insert
    remediated     -- 0 = unreviewed, 1 = confirmed by agent-analyzer
)

-- users.blocked set by agent-analyzer after verdict review
-- blocked=1 → dummy-be returns 403 Forbidden on login
users.blocked SMALLINT DEFAULT 0
```

Query unreviewed verdicts:

```bash
PGPASSWORD=your_password psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "SELECT source_ip, reason, confidence_score, detected_at FROM fraud_verdicts WHERE remediated=0;"
```

## Tests

```bash
# All tests (79)
python3 -m pytest -v

# Property tests only (35 — Hypothesis-based)
python3 -m pytest tests/properties/ -v

# Integration tests only
python3 -m pytest tests/integration/ -v
```

## Project Structure

```
agent-classifier/
├── config/
│   └── settings.py          # pydantic-settings config (CLASSIFIER_ prefix)
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
│   ├── writer.py             # JSON Lines to stdout
│   └── db_writer.py          # INSERT to fraud_verdicts
├── models.py                 # LogEntry, Verdict, ProfileContext, FraudFlag
├── main.py                   # pipeline loop
├── __main__.py               # CLI entry point (run with: python3 __main__.py)
└── start.sh                  # full-system startup script
```
