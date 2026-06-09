# DB Verdict Storage & User Blocking Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist FRAUDULENT classifier verdicts to PostgreSQL, and block flagged users at login in dummy-be.

**Architecture:** agent-classifier gains a `DBWriter` that inserts FRAUDULENT verdicts into a new `fraud_verdicts` table (with `remediated=0`). dummy-be gains a `blocked` column on `users` and rejects blocked users at login with 403.

**Tech Stack:** Python 3.11+, psycopg2-binary, Go 1.25, pgx/v5, PostgreSQL 15.

---

## Chunk 1: DB Schema + dummy-be

### Task 1: Update DB schema

**Context:** `dummy-be/db/schema.sql` is run against the shared PostgreSQL instance. It uses `CREATE TABLE IF NOT EXISTS` so it's safe to re-run. We add a new table and a new column.

**Files:**
- Modify: `dummy-be/db/schema.sql`

- [ ] **Step 1: Add `fraud_verdicts` table and `blocked` column to schema**

Replace the entire `dummy-be/db/schema.sql` with:

```sql
-- db/schema.sql
CREATE TABLE IF NOT EXISTS users (
    id         SERIAL PRIMARY KEY,
    username   VARCHAR(255),
    email      VARCHAR(255),
    password   VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    blocked    SMALLINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fraud_verdicts (
    id                           SERIAL PRIMARY KEY,
    source_ip                    VARCHAR(45),
    user_identity                VARCHAR(255),
    method                       VARCHAR(10),
    path                         VARCHAR(500),
    confidence_score             DECIMAL(4,2),
    reason                       VARCHAR(500),
    original_log_entry_reference TEXT,
    detected_at                  TIMESTAMP DEFAULT NOW(),
    remediated                   SMALLINT DEFAULT 0
);

INSERT INTO users (username, email, password)
VALUES ('admin', 'admin@dummy.com', 'admin123')
ON CONFLICT DO NOTHING;
```

- [ ] **Step 2: Apply schema to the database**

If postgres is on host:
```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db -f dummy-be/db/schema.sql
```

If postgres is in Docker:
```bash
sudo docker exec -i postgres psql -U myapp_user -d myapp_db < dummy-be/db/schema.sql
```

Expected: no errors. `ALTER TABLE` errors like "column already exists" are fine — `ADD COLUMN IF NOT EXISTS` prevents that.

- [ ] **Step 3: Verify tables exist**

```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db -c "\dt"
```

Expected: both `users` and `fraud_verdicts` in the list.

- [ ] **Step 4: Commit**

```bash
cd dummy-be
git add db/schema.sql
git commit -m "feat: add fraud_verdicts table and blocked column on users"
```

---

### Task 2: dummy-be User model + login blocked check

**Context:** `dummy-be/models/user.go` defines the `User` struct. `dummy-be/handlers/auth.go` has the `Login` handler. The login query uses string interpolation (intentional SQLi vuln — do NOT fix it). The query currently selects 5 columns and scans 5 fields. We need to add `blocked` as the 6th.

The hardcoded admin fallback (`admin`/`admin123`) creates a `User{}` struct — `Blocked` will default to `0` there, which is correct.

**Files:**
- Modify: `dummy-be/models/user.go`
- Modify: `dummy-be/handlers/auth.go`

- [ ] **Step 1: Add `Blocked` field to `User` struct in `models/user.go`**

Replace the entire file:

```go
// models/user.go
package models

import "time"

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"password"` // plaintext (intentional vuln)
	CreatedAt time.Time `json:"created_at"`
	Blocked   int       `json:"blocked"`
}
```

- [ ] **Step 2: Update the SELECT query and Scan in `handlers/auth.go`**

Find this block in `Login`:

```go
// SQL Injection vulnerability: string interpolation instead of parameterized query
query := fmt.Sprintf(
    "SELECT id, username, email, password, created_at FROM users WHERE username='%s' AND password='%s'",
    req.Username, req.Password,
)

var user models.User
err := pool.QueryRow(context.Background(), query).Scan(
    &user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt,
)
```

Replace with:

```go
// SQL Injection vulnerability: string interpolation instead of parameterized query
query := fmt.Sprintf(
    "SELECT id, username, email, password, created_at, blocked FROM users WHERE username='%s' AND password='%s'",
    req.Username, req.Password,
)

var user models.User
err := pool.QueryRow(context.Background(), query).Scan(
    &user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.Blocked,
)
```

- [ ] **Step 3: Add blocked check after user is set**

Find this line (after the hardcoded admin fallback block, just before the JWT generation):

```go
// JWT signed with weak hardcoded secret
token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
```

Insert before it:

```go
if user.Blocked == 1 {
    c.JSON(http.StatusForbidden, gin.H{"error": "account blocked"})
    return
}

```

- [ ] **Step 4: Verify the build compiles**

```bash
cd dummy-be && go build ./...
```

Expected: no errors.

- [ ] **Step 5: Run existing tests**

```bash
cd dummy-be && go test ./...
```

Expected: all pass (existing tests don't touch the DB query or blocked field).

- [ ] **Step 6: Manual smoke test**

Start dummy-be:
```bash
go run .
```

Try logging in normally — should work:
```bash
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq .
```
Expected: 200 with token.

Block the admin user directly in DB, then try again:
```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "UPDATE users SET blocked=1 WHERE username='admin';"

curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```
Expected: `{"error":"account blocked"}` with HTTP 403.

Unblock for further testing:
```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "UPDATE users SET blocked=0 WHERE username='admin';"
```

- [ ] **Step 7: Commit**

```bash
cd dummy-be
git add models/user.go handlers/auth.go
git commit -m "feat: add blocked check to login handler"
```

---

## Chunk 2: agent-classifier DB Writer

### Task 3: Add psycopg2 dependency + DB config fields

**Context:** `agent-classifier/pyproject.toml` lists project dependencies. `agent-classifier/config/settings.py` uses `pydantic-settings` with `CLASSIFIER_` prefix. The DB connection fields should read from the same `DB_*` env vars that dummy-be uses (no `CLASSIFIER_` prefix). We handle this by reading `os.environ` directly in `DBWriter.__init__` rather than adding them to `ClassifierConfig`.

**Files:**
- Modify: `agent-classifier/pyproject.toml`

- [ ] **Step 1: Add `psycopg2-binary` to `pyproject.toml` dependencies**

In the `dependencies` list, add `"psycopg2-binary>=2.9.9"`:

```toml
dependencies = [
    "boto3>=1.34.0",
    "pydantic-settings>=2.1.0",
    "pyyaml>=6.0.1",
    "psycopg2-binary>=2.9.9",
]
```

- [ ] **Step 2: Install the dependency**

```bash
cd agent-classifier && pip3 install psycopg2-binary
```

Expected: Successfully installed psycopg2-binary-...

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add psycopg2-binary dependency for DB output"
```

---

### Task 4: Implement `output/db_writer.py` with tests

**Context:** `output/writer.py` already exists as the file/stdout writer. `DBWriter` is a separate class in the same package. It reads DB connection params from environment variables `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` — same vars dummy-be uses. On any connection or insert failure it logs and continues; it never crashes the pipeline. The `fraud_verdicts` schema has: `source_ip`, `user_identity`, `method`, `path`, `confidence_score`, `reason`, `original_log_entry_reference`, `detected_at` (auto), `remediated` (auto 0).

**Files:**
- Create: `agent-classifier/output/db_writer.py`
- Create: `agent-classifier/tests/unit/test_db_writer.py`

- [ ] **Step 1: Write failing tests in `tests/unit/test_db_writer.py`**

```python
from unittest.mock import MagicMock, patch, call
import pytest
from output.db_writer import DBWriter
from models import Verdict


def _make_verdict():
    return Verdict(
        timestamp="2026-06-09T10:00:00Z",
        source_ip="1.2.3.4",
        user_identity="alice",
        method="POST",
        path="/login",
        classification="FRAUDULENT",
        confidence_score=0.9,
        reason="sql_injection",
        original_log_entry_reference='{"raw":"entry"}',
    )


def _make_writer(mock_connect):
    """Helper: build a DBWriter with a mocked psycopg2 connection."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_connect.return_value = mock_conn
    writer = DBWriter(db_host="localhost", db_port=5432, db_name="test", db_user="u", db_pass="p")
    return writer, mock_conn, mock_cursor


@patch("output.db_writer.psycopg2.connect")
def test_insert_verdict_executes_insert_into_fraud_verdicts(mock_connect):
    writer, mock_conn, mock_cursor = _make_writer(mock_connect)
    writer.insert_verdict(_make_verdict())
    assert mock_cursor.execute.called
    sql = mock_cursor.execute.call_args[0][0]
    assert "fraud_verdicts" in sql
    mock_conn.commit.assert_called_once()


@patch("output.db_writer.psycopg2.connect")
def test_insert_verdict_passes_correct_fields(mock_connect):
    writer, mock_conn, mock_cursor = _make_writer(mock_connect)
    v = _make_verdict()
    writer.insert_verdict(v)
    params = mock_cursor.execute.call_args[0][1]
    assert params[0] == v.source_ip
    assert params[1] == v.user_identity
    assert params[2] == v.method
    assert params[3] == v.path
    assert params[4] == v.confidence_score
    assert params[5] == v.reason
    assert params[6] == v.original_log_entry_reference


@patch("output.db_writer.psycopg2.connect")
def test_insert_verdict_does_not_raise_on_execute_error(mock_connect):
    writer, mock_conn, mock_cursor = _make_writer(mock_connect)
    mock_cursor.execute.side_effect = Exception("DB error")
    # Must not raise
    writer.insert_verdict(_make_verdict())


@patch("output.db_writer.psycopg2.connect")
def test_db_writer_disables_gracefully_on_connect_failure(mock_connect):
    mock_connect.side_effect = Exception("connection refused")
    writer = DBWriter(db_host="bad", db_port=5432, db_name="test", db_user="u", db_pass="p")
    # Must not raise even with no connection
    writer.insert_verdict(_make_verdict())


@patch("output.db_writer.psycopg2.connect")
def test_close_closes_connection(mock_connect):
    writer, mock_conn, _ = _make_writer(mock_connect)
    writer.close()
    mock_conn.close.assert_called_once()
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd agent-classifier && python3 -m pytest tests/unit/test_db_writer.py -v
```

Expected: `ImportError: cannot import name 'DBWriter' from 'output.db_writer'`

- [ ] **Step 3: Create `output/db_writer.py`**

```python
from __future__ import annotations
import logging
import os

import psycopg2

from models import Verdict

logger = logging.getLogger(__name__)

_INSERT_SQL = """
    INSERT INTO fraud_verdicts
        (source_ip, user_identity, method, path, confidence_score,
         reason, original_log_entry_reference)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
"""


class DBWriter:
    def __init__(
        self,
        db_host: str | None = None,
        db_port: int | None = None,
        db_name: str | None = None,
        db_user: str | None = None,
        db_pass: str | None = None,
    ):
        self._params = {
            "host": db_host or os.environ.get("DB_HOST", "localhost"),
            "port": int(db_port or os.environ.get("DB_PORT", 5432)),
            "dbname": db_name or os.environ.get("DB_NAME", "myapp_db"),
            "user": db_user or os.environ.get("DB_USER", "myapp_user"),
            "password": db_pass or os.environ.get("DB_PASS", ""),
        }
        self._conn = None
        self._connect()

    def _connect(self) -> None:
        try:
            self._conn = psycopg2.connect(**self._params)
            logger.info("DBWriter connected to PostgreSQL at %s", self._params["host"])
        except Exception as exc:
            logger.warning("DBWriter could not connect: %s — DB output disabled", exc)
            self._conn = None

    def insert_verdict(self, verdict: Verdict) -> None:
        if self._conn is None:
            self._connect()
        if self._conn is None:
            logger.error("DBWriter: no connection, skipping verdict for %s", verdict.source_ip)
            return

        try:
            with self._conn.cursor() as cur:
                cur.execute(_INSERT_SQL, (
                    verdict.source_ip,
                    verdict.user_identity,
                    verdict.method,
                    verdict.path,
                    verdict.confidence_score,
                    verdict.reason,
                    verdict.original_log_entry_reference,
                ))
            self._conn.commit()
        except Exception as exc:
            logger.error("DBWriter insert failed: %s", exc)
            try:
                self._conn.rollback()
            except Exception:
                pass
            self._conn = None  # force reconnect on next call

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/unit/test_db_writer.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Run full test suite to verify nothing broken**

```bash
python3 -m pytest -v
```

Expected: all tests pass (74 existing + 5 new = 79 total).

- [ ] **Step 6: Commit**

```bash
git add output/db_writer.py tests/unit/test_db_writer.py
git commit -m "feat: add DBWriter that inserts FRAUDULENT verdicts to PostgreSQL"
```

---

### Task 5: Wire DBWriter into main.py

**Context:** `agent-classifier/main.py` already has `OutputWriter` wired up. We add `DBWriter` alongside it. `DBWriter` is only called when `verdict.classification == "FRAUDULENT"`. If the DB is unavailable, `DBWriter` logs and skips — pipeline keeps running.

**Files:**
- Modify: `agent-classifier/main.py`

- [ ] **Step 1: Add import and instantiation in `main.py`**

Add import at the top of `main.py` (after the other output imports):

```python
from output.db_writer import DBWriter
```

Inside `run()`, after the `writer = OutputWriter(config)` line, add:

```python
db_writer = DBWriter()
```

- [ ] **Step 2: Call `db_writer.insert_verdict` for FRAUDULENT verdicts**

Find this block in `run()`:

```python
        for entry in entries:
            context = profiler.update(entry)
            verdict = engine.classify(entry, context)
            writer.write_verdict(verdict)
            for flag in writer.maybe_create_flag(verdict):
                logger.info("FraudFlag: ip=%s reason=%s confidence=%.2f",
                            flag.ip, flag.reason, flag.confidence_score)
```

Replace with:

```python
        for entry in entries:
            context = profiler.update(entry)
            verdict = engine.classify(entry, context)
            writer.write_verdict(verdict)
            if verdict.classification == "FRAUDULENT":
                db_writer.insert_verdict(verdict)
            for flag in writer.maybe_create_flag(verdict):
                logger.info("FraudFlag: ip=%s reason=%s confidence=%.2f",
                            flag.ip, flag.reason, flag.confidence_score)
```

- [ ] **Step 3: Close db_writer on shutdown**

Find `writer.close()` in `run()` and add `db_writer.close()` after it:

```python
    writer.close()
    db_writer.close()
    logger.info("Pipeline stopped.")
```

- [ ] **Step 4: Run all tests to verify nothing broken**

```bash
python3 -m pytest -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit and push**

```bash
git add main.py
git commit -m "feat: wire DBWriter into main pipeline for FRAUDULENT verdicts"
git push origin master
```

---

## End-to-End Smoke Test

After both dummy-be and agent-classifier are updated:

1. Apply the schema:
```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db -f dummy-be/db/schema.sql
```

2. Start dummy-be:
```bash
cd dummy-be && go run .
```

3. Start classifier (in another terminal, with DB env vars set):
```bash
cd agent-classifier
DB_HOST=127.0.0.1 DB_PASS=<your_pass> python3 -m agent_classifier
```

4. Fire a SQLi request:
```bash
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"'"'"' OR 1=1--","password":"x"}'
```

5. Check the DB for the verdict:
```bash
psql -h 127.0.0.1 -U myapp_user -d myapp_db \
  -c "SELECT source_ip, reason, confidence_score, remediated FROM fraud_verdicts;"
```

Expected: one row with `reason=sql_injection`, `remediated=0`.
