# DB Verdict Storage & User Blocking Design

**Date:** 2026-06-09

## Goal

Persist FRAUDULENT classifier verdicts to PostgreSQL (same DB as dummy-be) and block affected users at login.

## Scope

1. DB schema: `fraud_verdicts` table + `blocked` column on `users`
2. agent-classifier: `output/db_writer.py` inserts FRAUDULENT verdicts
3. dummy-be: login handler rejects blocked users

**Out of scope:** agent analyzer (future service that sets `remediated=1` and triggers blocking).

---

## Architecture

```
agent-classifier                   PostgreSQL
  main.py
    ├── engine.classify()
    ├── OutputWriter (file/stdout)  ──► logs/verdicts.jsonl
    └── DBWriter ─────────────────────► fraud_verdicts (remediated=0)

dummy-be                           PostgreSQL
  Login handler
    └── SELECT ... WHERE username=? ─► users (check blocked=1 → 403)

[future] agent-analyzer
    └── UPDATE fraud_verdicts SET remediated=1
    └── UPDATE users SET blocked=1 WHERE username=?
```

---

## DB Schema Changes (`dummy-be/db/schema.sql`)

### New table

```sql
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
```

### Alter users

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked SMALLINT DEFAULT 0;
```

---

## agent-classifier Changes

### `output/db_writer.py`

New `DBWriter` class:
- Connects to PostgreSQL using `psycopg2` with env vars `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` (same vars as dummy-be, no `CLASSIFIER_` prefix)
- `insert_verdict(verdict: Verdict) -> None` — inserts one row into `fraud_verdicts` with `remediated=0`
- On any DB error: log and skip (never crash the pipeline)
- Lazy reconnect: if connection is lost, attempt reconnect on next call

### `config/settings.py`

Add DB connection fields (read from `DB_*` env vars directly, not `CLASSIFIER_` prefixed):

```python
db_host: str = "localhost"
db_port: int = 5432
db_name: str = "myapp_db"
db_user: str = "myapp_user"
db_pass: str = ""
```

Use `model_config` override for these fields to ignore the `CLASSIFIER_` prefix.

### `main.py`

Wire up `DBWriter` and call after classification:

```python
db_writer = DBWriter(config)
# ...
verdict = engine.classify(entry, context)
writer.write_verdict(verdict)
if verdict.classification == "FRAUDULENT":
    db_writer.insert_verdict(verdict)
```

---

## dummy-be Changes

### `models/user.go`

Add `Blocked` field:

```go
type User struct {
    ID        int       `json:"id"`
    Username  string    `json:"username"`
    Email     string    `json:"email"`
    Password  string    `json:"password"`
    CreatedAt time.Time `json:"created_at"`
    Blocked   int       `json:"blocked"`
}
```

### `handlers/auth.go` — Login

1. Update SELECT to include `blocked`: `SELECT id, username, email, password, created_at, blocked FROM users WHERE ...`
2. Update `Scan(...)` to include `&user.Blocked`
3. After successful auth, check:

```go
if user.Blocked == 1 {
    c.JSON(http.StatusForbidden, gin.H{"error": "account blocked"})
    return
}
```

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| DB unreachable at startup | Log warning, `DBWriter` disabled (pipeline continues) |
| Insert fails mid-run | Log error, skip verdict (pipeline continues) |
| Login for blocked user | 403 Forbidden `{"error": "account blocked"}` |

---

## Testing

- `DBWriter`: unit test with a mock/real test DB — verify row inserted, `remediated=0`, fields correct
- Login block: unit test that a user with `blocked=1` gets 403
- No changes to existing 74 passing tests in agent-classifier
