#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Hackathon Full-Stack Startup Script
# Starts dummy-be + agent-classifier and wires them together.
#
# Prerequisites:
#   - PostgreSQL running on 127.0.0.1:5432
#   - .env file at ~/nexth-dummy-be/.env (or set DB_* vars below)
#   - Docker installed (for dummy-be)
#   - Python 3.11+ with agent-classifier deps installed
#
# Usage:
#   chmod +x start.sh
#   ./start.sh              # start everything
#   ./start.sh --schema     # only apply DB schema
#   ./start.sh --demo       # fire demo requests after startup
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLASSIFIER_DIR="${CLASSIFIER_DIR:-$HOME/agent-classifier}"
DUMMY_BE_DIR="${DUMMY_BE_DIR:-$HOME/nexth-dummy-be}"

# ── DB connection (matches dummy-be .env defaults) ────────────
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-myapp_db}"
DB_USER="${DB_USER:-myapp_user}"
DB_PASS="${DB_PASS:-}"

# ── Docker image / container names ────────────────────────────
IMAGE="nexth-dummy-be:latest"
CONTAINER="dummy-be"

# ── Colours ───────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; }

# ─────────────────────────────────────────────────────────────
apply_schema() {
  info "Applying DB schema..."
  PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" \
    -U "$DB_USER" -d "$DB_NAME" \
    -f "$DUMMY_BE_DIR/db/schema.sql" \
    && info "Schema applied." \
    || { error "Schema apply failed. Is PostgreSQL running?"; exit 1; }
}

# ─────────────────────────────────────────────────────────────
start_dummy_be() {
  info "Building dummy-be Docker image..."
  sudo docker build -t "$IMAGE" "$DUMMY_BE_DIR" -q

  # Stop old container if running
  if sudo docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    warn "Stopping existing dummy-be container..."
    sudo docker stop "$CONTAINER" >/dev/null 2>&1 || true
    sudo docker rm   "$CONTAINER" >/dev/null 2>&1 || true
  fi

  info "Starting dummy-be container..."
  sudo docker run -d \
    --name "$CONTAINER" \
    --network host \
    --env-file ~/nexth-dummy-be/.env \
    "$IMAGE"

  # Wait for it to be healthy
  for i in {1..10}; do
    if curl -sf http://localhost:8080/home >/dev/null 2>&1 || \
       curl -sf http://localhost:8080/login -X POST -H 'Content-Type: application/json' \
         -d '{}' >/dev/null 2>&1; then
      info "dummy-be is up at http://localhost:8080"
      return
    fi
    sleep 1
  done
  info "dummy-be started (check: sudo docker logs $CONTAINER)"
}

# ─────────────────────────────────────────────────────────────
start_classifier() {
  info "Starting agent-classifier..."

  LOG_FILE="${LOG_FILE:-$DUMMY_BE_DIR/logs/requests.jsonl}"
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"

  cd "$CLASSIFIER_DIR"
  DB_HOST="$DB_HOST" \
  DB_PORT="$DB_PORT" \
  DB_NAME="$DB_NAME" \
  DB_USER="$DB_USER" \
  DB_PASS="$DB_PASS" \
    python3 -m agent_classifier &

  CLASSIFIER_PID=$!
  info "agent-classifier started (PID $CLASSIFIER_PID)"
  info "Watching log file: $LOG_FILE"
}

# ─────────────────────────────────────────────────────────────
fire_demo_requests() {
  info "Firing demo requests..."
  sleep 2  # give dummy-be a moment

  info "  → clean login (admin)"
  curl -s -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | python3 -m json.tool 2>/dev/null || true

  info "  → SQL injection attempt"
  curl -s -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{"username":"'"'"' OR 1=1--","password":"x"}' | python3 -m json.tool 2>/dev/null || true

  info "  → Scanner user-agent"
  curl -s -X GET http://localhost:8080/home \
    -H "User-Agent: sqlmap/1.7.8" | python3 -m json.tool 2>/dev/null || true

  info "Demo requests sent. Check fraud_verdicts in DB:"
  echo ""
  echo "  PGPASSWORD=\"\$DB_PASS\" psql -h $DB_HOST -U $DB_USER -d $DB_NAME \\"
  echo "    -c \"SELECT source_ip, reason, confidence_score, remediated FROM fraud_verdicts;\""
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
case "${1:-}" in
  --schema)
    apply_schema
    ;;
  --demo)
    fire_demo_requests
    ;;
  *)
    apply_schema
    start_dummy_be
    start_classifier
    info ""
    info "System running. Ctrl+C to stop classifier."
    info "  dummy-be:        http://localhost:8080"
    info "  classifier logs: stdout"
    info "  verdicts DB:     fraud_verdicts table"
    info ""
    info "Run ./start.sh --demo to fire test requests."
    wait $CLASSIFIER_PID 2>/dev/null || true
    ;;
esac
