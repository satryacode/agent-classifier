from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import psycopg2

logger = logging.getLogger(__name__)

_HIGH_SEVERITY_SQL_REGEX = r"(sql_injection|scanner_detected|brute_force|credential_stuffing)"

_REPUTATION_SQL = """
    SELECT
        COUNT(*)                                                       AS total,
        COUNT(*) FILTER (WHERE reason ~ %(hs)s)                        AS high_sev,
        EXISTS (SELECT 1 FROM blocked_ips b WHERE b.source_ip = %(ip)s) AS already_blocked
    FROM fraud_verdicts
    WHERE source_ip = %(ip)s
      AND detected_at >= NOW() - (%(window_min)s * INTERVAL '1 minute')
"""


@dataclass(frozen=True)
class ReputationSummary:
    source_ip: str
    total_verdicts: int = 0
    high_severity_verdicts: int = 0
    already_blocked: bool = False

    @property
    def is_repeat_offender(self) -> bool:
        return self.total_verdicts > 1 or self.already_blocked


class IpReputation:
    """Reads per-IP reputation from PostgreSQL with a short in-process TTL cache.

    Lets the classifier escalate traffic from IPs the analyzer has already
    confirmed/blocked, closing the analyzer -> classifier feedback loop.
    """

    def __init__(
        self,
        window_minutes: int = 30,
        cache_ttl_seconds: float = 20.0,
        db_host: Optional[str] = None,
        db_port: Optional[int] = None,
        db_name: Optional[str] = None,
        db_user: Optional[str] = None,
        db_pass: Optional[str] = None,
    ) -> None:
        self._window_minutes = window_minutes
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[float, ReputationSummary]] = {}
        self._params = {
            "host": db_host or os.environ.get("DB_HOST", "127.0.0.1"),
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
            logger.info("IpReputation connected to PostgreSQL at %s", self._params["host"])
        except Exception as exc:
            logger.warning("IpReputation could not connect: %s — reputation disabled", exc)
            self._conn = None

    def lookup(self, source_ip: str) -> ReputationSummary:
        if not source_ip:
            return ReputationSummary(source_ip="")

        now = time.monotonic()
        cached = self._cache.get(source_ip)
        if cached is not None and (now - cached[0]) < self._cache_ttl:
            return cached[1]

        summary = self._query(source_ip)
        self._cache[source_ip] = (now, summary)
        return summary

    def _query(self, source_ip: str) -> ReputationSummary:
        if self._conn is None:
            self._connect()
        if self._conn is None:
            return ReputationSummary(source_ip=source_ip)
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    _REPUTATION_SQL,
                    {"ip": source_ip, "hs": _HIGH_SEVERITY_SQL_REGEX, "window_min": self._window_minutes},
                )
                row = cur.fetchone()
            self._conn.commit()
            if row is None:
                return ReputationSummary(source_ip=source_ip)
            return ReputationSummary(
                source_ip=source_ip,
                total_verdicts=int(row[0] or 0),
                high_severity_verdicts=int(row[1] or 0),
                already_blocked=bool(row[2]),
            )
        except Exception as exc:
            logger.error("IpReputation query failed for %s: %s", source_ip, exc)
            try:
                self._conn.rollback()
            except Exception:
                pass
            self._conn = None
            return ReputationSummary(source_ip=source_ip)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
