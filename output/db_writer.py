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
