from __future__ import annotations
import json
import logging
import sys
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
