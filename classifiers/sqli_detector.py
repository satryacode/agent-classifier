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
