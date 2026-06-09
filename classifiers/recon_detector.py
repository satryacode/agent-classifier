from __future__ import annotations
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

KNOWN_PATHS = frozenset(["/register", "/login", "/home"])
SCANNER_IDS = ["sqlmap", "nikto", "nmap", "dirbuster", "gobuster"]
PATH_DIVERSITY_THRESHOLD = 5


class ReconnaissanceDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        results = []

        # Path diversity reconnaissance
        if len(context.ip_distinct_paths) > PATH_DIVERSITY_THRESHOLD:
            results.append(DetectionResult(
                is_fraudulent=True, reason="reconnaissance", confidence=0.8
            ))

        # Path enumeration
        normalized = entry.path.split("?")[0].rstrip("/") or "/"
        if normalized not in KNOWN_PATHS:
            results.append(DetectionResult(
                is_fraudulent=True, reason="path_enumeration", confidence=0.7
            ))

        # Scanner user-agent
        ua_lower = entry.user_agent.lower()
        if any(sid in ua_lower for sid in SCANNER_IDS):
            results.append(DetectionResult(
                is_fraudulent=True, reason="scanner_detected", confidence=0.95
            ))

        return results
