from __future__ import annotations
from datetime import timedelta
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

RECOGNIZED_UA_PREFIXES = [
    "Mozilla/5.0", "Chrome/", "Safari/", "Firefox/", "Edge/",
    "PostmanRuntime/", "axios/", "python-requests/",
]
FORGED_TOKEN_WINDOW = timedelta(minutes=30)


class AuthAbuseDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        if entry.path != "/home":
            return []

        results = []

        # Unusual user-agent
        ua = entry.user_agent
        if not any(ua.startswith(p) for p in RECOGNIZED_UA_PREFIXES):
            results.append(DetectionResult(
                is_fraudulent=True, reason="unusual_user_agent", confidence=0.6
            ))

        # Token manipulation: 2+ distinct users from same IP
        if len(context.ip_distinct_users) >= 2:
            results.append(DetectionResult(
                is_fraudulent=True, reason="token_manipulation", confidence=0.9
            ))

        # Forged token: successful /home with no recent successful login,
        # but only when the IP has previously attempted authentication.
        # IPs that have never tried to log in are anonymous visitors, not attackers.
        if entry.status == 200 and context.ip_total_logins > 0:
            window_start = entry.timestamp - FORGED_TOKEN_WINDOW
            recent_logins = [
                t for t in context.ip_successful_logins
                if t >= window_start
            ]
            if not recent_logins:
                results.append(DetectionResult(
                    is_fraudulent=True, reason="forged_token", confidence=0.85
                ))

        return results
