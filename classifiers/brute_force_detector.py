from __future__ import annotations
from models import LogEntry, DetectionResult, ProfileContext
from classifiers.base import BaseDetector

IP_THRESHOLD = 10
USER_THRESHOLD = 5


class BruteForceDetector(BaseDetector):
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        results = []

        if context.ip_failed_logins > IP_THRESHOLD:
            t = context.ip_total_logins or context.ip_failed_logins
            conf = max(context.ip_failed_logins / t, 0.5)
            results.append(DetectionResult(
                is_fraudulent=True, reason="brute_force", confidence=round(conf, 4)
            ))

        if context.username and context.user_failed_logins > USER_THRESHOLD:
            t = context.user_total_logins or context.user_failed_logins
            conf = max(context.user_failed_logins / t, 0.5)
            results.append(DetectionResult(
                is_fraudulent=True, reason="credential_stuffing", confidence=round(conf, 4)
            ))

        return results
