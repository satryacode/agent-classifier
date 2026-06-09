from __future__ import annotations
from models import LogEntry, Verdict, ProfileContext, DetectionResult
from classifiers.base import BaseDetector
from config.settings import ClassifierConfig


class ClassificationEngine:
    def __init__(self, detectors: list[BaseDetector], config: ClassifierConfig):
        self._detectors = detectors
        self._config = config

    def classify(self, entry: LogEntry, context: ProfileContext) -> Verdict:
        all_results: list[DetectionResult] = []
        for detector in self._detectors:
            all_results.extend(detector.evaluate(entry, context))

        fraudulent = [r for r in all_results if r.is_fraudulent]

        if not fraudulent and not context.ip_suspicious and not context.user_suspicious:
            return Verdict(
                timestamp=entry.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                source_ip=entry.ip,
                user_identity=context.username,
                method=entry.method,
                path=entry.path,
                classification="LEGITIMATE",
                confidence_score=1.0,
                reason="clean",
                original_log_entry_reference=entry.raw,
            )

        max_confidence = max((r.confidence for r in fraudulent), default=0.5)
        reasons = ",".join(dict.fromkeys(r.reason for r in fraudulent))  # deduplicated, ordered
        if not reasons:
            reasons = "suspicious_profile"

        return Verdict(
            timestamp=entry.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            source_ip=entry.ip,
            user_identity=context.username,
            method=entry.method,
            path=entry.path,
            classification="FRAUDULENT",
            confidence_score=round(max_confidence, 4),
            reason=reasons[:500],
            original_log_entry_reference=entry.raw,
        )
