from __future__ import annotations
from typing import Optional

from models import LogEntry, Verdict, ProfileContext, DetectionResult
from classifiers.base import BaseDetector
from config.settings import ClassifierConfig
from ingestion.ip_reputation import ReputationSummary

# Confidence floor applied to traffic from an IP the analyzer has already
# confirmed and blocked — such an IP is a known bad actor, so even otherwise
# borderline requests should escalate rather than be dismissed in isolation.
_KNOWN_BAD_FLOOR = 0.9


class ClassificationEngine:
    def __init__(self, detectors: list[BaseDetector], config: ClassifierConfig):
        self._detectors = detectors
        self._config = config

    def classify(
        self,
        entry: LogEntry,
        context: ProfileContext,
        reputation: Optional[ReputationSummary] = None,
    ) -> Verdict:
        all_results: list[DetectionResult] = []
        for detector in self._detectors:
            all_results.extend(detector.evaluate(entry, context))

        fraudulent = [r for r in all_results if r.is_fraudulent]
        known_bad = reputation is not None and reputation.already_blocked
        repeat_offender = reputation is not None and reputation.is_repeat_offender

        if not fraudulent and not context.ip_suspicious and not context.user_suspicious and not known_bad:
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
        reasons_list = list(dict.fromkeys(r.reason for r in fraudulent))  # deduplicated, ordered

        # Reputation escalation: an IP the analyzer already blocked is a known
        # bad actor — floor its confidence and tag it so the verdict survives.
        if known_bad:
            max_confidence = max(max_confidence, _KNOWN_BAD_FLOOR)
            if "known_bad_ip" not in reasons_list:
                reasons_list.append("known_bad_ip")
        elif repeat_offender and fraudulent:
            # Seen before but not yet blocked — a modest bump so sustained
            # low-signal probing accumulates toward the flag threshold.
            max_confidence = min(0.95, max_confidence + 0.1)

        reasons = ",".join(reasons_list)
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
