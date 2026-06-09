# Feature: traffic-fraud-classifier, Property 23: Multiple fraud reasons reported
# Feature: traffic-fraud-classifier, Property 24: Verdict completeness and legitimate default
# Feature: traffic-fraud-classifier, Property 25: Fraud flag creation at confidence threshold
# Feature: traffic-fraud-classifier, Property 26: Verdict JSON serialization round-trip
import io
import json
import json as _json
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.engine import ClassificationEngine
from classifiers.sqli_detector import SQLInjectionDetector
from classifiers.brute_force_detector import BruteForceDetector
from classifiers.auth_abuse_detector import AuthAbuseDetector
from classifiers.recon_detector import ReconnaissanceDetector
from models import ProfileContext, Verdict
from config.settings import ClassifierConfig
from output.writer import OutputWriter

config = ClassifierConfig()
engine = ClassificationEngine(
    [SQLInjectionDetector(), BruteForceDetector(), AuthAbuseDetector(), ReconnaissanceDetector()],
    config,
)


def _parse(d):
    return parse_entry(json.dumps(d))


def test_property_23_multiple_reasons_reported():
    """Entry triggering multiple rules gets all reasons comma-separated."""
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 401,
        "ip": "1.2.3.4", "body": json.dumps({"username": "' OR 1=1--", "password": "x"}),
        "response_time_ms": 10, "user_agent": "sqlmap/1.0",
    }
    entry = _parse(d)
    ctx = ProfileContext(ip="1.2.3.4")
    verdict = engine.classify(entry, ctx)
    assert verdict.classification == "FRAUDULENT"
    reasons = verdict.reason.split(",")
    assert len(reasons) >= 2
    assert "sql_injection" in verdict.reason
    assert "scanner_detected" in verdict.reason


def test_property_24_legitimate_default():
    """Clean entry with no suspicious profile → LEGITIMATE with confidence 1.0."""
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 200,
        "ip": "1.2.3.4", "body": json.dumps({"username": "admin", "password": "pass"}),
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = _parse(d)
    ctx = ProfileContext(ip="1.2.3.4")
    verdict = engine.classify(entry, ctx)
    assert verdict.classification == "LEGITIMATE"
    assert verdict.confidence_score == 1.0


def test_property_24_verdict_has_all_fields():
    """Every verdict has all required fields."""
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": "/home", "status": 200,
        "ip": "1.2.3.4", "body": "", "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = _parse(d)
    ctx = ProfileContext(ip="1.2.3.4")
    verdict = engine.classify(entry, ctx)
    for f in ["timestamp", "source_ip", "method", "path", "classification",
              "confidence_score", "reason", "original_log_entry_reference"]:
        assert hasattr(verdict, f)


def _make_verdict(classification="FRAUDULENT", confidence=0.9, reason="sql_injection"):
    return Verdict(
        timestamp="2026-06-09T10:00:00Z",
        source_ip="1.2.3.4",
        user_identity="alice",
        method="POST",
        path="/login",
        classification=classification,
        confidence_score=confidence,
        reason=reason,
        original_log_entry_reference='{"raw":"entry"}',
    )


@given(st.floats(min_value=0.0, max_value=1.0))
@settings(max_examples=100)
def test_property_25_fraud_flag_threshold(confidence):
    verdict = _make_verdict(confidence=confidence)
    writer = OutputWriter(config=ClassifierConfig())
    flags = writer.maybe_create_flag(verdict)
    if confidence >= 0.7:
        assert len(flags) == 1
        assert flags[0].ip == verdict.source_ip
        assert flags[0].confidence_score == confidence
    else:
        assert len(flags) == 0


def test_property_26_verdict_serialization_roundtrip():
    """Serialize to JSON line and parse back → identical fields."""
    verdict = _make_verdict()
    writer = OutputWriter(config=ClassifierConfig())
    buf = io.StringIO()
    writer._write_to(verdict, buf)
    line = buf.getvalue().strip()
    parsed = _json.loads(line)
    assert parsed["classification"] == verdict.classification
    assert parsed["source_ip"] == verdict.source_ip
    assert f"{parsed['confidence_score']:.2f}" == f"{verdict.confidence_score:.2f}"
    assert parsed["timestamp"].endswith("Z")
    for f in ["timestamp", "source_ip", "user_identity", "method", "path",
              "classification", "confidence_score", "reason", "original_log_entry_reference"]:
        assert f in parsed
