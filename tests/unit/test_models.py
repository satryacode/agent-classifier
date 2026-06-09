from datetime import datetime, timezone
import pytest
from models import LogEntry, Verdict, FraudFlag, DetectionResult, ProfileContext


def test_log_entry_is_frozen():
    entry = LogEntry(
        timestamp=datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc),
        method="POST", path="/login", status=200,
        ip="1.2.3.4", body='{"username":"admin"}',
        response_time_ms=12, user_agent="Mozilla/5.0", raw="{}",
    )
    with pytest.raises((AttributeError, TypeError)):
        entry.method = "GET"


def test_verdict_fields():
    v = Verdict(
        timestamp="2026-06-09T10:00:00Z", source_ip="1.2.3.4",
        user_identity=None, method="POST", path="/login",
        classification="FRAUDULENT", confidence_score=0.9,
        reason="sql_injection", original_log_entry_reference="{}",
    )
    assert v.classification == "FRAUDULENT"
    assert v.confidence_score == 0.9


def test_fraud_flag_fields():
    f = FraudFlag(ip="1.2.3.4", user_identity="alice",
                  timestamp="2026-06-09T10:00:00Z", reason="brute_force", confidence_score=0.8)
    assert f.ip == "1.2.3.4"


def test_detection_result():
    r = DetectionResult(is_fraudulent=True, reason="sql_injection", confidence=0.9)
    assert r.is_fraudulent


def test_profile_context_defaults():
    ctx = ProfileContext(ip="1.2.3.4")
    assert ctx.ip_request_count == 0
    assert ctx.ip_distinct_paths == set()
    assert ctx.ip_successful_logins == []
