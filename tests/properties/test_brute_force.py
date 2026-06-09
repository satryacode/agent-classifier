# Feature: traffic-fraud-classifier, Property 14: Brute-force detection and propagation
# Feature: traffic-fraud-classifier, Property 15: Credential stuffing detection
# Feature: traffic-fraud-classifier, Property 16: Brute-force confidence calculation
import json
from datetime import datetime, timezone, timedelta
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.brute_force_detector import BruteForceDetector
from models import ProfileContext


def _make_ctx(ip_failed=0, ip_total=0, user_failed=0, user_total=0, username=None):
    ctx = ProfileContext(ip="1.2.3.4")
    ctx.ip_failed_logins = ip_failed
    ctx.ip_total_logins = ip_total
    ctx.username = username
    ctx.user_failed_logins = user_failed
    ctx.user_total_logins = user_total
    return ctx


def _make_entry(path="/login", status=401):
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": path, "status": status,
        "ip": "1.2.3.4", "body": json.dumps({"username": "alice", "password": "x"}),
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    return parse_entry(json.dumps(d))


detector = BruteForceDetector()


@given(st.integers(min_value=1, max_value=30))
@settings(max_examples=50)
def test_property_14_brute_force_detection(n):
    """IP with > 10 failed logins → brute_force verdict."""
    entry = _make_entry()
    ctx = _make_ctx(ip_failed=n, ip_total=n)
    results = detector.evaluate(entry, ctx)
    has_bf = any(r.reason == "brute_force" for r in results)
    assert has_bf == (n > 10)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=50)
def test_property_15_credential_stuffing(n):
    """User with > 5 failed logins → credential_stuffing verdict."""
    entry = _make_entry()
    ctx = _make_ctx(user_failed=n, user_total=n, username="alice")
    results = detector.evaluate(entry, ctx)
    has_cs = any(r.reason == "credential_stuffing" for r in results)
    assert has_cs == (n > 5)


@given(
    st.integers(min_value=1, max_value=30),
    st.integers(min_value=1, max_value=50),
)
@settings(max_examples=100)
def test_property_16_confidence_calculation(failed, total):
    if failed > total:
        total = failed
    entry = _make_entry()
    ctx = _make_ctx(ip_failed=failed, ip_total=total)
    results = detector.evaluate(entry, ctx)
    bf = [r for r in results if r.reason == "brute_force"]
    if bf:
        expected = max(failed / total, 0.5)
        assert abs(bf[0].confidence - expected) < 0.01
