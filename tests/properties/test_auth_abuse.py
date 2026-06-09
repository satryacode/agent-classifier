# Feature: traffic-fraud-classifier, Property 17: Unusual user-agent
# Feature: traffic-fraud-classifier, Property 18: Token manipulation
# Feature: traffic-fraud-classifier, Property 19: Forged token
import json
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.auth_abuse_detector import AuthAbuseDetector, RECOGNIZED_UA_PREFIXES
from models import ProfileContext
from datetime import datetime, timezone, timedelta

detector = AuthAbuseDetector()

RECOGNIZED_UAS = [p + "something" for p in RECOGNIZED_UA_PREFIXES]


def _home_entry(ua, status=200, ip="1.2.3.4"):
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": "/home", "status": status,
        "ip": ip, "body": "", "response_time_ms": 10, "user_agent": ua,
    }
    return parse_entry(json.dumps(d))


@given(st.text(min_size=1, max_size=100).filter(
    lambda ua: not any(ua.startswith(p) for p in RECOGNIZED_UA_PREFIXES)
))
@settings(max_examples=100)
def test_property_17_unusual_ua_detected(ua):
    entry = _home_entry(ua)
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert any(r.reason == "unusual_user_agent" and r.confidence == 0.6 for r in results)


@given(st.sampled_from(RECOGNIZED_UAS))
@settings(max_examples=50)
def test_property_17_recognized_ua_not_flagged(ua):
    entry = _home_entry(ua)
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert not any(r.reason == "unusual_user_agent" for r in results)


@given(st.integers(min_value=2, max_value=5))
@settings(max_examples=50)
def test_property_18_token_manipulation(n_users):
    """2+ distinct users from same IP → token_manipulation."""
    ctx = ProfileContext(ip="1.2.3.4")
    ctx.ip_distinct_users = {f"user{i}" for i in range(n_users)}
    entry = _home_entry("Mozilla/5.0")
    results = detector.evaluate(entry, ctx)
    assert any(r.reason == "token_manipulation" and r.confidence == 0.9 for r in results)


def test_property_19_forged_token_no_prior_login():
    """Successful /home with no prior successful login → forged_token."""
    ctx = ProfileContext(ip="1.2.3.4")
    ctx.ip_successful_logins = []  # no logins
    entry = _home_entry("Mozilla/5.0", status=200)
    results = detector.evaluate(entry, ctx)
    assert any(r.reason == "forged_token" and r.confidence == 0.85 for r in results)


def test_property_19_recent_login_no_forged_token():
    """Successful /home with recent successful login → no forged_token."""
    ctx = ProfileContext(ip="1.2.3.4")
    now = datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc)
    ctx.ip_successful_logins = [now - timedelta(minutes=5)]
    entry = _home_entry("Mozilla/5.0", status=200)
    from dataclasses import replace
    entry = replace(entry, timestamp=now)
    results = detector.evaluate(entry, ctx)
    assert not any(r.reason == "forged_token" for r in results)
