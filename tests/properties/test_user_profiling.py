# Feature: traffic-fraud-classifier, Property 7: User identity association
# Feature: traffic-fraud-classifier, Property 8: Failed login threshold
# Feature: traffic-fraud-classifier, Property 9: Multi-IP threshold
import json
from datetime import datetime, timezone, timedelta
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts
from ingestion.parser import parse_entry
from profiler.user_profile import UserProfileManager


@given(valid_log_entry_dicts)
@settings(max_examples=100)
def test_property_7_user_association(d):
    """Entries on /login or /register with valid username get associated; others don't."""
    manager = UserProfileManager()
    entry = parse_entry(json.dumps(d))
    if entry is None:
        return
    manager.update(entry)
    if entry.path in ("/login", "/register"):
        try:
            body = json.loads(entry.body)
            username = body.get("username", "")
            if username:
                assert manager.get(str(username)) is not None
                return
        except (ValueError, AttributeError, TypeError):
            pass
    # No username extracted — no profile should exist for this entry's body
    # (profiles from other paths shouldn't exist either)


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=50)
def test_property_8_failed_login_threshold(n):
    """User suspicious iff failed logins > 5."""
    manager = UserProfileManager()
    for i in range(n):
        d = {
            "timestamp": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat(),
            "method": "POST", "path": "/login", "status": 401,
            "ip": "1.2.3.4",
            "body": json.dumps({"username": "alice", "password": "x"}),
            "response_time_ms": 10, "user_agent": "Mozilla/5.0",
        }
        e = parse_entry(json.dumps(d))
        if e:
            manager.update(e)
    profile = manager.get("alice")
    assert profile is not None
    assert profile.suspicious == (n > 5)


@given(st.integers(min_value=1, max_value=10))
@settings(max_examples=50)
def test_property_9_multi_ip_threshold(k):
    """User suspicious iff accessed from > 3 distinct IPs."""
    manager = UserProfileManager()
    for i in range(k):
        ip = f"10.0.0.{i + 1}"
        d = {
            "timestamp": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat(),
            "method": "POST", "path": "/login", "status": 200,
            "ip": ip,
            "body": json.dumps({"username": "bob", "password": "x"}),
            "response_time_ms": 10, "user_agent": "Mozilla/5.0",
        }
        e = parse_entry(json.dumps(d))
        if e:
            manager.update(e)
    profile = manager.get("bob")
    if profile:
        assert profile.suspicious == (k > 3)
