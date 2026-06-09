# Feature: traffic-fraud-classifier, Property 4: IP profile metrics accuracy
# Feature: traffic-fraud-classifier, Property 5: Time window reset zeroes counters
# Feature: traffic-fraud-classifier, Property 6: Malformed IP entries discarded
# Feature: traffic-fraud-classifier, Property 10: Endpoint profile metrics
# Feature: traffic-fraud-classifier, Property 11: Rate-abuse detection
import json
from collections import Counter, defaultdict
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts
from ingestion.parser import parse_entry
from profiler.ip_profile import IPProfileManager
from profiler.endpoint_profile import EndpointProfileManager


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=30))
@settings(max_examples=100)
def test_property_4_ip_metrics_accuracy(dicts):
    """request_count equals entries from that IP; endpoints is the distinct set."""
    manager = IPProfileManager()
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d)))]
    for e in entries:
        manager.update(e)
    ip_counts = Counter(e.ip for e in entries)
    for ip, count in ip_counts.items():
        profile = manager.get(ip)
        assert profile.request_count == count
        expected_endpoints = {
            f"{e.method} {e.path.split('?')[0].rstrip('/') or '/'}"
            for e in entries if e.ip == ip
        }
        assert profile.endpoints == expected_endpoints


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=20))
@settings(max_examples=50)
def test_property_5_reset_zeroes_counters(dicts):
    """After reset_window(), all request counts and endpoints are zero/empty."""
    manager = IPProfileManager()
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d)))]
    for e in entries:
        manager.update(e)
    manager.reset_window()
    for ip in manager.all_ips():
        profile = manager.get(ip)
        assert profile.request_count == 0
        assert len(profile.endpoints) == 0


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=20))
@settings(max_examples=50)
def test_property_6_malformed_ip_discarded(dicts):
    """Entries with empty IP are not added to any profile; dropped_count increments."""
    manager = IPProfileManager()
    bad_dicts = [dict(d, ip="") for d in dicts]
    entries = [e for d in bad_dicts if (e := parse_entry(json.dumps(d)))]
    before_count = manager.dropped_count
    for e in entries:
        manager.update(e)
    assert manager.dropped_count == before_count + len(entries)
    assert len(list(manager.all_ips())) == 0


@given(st.lists(valid_log_entry_dicts, min_size=1, max_size=30))
@settings(max_examples=100)
def test_property_10_endpoint_metrics(dicts):
    """request_count, error_count, error_rate, unique_ips are accurate."""
    manager = EndpointProfileManager()
    entries = [e for d in dicts if (e := parse_entry(json.dumps(d)))]
    for e in entries:
        manager.update(e)
    ep_counts = defaultdict(lambda: {"total": 0, "errors": 0, "ips": set()})
    for e in entries:
        key = f"{e.method} {e.path.split('?')[0].rstrip('/') or '/'}"
        ep_counts[key]["total"] += 1
        if e.status >= 400:
            ep_counts[key]["errors"] += 1
        ep_counts[key]["ips"].add(e.ip)
    for key, expected in ep_counts.items():
        profile = manager.get(key)
        assert profile is not None
        assert profile.request_count == expected["total"]
        assert profile.error_count == expected["errors"]
        assert abs(profile.error_rate - (expected["errors"] / expected["total"] * 100)) < 0.01
        assert profile.unique_ips == expected["ips"]


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=50)
def test_property_11_rate_abuse_threshold(n):
    """rate_abuse flag set iff IP sends > 50 requests to same endpoint."""
    import json as _json
    from datetime import datetime, timezone, timedelta
    manager = EndpointProfileManager()
    for i in range(n):
        d = {
            "timestamp": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat(),
            "method": "POST", "path": "/login", "status": 200,
            "ip": "1.2.3.4", "body": "{}", "response_time_ms": 10,
            "user_agent": "Mozilla/5.0",
        }
        e = parse_entry(_json.dumps(d))
        if e:
            manager.update(e)
    profile = manager.get("POST /login")
    assert profile is not None
    assert ("1.2.3.4" in profile.rate_abuse_ips) == (n > 50)
