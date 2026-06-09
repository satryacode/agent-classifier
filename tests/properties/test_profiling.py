# Feature: traffic-fraud-classifier, Property 4: IP profile metrics accuracy
# Feature: traffic-fraud-classifier, Property 5: Time window reset zeroes counters
# Feature: traffic-fraud-classifier, Property 6: Malformed IP entries discarded
import json
from collections import Counter
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts
from ingestion.parser import parse_entry
from profiler.ip_profile import IPProfileManager


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
