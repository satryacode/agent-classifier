# Feature: traffic-fraud-classifier, Property 1: Log entry parsing round-trip
# Feature: traffic-fraud-classifier, Property 2: Invalid entries are rejected without halting
import json
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts, REQUIRED_FIELDS
from ingestion.parser import parse_entry


@given(valid_log_entry_dicts)
@settings(max_examples=100)
def test_property_1_parse_roundtrip(d):
    """Valid entries parse to LogEntry with matching field values."""
    raw = json.dumps(d)
    entry = parse_entry(raw)
    assert entry is not None
    assert entry.method == d["method"]
    assert entry.path == d["path"]
    assert entry.status == d["status"]
    assert entry.ip == d["ip"]
    assert entry.body == d["body"]
    assert entry.response_time_ms == d["response_time_ms"]
    assert entry.user_agent == d["user_agent"]
    assert entry.raw == raw


@given(st.text())
@settings(max_examples=100)
def test_property_2a_malformed_json_returns_none(raw):
    """Malformed JSON returns None without raising."""
    try:
        json.loads(raw)
        return  # valid JSON — skip this sample
    except json.JSONDecodeError:
        pass
    result = parse_entry(raw)
    assert result is None


@given(valid_log_entry_dicts, st.sampled_from(REQUIRED_FIELDS))
@settings(max_examples=100)
def test_property_2b_missing_field_returns_none(d, missing_field):
    """Entry missing a required field returns None."""
    d.pop(missing_field)
    result = parse_entry(json.dumps(d))
    assert result is None
