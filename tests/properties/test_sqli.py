# Feature: traffic-fraud-classifier, Property 12: SQL injection case-insensitive
# Feature: traffic-fraud-classifier, Property 13: SQL injection confidence scoring
import json
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.conftest import valid_log_entry_dicts
from ingestion.parser import parse_entry
from classifiers.sqli_detector import SQLInjectionDetector
from models import ProfileContext

detector = SQLInjectionDetector()

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users;",
    "' UNION SELECT * FROM users--",
    "admin'--",
    "' AND 1=1",
]

OTHER_PATHS = ["/home", "/api/data", "/users"]


@given(
    st.sampled_from(["/login", "/register"]),
    st.sampled_from(SQLI_PAYLOADS),
    st.sampled_from(["lower", "upper", "mixed"]),
)
@settings(max_examples=100)
def test_property_12_sqli_detected_case_insensitive(path, payload, case):
    if case == "upper":
        payload = payload.upper()
    elif case == "lower":
        payload = payload.lower()
    body = json.dumps({"username": payload, "password": "x"})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": path, "status": 200,
        "ip": "1.2.3.4", "body": body,
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = parse_entry(json.dumps(d))
    assert entry is not None
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert any(r.is_fraudulent and r.reason == "sql_injection" for r in results)


@given(st.sampled_from(OTHER_PATHS), st.sampled_from(SQLI_PAYLOADS))
@settings(max_examples=50)
def test_property_12_sqli_skipped_for_other_paths(path, payload):
    body = json.dumps({"q": payload})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": path, "status": 200,
        "ip": "1.2.3.4", "body": body,
        "response_time_ms": 10, "user_agent": "Mozilla/5.0",
    }
    entry = parse_entry(json.dumps(d))
    assert entry is not None
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    assert not any(r.reason == "sql_injection" for r in results)


def test_property_13_two_indicators_confidence_gte_09():
    """2+ indicators → confidence >= 0.9."""
    body = json.dumps({"username": "' OR 1=1 UNION SELECT * FROM users--"})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 401,
        "ip": "1.2.3.4", "body": body, "response_time_ms": 10, "user_agent": "x",
    }
    entry = parse_entry(json.dumps(d))
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    sqli = [r for r in results if r.reason == "sql_injection"]
    assert sqli and sqli[0].confidence >= 0.9


def test_property_13_one_indicator_confidence_07_to_089():
    """1 indicator → confidence in [0.7, 0.89]."""
    body = json.dumps({"username": "admin'--"})
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "POST", "path": "/login", "status": 401,
        "ip": "1.2.3.4", "body": body, "response_time_ms": 10, "user_agent": "x",
    }
    entry = parse_entry(json.dumps(d))
    ctx = ProfileContext(ip="1.2.3.4")
    results = detector.evaluate(entry, ctx)
    sqli = [r for r in results if r.reason == "sql_injection"]
    assert sqli and 0.7 <= sqli[0].confidence <= 0.89
