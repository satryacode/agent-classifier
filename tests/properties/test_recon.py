# Feature: traffic-fraud-classifier, Property 20: Reconnaissance by path diversity
# Feature: traffic-fraud-classifier, Property 21: Path enumeration
# Feature: traffic-fraud-classifier, Property 22: Scanner user-agent
import json
from hypothesis import given, settings
from hypothesis import strategies as st
from ingestion.parser import parse_entry
from classifiers.recon_detector import ReconnaissanceDetector, KNOWN_PATHS, SCANNER_IDS
from models import ProfileContext

detector = ReconnaissanceDetector()

UNKNOWN_PATHS = ["/admin", "/wp-admin", "/etc/passwd", "/.env", "/api/v1/secret"]
KNOWN_PATH_LIST = list(KNOWN_PATHS)


def _entry(path="/login", ua="Mozilla/5.0", ip="1.2.3.4", distinct_paths=None):
    d = {
        "timestamp": "2026-06-09T10:00:00+00:00",
        "method": "GET", "path": path, "status": 200,
        "ip": ip, "body": "", "response_time_ms": 10, "user_agent": ua,
    }
    e = parse_entry(json.dumps(d))
    ctx = ProfileContext(ip=ip)
    if distinct_paths is not None:
        ctx.ip_distinct_paths = set(distinct_paths)
    return e, ctx


@given(st.integers(min_value=1, max_value=15))
@settings(max_examples=50)
def test_property_20_recon_by_path_diversity(n):
    """IP targeting > 5 distinct paths → reconnaissance."""
    paths = [f"/path{i}" for i in range(n)]
    e, ctx = _entry(distinct_paths=paths)
    results = detector.evaluate(e, ctx)
    has_recon = any(r.reason == "reconnaissance" for r in results)
    assert has_recon == (n > 5)


@given(st.sampled_from(UNKNOWN_PATHS))
@settings(max_examples=50)
def test_property_21_path_enumeration(path):
    """Unknown path → path_enumeration."""
    e, ctx = _entry(path=path)
    results = detector.evaluate(e, ctx)
    assert any(r.reason == "path_enumeration" for r in results)


@given(st.sampled_from(KNOWN_PATH_LIST))
@settings(max_examples=20)
def test_property_21_known_path_not_flagged(path):
    """Known path → no path_enumeration."""
    e, ctx = _entry(path=path)
    results = detector.evaluate(e, ctx)
    assert not any(r.reason == "path_enumeration" for r in results)


@given(
    st.sampled_from(SCANNER_IDS),
    st.sampled_from(["lower", "upper", "mixed"]),
)
@settings(max_examples=50)
def test_property_22_scanner_ua(scanner_id, case):
    """Scanner UA → scanner_detected."""
    ua = scanner_id.upper() if case == "upper" else (
        scanner_id.lower() if case == "lower" else scanner_id
    )
    ua = "prefix-" + ua + "/1.0"
    e, ctx = _entry(ua=ua)
    results = detector.evaluate(e, ctx)
    assert any(r.reason == "scanner_detected" for r in results)
