"""End-to-end pipeline integration tests using temp log files."""
import io
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta

from config.settings import ClassifierConfig
from ingestion.file_ingestor import FileIngestor
from profiler.profiler import TrafficProfiler
from classifiers.engine import ClassificationEngine
from classifiers.sqli_detector import SQLInjectionDetector
from classifiers.brute_force_detector import BruteForceDetector
from classifiers.auth_abuse_detector import AuthAbuseDetector
from classifiers.recon_detector import ReconnaissanceDetector
from output.writer import OutputWriter


def _make_log_line(path="/login", method="POST", status=200, ip="1.2.3.4",
                   body=None, ua="Mozilla/5.0", offset_secs=0):
    ts = (datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_secs))
    d = {
        "timestamp": ts.isoformat(),
        "method": method, "path": path, "status": status,
        "ip": ip, "body": body or json.dumps({"username": "user", "password": "pass"}),
        "response_time_ms": 10, "user_agent": ua,
    }
    return json.dumps(d) + "\n"


def _run_pipeline(lines: list[str], config: ClassifierConfig = None):
    config = config or ClassifierConfig()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.writelines(lines)
        fname = f.name

    try:
        ingestor = FileIngestor(fname)
        profiler = TrafficProfiler()
        engine = ClassificationEngine(
            [SQLInjectionDetector(), BruteForceDetector(),
             AuthAbuseDetector(), ReconnaissanceDetector()],
            config,
        )
        buf = io.StringIO()
        writer = OutputWriter(ClassifierConfig(output_destination="stdout"))
        writer._file_handle = buf

        for entry in ingestor.poll():
            ctx = profiler.update(entry)
            verdict = engine.classify(entry, ctx)
            writer._write_to(verdict, buf)

        buf.seek(0)
        return [json.loads(line) for line in buf if line.strip()]
    finally:
        os.unlink(fname)


def test_sqli_detected_end_to_end():
    body = json.dumps({"username": "' OR 1=1--", "password": "x"})
    verdicts = _run_pipeline([_make_log_line(body=body)])
    assert any(v["classification"] == "FRAUDULENT" and "sql_injection" in v["reason"]
               for v in verdicts)


def test_clean_request_is_legitimate():
    verdicts = _run_pipeline([_make_log_line()])
    assert all(v["classification"] == "LEGITIMATE" for v in verdicts)


def test_brute_force_detected_after_threshold():
    lines = [
        _make_log_line(status=401, ip="5.5.5.5", offset_secs=i)
        for i in range(12)
    ]
    verdicts = _run_pipeline(lines)
    fraudulent = [v for v in verdicts if v["classification"] == "FRAUDULENT"]
    assert len(fraudulent) > 0
    assert any("brute_force" in v["reason"] for v in fraudulent)


def test_scanner_ua_detected():
    verdicts = _run_pipeline([_make_log_line(ua="sqlmap/1.5.8")])
    assert any(v["classification"] == "FRAUDULENT" and "scanner_detected" in v["reason"]
               for v in verdicts)


def test_verdict_has_required_fields():
    verdicts = _run_pipeline([_make_log_line()])
    for v in verdicts:
        for f in ["timestamp", "source_ip", "method", "path", "classification",
                  "confidence_score", "reason", "original_log_entry_reference"]:
            assert f in v
