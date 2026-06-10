from __future__ import annotations
import logging
import signal
import time
from datetime import datetime, timezone

from config.settings import ClassifierConfig
from ingestion.file_ingestor import FileIngestor
from profiler.profiler import TrafficProfiler
from classifiers.engine import ClassificationEngine
from classifiers.sqli_detector import SQLInjectionDetector
from classifiers.brute_force_detector import BruteForceDetector
from classifiers.auth_abuse_detector import AuthAbuseDetector
from classifiers.recon_detector import ReconnaissanceDetector
from output.writer import OutputWriter
from output.db_writer import DBWriter
from ingestion.ip_reputation import IpReputation

logger = logging.getLogger(__name__)


def run(config: ClassifierConfig) -> None:
    profiler = TrafficProfiler(rate_abuse_threshold=config.rate_abuse_threshold)
    engine = ClassificationEngine(
        [
            SQLInjectionDetector(),
            BruteForceDetector(),
            AuthAbuseDetector(),
            ReconnaissanceDetector(),
        ],
        config,
    )
    writer = OutputWriter(config)
    db_writer = DBWriter()
    reputation = IpReputation()
    ingestor = FileIngestor(
        config.log_file_path,
        poll_interval=config.poll_interval_seconds,
        tail_from_end=True,
    )

    window_start = datetime.now(tz=timezone.utc)
    running = True

    def _handle_shutdown(sig, frame):
        nonlocal running
        logger.info("Shutting down...")
        running = False

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    logger.info("Pipeline started. Tailing %s", config.log_file_path)

    while running:
        now = datetime.now(tz=timezone.utc)
        if (now - window_start).total_seconds() >= config.time_window_seconds:
            profiler.reset_window()
            window_start = now

        entries = ingestor.poll()
        for entry in entries:
            context = profiler.update(entry)
            rep = reputation.lookup(entry.ip)
            verdict = engine.classify(entry, context, reputation=rep)
            writer.write_verdict(verdict)
            if verdict.classification == "FRAUDULENT":
                db_writer.insert_verdict(verdict)
            for flag in writer.maybe_create_flag(verdict):
                logger.info("FraudFlag: ip=%s reason=%s confidence=%.2f",
                            flag.ip, flag.reason, flag.confidence_score)

        time.sleep(config.poll_interval_seconds)

    writer.close()
    db_writer.close()
    reputation.close()
    logger.info("Pipeline stopped.")
