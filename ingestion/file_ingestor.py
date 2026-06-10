from __future__ import annotations
import logging
import time
from collections import OrderedDict
from pathlib import Path
from typing import Iterator

from models import LogEntry
from ingestion.parser import parse_entry

logger = logging.getLogger(__name__)


def sort_entries_chronologically(entries: list[LogEntry]) -> list[LogEntry]:
    """Stable sort entries by timestamp (ascending)."""
    return sorted(entries, key=lambda e: e.timestamp)


class FileIngestor:
    """Tails a JSON Lines log file, yielding parsed LogEntry objects as lines appear."""

    def __init__(
        self,
        file_path: str,
        poll_interval: float = 1.0,
        dedup_window: int = 5000,
        tail_from_end: bool = False,
    ):
        self._path = Path(file_path)
        self._poll_interval = poll_interval
        self._position = 0
        # When tailing a live log, skip the existing backlog on startup so a
        # restart does not reprocess (and re-insert) the whole file. Primed
        # lazily on first poll so it works even if the file is created later.
        self._tail_from_end = tail_from_end
        self._primed = not tail_from_end
        # Idempotency guard: exact duplicate log lines (e.g. from a leaked
        # `docker logs -f` bridge appending the container's output more than
        # once, or upstream double-logging) must never produce duplicate
        # verdicts. A genuine repeated request carries a distinct millisecond
        # timestamp, so an exact line match is a safe duplicate signal.
        self._dedup_window = dedup_window
        self._seen: OrderedDict[int, None] = OrderedDict()

    def _is_duplicate(self, raw: str) -> bool:
        key = hash(raw)
        if key in self._seen:
            return True
        self._seen[key] = None
        if len(self._seen) > self._dedup_window:
            self._seen.popitem(last=False)
        return False

    def poll(self) -> list[LogEntry]:
        """Read any new lines since last poll. Returns entries in chronological order."""
        if not self._path.exists():
            logger.warning("Log file not found: %s", self._path)
            return []

        # On first poll of a live tail, jump to the current end of file and
        # process only lines appended from now on.
        if not self._primed:
            try:
                with self._path.open("r", encoding="utf-8") as f:
                    f.seek(0, 2)  # SEEK_END
                    self._position = f.tell()
                logger.info("FileIngestor: tailing %s from offset %d (skipping backlog)",
                            self._path, self._position)
            except OSError as exc:
                logger.error("FileIngestor: could not seek to end of %s: %s", self._path, exc)
            self._primed = True
            return []

        entries: list[LogEntry] = []
        duplicates = 0
        try:
            with self._path.open("r", encoding="utf-8") as f:
                f.seek(self._position)
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    if self._is_duplicate(line):
                        duplicates += 1
                        continue
                    entry = parse_entry(line)
                    if entry is not None:
                        entries.append(entry)
                self._position = f.tell()
        except OSError as exc:
            logger.error("Error reading log file %s: %s", self._path, exc)

        if duplicates:
            logger.info("FileIngestor: skipped %d duplicate log line(s)", duplicates)

        return sort_entries_chronologically(entries)

    def reset(self) -> None:
        """Reset file position to beginning (useful for testing)."""
        self._position = 0
        self._seen.clear()
        self._primed = not self._tail_from_end

    def tail(self) -> Iterator[list[LogEntry]]:
        """Continuously yield batches of new entries as they appear."""
        while True:
            batch = self.poll()
            yield batch
            time.sleep(self._poll_interval)
