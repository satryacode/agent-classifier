from __future__ import annotations
import logging
import time
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

    def __init__(self, file_path: str, poll_interval: float = 1.0):
        self._path = Path(file_path)
        self._poll_interval = poll_interval
        self._position = 0

    def poll(self) -> list[LogEntry]:
        """Read any new lines since last poll. Returns entries in chronological order."""
        if not self._path.exists():
            logger.warning("Log file not found: %s", self._path)
            return []

        entries: list[LogEntry] = []
        try:
            with self._path.open("r", encoding="utf-8") as f:
                f.seek(self._position)
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    entry = parse_entry(line)
                    if entry is not None:
                        entries.append(entry)
                self._position = f.tell()
        except OSError as exc:
            logger.error("Error reading log file %s: %s", self._path, exc)

        return sort_entries_chronologically(entries)

    def reset(self) -> None:
        """Reset file position to beginning (useful for testing)."""
        self._position = 0

    def tail(self) -> Iterator[list[LogEntry]]:
        """Continuously yield batches of new entries as they appear."""
        while True:
            batch = self.poll()
            yield batch
            time.sleep(self._poll_interval)
