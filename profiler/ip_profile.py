from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

from models import LogEntry

logger = logging.getLogger(__name__)

_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
    r'|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
)


def _is_valid_ip(ip: str) -> bool:
    return bool(ip and _IP_RE.match(ip))


def _normalize_path(path: str) -> str:
    return path.split("?")[0].rstrip("/") or "/"


@dataclass
class IPProfile:
    ip: str
    request_count: int = 0
    endpoints: set = field(default_factory=set)
    first_request_time: Optional[datetime] = None
    request_rate: float = 0.0
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class IPProfileManager:
    def __init__(self):
        self._profiles: dict[str, IPProfile] = {}
        self.dropped_count: int = 0

    def update(self, entry: LogEntry) -> None:
        if not _is_valid_ip(entry.ip):
            logger.warning("Dropping entry with invalid IP: %r", entry.ip)
            self.dropped_count += 1
            return

        if entry.ip not in self._profiles:
            self._profiles[entry.ip] = IPProfile(ip=entry.ip)

        p = self._profiles[entry.ip]
        p.request_count += 1

        endpoint = f"{entry.method} {_normalize_path(entry.path)}"
        p.endpoints.add(endpoint)

        now = entry.timestamp
        if p.first_request_time is None:
            p.first_request_time = now

        elapsed = (now - p.first_request_time).total_seconds()
        if elapsed > 0:
            p.request_rate = round(p.request_count / elapsed, 2)
        else:
            p.request_rate = float(p.request_count)

    def get(self, ip: str) -> Optional[IPProfile]:
        return self._profiles.get(ip)

    def all_ips(self) -> Iterator[str]:
        return iter(self._profiles.keys())

    def reset_window(self) -> None:
        for p in self._profiles.values():
            p.request_count = 0
            p.endpoints = set()
            p.first_request_time = None
            p.request_rate = 0.0
            p.suspicious = False
            p.suspicious_reason = None
