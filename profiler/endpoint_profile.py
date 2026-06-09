from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Optional

from models import LogEntry

logger = logging.getLogger(__name__)

RATE_ABUSE_THRESHOLD = 50


def _normalize(method: str, path: str) -> str:
    return f"{method} {path.split('?')[0].rstrip('/') or '/'}"


@dataclass
class EndpointProfile:
    endpoint: str
    request_count: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    unique_ips: set = field(default_factory=set)
    rate_abuse_ips: set = field(default_factory=set)
    _ip_counts: dict = field(default_factory=dict, repr=False)


class EndpointProfileManager:
    def __init__(self, rate_abuse_threshold: int = RATE_ABUSE_THRESHOLD):
        self._profiles: dict[str, EndpointProfile] = {}
        self._threshold = rate_abuse_threshold

    def update(self, entry: LogEntry) -> None:
        key = _normalize(entry.method, entry.path)
        if key not in self._profiles:
            self._profiles[key] = EndpointProfile(endpoint=key)

        p = self._profiles[key]
        p.request_count += 1
        if entry.status >= 400:
            p.error_count += 1
        p.error_rate = p.error_count / p.request_count * 100
        p.unique_ips.add(entry.ip)

        p._ip_counts[entry.ip] = p._ip_counts.get(entry.ip, 0) + 1
        if p._ip_counts[entry.ip] > self._threshold:
            p.rate_abuse_ips.add(entry.ip)

    def get(self, key: str) -> Optional[EndpointProfile]:
        return self._profiles.get(key)

    def reset_window(self) -> None:
        for p in self._profiles.values():
            p.request_count = 0
            p.error_count = 0
            p.error_rate = 0.0
            p.unique_ips = set()
            p.rate_abuse_ips = set()
            p._ip_counts = {}
