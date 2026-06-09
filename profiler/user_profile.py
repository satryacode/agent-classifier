from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from models import LogEntry

logger = logging.getLogger(__name__)

FAILED_LOGIN_THRESHOLD = 5
MULTI_IP_THRESHOLD = 3


def _extract_username(entry: LogEntry) -> Optional[str]:
    if entry.path not in ("/login", "/register"):
        return None
    try:
        body = json.loads(entry.body)
        username = body.get("username", "")
        return str(username) if username else None
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None


@dataclass
class UserProfile:
    username: str
    failed_login_count: int = 0
    total_login_count: int = 0
    distinct_ips: set = field(default_factory=set)
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class UserProfileManager:
    def __init__(self):
        self._profiles: dict[str, UserProfile] = {}

    def update(self, entry: LogEntry) -> None:
        username = _extract_username(entry)
        if username is None:
            return

        if username not in self._profiles:
            self._profiles[username] = UserProfile(username=username)

        p = self._profiles[username]
        p.distinct_ips.add(entry.ip)

        if entry.path == "/login":
            p.total_login_count += 1
            if entry.status == 401:
                p.failed_login_count += 1

        if not p.suspicious:
            if p.failed_login_count > FAILED_LOGIN_THRESHOLD:
                p.suspicious = True
                p.suspicious_reason = f"failed_logins={p.failed_login_count}"
            elif len(p.distinct_ips) > MULTI_IP_THRESHOLD:
                p.suspicious = True
                p.suspicious_reason = f"distinct_ips={len(p.distinct_ips)}"

    def get(self, username: str) -> Optional[UserProfile]:
        return self._profiles.get(username)

    def reset_window(self) -> None:
        for p in self._profiles.values():
            p.failed_login_count = 0
            p.total_login_count = 0
            p.distinct_ips = set()
            p.suspicious = False
            p.suspicious_reason = None
