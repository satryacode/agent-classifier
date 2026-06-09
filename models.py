from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class LogEntry:
    timestamp: datetime
    method: str
    path: str
    status: int
    ip: str
    body: str
    response_time_ms: int
    user_agent: str
    raw: str


@dataclass
class DetectionResult:
    is_fraudulent: bool
    reason: str
    confidence: float


@dataclass
class ProfileContext:
    ip: str
    ip_request_count: int = 0
    ip_distinct_paths: set = field(default_factory=set)
    ip_suspicious: bool = False
    ip_suspicious_reason: Optional[str] = None
    ip_failed_logins: int = 0
    ip_total_logins: int = 0
    ip_distinct_users: set = field(default_factory=set)
    ip_successful_logins: list = field(default_factory=list)
    username: Optional[str] = None
    user_failed_logins: int = 0
    user_total_logins: int = 0
    user_distinct_ips: set = field(default_factory=set)
    user_suspicious: bool = False
    user_suspicious_reason: Optional[str] = None
    endpoint_request_count: int = 0
    endpoint_error_count: int = 0
    endpoint_rate_abuse: bool = False


@dataclass
class Verdict:
    timestamp: str
    source_ip: str
    user_identity: Optional[str]
    method: str
    path: str
    classification: str  # "LEGITIMATE" or "FRAUDULENT"
    confidence_score: float
    reason: str
    original_log_entry_reference: str


@dataclass
class FraudFlag:
    ip: str
    user_identity: Optional[str]
    timestamp: str
    reason: str
    confidence_score: float
