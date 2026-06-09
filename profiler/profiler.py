from __future__ import annotations
from models import LogEntry, ProfileContext
from profiler.ip_profile import IPProfileManager
from profiler.user_profile import UserProfileManager, _extract_username
from profiler.endpoint_profile import EndpointProfileManager, _normalize


class TrafficProfiler:
    def __init__(self, rate_abuse_threshold: int = 50):
        self.ip = IPProfileManager()
        self.user = UserProfileManager()
        self.endpoint = EndpointProfileManager(rate_abuse_threshold)
        self._ip_successful_logins: dict[str, list] = {}

    def update(self, entry: LogEntry) -> ProfileContext:
        self.ip.update(entry)
        self.user.update(entry)
        self.endpoint.update(entry)

        if entry.path == "/login" and entry.status == 200:
            self._ip_successful_logins.setdefault(entry.ip, []).append(entry.timestamp)

        return self._build_context(entry)

    def _build_context(self, entry: LogEntry) -> ProfileContext:
        ip_p = self.ip.get(entry.ip)
        username = _extract_username(entry)
        user_p = self.user.get(username) if username else None
        ep_key = _normalize(entry.method, entry.path)
        ep_p = self.endpoint.get(ep_key)

        ctx = ProfileContext(ip=entry.ip)
        if ip_p:
            ctx.ip_request_count = ip_p.request_count
            ctx.ip_distinct_paths = {e.split(" ", 1)[1] for e in ip_p.endpoints}
            ctx.ip_suspicious = ip_p.suspicious
            ctx.ip_suspicious_reason = ip_p.suspicious_reason
            ctx.ip_distinct_users = self._get_ip_users(entry.ip)
            ctx.ip_successful_logins = self._get_ip_successful_logins(entry.ip)
        if user_p:
            ctx.username = username
            ctx.user_failed_logins = user_p.failed_login_count
            ctx.user_total_logins = user_p.total_login_count
            ctx.user_distinct_ips = user_p.distinct_ips
            ctx.user_suspicious = user_p.suspicious
            ctx.user_suspicious_reason = user_p.suspicious_reason
        if ep_p:
            ctx.endpoint_request_count = ep_p.request_count
            ctx.endpoint_error_count = ep_p.error_count
            ctx.endpoint_rate_abuse = entry.ip in ep_p.rate_abuse_ips
        return ctx

    def _get_ip_users(self, ip: str) -> set:
        users = set()
        for username, profile in self.user._profiles.items():
            if ip in profile.distinct_ips:
                users.add(username)
        return users

    def _get_ip_successful_logins(self, ip: str) -> list:
        return self._ip_successful_logins.get(ip, [])

    def reset_window(self) -> None:
        self.ip.reset_window()
        self.user.reset_window()
        self.endpoint.reset_window()
        self._ip_successful_logins.clear()

    def get_ip_profiles(self):
        return self.ip

    def get_user_profiles(self):
        return self.user

    def get_endpoint_profiles(self):
        return self.endpoint
