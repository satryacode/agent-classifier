"""Shared fixtures and Hypothesis strategies for the Traffic Fraud Classifier tests."""
from datetime import timezone
from hypothesis import strategies as st

REQUIRED_FIELDS = ["timestamp", "method", "path", "status", "ip", "body", "response_time_ms", "user_agent"]

valid_log_entry_dicts = st.fixed_dictionaries({
    "timestamp": st.datetimes(timezones=st.just(timezone.utc)).map(lambda d: d.isoformat()),
    "method": st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    "path": st.sampled_from(["/login", "/register", "/home", "/other"]),
    "status": st.integers(min_value=100, max_value=599),
    "ip": st.ip_addresses(v=4).map(str),
    "body": st.text(max_size=200),
    "response_time_ms": st.integers(min_value=0, max_value=60000),
    "user_agent": st.text(min_size=1, max_size=100),
})
