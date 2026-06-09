"""Configuration module for Traffic Fraud Classifier.

Supports:
- Environment variables with CLASSIFIER_ prefix
- Optional YAML config file
- Env var precedence over config file values
- Range validation with fallback to defaults
- Graceful handling of malformed/unreadable config files
"""

from __future__ import annotations

import logging
import warnings
from pathlib import Path
from typing import Any, ClassVar

import yaml
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# Valid ranges for configurable parameters
_VALID_RANGES: dict[str, tuple[float, float]] = {
    "time_window_seconds": (1, 3600),
    "brute_force_ip_threshold": (1, 10000),
    "brute_force_user_threshold": (1, 10000),
    "rate_abuse_threshold": (1, 100000),
    "fraud_flag_confidence_threshold": (0.0, 1.0),
}

# Default values for parameters that have range validation
_DEFAULTS: dict[str, int | float] = {
    "time_window_seconds": 300,
    "brute_force_ip_threshold": 10,
    "brute_force_user_threshold": 5,
    "rate_abuse_threshold": 50,
    "fraud_flag_confidence_threshold": 0.7,
}


def _load_yaml_config(config_file: str | None) -> dict[str, Any]:
    """Load and return YAML config file contents.

    Returns empty dict on any error (file not found, unreadable, malformed YAML).
    Logs a warning on failure per Req 10.7.
    """
    if not config_file:
        return {}

    path = Path(config_file)
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, PermissionError) as exc:
        logger.warning(
            "Config file '%s' is unreadable (%s). Using defaults for all parameters.",
            config_file,
            exc,
        )
        return {}

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        logger.warning(
            "Config file '%s' is malformed (%s). Using defaults for all parameters.",
            config_file,
            exc,
        )
        return {}

    if not isinstance(data, dict):
        logger.warning(
            "Config file '%s' does not contain a YAML mapping. Using defaults for all parameters.",
            config_file,
        )
        return {}

    return data


class ClassifierConfig(BaseSettings):
    """Configuration for the Traffic Fraud Classifier.

    Precedence (highest to lowest):
    1. Environment variables (CLASSIFIER_ prefix)
    2. YAML config file values
    3. Default values

    Invalid range values are replaced with defaults and a warning is logged.
    """

    model_config = SettingsConfigDict(
        env_prefix="CLASSIFIER_",
        env_file=None,
        extra="ignore",
    )

    # CloudWatch
    aws_region: str = "us-east-1"
    log_group: str = "/dummy-be/app"
    poll_interval_seconds: int = 5

    # Time windows
    time_window_seconds: int = 300  # 5 minutes default

    # Thresholds
    brute_force_ip_threshold: int = 10
    brute_force_user_threshold: int = 5
    rate_abuse_threshold: int = 50
    fraud_flag_confidence_threshold: float = 0.7

    # Output
    output_destination: str = "stdout"  # "stdout", file path, or CW log group
    output_buffer_size: int = 1000
    output_retry_interval_seconds: int = 5

    # Config file path
    config_file: str | None = None

    # Class-level constant (not a settings field)
    _valid_ranges: ClassVar[dict[str, tuple[float, float]]] = _VALID_RANGES
    _defaults: ClassVar[dict[str, int | float]] = _DEFAULTS

    def __init__(self, **kwargs: Any) -> None:
        """Initialize config with YAML file support.

        Loads YAML config file values first, then lets env vars and explicit
        kwargs override them (pydantic-settings handles env var loading).
        """
        # Determine config_file path from kwargs or env
        import os

        config_file = kwargs.get("config_file") or os.environ.get(
            "CLASSIFIER_CONFIG_FILE"
        )

        # Load YAML config if available
        yaml_values = _load_yaml_config(config_file)

        # Merge: YAML values are the base, but env vars must win (Req 10.4).
        # Filter out YAML keys that have a corresponding env var set so that
        # pydantic-settings env-var loading takes precedence.
        if yaml_values:
            env_prefix = "CLASSIFIER_"
            filtered_yaml = {
                k: v for k, v in yaml_values.items()
                if (env_prefix + k.upper()) not in os.environ
            }
            merged = {**filtered_yaml, **kwargs}
            if config_file and "config_file" not in kwargs:
                merged["config_file"] = config_file
        else:
            merged = kwargs
            if config_file and "config_file" not in kwargs:
                merged["config_file"] = config_file

        super().__init__(**merged)

    @model_validator(mode="after")
    def _validate_ranges(self) -> "ClassifierConfig":
        """Validate that configurable parameters are within valid ranges.

        If a value is out of range, log a warning and reset to default.
        """
        for field_name, (min_val, max_val) in _VALID_RANGES.items():
            value = getattr(self, field_name)
            if value < min_val or value > max_val:
                default = _DEFAULTS[field_name]
                logger.warning(
                    "Config value '%s=%s' is outside valid range [%s, %s]. "
                    "Using default value %s.",
                    field_name,
                    value,
                    min_val,
                    max_val,
                    default,
                )
                object.__setattr__(self, field_name, default)
        return self
