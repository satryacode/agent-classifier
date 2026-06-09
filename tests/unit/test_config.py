"""Unit tests for the configuration module."""

import logging
import os
import tempfile
from pathlib import Path

import pytest

from config.settings import ClassifierConfig


class TestDefaults:
    """Test that default values are correctly applied."""

    def test_default_time_window(self):
        config = ClassifierConfig()
        assert config.time_window_seconds == 300

    def test_default_brute_force_ip_threshold(self):
        config = ClassifierConfig()
        assert config.brute_force_ip_threshold == 10

    def test_default_brute_force_user_threshold(self):
        config = ClassifierConfig()
        assert config.brute_force_user_threshold == 5

    def test_default_rate_abuse_threshold(self):
        config = ClassifierConfig()
        assert config.rate_abuse_threshold == 50

    def test_default_fraud_flag_confidence_threshold(self):
        config = ClassifierConfig()
        assert config.fraud_flag_confidence_threshold == 0.7

    def test_default_aws_region(self):
        config = ClassifierConfig()
        assert config.aws_region == "us-east-1"

    def test_default_output_destination(self):
        config = ClassifierConfig()
        assert config.output_destination == "stdout"


class TestEnvVarOverride:
    """Test that environment variables override defaults."""

    def test_env_var_overrides_time_window(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_TIME_WINDOW_SECONDS", "600")
        config = ClassifierConfig()
        assert config.time_window_seconds == 600

    def test_env_var_overrides_brute_force_ip_threshold(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_BRUTE_FORCE_IP_THRESHOLD", "20")
        config = ClassifierConfig()
        assert config.brute_force_ip_threshold == 20

    def test_env_var_overrides_rate_abuse_threshold(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_RATE_ABUSE_THRESHOLD", "100")
        config = ClassifierConfig()
        assert config.rate_abuse_threshold == 100

    def test_env_var_overrides_confidence_threshold(self, monkeypatch):
        monkeypatch.setenv("CLASSIFIER_FRAUD_FLAG_CONFIDENCE_THRESHOLD", "0.9")
        config = ClassifierConfig()
        assert config.fraud_flag_confidence_threshold == 0.9


class TestYamlConfig:
    """Test YAML config file loading."""

    def test_yaml_config_file_values_loaded(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "time_window_seconds: 600\n"
            "brute_force_ip_threshold: 20\n"
        )
        config = ClassifierConfig(config_file=str(config_file))
        assert config.time_window_seconds == 600
        assert config.brute_force_ip_threshold == 20

    def test_yaml_config_non_threshold_values(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "aws_region: eu-west-1\n"
            "output_destination: /var/log/verdicts.jsonl\n"
        )
        config = ClassifierConfig(config_file=str(config_file))
        assert config.aws_region == "eu-west-1"
        assert config.output_destination == "/var/log/verdicts.jsonl"


class TestEnvVarPrecedence:
    """Test that env vars take precedence over config file values (Req 10.4)."""

    def test_env_var_overrides_yaml_value(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("time_window_seconds: 600\n")
        monkeypatch.setenv("CLASSIFIER_TIME_WINDOW_SECONDS", "900")
        config = ClassifierConfig(config_file=str(config_file))
        assert config.time_window_seconds == 900

    def test_env_var_overrides_yaml_for_threshold(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("brute_force_ip_threshold: 20\n")
        monkeypatch.setenv("CLASSIFIER_BRUTE_FORCE_IP_THRESHOLD", "30")
        config = ClassifierConfig(config_file=str(config_file))
        assert config.brute_force_ip_threshold == 30


class TestRangeValidation:
    """Test range validation with fallback to defaults (Req 10.6)."""

    def test_time_window_below_min_falls_back(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(time_window_seconds=0)
        assert config.time_window_seconds == 300
        assert "time_window_seconds" in caplog.text

    def test_time_window_above_max_falls_back(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(time_window_seconds=7200)
        assert config.time_window_seconds == 300
        assert "time_window_seconds" in caplog.text

    def test_brute_force_ip_threshold_below_min(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(brute_force_ip_threshold=0)
        assert config.brute_force_ip_threshold == 10
        assert "brute_force_ip_threshold" in caplog.text

    def test_brute_force_ip_threshold_above_max(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(brute_force_ip_threshold=20000)
        assert config.brute_force_ip_threshold == 10
        assert "brute_force_ip_threshold" in caplog.text

    def test_confidence_below_min(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(fraud_flag_confidence_threshold=-0.1)
        assert config.fraud_flag_confidence_threshold == 0.7
        assert "fraud_flag_confidence_threshold" in caplog.text

    def test_confidence_above_max(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(fraud_flag_confidence_threshold=1.5)
        assert config.fraud_flag_confidence_threshold == 0.7
        assert "fraud_flag_confidence_threshold" in caplog.text

    def test_valid_boundary_min_accepted(self):
        config = ClassifierConfig(time_window_seconds=1)
        assert config.time_window_seconds == 1

    def test_valid_boundary_max_accepted(self):
        config = ClassifierConfig(time_window_seconds=3600)
        assert config.time_window_seconds == 3600

    def test_confidence_exact_zero_accepted(self):
        config = ClassifierConfig(fraud_flag_confidence_threshold=0.0)
        assert config.fraud_flag_confidence_threshold == 0.0

    def test_confidence_exact_one_accepted(self):
        config = ClassifierConfig(fraud_flag_confidence_threshold=1.0)
        assert config.fraud_flag_confidence_threshold == 1.0


class TestMalformedConfigFile:
    """Test graceful handling of malformed/unreadable config files (Req 10.7)."""

    def test_nonexistent_config_file(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(config_file="/nonexistent/path/config.yaml")
        # Should use all defaults
        assert config.time_window_seconds == 300
        assert config.brute_force_ip_threshold == 10
        assert "unreadable" in caplog.text.lower() or "config file" in caplog.text.lower()

    def test_malformed_yaml(self, tmp_path, caplog):
        config_file = tmp_path / "bad.yaml"
        config_file.write_text(":::invalid yaml{{{\n  - broken: [")
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(config_file=str(config_file))
        assert config.time_window_seconds == 300
        assert "malformed" in caplog.text.lower() or "config file" in caplog.text.lower()

    def test_yaml_with_non_mapping_content(self, tmp_path, caplog):
        config_file = tmp_path / "list.yaml"
        config_file.write_text("- item1\n- item2\n")
        with caplog.at_level(logging.WARNING):
            config = ClassifierConfig(config_file=str(config_file))
        assert config.time_window_seconds == 300
        assert "mapping" in caplog.text.lower() or "config file" in caplog.text.lower()

    def test_unreadable_file(self, tmp_path, caplog):
        config_file = tmp_path / "noperm.yaml"
        config_file.write_text("time_window_seconds: 600\n")
        config_file.chmod(0o000)
        try:
            with caplog.at_level(logging.WARNING):
                config = ClassifierConfig(config_file=str(config_file))
            assert config.time_window_seconds == 300
            assert "unreadable" in caplog.text.lower() or "config file" in caplog.text.lower()
        finally:
            config_file.chmod(0o644)
