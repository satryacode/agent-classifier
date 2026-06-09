# Feature: traffic-fraud-classifier, Property 27: Configuration precedence and validation
import os
import tempfile
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st
from config.settings import ClassifierConfig


@given(
    st.integers(min_value=1, max_value=3600),
    st.integers(min_value=0, max_value=7200),
)
@settings(max_examples=100)
def test_property_27_env_overrides_yaml(env_val, yaml_val):
    """Env var always wins over YAML config file value."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"time_window_seconds": yaml_val}, f)
        fname = f.name
    try:
        os.environ["CLASSIFIER_TIME_WINDOW_SECONDS"] = str(env_val)
        config = ClassifierConfig(config_file=fname)
        if 1 <= env_val <= 3600:
            assert config.time_window_seconds == env_val
        else:
            assert config.time_window_seconds == 300  # default
    finally:
        del os.environ["CLASSIFIER_TIME_WINDOW_SECONDS"]
        os.unlink(fname)


@given(st.floats(min_value=-1.0, max_value=2.0))
@settings(max_examples=100)
def test_property_27_out_of_range_uses_default(val):
    """Out-of-range confidence threshold → default 0.7."""
    config = ClassifierConfig(fraud_flag_confidence_threshold=val)
    if 0.0 <= val <= 1.0:
        assert abs(config.fraud_flag_confidence_threshold - val) < 1e-9
    else:
        assert config.fraud_flag_confidence_threshold == 0.7
