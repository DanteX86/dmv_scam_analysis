import pandas as pd
import pytest

from dmv_scam_analysis.utils.validation import DataValidator, OutputValidator, ValidationError


def test_validation_success_and_warnings():
    df = pd.DataFrame({
        "datetime": ["2025-08-18T10:00:00Z", "2025-08-18T11:00:00Z"],
        "contact_id": ["c1", "c2"],
        "text": ["hello", "world"],
        "is_from_me": [1, 0],
    })
    v = DataValidator()
    res = v.validate_input_data(df)
    assert res["is_valid"] is True
    # No errors, possibly zero or more warnings acceptable
    assert isinstance(res["warnings"], list)


def test_validation_detects_missing_columns():
    df = pd.DataFrame({"text": ["hi"], "is_from_me": [True]})
    v = DataValidator()
    res = v.validate_input_data(df)
    assert res["is_valid"] is False
    assert any("Missing required columns" in e for e in res["errors"]) 


def test_output_validator_path_and_format(tmp_path):
    ov = OutputValidator()
    # Absolute path under tmp
    out_file = tmp_path / "out" / "file.json"
    ok = ov.validate_output_path(str(out_file))
    assert ok is True

    assert ov.validate_output_format("json") is True
    assert ov.validate_output_format("CSV") is True
    with pytest.raises(ValidationError):
        ov.validate_output_format("exe")

