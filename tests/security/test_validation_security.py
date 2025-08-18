import pandas as pd
import pytest

from dmv_scam_analysis.utils.validation import DataValidator, ValidationError


@pytest.mark.security
def test_validation_required_columns_and_types():
    dv = DataValidator()
    # Missing required columns
    df_missing = pd.DataFrame({"text": ["hi"]})
    result = dv.validate_input_data(df_missing)
    assert result["is_valid"] is False
    assert any("Missing required columns" in e for e in result["errors"])

    # Correct minimal schema
    df_ok = pd.DataFrame(
        {
            "datetime": ["2025-01-01 00:00:00"],
            "contact_id": ["c1"],
            "text": ["hello"],
            "is_from_me": [True],
        }
    )
    result_ok = dv.validate_input_data(df_ok)
    assert result_ok["is_valid"] is True


@pytest.mark.security
def test_validation_rules_invalids():
    dv = DataValidator()
    df = pd.DataFrame(
        {
            "datetime": ["not-a-date", "2025-01-01 00:00:00"],
            "contact_id": ["c1", "c2"],
            "text": [None, "ok"],
            "is_from_me": [
                "not_bool",
                None,
            ],  # include None to avoid coercion and trigger boolean rule
        }
    )
    res = dv.validate_input_data(df)
    assert res["is_valid"] is False
    assert any("Invalid datetime" in e for e in res["errors"]) or any(
        "Invalid data type" in e for e in res["errors"]
    )
    # Expect boolean rule to complain about non-boolean values
    assert any("non-boolean" in e for e in res["errors"])


@pytest.mark.security
def test_output_path_and_format_validation(tmp_path):
    from dmv_scam_analysis.utils.validation import OutputValidator

    ov = OutputValidator()

    # Bad path (relative)
    # Truly relative path should be rejected
    assert ov.validate_output_path("relative.out") is False

    # Good absolute path
    good_file = tmp_path / "sub" / "out.json"
    good_path = "/" + "/".join(good_file.parts[1:])
    assert ov.validate_output_path(good_path) is True

    # Good formats
    assert ov.validate_output_format("json") is True
    assert ov.validate_output_format("CSV") is True

    # Bad format
    with pytest.raises(ValidationError):
        ov.validate_output_format("exe")
