import pytest

from dmv_scam_analysis.utils.test_helpers import create_test_dataset


def test_create_test_dataset_shapes_and_ratios() -> None:
    df = create_test_dataset(size=50, scam_ratio=0.4)
    assert len(df) == 50
    assert set(["text", "is_scam", "confidence", "source", "timestamp"]).issubset(
        df.columns
    )


def test_create_test_dataset_invalid_ratios() -> None:
    with pytest.raises(ValueError):
        create_test_dataset(size=10, scam_ratio=0.8, legitimate_ratio=0.3)
