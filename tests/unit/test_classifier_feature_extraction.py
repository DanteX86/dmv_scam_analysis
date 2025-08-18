import pandas as pd

from dmv_scam_analysis.core.classifier import MLThreatClassifier


def build_df() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "text": "DMV NOTICE: pay your fee now",
                "readable_date": "2025-01-01T10:00:00",
                "is_from_me": 0,
                "handle_id": "x@example.com",
            },
            {
                "text": "Meeting at 11?",
                "readable_date": "2025-01-01T11:30:00",
                "is_from_me": 1,
                "handle_id": "y@example.com",
            },
        ]
    )


def test_extract_ml_features_aggregated() -> None:
    clf = MLThreatClassifier()
    df = build_df()
    res = clf.extract_ml_features(df, include_labels=False)
    assert res is not None
    feats = res["features"].iloc[0]
    # Check presence of some expected features
    for key in [
        "total_messages",
        "total_words",
        "message_count",
        "sent_ratio",
        "contact_entropy",
    ]:
        assert key in res["feature_names"] or key in feats.index


def test_extract_ml_features_per_message_labels() -> None:
    clf = MLThreatClassifier()
    df = build_df()
    res = clf.extract_ml_features(df, include_labels=True)
    assert res is not None
    feature_df = res["features"]
    assert not feature_df.empty
    assert "message_length" in feature_df.columns
    # Synthetic labels should be present
    assert "labels" in res
    assert len(res["labels"]) == len(df)
