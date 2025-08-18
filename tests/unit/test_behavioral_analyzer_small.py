import pandas as pd
import pytest

from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer


def test_behavioral_analyzer_basic_paths():
    analyzer = BehavioralAnalyzer()
    # Valid input
    df = pd.DataFrame({"text": ["Test message"], "timestamp": ["2025-08-18T10:00:00Z"]})
    res = analyzer.analyze(df)
    assert isinstance(res, dict)
    assert "threat_score" in res and 0.0 <= res["threat_score"] <= 1.0
    assert "indicators" in res

    # Invalid: empty text row should raise
    df_bad = pd.DataFrame({"text": [" "]})
    with pytest.raises(ValueError):
        analyzer.analyze(df_bad)

    # Invalid timestamp should raise
    df_ts = pd.DataFrame({"text": ["ok"], "timestamp": ["not-a-date"]})
    with pytest.raises(ValueError):
        analyzer.analyze(df_ts)

