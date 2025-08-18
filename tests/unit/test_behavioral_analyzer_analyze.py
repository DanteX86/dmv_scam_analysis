import pandas as pd
import pytest

from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer


def test_behavioral_analyzer_analyze_happy() -> None:
    analyzer = BehavioralAnalyzer()
    messages = [
        {"text": "please respond", "timestamp": "2025-01-01T00:00:00Z"},
        {"text": "DMV urgent notice", "timestamp": "2025-01-01T01:00:00Z"},
    ]
    out = analyzer.analyze(messages)
    assert "threat_score" in out
    assert "indicators" in out
    assert isinstance(out["risk_scores"], list)


def test_behavioral_analyzer_invalid_timestamp_raises() -> None:
    analyzer = BehavioralAnalyzer()
    df = pd.DataFrame([{"text": "x", "timestamp": "not-a-date"}])
    with pytest.raises(ValueError):
        analyzer.analyze(df)
