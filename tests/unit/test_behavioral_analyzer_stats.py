from datetime import datetime

from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer


def test_get_statistics_stub() -> None:
    analyzer = BehavioralAnalyzer()
    start = datetime(2025, 1, 1)
    end = datetime(2025, 1, 2)
    stats = analyzer.get_statistics(start, end)
    assert isinstance(stats, dict)
    assert set(["total_analyzed", "risk_distribution"]).issubset(stats.keys())
