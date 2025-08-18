import pandas as pd

from dmv_scam_analysis.core.extractor import iMessageAnalyzer


def make_df() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "ROWID": 1,
                "text": "URGENT: pay now at http://gov-pay.vip",
                "readable_date": "2025-01-01T00:00:00",
                "is_from_me": 0,
            },
            {
                "ROWID": 2,
                "text": "normal message",
                "readable_date": "2025-01-01T01:00:00",
                "is_from_me": 1,
            },
        ]
    )


def test_analyze_message_content_detects_threats() -> None:
    analyzer = iMessageAnalyzer(db_path="/tmp/none")
    df = make_df()
    res = analyzer.analyze_message_content(df)
    assert res is not None
    assert res["total_messages"] == 2
    # Should detect categories due to vip TLD and urgent/pay
    indicators = res["threat_indicators"]
    assert "suspicious_urls" in indicators or "financial_threats" in indicators
    assert res["risk_score"] >= 5
