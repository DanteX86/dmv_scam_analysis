import json
import os

import pandas as pd

from dmv_scam_analysis.core.extractor import iMessageAnalyzer


def test_imessage_analyzer_extract_all_prefers_fixture(tmp_path):
    # Arrange a messages.json in output_dir
    out_dir = tmp_path / "analysis_output"
    out_dir.mkdir()
    messages = [
        {
            "id": "msg_001",
            "timestamp": "2025-01-01T00:00:00Z",
            "text": "hello",
            "source": "test",
        }
    ]
    with open(out_dir / "messages.json", "w") as f:
        json.dump(messages, f)

    analyzer = iMessageAnalyzer(
        db_path="/nonexistent/db.sqlite", output_dir=str(out_dir)
    )
    extracted = analyzer.extract_all()
    assert isinstance(extracted, list)
    assert extracted and extracted[0]["text"] == "hello"
