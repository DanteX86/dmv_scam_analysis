import json
from pathlib import Path

import pandas as pd

from dmv_scam_analysis.core.extractor import iMessageAnalyzer


def test_read_messages_from_json_list(tmp_path: Path) -> None:
    data = [{"text": "Hello"}, {"text": "World", "id": "abc"}]
    p = tmp_path / "msgs.json"
    p.write_text(json.dumps(data))

    analyzer = iMessageAnalyzer(db_path="/tmp/none", output_dir=str(tmp_path))
    msgs = analyzer.read_messages(str(p))
    assert isinstance(msgs, list)
    assert len(msgs) == 2
    assert all("text" in m for m in msgs)
    # Ensure defaults filled
    assert any(m.get("id") for m in msgs)
    assert any(m.get("timestamp") for m in msgs)


def test_read_messages_from_json_with_container_key(tmp_path: Path) -> None:
    data = {"messages": [{"text": "A"}, {"text": "B"}]}
    p = tmp_path / "container.json"
    p.write_text(json.dumps(data))

    analyzer = iMessageAnalyzer(db_path="/tmp/none", output_dir=str(tmp_path))
    msgs = analyzer.read_messages(str(p))
    assert len(msgs) == 2


def test_read_messages_from_csv_and_txt(tmp_path: Path) -> None:
    # CSV
    df = pd.DataFrame({"text": ["x", "y"], "source": ["s", "s2"]})
    csvp = tmp_path / "in.csv"
    df.to_csv(csvp, index=False)

    analyzer = iMessageAnalyzer(db_path="/tmp/none", output_dir=str(tmp_path))
    csv_msgs = analyzer.read_messages(str(csvp))
    assert len(csv_msgs) == 2
    assert all("source" in m for m in csv_msgs)

    # TXT
    txtp = tmp_path / "in.txt"
    txtp.write_text("one\n\n two \n")
    txt_msgs = analyzer.read_messages(str(txtp))
    assert [m["text"] for m in txt_msgs] == ["one", "two"]


def test_extract_all_prefers_fixture_files(tmp_path: Path) -> None:
    base = tmp_path / "messages.json"
    base.write_text(json.dumps([{"text": "foo", "id": "1"}]))
    new = tmp_path / "new_messages.json"
    new.write_text(json.dumps([{"text": "bar", "id": "2"}, {"text": "dup", "id": "1"}]))

    analyzer = iMessageAnalyzer(db_path="/tmp/none", output_dir=str(tmp_path))
    out = analyzer.extract_all()
    # Should have appended non-duplicate only
    assert len(out) == 2
    ids = {m["id"] for m in out}
    assert ids == {"1", "2"}
