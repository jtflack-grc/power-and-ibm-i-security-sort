"""Tests for sample fixture integrity (portfolio no-keys path)."""

import json
from pathlib import Path

SAMPLE = (
    Path(__file__).resolve().parents[2]
    / "frontend"
    / "public"
    / "sample-triage.json"
)


def test_sample_fixture_exists_and_shapes():
    assert SAMPLE.is_file()
    data = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert data["mode"] == "sample"
    assert len(data["findings"]) >= 5
    ids = {f["cve_id"] for f in data["findings"]}
    assert "CVE-2021-44228" in ids
    assert "CVE-2024-25050" in ids
    for f in data["findings"]:
        assert f["cve_id"].startswith("CVE-")
        assert f["bucket"] in {"urgent", "watch", "low"}
        assert f["action_lane"] in {"apply", "contain", "monitor"}
        assert {p["platform"] for p in f["platforms"]} == {"ibm_i"}
