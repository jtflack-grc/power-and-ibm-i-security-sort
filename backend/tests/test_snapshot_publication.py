import json
from types import SimpleNamespace

from app.models import Bulletin, Finding
from app.scripts.refresh_live_snapshot import annotate_snapshot_changes, publication_safe


def _result(*, status: str = "ok", findings: int = 75, bulletins: int = 20):
    bulletin_rows = [
        Bulletin(bulletin_id=f"b-{index}", url=f"https://www.ibm.com/support/pages/node/{index}", title="IBM i")
        for index in range(bulletins)
    ]
    finding_rows = [
        Finding(cve_id=f"CVE-2026-{10000 + index}", title="IBM i", description="test", bulletin_id=f"b-{index % max(1, bulletins)}")
        for index in range(findings)
    ]
    return SimpleNamespace(
        feed_health=[{"id": "ibm", "status": status}],
        findings=finding_rows,
        bulletins=bulletin_rows,
    )


def test_publication_gate_accepts_credible_psirt_snapshot():
    assert publication_safe(_result())[0] is True


def test_publication_gate_rejects_nvd_fallback():
    safe, reason = publication_safe(_result(status="empty", findings=20, bulletins=0))
    assert safe is False
    assert "PSIRT" in reason


def test_publication_gate_rejects_materially_narrow_snapshot():
    assert publication_safe(_result(findings=74))[0] is False
    assert publication_safe(_result(bulletins=19))[0] is False


def test_snapshot_change_annotation_distinguishes_new_and_modified(tmp_path):
    unchanged = Bulletin(bulletin_id="same", url="https://www.ibm.com/support/pages/node/1", title="Same")
    modified = Bulletin(bulletin_id="changed", url="https://www.ibm.com/support/pages/node/2", title="Updated")
    new = Bulletin(bulletin_id="new", url="https://www.ibm.com/support/pages/node/3", title="New")
    old_changed = modified.model_dump(mode="json")
    old_changed["title"] = "Old title"
    previous = {
        "generated_at": "2026-08-08T12:00:00Z",
        "bulletins": [unchanged.model_dump(mode="json"), old_changed],
    }
    path = tmp_path / "previous.json"
    path.write_text(json.dumps(previous), encoding="utf-8")
    result = SimpleNamespace(bulletins=[unchanged, modified, new], previous_snapshot_at=None)

    annotate_snapshot_changes(result, path)

    assert result.previous_snapshot_at == "2026-08-08T12:00:00Z"
    assert [item.change_status for item in result.bulletins] == ["unchanged", "modified", "new"]
