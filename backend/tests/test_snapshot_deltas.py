import json
from types import SimpleNamespace

from app.models import Finding, Bulletin, BulletinApplicability
from app.scripts.refresh_live_snapshot import annotate_snapshot_changes


def test_delta_distinguishes_score_fix_and_editorial_changes(tmp_path):
    old = Finding(cve_id="CVE-2026-10000", title="IBM i", description="Test", cvss_score=8, bulletin_id="b")
    bulletin = Bulletin(bulletin_id="b", url="https://www.ibm.com/support/pages/node/1", title="Old title")
    previous = {"generated_at": "2026-10-24T12:00:00Z", "findings": [old.model_dump(mode="json")], "bulletins": [bulletin.model_dump(mode="json")]}
    path = tmp_path / "previous.json"
    path.write_text(json.dumps(previous), encoding="utf-8")
    current = old.model_copy(update={"cvss_score": 9})
    new = old.model_copy(update={"cve_id": "CVE-2026-10001"})
    bulletin.title = "Editorial title update"
    result = SimpleNamespace(findings=[current, new], bulletins=[bulletin])
    annotate_snapshot_changes(result, path)
    assert current.snapshot_changes == ["score"]
    assert new.snapshot_changes == ["new"]
    assert result.snapshot_comparison_available is True

    bulletin.applicability = [BulletinApplicability(applicability_id="a", product_name="IBM i", release="7.5", individual_ptfs=["SJ12345"])]
    annotate_snapshot_changes(result, path)
    assert current.snapshot_changes == ["score", "fix"]


def test_unchanged_and_missing_baselines_do_not_invent_changes(tmp_path):
    finding = Finding(cve_id="CVE-2026-10000", title="IBM i", description="Test")
    result = SimpleNamespace(findings=[finding], bulletins=[], snapshot_comparison_available=False)
    annotate_snapshot_changes(result, tmp_path / "absent.json")
    assert result.snapshot_comparison_available is False
    assert finding.snapshot_changes == []
    path = tmp_path / "previous.json"
    path.write_text(json.dumps({"generated_at": "2026-10-24T12:00:00Z", "findings": [finding.model_dump(mode="json")], "bulletins": []}), encoding="utf-8")
    annotate_snapshot_changes(result, path)
    assert result.snapshot_comparison_available is True
    assert finding.snapshot_changes == []


def test_existing_fix_is_not_new_and_apar_alone_is_not_a_fix(tmp_path):
    finding = Finding(cve_id="CVE-2026-10000", title="IBM i", description="Test", resolution_steps=[{"kind": "ptf", "title": "Fix", "detail": "SJ12345"}])
    path = tmp_path / "previous.json"
    path.write_text(json.dumps({"generated_at": "2026-10-24T12:00:00Z", "findings": [finding.model_dump(mode="json")], "bulletins": []}), encoding="utf-8")
    finding.resolution_steps.append({"kind": "apar", "title": "APAR", "detail": "SE123456"})
    annotate_snapshot_changes(SimpleNamespace(findings=[finding], bulletins=[]), path)
    assert finding.snapshot_changes == []
