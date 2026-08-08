"""Golden checks against the shipped sample fixture — portfolio never empty-screens."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import Finding
from app.scoring.guidance import attach_guidance
from app.scoring.ranker import apply_levers
from app.scoring.surfaces import annotate_surfaces

SAMPLE = (
    Path(__file__).resolve().parents[2] / "frontend" / "public" / "sample-triage.json"
)


def _load_findings() -> list[Finding]:
    data = json.loads(SAMPLE.read_text(encoding="utf-8"))
    return [Finding.model_validate(row) for row in data["findings"]]


def test_sample_flagship_is_apply_with_bulletin():
    findings = {f.cve_id: f for f in _load_findings()}
    f = findings["CVE-2024-25050"]
    assert f.bucket.value in {"urgent", "watch"}
    assert f.ibm_bulletin_status == "confirmed"
    assert f.action_lane == "apply"
    assert any(
        str(s.get("kind")) in {"bulletin", "ptf", "fixcentral"}
        for s in f.resolution_steps
    )


def test_log4shell_kev_urgent_supply_chain():
    findings = {f.cve_id: f for f in _load_findings()}
    f = findings["CVE-2021-44228"]
    assert f.on_kev is True
    assert f.bucket.value == "urgent"
    assert f.risk_surface == "supply_chain"


def test_attach_guidance_idempotent_on_fixture():
    findings = _load_findings()
    f = next(x for x in findings if x.cve_id == "CVE-2024-31879")
    out = attach_guidance(f, {"ptfs": ["SJ00619"], "apars": [], "summary": "Apply Option 3 PTF"})
    kinds = {str(s.get("kind")) for s in out.resolution_steps}
    assert "ptf" in kinds
    assert "search" in kinds or "fixcentral" in kinds
    assert out.interim_mitigations


def test_re_rank_museum_cve_stays_lowish():
    findings = {f.cve_id: f for f in _load_findings()}
    f = findings["CVE-2019-1010022"]
    # Strip precomputed score path — re-apply levers from signals
    f.score = 0
    f.levers = []
    apply_levers(f)
    annotate_surfaces([f])
    assert f.bucket.value in {"low", "watch"}
    assert f.action_lane in {"monitor", "contain"}
