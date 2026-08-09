from types import SimpleNamespace

from app.models import Bulletin, Finding
from app.scripts.refresh_live_snapshot import publication_safe


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
