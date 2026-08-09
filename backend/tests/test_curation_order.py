"""Calibration tests for the operator-facing queue order."""

from app.models import Finding
from app.triage_service import _curation_order


def _finding(
    cve_id: str,
    *,
    published: str | None,
    on_kev: bool = False,
    score: float = 0,
) -> Finding:
    return Finding(
        cve_id=cve_id,
        title=cve_id,
        description="Calibration fixture",
        published=published,
        on_kev=on_kev,
        score=score,
    )


def test_new_bulletin_precedes_old_kev_entry():
    """An old KEV must not pull historical work above a new IBM disclosure."""
    old_kev = _finding(
        "CVE-2020-0001", published="2025-08-01", on_kev=True, score=200
    )
    new_disclosure = _finding("CVE-2026-0001", published="2026-08-01", score=10)

    assert _curation_order([old_kev, new_disclosure]) == [new_disclosure, old_kev]


def test_kev_is_the_same_day_tie_breaker():
    kev = _finding(
        "CVE-2026-0002", published="2026-08-01", on_kev=True, score=40
    )
    higher_score = _finding("CVE-2026-0003", published="2026-08-01", score=150)

    assert _curation_order([higher_score, kev]) == [kev, higher_score]


def test_score_orders_findings_after_date_and_kev_match():
    lower = _finding("CVE-2026-0004", published="2026-08-01", score=40)
    higher = _finding("CVE-2026-0005", published="2026-08-01", score=80)

    assert _curation_order([lower, higher]) == [higher, lower]


def test_missing_or_malformed_dates_sort_last():
    current = _finding("CVE-2026-0006", published="2026-08-01")
    missing = _finding("CVE-2026-0007", published=None, on_kev=True, score=200)
    malformed = _finding("CVE-2026-0008", published="not-a-date", score=300)

    ordered = _curation_order([missing, malformed, current])

    assert ordered[0] == current
    assert {finding.cve_id for finding in ordered[1:]} == {
        "CVE-2026-0007",
        "CVE-2026-0008",
    }
