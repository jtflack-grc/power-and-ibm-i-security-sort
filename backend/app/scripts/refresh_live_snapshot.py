"""Refresh frontend/public/live-triage.json for GitHub Pages (scheduled / CI).

Usage (from repo root, with PYTHONPATH=backend):

    python -m app.scripts.refresh_live_snapshot

Optional env:
    NVD_API_KEY — fuller NVD recipe when set (never bake into the SPA)
    LIVE_SNAPSHOT_OUT — override output path
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Any

from app.triage_service import build_live_result
from app.models import Bulletin

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = REPO_ROOT / "frontend" / "public" / "live-triage.json"
PUBLISH_NOTE = "Published snapshot for GitHub Pages (scheduled refresh)."
MIN_PSIRT_CVES = 75
MIN_PSIRT_BULLETINS = 20


def _bulletin_fingerprint(bulletin: Any) -> str:
    payload = bulletin.model_dump(mode="json", exclude={"change_status"})
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def annotate_snapshot_changes(result: Any, previous_path: Path | None) -> None:
    """Mark bulletin additions/changes against the last deployed static snapshot."""
    if previous_path is None or not previous_path.is_file():
        return
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        if not isinstance(previous, dict) or not isinstance(previous.get("findings"), list) or not previous.get("generated_at"):
            return
        old_bulletins = {
            item.get("bulletin_id"): item
            for item in previous.get("bulletins", [])
            if isinstance(item, dict) and item.get("bulletin_id")
        }
        result.previous_snapshot_at = previous.get("generated_at")
        result.snapshot_comparison_available = True
        old_findings = {item["cve_id"]: item for item in previous["findings"] if isinstance(item, dict) and item.get("cve_id")}
        score_fields = ("cvss_score", "cvss_vector", "cvss_source", "ibm_cvss_score", "ibm_cvss_vector")
        for finding in result.findings:
            finding.snapshot_changes = []
            old = old_findings.get(finding.cve_id)
            if old is None:
                finding.snapshot_changes.append("new")
                continue
            if any(getattr(finding, key) != old.get(key) for key in score_fields):
                finding.snapshot_changes.append("score")
            bulletin = next((b for b in result.bulletins if b.bulletin_id == finding.bulletin_id), None)
            old_bulletin = old_bulletins.get(finding.bulletin_id)
            old_fixes = _fix_packages(old, old_bulletin)
            new_fixes = _fix_packages(finding.model_dump(mode="json"), bulletin.model_dump(mode="json") if bulletin else None)
            if new_fixes - old_fixes:
                finding.snapshot_changes.append("fix")
        for bulletin in result.bulletins:
            old = old_bulletins.get(bulletin.bulletin_id)
            if old is None:
                bulletin.change_status = "new"
                continue
            old_hash = _bulletin_fingerprint(Bulletin.model_validate(old))
            bulletin.change_status = "unchanged" if old_hash == _bulletin_fingerprint(bulletin) else "modified"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return


def _fix_packages(finding: dict, bulletin: dict | None) -> set[str]:
    """Compare actual package evidence, excluding APAR-only or editorial changes."""
    packages = set()
    for row in (bulletin or {}).get("applicability", []):
        scope = (row.get("product_id"), row.get("release"), row.get("release_system"))
        for kind in ("individual_ptfs", "group_ptfs"):
            for package in row.get(kind, []):
                level = row.get("group_ptf_levels", {}).get(package) if kind == "group_ptfs" else None
                packages.add(json.dumps([scope, kind, package, level]))
    # Structured bulletin rows are preferred; fallback only for older feeds.
    if not packages:
        import re
        for step in finding.get("resolution_steps", []):
            if step.get("kind") in ("ptf", "ptf_group", "summary", "snippet", "bulletin"):
                packages.update(re.findall(r"\b(?:SI|SJ|MF|MJ|UJ|UI|SE|UA|UB|UC|SF)\d{4,7}\b", f"{step.get('title', '')} {step.get('detail', '')}", re.I))
    return packages


def publication_safe(result: Any) -> tuple[bool, str]:
    """Prevent a degraded discovery run from replacing a healthy Pages snapshot."""
    ibm = next((item for item in result.feed_health if item.get("id") == "ibm"), {})
    if ibm.get("status") != "ok":
        return False, "IBM PSIRT was not healthy; refusing degraded Pages publication"
    if len(result.findings) < MIN_PSIRT_CVES:
        return False, f"PSIRT finding count {len(result.findings)} is below safety floor {MIN_PSIRT_CVES}"
    if len(result.bulletins) < MIN_PSIRT_BULLETINS:
        return False, f"PSIRT bulletin count {len(result.bulletins)} is below safety floor {MIN_PSIRT_BULLETINS}"
    if any(finding.bulletin_id is None for finding in result.findings):
        return False, "one or more published findings lack PSIRT bulletin membership"
    return True, "PSIRT publication gate passed"


async def _log_progress(
    stage: str, message: str, pct: int, detail: dict[str, Any] | None = None
) -> None:
    extra = ""
    if detail:
        bits = [f"{k}={v}" for k, v in list(detail.items())[:4]]
        if bits:
            extra = " | " + ", ".join(bits)
    print(f"[{pct:3d}%] {stage}: {message}{extra}", flush=True)


async def refresh(out_path: Path, force_refresh: bool) -> int:
    result = await build_live_result(
        job_id="pages-snapshot",
        force_refresh=force_refresh,
        on_progress=_log_progress,
        extra_notes=[PUBLISH_NOTE],
        max_bulletin_fetches=None,
    )
    previous_raw = os.environ.get("PREVIOUS_SNAPSHOT_PATH")
    annotate_snapshot_changes(result, Path(previous_raw) if previous_raw else None)
    safe, reason = publication_safe(result)
    if not safe:
        print(f"ERROR: {reason}.", file=sys.stderr)
        for note in result.notes or []:
            print(f"  note: {note}", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = result.model_dump(mode="json")
    payload["mode"] = "live"
    notes = list(payload.get("notes") or [])
    if PUBLISH_NOTE not in notes:
        notes.insert(0, PUBLISH_NOTE)
    payload["notes"] = notes
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(
        f"Wrote {out_path} — {result.metrics.total} findings "
        f"(urgent={result.metrics.urgent}, watch={result.metrics.watch}, low={result.metrics.low})",
        flush=True,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh Pages live-triage.json snapshot")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSON path (default: frontend/public/live-triage.json)",
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Bypass collector disk cache",
    )
    args = parser.parse_args(argv)
    out = args.out or Path(os.environ.get("LIVE_SNAPSHOT_OUT", str(DEFAULT_OUT)))
    try:
        return asyncio.run(refresh(out.resolve(), args.force_refresh))
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: snapshot failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
