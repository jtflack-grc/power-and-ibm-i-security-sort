from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.collectors.cache import DiskCache
from app.collectors.epss import fetch_epss_for_cves
from app.collectors.ibm_bulletins import enrich_ibm_bulletins
from app.collectors.kev import fetch_kev_index, ransomware_flag
from app.collectors.nvd import collect_platform_cves, count_nvd_queries, has_nvd_api_key
from app.models import ProgressEvent, TriageResult
from app.scoring.ranker import build_metrics, rank_findings
from app.scoring.guidance import enrich_guidance
from app.scoring.surfaces import annotate_surfaces

CACHE_DIR = Path(__file__).resolve().parents[2] / ".cache"
LAST_LIVE_PATH = CACHE_DIR / "last_live_result.json"


def save_last_live(result: TriageResult) -> None:
    if not result.findings:
        return
    if any("cancelled" in n.lower() for n in (result.notes or [])):
        return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump(mode="json")
        payload["mode"] = "live"
        notes = list(payload.get("notes") or [])
        stamp = result.generated_at
        cache_note = f"Cached live snapshot from {stamp}. Refreshing will update this file."
        if cache_note not in notes:
            notes.append(cache_note)
        payload["notes"] = notes
        LAST_LIVE_PATH.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def load_last_live() -> TriageResult | None:
    if not LAST_LIVE_PATH.is_file():
        return None
    try:
        raw = json.loads(LAST_LIVE_PATH.read_text(encoding="utf-8"))
        result = TriageResult.model_validate(raw)
        if not result.findings:
            return None
        return result
    except (OSError, ValueError, json.JSONDecodeError):
        return None



class TriageJobStore:
    def __init__(self) -> None:
        self._events: dict[str, list[ProgressEvent]] = {}
        self._results: dict[str, TriageResult] = {}
        self._subscribers: dict[str, list[asyncio.Queue[ProgressEvent | None]]] = {}
        self._cancelled: set[str] = set()
        self._lock = asyncio.Lock()

    async def create(self) -> str:
        job_id = uuid.uuid4().hex[:12]
        async with self._lock:
            self._events[job_id] = []
            self._subscribers[job_id] = []
            self._cancelled.discard(job_id)
        return job_id

    async def cancel(self, job_id: str) -> bool:
        async with self._lock:
            if job_id in self._results:
                return False
            self._cancelled.add(job_id)
        await self.emit(
            job_id,
            ProgressEvent(
                stage="cancelled",
                message="Cancel requested — finishing current feed step…",
                pct=0,
                detail={"cancelled": True},
            ),
        )
        return True

    def is_cancelled(self, job_id: str) -> bool:
        return job_id in self._cancelled

    async def emit(self, job_id: str, event: ProgressEvent) -> None:
        async with self._lock:
            self._events.setdefault(job_id, []).append(event)
            subs = list(self._subscribers.get(job_id, []))
        for q in subs:
            await q.put(event)

    async def complete(self, job_id: str, result: TriageResult) -> None:
        async with self._lock:
            self._results[job_id] = result
            self._cancelled.discard(job_id)
            subs = list(self._subscribers.get(job_id, []))
        for q in subs:
            await q.put(None)

    def get_result(self, job_id: str) -> TriageResult | None:
        return self._results.get(job_id)

    def history(self, job_id: str) -> list[ProgressEvent]:
        return list(self._events.get(job_id, []))

    async def subscribe(self, job_id: str) -> asyncio.Queue[ProgressEvent | None]:
        q: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()
        async with self._lock:
            self._subscribers.setdefault(job_id, []).append(q)
            for ev in self._events.get(job_id, []):
                await q.put(ev)
            if job_id in self._results:
                await q.put(None)
        return q


store = TriageJobStore()


class TriageCancelled(Exception):
    """User cancelled a live triage job."""


def _cancelled_result(job_id: str) -> TriageResult:
    return TriageResult(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=[],
        metrics=build_metrics([]),
        sources=[],
        mode="live",
        feed_health=[
            {
                "id": "run",
                "label": "Live triage",
                "status": "empty",
                "detail": "cancelled",
            }
        ],
        notes=["Live triage cancelled. Sample queue (if loaded) is unchanged."],
    )

async def run_triage(job_id: str, force_refresh: bool = False) -> None:
    cache = DiskCache(CACHE_DIR, ttl_seconds=0 if force_refresh else 12 * 3600)

    async def progress(stage: str, message: str, pct: int, detail: dict[str, Any] | None = None):
        if store.is_cancelled(job_id) and stage not in {"cancelled", "error", "done"}:
            raise TriageCancelled()
        await store.emit(
            job_id,
            ProgressEvent(stage=stage, message=message, pct=pct, detail=detail or {}),
        )

    try:
        await progress("init", "Opening live feeds (UI stays usable — cancel anytime)…", 2)
        mode = "full" if has_nvd_api_key() else "slim"
        budget = count_nvd_queries()
        await progress(
            "nvd",
            f"NVD {mode} recipe — ~{budget} queries"
            + (" (API key)" if mode == "full" else "; cache hits are instant"),
            5,
            {"mode": mode, "query_budget": budget},
        )
        feed_health: list[dict[str, Any]] = []
        notes: list[str] = []
        async with httpx.AsyncClient() as client:
            await progress("kev", "Pulling CISA Known Exploited Vulnerabilities catalog…", 8)
            try:
                kev = await fetch_kev_index(client, cache)
                feed_health.append(
                    {
                        "id": "kev",
                        "label": "CISA KEV",
                        "status": "ok",
                        "detail": f"{len(kev)} entries",
                    }
                )
                await progress(
                    "kev",
                    f"CISA KEV loaded ({len(kev)} entries).",
                    15,
                    {"kev_count": len(kev)},
                )
            except TriageCancelled:
                raise
            except Exception as kev_exc:  # noqa: BLE001
                kev = {}
                feed_health.append(
                    {
                        "id": "kev",
                        "label": "CISA KEV",
                        "status": "degraded",
                        "detail": str(kev_exc)[:180],
                    }
                )
                notes.append("KEV unavailable — ranking continues without KEV boost.")
                await progress(
                    "kev",
                    f"CISA KEV unavailable ({kev_exc}); continuing without KEV boost.",
                    15,
                    {"error": str(kev_exc)},
                )

            async def nvd_cb(stage: str, detail: dict[str, Any]) -> None:
                if store.is_cancelled(job_id):
                    raise TriageCancelled()
                label = detail.get("label", detail.get("platform", ""))
                status = detail.get("status")
                if status == "start":
                    await progress(
                        "nvd",
                        f"Querying NVD for {label}…",
                        20,
                        detail,
                    )
                else:
                    await progress(
                        "nvd",
                        f"NVD {label}: {detail.get('count', 0)} related findings.",
                        45,
                        detail,
                    )

            try:
                findings_map = await collect_platform_cves(
                    client, cache, days_back=400, on_progress=nvd_cb
                )
                findings = list(findings_map.values())
                feed_health.append(
                    {
                        "id": "nvd",
                        "label": "NVD CVE API",
                        "status": "ok" if findings else "empty",
                        "detail": f"{len(findings)} unique CVEs",
                    }
                )
                if not findings:
                    notes.append(
                        "NVD returned no Power-family CVEs in window — try sample mode or Refresh live later."
                    )
            except TriageCancelled:
                raise
            except Exception as nvd_exc:  # noqa: BLE001
                findings = []
                feed_health.append(
                    {
                        "id": "nvd",
                        "label": "NVD CVE API",
                        "status": "degraded",
                        "detail": str(nvd_exc)[:180],
                    }
                )
                notes.append(f"NVD failed: {nvd_exc}")
            await progress(
                "nvd",
                f"Merged {len(findings)} unique CVEs across Power platforms.",
                55,
                {"unique_cves": len(findings)},
            )

            # Attach KEV
            for f in findings:
                entry = kev.get(f.cve_id.upper())
                if entry:
                    f.on_kev = True
                    f.kev_date_added = entry.get("dateAdded")
                    f.kev_required_action = entry.get("requiredAction")
                    f.kev_ransomware = ransomware_flag(entry)

            await progress("epss", "Scoring exploit likelihood via FIRST EPSS…", 65)
            epss_attached = 0
            try:
                epss = await fetch_epss_for_cves(
                    client, cache, [f.cve_id for f in findings]
                )
                for f in findings:
                    rec = epss.get(f.cve_id.upper())
                    if rec:
                        f.epss = rec["epss"]
                        f.epss_percentile = rec["percentile"]
                        epss_attached += 1
                feed_health.append(
                    {
                        "id": "epss",
                        "label": "FIRST EPSS",
                        "status": "ok" if epss_attached or not findings else "empty",
                        "detail": f"attached {epss_attached}/{len(findings)}",
                    }
                )
                await progress(
                    "epss",
                    f"EPSS attached for {epss_attached} CVEs.",
                    75,
                )
            except Exception as epss_exc:  # noqa: BLE001 — keep triage moving
                feed_health.append(
                    {
                        "id": "epss",
                        "label": "FIRST EPSS",
                        "status": "degraded",
                        "detail": str(epss_exc)[:180],
                    }
                )
                notes.append("EPSS unavailable — ranking continues without exploit likelihood.")
                await progress(
                    "epss",
                    f"EPSS unavailable ({epss_exc}); continuing without exploit scores.",
                    75,
                    {"error": str(epss_exc)},
                )

            await progress(
                "ibm",
                "Resolving IBM Security Bulletin confirmation…",
                80,
            )
            try:
                confirmed = await enrich_ibm_bulletins(
                    client, cache, findings, max_lookups=40
                )
                from_nvd = sum(
                    1 for f in findings if f.ibm_bulletin_status == "confirmed"
                )
                feed_health.append(
                    {
                        "id": "ibm",
                        "label": "IBM bulletins",
                        "status": "ok",
                        "detail": f"{from_nvd} confirmed ({confirmed} via search)",
                    }
                )
                await progress(
                    "ibm",
                    f"IBM PSIRT confirmation on {confirmed} findings (plus NVD reference hits).",
                    88,
                    {"newly_confirmed": confirmed},
                )
            except Exception as ibm_exc:  # noqa: BLE001
                feed_health.append(
                    {
                        "id": "ibm",
                        "label": "IBM bulletins",
                        "status": "degraded",
                        "detail": str(ibm_exc)[:180],
                    }
                )
                notes.append("IBM bulletin enrichment degraded — Fix Central links still offered.")
                await progress("ibm", f"IBM enrichment degraded ({ibm_exc})", 88)

            await progress("rank", "Applying counter-lever ranking (CISA · EPSS · OWASP · CVSS · PSIRT)…", 92)
            ranked = rank_findings(findings)
            await progress(
                "guidance",
                "Extracting PTF / APAR fix paths and interim mitigations…",
                96,
            )
            try:
                await enrich_guidance(client, cache, ranked, max_bulletin_fetches=30)
                feed_health.append(
                    {
                        "id": "guidance",
                        "label": "Resolve / Interim",
                        "status": "ok",
                        "detail": "built",
                    }
                )
            except Exception as guide_exc:  # noqa: BLE001
                from app.scoring.guidance import attach_guidance

                for f in ranked:
                    attach_guidance(f, {})
                feed_health.append(
                    {
                        "id": "guidance",
                        "label": "Resolve / Interim",
                        "status": "degraded",
                        "detail": str(guide_exc)[:180],
                    }
                )
                notes.append("Bulletin scrape degraded — Fix Central / search steps still attached.")
            annotate_surfaces(ranked)
            metrics = build_metrics(ranked)
            result = TriageResult(
                job_id=job_id,
                generated_at=datetime.now(timezone.utc).isoformat(),
                findings=ranked,
                metrics=metrics,
                mode="live",
                feed_health=feed_health,
                notes=notes,
                sources=[
                    "CISA KEV",
                    "FIRST EPSS",
                    "NVD CVE API 2.0",
                    "OWASP Top 10 (2021) via CWE",
                    "IBM Security Bulletins",
                ],
            )
            await progress(
                "done",
                f"Curated {metrics.total} findings → {metrics.urgent} urgent, "
                f"{metrics.watch} watch, {metrics.low} low.",
                100,
                metrics.model_dump(),
            )
            save_last_live(result)
            await store.complete(job_id, result)
    except TriageCancelled:
        await store.emit(
            job_id,
            ProgressEvent(
                stage="cancelled",
                message="Live triage cancelled.",
                pct=100,
                detail={"cancelled": True},
            ),
        )
        await store.complete(job_id, _cancelled_result(job_id))
    except Exception as exc:  # noqa: BLE001 — surface to UI
        import traceback

        await progress(
            "error",
            f"Triage failed: {exc}",
            100,
            {"error": str(exc), "trace": traceback.format_exc()[-2000:]},
        )
        empty = TriageResult(
            job_id=job_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            findings=[],
            metrics=build_metrics([]),
            sources=[],
            mode="live",
            feed_health=[
                {
                    "id": "run",
                    "label": "Live triage",
                    "status": "degraded",
                    "detail": str(exc)[:180],
                }
            ],
            notes=[
                "Live triage failed. Load sample for a keyless demo, then retry live later.",
                str(exc)[:240],
            ],
        )
        await store.complete(job_id, empty)
