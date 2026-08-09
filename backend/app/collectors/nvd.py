from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

import httpx

from app.collectors.cache import DiskCache
from app.models import Finding, Platform, PlatformHit

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Full recipe (NVD API key present — faster delay, more coverage)
PLATFORM_QUERIES_FULL: dict[Platform, dict[str, Any]] = {
    Platform.IBM_I: {
        "label": "IBM i",
        "virtual_matches": [
            "cpe:2.3:o:ibm:i",
            "cpe:2.3:a:ibm:i",
            "cpe:2.3:o:ibm:i_operating_system",
        ],
        "keywords": [
            "IBM i Security Bulletin",
            "IBM i OS",
            "OS/400",
        ],
    },
}

# Keyless demo recipe — ~8 queries, 1 page each (~1 min worst case vs several)
PLATFORM_QUERIES_SLIM: dict[Platform, dict[str, Any]] = {
    Platform.IBM_I: {
        "label": "IBM i",
        "virtual_matches": ["cpe:2.3:o:ibm:i"],
        "keywords": ["IBM i Security Bulletin"],
    },
}


def has_nvd_api_key() -> bool:
    return bool(os.getenv("NVD_API_KEY", "").strip())


def active_platform_queries() -> dict[Platform, dict[str, Any]]:
    return PLATFORM_QUERIES_FULL if has_nvd_api_key() else PLATFORM_QUERIES_SLIM


# Back-compat for imports/tests
PLATFORM_QUERIES = PLATFORM_QUERIES_SLIM


def _headers() -> dict[str, str]:
    headers = {"User-Agent": "IBMiVulnerabilityCurator/1.0 (portfolio-demo)"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _nvd_delay() -> float:
    if has_nvd_api_key():
        return 0.65
    return 6.5


def _sanitize_text(text: str, limit: int = 600) -> str:
    cleaned = "".join(ch for ch in text if ch == "\n" or ord(ch) >= 32)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        sev = data.get("baseSeverity") or primary.get("baseSeverity")
        vector = data.get("vectorString")
        return (
            float(score) if score is not None else None,
            str(sev) if sev else None,
            str(vector) if vector else None,
        )
    return None, None, None


def _extract_cwes(weaknesses: list[dict[str, Any]] | None) -> list[str]:
    out: list[str] = []
    for w in weaknesses or []:
        for desc in w.get("description") or []:
            val = str(desc.get("value", "")).upper()
            if val.startswith("CWE-") and val not in out and val != "CWE-NOINFO":
                out.append(val)
    return out


def _description(cve: dict[str, Any]) -> tuple[str, str]:
    descs = cve.get("descriptions") or []
    en = next((d for d in descs if d.get("lang") == "en"), None) or (
        descs[0] if descs else {}
    )
    text = _sanitize_text(str(en.get("value", "No description")))
    title = text.split(".")[0][:140] if text else "Untitled"
    return title, text


def _cpe_mentions_platform(configurations: list[dict[str, Any]] | None, platform: Platform) -> bool:
    blob = str(configurations or []).lower()
    needles = {
        Platform.IBM_I: ["ibm:i", "ibm i", "os400", "os/400", "i_operating_system"],
    }
    return any(n in blob for n in needles[platform])


def _keyword_text_match(item: dict[str, Any], platform: Platform) -> bool:
    cve = item.get("cve") or {}
    title, desc = _description(cve)
    blob = f"{title} {desc} {cve.get('configurations') or ''}".lower()
    must = {
        Platform.IBM_I: ["ibm i", "os/400", "os400", "as/400", "ibm:i"],
    }
    if _cpe_mentions_platform(cve.get("configurations"), platform):
        return True
    return any(tok in blob for tok in must[platform])


def _extract_ibm_bulletin(refs: list[dict[str, Any]] | None) -> tuple[str | None, str | None]:
    scored: list[tuple[int, str, str]] = []
    for ref in refs or []:
        url = str(ref.get("url") or "")
        low = url.lower()
        if "ibm.com" not in low:
            continue
        tags = " ".join(str(t).lower() for t in (ref.get("tags") or []))
        score = 0
        if "/support/pages/node/" in low:
            score += 8
            url = url.split("?")[0]
        if "security-bulletin" in low or "security bulletin" in tags:
            score += 3
            # Slug pages often render as search dead-ends in-browser
            if "/node/" not in low:
                score -= 4
        if "vendor advisory" in tags:
            score += 4
        if "psirt" in low or "/blogs/psirt" in low:
            score += 3
        if "/support/" in low or "support/pages" in low:
            score += 2
        if "fixcentral" in low:
            score += 1
        if score > 0:
            scored.append((score, url, tags))
    if not scored:
        return None, None
    scored.sort(key=lambda t: t[0], reverse=True)
    _, url, tags = scored[0]
    title = "IBM Security Bulletin"
    if "vendor advisory" in tags:
        title = "IBM Security Bulletin (NVD vendor advisory)"
    return url, title


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        raw = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _parse_item(item: dict[str, Any], platform: Platform, via: str) -> Finding | None:
    cve = item.get("cve") or {}
    cve_id = str(cve.get("id", "")).upper()
    if not cve_id.startswith("CVE-"):
        return None
    if via == "keyword" and not _keyword_text_match(item, platform):
        return None
    title, desc = _description(cve)
    score, sev, vector = _extract_cvss(cve.get("metrics") or {})
    strength: str = "cpe" if via == "cpe" else "keyword"
    if via == "keyword" and _cpe_mentions_platform(cve.get("configurations"), platform):
        strength = "cpe"
    bulletin_url, bulletin_title = _extract_ibm_bulletin(cve.get("references"))
    status = "confirmed" if bulletin_url else "unconfirmed"
    label = active_platform_queries()[platform]["label"]
    return Finding(
        cve_id=cve_id,
        title=title,
        description=desc,
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        cvss_score=score,
        cvss_severity=sev,
        cvss_vector=vector,
        cwes=_extract_cwes(cve.get("weaknesses")),
        platforms=[
            PlatformHit(
                platform=platform,
                match_strength=strength,  # type: ignore[arg-type]
                products=[label],
            )
        ],
        ibm_bulletin_url=bulletin_url,
        ibm_bulletin_title=bulletin_title,
        ibm_bulletin_status=status,  # type: ignore[arg-type]
        nvd_url=f"https://www.cve.org/CVERecord?id={cve_id}",
    )


async def _paged_fetch(
    client: httpx.AsyncClient,
    params: dict[str, Any],
    cache: DiskCache,
    cache_key: str,
    max_pages: int = 1,
) -> tuple[list[dict[str, Any]], bool]:
    """Return (items, from_cache). Skip network delay when cache hits."""
    cached = cache.get(cache_key)
    if cached is not None:
        return cached, True

    results: list[dict[str, Any]] = []
    start = 0
    page = 0
    while page < max_pages:
        q = dict(params)
        q["startIndex"] = start
        q.setdefault("resultsPerPage", 100)
        try:
            resp = await client.get(NVD_API, params=q, headers=_headers(), timeout=90.0)
        except httpx.HTTPError:
            break
        if resp.status_code in {403, 404, 429}:
            break
        if resp.status_code >= 400:
            break
        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        results.extend(vulns)
        total = int(data.get("totalResults") or 0)
        per = int(data.get("resultsPerPage") or len(vulns) or 1)
        start += per
        page += 1
        if start >= total or not vulns:
            break
        await asyncio.sleep(_nvd_delay())

    cache.set(cache_key, results)
    return results, False


ProgressCb = Callable[[str, dict[str, Any]], Awaitable[None]]


def _merge_finding(merged: dict[str, Finding], finding: Finding) -> None:
    existing = merged.get(finding.cve_id)
    if not existing:
        merged[finding.cve_id] = finding
        return
    seen = {p.platform for p in existing.platforms}
    for hit in finding.platforms:
        if hit.platform not in seen:
            existing.platforms.append(hit)
        else:
            for ep in existing.platforms:
                if (
                    ep.platform == hit.platform
                    and ep.match_strength == "keyword"
                    and hit.match_strength == "cpe"
                ):
                    ep.match_strength = "cpe"
    if finding.cvss_score and (
        existing.cvss_score is None or finding.cvss_score > existing.cvss_score
    ):
        existing.cvss_score = finding.cvss_score
        existing.cvss_severity = finding.cvss_severity
        existing.cvss_vector = finding.cvss_vector
    if finding.cwes and not existing.cwes:
        existing.cwes = finding.cwes
    if (
        finding.ibm_bulletin_status == "confirmed"
        and existing.ibm_bulletin_status != "confirmed"
    ):
        existing.ibm_bulletin_url = finding.ibm_bulletin_url
        existing.ibm_bulletin_title = finding.ibm_bulletin_title
        existing.ibm_bulletin_status = "confirmed"
    if len(finding.description or "") > len(existing.description or "") + 40:
        existing.description = finding.description
        existing.title = finding.title


def count_nvd_queries(slim: bool | None = None) -> int:
    recipes = PLATFORM_QUERIES_SLIM if (slim if slim is not None else not has_nvd_api_key()) else PLATFORM_QUERIES_FULL
    return sum(
        len(r.get("virtual_matches") or []) + len(r.get("keywords") or [])
        for r in recipes.values()
    )


async def collect_platform_cves(
    client: httpx.AsyncClient,
    cache: DiskCache,
    days_back: int = 400,
    on_progress: ProgressCb | None = None,
) -> dict[str, Finding]:
    """
    Collect NVD CVEs with an IBM i operating-system or product signal.

    Keyless mode uses a slim CPE/keyword recipe and single-page pulls so cold
    demos finish in about a minute instead of several. Cache hits skip the
    NVD politeness delay entirely.
    """
    slim = not has_nvd_api_key()
    recipes = active_platform_queries()
    max_pages_cpe = 1 if slim else 3
    max_pages_kw = 1 if slim else 2
    cache_tag = "slim" if slim else "full"

    merged: dict[str, Finding] = {}
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    severe_cutoff = datetime.now(timezone.utc) - timedelta(days=max(days_back, 3650))

    if on_progress:
        await on_progress(
            "nvd",
            {
                "status": "plan",
                "mode": cache_tag,
                "query_budget": count_nvd_queries(slim),
                "label": f"NVD {cache_tag} recipe",
            },
        )

    for platform, recipe in recipes.items():
        if on_progress:
            await on_progress(
                "nvd",
                {"platform": platform.value, "label": recipe["label"], "status": "start"},
            )
        collected_items: list[tuple[dict[str, Any], str]] = []

        for vm in recipe.get("virtual_matches") or []:
            key = f"nvd:{platform.value}:vm:{vm}:{cache_tag}:v3"
            try:
                items, from_cache = await _paged_fetch(
                    client,
                    {"virtualMatchString": vm, "resultsPerPage": 100},
                    cache,
                    key,
                    max_pages=max_pages_cpe,
                )
                collected_items.extend((it, "cpe") for it in items)
            except httpx.HTTPError:
                from_cache = True
            if not from_cache:
                await asyncio.sleep(_nvd_delay())

        for kw in recipe.get("keywords") or []:
            key = f"nvd:{platform.value}:kw:{kw}:{cache_tag}:v3"
            try:
                items, from_cache = await _paged_fetch(
                    client,
                    {"keywordSearch": kw, "resultsPerPage": 50},
                    cache,
                    key,
                    max_pages=max_pages_kw,
                )
                collected_items.extend((it, "keyword") for it in items)
            except httpx.HTTPError:
                from_cache = True
            if not from_cache:
                await asyncio.sleep(_nvd_delay())

        kept = 0
        for item, via in collected_items:
            finding = _parse_item(item, platform, via)
            if not finding:
                continue
            pub = _parse_dt(finding.published)
            mod = _parse_dt(finding.last_modified)
            newest = max([d for d in (pub, mod) if d is not None], default=None)
            severe = finding.cvss_score is not None and finding.cvss_score >= 7.0
            has_bulletin = finding.ibm_bulletin_status == "confirmed"
            if newest is not None:
                if newest < cutoff and not severe and not has_bulletin:
                    continue
                if newest < severe_cutoff and severe and not has_bulletin:
                    continue
            _merge_finding(merged, finding)
            kept += 1

        if on_progress:
            await on_progress(
                "nvd",
                {
                    "platform": platform.value,
                    "label": recipe["label"],
                    "status": "done",
                    "count": sum(
                        1
                        for f in merged.values()
                        if any(p.platform == platform for p in f.platforms)
                    ),
                    "raw_kept_pass": kept,
                },
            )

    return merged
