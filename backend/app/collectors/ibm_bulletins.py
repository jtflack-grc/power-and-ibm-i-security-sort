from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import quote

import httpx
from bs4 import BeautifulSoup

from app.collectors.cache import DiskCache
from app.models import Finding

BULLETIN_HINTS = (
    "security bulletin",
    "security-bulletin",
    "psirt",
    "security advisory",
)


def _sanitize(text: str, limit: int = 200) -> str:
    cleaned = " ".join("".join(ch for ch in text if ord(ch) >= 32).split())
    return cleaned[: limit - 1] + "…" if len(cleaned) > limit else cleaned


def _normalize_ibm_href(href: str) -> str:
    if href.startswith("/"):
        href = "https://www.ibm.com" + href
    # Strip tracking junk; keep node ids
    if "/support/pages/node/" in href.lower():
        base = href.split("?")[0]
        return base
    return href


def _score_result(href: str, text: str, cve_id: str) -> int:
    blob = f"{href} {text}".lower()
    cve = cve_id.lower()
    score = 0
    if cve in blob:
        score += 4
    if "/support/pages/node/" in href.lower():
        score += 6  # durable bulletin pages
    if any(h in blob for h in BULLETIN_HINTS):
        score += 3
    if "security-bulletin" in href.lower() and "/node/" not in href.lower():
        score -= 2  # SEO slugs often dump into search dead-ends
    if "/support/pages/" in href.lower() or "/support/docview" in href.lower():
        score += 2
    if "fixcentral" in href.lower():
        score += 1
    return score


async def enrich_ibm_bulletins(
    client: httpx.AsyncClient,
    cache: DiskCache,
    findings: Iterable[Finding],
    max_lookups: int = 40,
) -> int:
    """
    For findings still lacking a bulletin URL, probe IBM Support search HTML.
    Caps lookups for demo latency. Returns count newly confirmed.
    """
    confirmed = 0
    candidates = [f for f in findings if f.ibm_bulletin_status != "confirmed"]
    candidates.sort(
        key=lambda f: (
            0 if f.on_kev else 1,
            -(f.cvss_score or 0.0),
            -(f.score or 0.0),
        )
    )

    headers = {
        "User-Agent": "PowerSystemVulnerabilityCurator/1.0 (portfolio-demo)",
        "Accept": "text/html,application/xhtml+xml",
    }

    for finding in candidates[:max_lookups]:
        cache_key = f"ibm_bulletin:{finding.cve_id}:v2"
        cached = cache.get(cache_key)
        if cached is not None:
            if cached.get("url"):
                finding.ibm_bulletin_url = cached["url"]
                finding.ibm_bulletin_title = cached.get("title") or "IBM Security Bulletin"
                finding.ibm_bulletin_status = "confirmed"
                confirmed += 1
            else:
                finding.ibm_bulletin_status = "unconfirmed"
            continue

        queries = [
            f"https://www.ibm.com/support/pages/search?q={quote(finding.cve_id)}",
            f"https://www.ibm.com/support/pages/search?q={quote(finding.cve_id + ' security bulletin')}",
        ]
        record: dict[str, Any] = {"url": None, "title": None}
        best: tuple[int, str, str] | None = None

        for url in queries:
            try:
                resp = await client.get(
                    url,
                    timeout=25.0,
                    follow_redirects=True,
                    headers=headers,
                )
                if resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, "lxml")
                for a in soup.select("a[href]"):
                    href = _normalize_ibm_href(str(a.get("href") or ""))
                    text = a.get_text(" ", strip=True)
                    if "ibm.com" not in href.lower():
                        continue
                    if "support" not in href.lower() and "psirt" not in href.lower():
                        continue
                    score = _score_result(href, text, finding.cve_id)
                    if score < 4:
                        continue
                    if best is None or score > best[0]:
                        best = (score, href, _sanitize(text) or "IBM Security Bulletin")
                if best and best[0] >= 6:
                    break
            except httpx.HTTPError:
                continue

        if best:
            record = {"url": best[1], "title": best[2]}

        cache.set(cache_key, record)
        if record.get("url"):
            finding.ibm_bulletin_url = record["url"]
            finding.ibm_bulletin_title = record.get("title")
            finding.ibm_bulletin_status = "confirmed"
            confirmed += 1
        else:
            finding.ibm_bulletin_status = "unconfirmed"

    for finding in candidates[max_lookups:]:
        if finding.ibm_bulletin_status == "not_checked":
            finding.ibm_bulletin_status = "unconfirmed"

    return confirmed
