from __future__ import annotations

from typing import Any

import httpx

from app.collectors.cache import DiskCache

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


async def fetch_kev_index(
    client: httpx.AsyncClient, cache: DiskCache
) -> dict[str, dict[str, Any]]:
    """
    Return map of CVE ID → KEV entry.
    Fields used: dateAdded, knownRansomwareCampaignUse, requiredAction, shortDescription.
    """
    cached = cache.get("cisa_kev")
    if cached is not None:
        return cached

    resp = await client.get(KEV_URL, timeout=60.0)
    resp.raise_for_status()
    catalog = resp.json()
    index: dict[str, dict[str, Any]] = {}
    for item in catalog.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            index[cve.upper()] = item
    cache.set("cisa_kev", index)
    return index


def ransomware_flag(entry: dict[str, Any] | None) -> bool:
    if not entry:
        return False
    val = str(entry.get("knownRansomwareCampaignUse", "")).strip().lower()
    return val in {"known", "yes", "true", "1"}
