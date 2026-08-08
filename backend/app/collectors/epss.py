from __future__ import annotations

from typing import Any

import httpx

from app.collectors.cache import DiskCache

EPSS_API = "https://api.first.org/data/v1/epss"


async def fetch_epss_for_cves(
    client: httpx.AsyncClient,
    cache: DiskCache,
    cve_ids: list[str],
    chunk_size: int = 100,
) -> dict[str, dict[str, float]]:
    """
    Return CVE → {epss, percentile}.
    FIRST allows comma-separated CVE queries; we chunk to stay polite.
    Soft-fails per chunk so one bad response does not abandon the batch.
    """
    unique = sorted({c.upper() for c in cve_ids if c})
    out: dict[str, dict[str, float]] = {}
    pending: list[str] = []

    for cve in unique:
        cached = cache.get(f"epss:{cve}")
        if cached is not None:
            out[cve] = cached
        else:
            pending.append(cve)

    for i in range(0, len(pending), chunk_size):
        chunk = pending[i : i + chunk_size]
        params = {"cve": ",".join(chunk)}
        try:
            resp = await client.get(EPSS_API, params=params, timeout=60.0)
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
        except (httpx.HTTPError, ValueError, KeyError):
            continue
        for row in payload.get("data", []):
            cve = str(row.get("cve", "")).upper()
            if not cve:
                continue
            rec = {
                "epss": float(row.get("epss", 0.0)),
                "percentile": float(row.get("percentile", 0.0)),
            }
            out[cve] = rec
            cache.set(f"epss:{cve}", rec)
    return out
