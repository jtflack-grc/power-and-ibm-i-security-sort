from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

import httpx

from app.collectors.cache import DiskCache
from app.models import Finding, Platform, PlatformHit

PSIRT_SEARCH_API = "https://www.ibm.com/support/pages/securityapp/api/search"
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_RESULTS = 1000
_MAX_CVES = 750


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _plain(value: Any, limit: int = 5000) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(str(value or ""))
    except (ValueError, TypeError):
        return ""
    text = " ".join(" ".join(parser.parts).split())
    text = "".join(ch for ch in text if ord(ch) >= 32)
    return text[:limit]


def _support_url(value: Any) -> str | None:
    raw = str(value or "").strip()
    if raw.startswith("node/"):
        raw = f"https://www.ibm.com/support/pages/{raw}"
    elif raw.startswith("/support/pages/"):
        raw = f"https://www.ibm.com{raw}"
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme != "https" or parsed.hostname not in {"ibm.com", "www.ibm.com"}:
        return None
    if not parsed.path.startswith("/support/pages/"):
        return None
    return f"https://www.ibm.com{parsed.path}"


def _date(value: Any) -> str | None:
    raw = str(value or "").strip()
    match = re.search(r"\d{4}-\d{2}-\d{2}", raw)
    return match.group(0) if match else None


def _ibmi_record(record: dict[str, Any]) -> bool:
    product = _plain(record.get("field_product"), 500)
    affected = _plain(record.get("field_affected_products"), 4000)
    blob = f"{product} {affected}".lower()
    return bool(re.search(r"\bibm\s+i\b|\bos/400\b|\bos400\b", blob))


def _records(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    rows = payload.get("results")
    if not isinstance(rows, list):
        return []
    return [row for row in rows[:_MAX_RESULTS] if isinstance(row, dict)]


def parse_psirt_payload(
    payload: Any, *, published_after: str | None = None
) -> dict[str, Finding]:
    """Expand IBM bulletin search records into one authoritative row per CVE."""
    findings: dict[str, Finding] = {}
    for record in _records(payload):
        if not _ibmi_record(record):
            continue
        title = _plain(record.get("title"), 2000) or "IBM i Security Bulletin"
        summary = _plain(record.get("field_cvss_desc"), 5000)
        details = _plain(
            record.get("field_vulnerability_details")
            or record.get("field_vulnerablity_details"),
            5000,
        )
        affected = _plain(record.get("field_affected_products"), 3000)
        product = _plain(record.get("field_product"), 200) or "IBM i"
        url = _support_url(record.get("field_published_url"))
        if not url:
            continue
        published = _date(record.get("field_pub_date") or record.get("field_created"))
        if published_after and (not published or published < published_after):
            continue
        searchable = " ".join(str(v or "") for v in record.values())
        cves = list(dict.fromkeys(c.upper() for c in _CVE_RE.findall(searchable)))
        for cve_id in cves:
            if len(findings) >= _MAX_CVES and cve_id not in findings:
                break
            description = summary or details or title
            finding = Finding(
                cve_id=cve_id,
                title=title,
                description=description,
                published=published,
                last_modified=_date(
                    record.get("field_modified_date") or record.get("field_updated")
                ),
                cvss_severity=_plain(record.get("field_cvss_base_score"), 20).upper() or None,
                platforms=[
                    PlatformHit(
                        platform=Platform.IBM_I,
                        match_strength="keyword",
                        products=[product] + ([affected] if affected else []),
                    )
                ],
                ibm_bulletin_url=url,
                ibm_bulletin_title=title,
                ibm_bulletin_status="confirmed",
                nvd_url=f"https://www.cve.org/CVERecord?id={cve_id}",
            )
            existing = findings.get(cve_id)
            if existing is None or (finding.published or "") > (existing.published or ""):
                findings[cve_id] = finding
    return findings


async def collect_ibmi_psirt(
    client: httpx.AsyncClient, cache: DiskCache, *, days_back: int = 400
) -> dict[str, Finding]:
    cache_key = "ibm_psirt:ibm-i:v1"
    cached = cache.get(cache_key)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, days_back))).date().isoformat()
    if cached is not None:
        return parse_psirt_payload(cached, published_after=cutoff)

    body = bytearray()
    async with client.stream(
        "GET",
        PSIRT_SEARCH_API,
        params={"q": "IBM i"},
        headers={
            "Accept": "application/json",
            "User-Agent": "IBMiVulnerabilityCurator/1.0 (public-security-research)",
        },
        timeout=60.0,
        follow_redirects=False,
    ) as response:
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").lower()
        if "json" not in content_type:
            raise ValueError("IBM PSIRT search returned a non-JSON response")
        declared = int(response.headers.get("content-length") or 0)
        if declared > _MAX_RESPONSE_BYTES:
            raise ValueError("IBM PSIRT search response exceeded the size limit")
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError("IBM PSIRT search response exceeded the size limit")
    payload = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("IBM PSIRT search returned an unexpected response shape")
    cache.set(cache_key, payload)
    return parse_psirt_payload(payload, published_after=cutoff)


def enrich_psirt_from_nvd(
    psirt: dict[str, Finding], nvd: dict[str, Finding]
) -> dict[str, Finding]:
    """Attach NVD detail without allowing NVD to admit findings to the queue."""
    for cve_id, finding in psirt.items():
        extra = nvd.get(cve_id)
        if not extra:
            continue
        finding.cvss_score = extra.cvss_score
        finding.cvss_vector = extra.cvss_vector
        finding.cvss_severity = extra.cvss_severity or finding.cvss_severity
        finding.cwes = list(extra.cwes)
        if len(extra.description or "") > len(finding.description or ""):
            finding.description = extra.description
        if not finding.last_modified:
            finding.last_modified = extra.last_modified
        for hit in finding.platforms:
            if hit.platform == Platform.IBM_I and any(
                nvd_hit.match_strength == "cpe" for nvd_hit in extra.platforms
            ):
                hit.match_strength = "cpe"
    return psirt
