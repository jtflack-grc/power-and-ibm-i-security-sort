from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.collectors.cache import DiskCache
from app.models import Bulletin, BulletinApplicability, Finding, Platform, PlatformHit

PSIRT_SEARCH_API = "https://www.ibm.com/support/pages/securityapp/api/search"
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_RESULTS = 1000
_MAX_CVES = 750
_RELEASE_RE = re.compile(r"\b(?:7\.([2-6])|V7R([2-6])M\d)\b", re.IGNORECASE)
_PRODUCT_ID_RE = re.compile(r"\b(\d{4})-?([A-Z0-9]{3})\b", re.IGNORECASE)


@dataclass
class PsirtBundle:
    findings: dict[str, Finding]
    bulletins: list[Bulletin]


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


def _bulletin_id(url: str) -> str:
    node = url.rstrip("/").rsplit("/", 1)[-1]
    safe = re.sub(r"[^a-z0-9-]+", "-", node.lower()).strip("-") or "unknown"
    return f"ibm-psirt-{safe}"


def _release_values(text: str) -> list[tuple[str, str]]:
    releases: list[tuple[str, str]] = []
    for match in _RELEASE_RE.finditer(text):
        minor = match.group(1) or match.group(2)
        value = (f"7.{minor}", f"V7R{minor}M0")
        if value not in releases:
            releases.append(value)
    return releases


def _product_id(text: str) -> str | None:
    match = _PRODUCT_ID_RE.search(text)
    return f"{match.group(1)}{match.group(2)}".upper() if match else None


def _component_type(product_id: str | None, text: str) -> str:
    low = text.lower()
    if product_id == "5770999" or "licensed internal code" in low or re.search(r"\blic\b", low):
        return "licensed_internal_code"
    if product_id == "5770SS1":
        return "operating_system"
    if product_id:
        return "licensed_program"
    if re.search(r"\bibm\s+i\b", low):
        return "operating_system"
    if any(token in low for token in ("java", "openssl", "bind", "liberty")):
        return "bundled_component"
    return "unknown"


def _applicability_rows(
    affected_html: Any, *, product: str, url: str, bulletin_id: str
) -> list[BulletinApplicability]:
    """Normalize releases conservatively without associating remedy tokens yet."""
    raw = str(affected_html or "")
    soup = BeautifulSoup(raw, "lxml")
    table_rows = [
        _plain(" ".join(cell.get_text(" ", strip=True) for cell in row.find_all("td")), 1000)
        for row in soup.find_all("tr")
        if row.find_all("td")
    ]
    candidates = [row for row in table_rows if row] or [_plain(raw, 3000)]
    rows: list[BulletinApplicability] = []
    seen: set[tuple[str | None, str | None, str]] = set()
    for source in candidates:
        if not source:
            continue
        product_id = _product_id(source) or _product_id(product)
        releases: list[tuple[str | None, str | None]] = list(_release_values(source))
        if not releases:
            releases = [(None, None)]
        for release, release_system in releases:
            key = (product_id, release, source)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                BulletinApplicability(
                    applicability_id=f"{bulletin_id}-a{len(rows) + 1}",
                    product_id=product_id,
                    product_name=product or "IBM i",
                    component_type=_component_type(product_id, f"{product} {source}"),
                    release=release,
                    release_system=release_system,
                    source_excerpt=source,
                    source_url=url,
                    confidence="structured" if table_rows else "heuristic",
                )
            )
    if rows:
        return rows
    return [
        BulletinApplicability(
            applicability_id=f"{bulletin_id}-a1",
            product_name=product or "IBM i",
            component_type=_component_type(_product_id(product), product),
            source_url=url,
            confidence="unresolved",
        )
    ]


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


def _validate_payload_contract(payload: Any) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("IBM PSIRT search returned an unexpected response shape")
    rows = [row for row in payload["results"] if isinstance(row, dict)]
    if not rows:
        return
    required_signals = ("field_product", "field_affected_products", "field_published_url")
    if not any(all(key in row for key in required_signals) for row in rows):
        raise ValueError("IBM PSIRT search schema changed: required bulletin fields are absent")


def parse_psirt_bundle(
    payload: Any, *, published_after: str | None = None
) -> PsirtBundle:
    """Preserve bulletin records while expanding one authoritative finding per CVE."""
    findings: dict[str, Finding] = {}
    bulletins: dict[str, Bulletin] = {}
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
        bulletin_id = _bulletin_id(url)
        published = _date(record.get("field_pub_date") or record.get("field_created"))
        if published_after and (not published or published < published_after):
            continue
        searchable = " ".join(str(v or "") for v in record.values())
        cves = list(dict.fromkeys(c.upper() for c in _CVE_RE.findall(searchable)))
        applicability = _applicability_rows(
            record.get("field_affected_products"),
            product=product,
            url=url,
            bulletin_id=bulletin_id,
        )
        bulletin = bulletins.get(bulletin_id)
        if bulletin is None:
            bulletin = Bulletin(
                bulletin_id=bulletin_id,
                url=url,
                title=title,
                published=published,
                last_modified=_date(
                    record.get("field_modified_date") or record.get("field_updated")
                ),
                cve_ids=list(cves),
                applicability=applicability,
                affected_source_text=affected,
            )
            bulletins[bulletin_id] = bulletin
        else:
            bulletin.cve_ids = list(dict.fromkeys([*bulletin.cve_ids, *cves]))
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
                bulletin_id=bulletin_id,
                nvd_url=f"https://www.cve.org/CVERecord?id={cve_id}",
            )
            existing = findings.get(cve_id)
            if existing is None or (finding.published or "") > (existing.published or ""):
                findings[cve_id] = finding
    return PsirtBundle(findings=findings, bulletins=list(bulletins.values()))


def parse_psirt_payload(
    payload: Any, *, published_after: str | None = None
) -> dict[str, Finding]:
    """Compatibility wrapper returning the authoritative CVE index."""
    return parse_psirt_bundle(payload, published_after=published_after).findings


async def _load_psirt_payload(
    client: httpx.AsyncClient, cache: DiskCache
) -> Any:
    """Return cached or freshly downloaded PSIRT JSON without a cache round-trip."""
    cache_key = "ibm_psirt:ibm-i:v1"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

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
            raise ValueError(
                "IBM PSIRT search returned non-JSON content "
                f"({content_type or 'missing content-type'}, HTTP {response.status_code})"
            )
        declared = int(response.headers.get("content-length") or 0)
        if declared > _MAX_RESPONSE_BYTES:
            raise ValueError("IBM PSIRT search response exceeded the size limit")
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError("IBM PSIRT search response exceeded the size limit")
    payload = json.loads(body)
    _validate_payload_contract(payload)
    cache.set(cache_key, payload)
    return payload


async def collect_ibmi_psirt(
    client: httpx.AsyncClient, cache: DiskCache, *, days_back: int = 400
) -> dict[str, Finding]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, days_back))).date().isoformat()
    payload = await _load_psirt_payload(client, cache)
    return parse_psirt_payload(payload, published_after=cutoff)


async def collect_ibmi_psirt_bundle(
    client: httpx.AsyncClient, cache: DiskCache, *, days_back: int = 400
) -> PsirtBundle:
    """Collect the same bounded PSIRT feed while retaining bulletin structure."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, days_back))).date().isoformat()
    payload = await _load_psirt_payload(client, cache)
    return parse_psirt_bundle(payload, published_after=cutoff)


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
