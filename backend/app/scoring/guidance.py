"""
Remediation and interim-mitigation guidance for curated findings.

Pulls:
  - CISA KEV requiredAction when present
  - IBM Security Bulletin text (PTF / fix tables) when a bulletin URL exists
  - Platform-aware interim controls keyed off CWE / OWASP / CVSS vector

All scraped/external text is sanitized before storage or display.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.collectors.cache import DiskCache
from app.models import Finding, Platform

# IBM i PTFs (SI/MF/UJ/UI/SE), AIX APARs (IJ/IV/IX), z/OS (UA/UJ) — best-effort scrape.
PTF_TOKEN_RE = re.compile(
    r"\b(?:SI|MF|UJ|UI|SE|UA|UB|UC)\d{4,7}\b",
    re.IGNORECASE,
)
APAR_RE = re.compile(
    r"\b(?:APAR|apar)\s*[:=]?\s*([A-Z]{2}\d{5,7})\b|\b(?:IJ|IV|IX|PH|OA)\d{5,7}\b",
    re.IGNORECASE,
)
FIX_LINE_RE = re.compile(
    r"(?i)(apply|install|upgrade|update|remediat|fix|patch|ptf|apar|fileset).{0,160}"
)
FILESET_RE = re.compile(
    r"\b(?:bos|devices|rsct|xlsmp|perl|openssl|openssh)\.[A-Za-z0-9._-]{2,40}\b"
)


def _sanitize(text: str, limit: int = 500) -> str:
    cleaned = " ".join("".join(ch for ch in text if ord(ch) >= 32).split())
    return cleaned[: limit - 1] + "…" if len(cleaned) > limit else cleaned


def _is_allowed_bulletin_fetch(url: str) -> bool:
    """SSRF guard — only fetch IBM hosts over http(s)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    return host == "ibm.com" or host.endswith(".ibm.com")


def _vector_map(vector: str | None) -> dict[str, str]:
    if not vector:
        return {}
    out: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        k, _, v = part.partition(":")
        if k.upper() == "CVSS":
            continue
        out[k.upper()] = v.upper()
    return out


def _platform_interims(finding: Finding) -> list[dict[str, str]]:
    """Deterministic interim controls — not pretend patches."""
    plats = {p.platform for p in finding.platforms}
    cwes = {c.upper() for c in finding.cwes}
    owasp = " ".join(finding.owasp_top10).lower()
    metrics = _vector_map(finding.cvss_vector)
    items: list[dict[str, str]] = []

    def add(title: str, detail: str, kind: str = "interim") -> None:
        items.append({"title": title, "detail": detail, "kind": kind})

    if Platform.IBM_I in plats:
        add(
            "Verify cumulative PTF currency",
            "Confirm the partition is on a current IBM i Preventive Service Planning "
            "(PSP) group / HIPER cumulative before hunting one-off PTFs.",
        )
        add(
            "Constrain privileged profiles",
            "Review *ALLOBJ / *SECADM / *IOSYSCFG holders and recent *AUDLVL journal "
            "(QAUDJRN) for unusual elevation tied to this class of flaw.",
        )
        if "A01" in owasp or any(c in cwes for c in ("CWE-284", "CWE-862", "CWE-863", "CWE-250")):
            add(
                "Tighten object authority on exposed libraries",
                "Where the issue is authority-related, reduce *PUBLIC and adopted-authority "
                "paths on the implicated libraries/programs until the PTF is applied.",
            )
        if any(c in cwes for c in ("CWE-319", "CWE-326", "CWE-327")) or "A02" in owasp:
            add(
                "Raise TLS floor in DCM",
                "Disable weak protocols/ciphers in Digital Certificate Manager and "
                "restrict service listeners that still offer legacy TLS.",
            )

    if Platform.AIX in plats:
        add(
            "Check Advisory / APAR currency",
            "Map the CVE to the latest IBM AIX security advisory and confirm "
            "emgr / instfix output reflects the listed APAR/fileset level.",
        )
        add(
            "Reduce remote service exposure",
            "Limit inetd/sshd/rservices listeners and management networks until "
            "the fix package is staged.",
        )

    if Platform.LINUX_ON_POWER in plats:
        add(
            "Vendor package channel",
            "Prefer distro or PowerSC/PowerVM advisory packages over ad-hoc rebuilds; "
            "confirm architecture (ppc64le) packages specifically.",
        )

    if Platform.ZOS in plats:
        add(
            "Apply Holddata / ++APAR discipline",
            "Route through SMP/E HOLDDATA review and staged APPLY CHECK before "
            "production APPLY/ACCEPT of the remediating PTF.",
        )

    if finding.on_kev and finding.kev_required_action:
        add(
            "CISA required action",
            _sanitize(finding.kev_required_action, 420),
            kind="kev",
        )

    if metrics.get("AV") == "N":
        add(
            "Network path control",
            "Until patched, constrain the network path to the affected service "
            "(ACL / firewall / service proxy) — Attack Vector is Network.",
        )
    elif metrics.get("AV") == "L":
        add(
            "Local access hygiene",
            "Prioritize privileged-user and console/session controls; remote blast "
            "radius is lower but insider / jump-host abuse remains relevant.",
        )

    if finding.epss is not None and finding.epss >= 0.1:
        add(
            "Treat as actively chaseable",
            f"EPSS is elevated ({finding.epss:.3f}) — accelerate change window "
            "and monitoring even if a full PTF cycle takes days.",
        )

    # De-dupe by title
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for it in items:
        if it["title"] in seen:
            continue
        seen.add(it["title"])
        unique.append(it)
    return unique[:8]


async def scrape_bulletin_fixes(
    client: httpx.AsyncClient,
    cache: DiskCache,
    url: str,
) -> dict[str, Any]:
    cache_key = f"bulletin_fixes:{url}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    record: dict[str, Any] = {
        "ptfs": [],
        "apars": [],
        "filesets": [],
        "fix_snippets": [],
        "summary": None,
        "affected": None,
    }
    if not _is_allowed_bulletin_fetch(url):
        cache.set(cache_key, record)
        return record
    try:
        resp = await client.get(
            url,
            timeout=25.0,
            follow_redirects=True,
            headers={
                "User-Agent": "PowerSystemVulnerabilityCurator/1.0 (portfolio-demo)"
            },
        )
        # Reject SSRF via open redirect off ibm.com
        if not _is_allowed_bulletin_fetch(str(resp.url)):
            cache.set(cache_key, record)
            return record
        if resp.status_code != 200:
            cache.set(cache_key, record)
            return record
        soup = BeautifulSoup(resp.text, "lxml")
        text = _sanitize(soup.get_text(" ", strip=True), limit=20000)
        # Prefer table cells — IBM bulletins often list PTFs in remediation tables
        table_blob = " ".join(
            td.get_text(" ", strip=True)
            for td in soup.select("table td, table th, li")
        )
        search_blob = f"{table_blob} {text}"
        record["ptfs"] = sorted({p.upper() for p in PTF_TOKEN_RE.findall(search_blob)})[:20]
        apars: list[str] = []
        for match in APAR_RE.finditer(search_blob):
            token = match.group(1) if match.lastindex else match.group(0)
            if token:
                apars.append(token.upper())
        record["apars"] = sorted(set(apars))[:20]
        filesets = FILESET_RE.findall(search_blob)
        record["filesets"] = sorted({f.lower() for f in filesets})[:12]
        snippets: list[str] = []
        for m in FIX_LINE_RE.finditer(text):
            snip = _sanitize(m.group(0), 220)
            if snip and snip not in snippets:
                snippets.append(snip)
            if len(snippets) >= 5:
                break
        record["fix_snippets"] = snippets
        for heading in soup.find_all(["h1", "h2", "h3", "h4", "strong", "b"]):
            label = heading.get_text(" ", strip=True).lower()
            if any(
                tok in label
                for tok in (
                    "remediat",
                    "fix",
                    "solution",
                    "workaround",
                    "get the fix",
                    "apply",
                )
            ):
                sibling = heading.find_next(["p", "li", "div", "td"])
                if sibling:
                    record["summary"] = _sanitize(
                        sibling.get_text(" ", strip=True), 360
                    )
                    break
        if not record["summary"]:
            for heading in soup.find_all(["h2", "h3", "strong"]):
                if "remediat" in heading.get_text(" ", strip=True).lower():
                    nxt = heading.parent
                    if nxt:
                        record["summary"] = _sanitize(nxt.get_text(" ", strip=True), 360)
                        break
        for heading in soup.find_all(["h2", "h3", "h4", "strong"]):
            label = heading.get_text(" ", strip=True).lower()
            if "affected" in label and "product" in label:
                sibling = heading.find_next(["p", "li", "div", "td", "ul"])
                if sibling:
                    record["affected"] = _sanitize(
                        sibling.get_text(" ", strip=True), 280
                    )
                    break
    except httpx.HTTPError:
        pass

    cache.set(cache_key, record)
    return record


def _fix_central_links(finding: Finding) -> list[dict[str, str]]:
    """Always-useful next hops for systems folks — even when scrape is thin."""
    cve = finding.cve_id
    steps: list[dict[str, str]] = [
        {
            "title": "Search IBM Support for this CVE",
            "detail": (
                "Open IBM’s support search with the CVE preloaded. Confirm bulletin "
                "scope against your release / TR / fileset before scheduling change."
            ),
            "kind": "search",
            "url": f"https://www.ibm.com/support/pages/search?q={cve}",
        },
        {
            "title": "Fix Central",
            "detail": (
                "Use Fix Central to locate downloadable PTF groups / APARs once the "
                "bulletin names the package. Prefer cumulative / HIPER groups where directed."
            ),
            "kind": "fixcentral",
            "url": "https://www.ibm.com/support/fixcentral",
        },
    ]
    plats = {p.platform for p in finding.platforms}
    if Platform.IBM_I in plats:
        steps.append(
            {
                "title": "Verify on IBM i (systems check)",
                "detail": (
                    "After apply: confirm PTF level with DSPPTF / GO PTF and that the "
                    "partition matches the bulletin’s affected product table (release + product)."
                ),
                "kind": "verify",
            }
        )
    if Platform.AIX in plats:
        steps.append(
            {
                "title": "Verify on AIX (systems check)",
                "detail": (
                    "After apply: instfix -l / emgr -l and match fileset + APAR level to "
                    "the advisory before closing the change."
                ),
                "kind": "verify",
            }
        )
    if Platform.ZOS in plats:
        steps.append(
            {
                "title": "Verify on z/OS (systems check)",
                "detail": (
                    "After APPLY: review SMP/E CSI for the PTF, confirm HOLDDATA cleared, "
                    "and retain APPLY CHECK evidence for audit."
                ),
                "kind": "verify",
            }
        )
    return steps


def attach_guidance(finding: Finding, bulletin: dict[str, Any] | None = None) -> Finding:
    """Build Resolve + Interim cards systems and GRC can both read."""
    bulletin = bulletin or {}
    resolution_steps: list[dict[str, str]] = []

    if finding.ibm_bulletin_status == "confirmed" and finding.ibm_bulletin_url:
        bulletin_url = finding.ibm_bulletin_url
        low = bulletin_url.lower()
        # SEO slug pages often render as support-search dead-ends; prefer node or CVE search.
        if "security-bulletin" in low and "/node/" not in low:
            from urllib.parse import quote

            bulletin_url = (
                f"https://www.ibm.com/support/pages/search?q={quote(finding.cve_id)}"
            )
        elif "/support/pages/node/" in low:
            bulletin_url = bulletin_url.split("?")[0]
        resolution_steps.append(
            {
                "title": "IBM Security Bulletin (source of truth)",
                "detail": finding.ibm_bulletin_title
                or "Vendor bulletin confirms product impact — apply listed fixes from this page.",
                "kind": "bulletin",
                "url": bulletin_url,
            }
        )
    if bulletin.get("summary"):
        resolution_steps.append(
            {
                "title": "Vendor remediation summary",
                "detail": bulletin["summary"],
                "kind": "summary",
            }
        )
    if bulletin.get("affected"):
        resolution_steps.append(
            {
                "title": "Affected products (bulletin)",
                "detail": bulletin["affected"],
                "kind": "summary",
            }
        )
    for ptf in bulletin.get("ptfs") or []:
        resolution_steps.append(
            {
                "title": f"PTF {ptf}",
                "detail": (
                    "Extracted from bulletin text/tables. Confirm against your release "
                    "before apply — identifiers can appear in related-product sections."
                ),
                "kind": "ptf",
            }
        )
    for apar in bulletin.get("apars") or []:
        resolution_steps.append(
            {
                "title": f"APAR {apar}",
                "detail": "APAR referenced in bulletin / advisory text.",
                "kind": "apar",
            }
        )
    for fs in bulletin.get("filesets") or []:
        resolution_steps.append(
            {
                "title": f"Fileset {fs}",
                "detail": "AIX/Power fileset token extracted from bulletin text — confirm level on the box.",
                "kind": "apar",
            }
        )
    for snip in bulletin.get("fix_snippets") or []:
        resolution_steps.append(
            {
                "title": "Bulletin guidance",
                "detail": snip,
                "kind": "snippet",
            }
        )

    # Always append Fix Central / search / verify — the aisle-crossing money shot
    for step in _fix_central_links(finding):
        resolution_steps.append(step)

    if not any(str(s.get("kind")) in {"ptf", "apar", "bulletin"} for s in resolution_steps):
        resolution_steps.insert(
            0,
            {
                "title": "No PTF/APAR extracted yet",
                "detail": (
                    "Public feeds did not yield a packaged fix id for this CVE. Use Search / "
                    "Fix Central below, keep Interim controls in place, and treat this as "
                    "contain-first until a bulletin package is confirmed."
                ),
                "kind": "unknown",
            },
        )

    # Deduplicate by title
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for step in resolution_steps:
        if step["title"] in seen:
            continue
        seen.add(step["title"])
        unique.append(step)

    finding.resolution_steps = unique[:12]
    finding.interim_mitigations = _platform_interims(finding)
    return finding


async def enrich_guidance(
    client: httpx.AsyncClient,
    cache: DiskCache,
    findings: list[Finding],
    max_bulletin_fetches: int = 30,
) -> None:
    """Populate remediation fields; fetch bulletin HTML for top findings first."""
    ranked = sorted(
        findings,
        key=lambda f: (0 if f.on_kev else 1, 0 if f.bucket.value == "urgent" else 1, -(f.score or 0)),
    )
    fetched = 0
    for f in ranked:
        bulletin: dict[str, Any] = {}
        if (
            f.ibm_bulletin_url
            and fetched < max_bulletin_fetches
        ):
            bulletin = await scrape_bulletin_fixes(client, cache, f.ibm_bulletin_url)
            fetched += 1
        attach_guidance(f, bulletin)
