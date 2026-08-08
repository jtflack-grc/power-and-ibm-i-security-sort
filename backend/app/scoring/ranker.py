"""
Multi-source counter-lever ranker for Power System Vulnerability Curator.

Philosophy
----------
CVSS alone sorts by theoretical blast radius. That floods Urgents with
"scary math" that no one is exploiting. Real analyst judgment balances
*mutually corrective* signals ("counter-levers"):

  Upward levers (raise priority)
    - CISA KEV (actively exploited — BOD-class signal)
    - CISA KEV ransomware-use flag
    - FIRST EPSS high percentile (likely to be exploited soon)
    - NVD CVSS severity / score
    - Network / adjacent attack vector from CVSS vector string
    - OWASP Top 10 CWE mapping (context, not automatic urgency)
    - IBM Security Bulletin confirmation (vendor acknowledges Power/IBM i impact)
    - Strong CPE platform match
    - Recent publication / modification window

  Downward / tempering levers (counterweight overheated scores)
    - Low EPSS *against* high CVSS (critical on paper, cold in the wild)
    - Local/Physical attack vector only
    - High privilege required + user interaction required
    - Age without KEV and with cold EPSS (stale refrigerator findings)
    - Keyword-only platform match (weaker confidence than CPE)
    - Missing IBM bulletin for clearly IBM-branded products when NVD claims impact
      (soft temper — PSIRT lag is common; never a hard veto)

KEV is nearly an absolute escalator: on-KEV items land in Urgent regardless
of tempering, then tempering still shows in the reason trail so humans see
the full ledger.

The output is an explainable ledger of Lever objects — portfolio / interview
friendly, not an LLM black box.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from dateutil import parser as date_parser

from app.models import Bucket, Finding, Lever, LeverDirection, TriageMetrics
from app.scoring.owasp_map import map_cwes_to_owasp, strongest_owasp_weight


@dataclass(frozen=True)
class RankerConfig:
    # CISA
    kev_weight: float = 100.0
    kev_ransomware_bonus: float = 25.0

    # EPSS (0–1 probability → scored via tiers)
    epss_hot: float = 0.5  # ≥ this → strong up
    epss_warm: float = 0.1
    epss_hot_weight: float = 40.0
    epss_warm_weight: float = 20.0
    epss_cold: float = 0.01  # ≤ this and high CVSS → temper
    epss_vs_cvss_temper: float = -22.0

    # CVSS
    cvss_critical: float = 35.0  # ≥ 9.0
    cvss_high: float = 22.0  # ≥ 7.0
    cvss_medium: float = 10.0  # ≥ 4.0
    cvss_low: float = 3.0

    # Vector tempering / boosts
    network_av_boost: float = 12.0
    adjacent_av_boost: float = 6.0
    local_av_temper: float = -10.0
    physical_av_temper: float = -18.0
    priv_and_ui_temper: float = -8.0

    # OWASP
    owasp_scale: float = 1.0  # multiplies strongest_owasp_weight()

    # IBM PSIRT
    psirt_confirmed: float = 40.0
    psirt_missing_temper: float = -6.0  # soft; applied only with IBM product signal

    # Platform / freshness
    cpe_match_boost: float = 15.0
    keyword_match_temper: float = -5.0
    recent_days: int = 90
    recent_boost: float = 10.0
    stale_days: int = 730
    stale_temper: float = -12.0  # only if not KEV and EPSS cold/missing
    # Strong counter-lever: museum CVEs without active exploitation signal
    ancient_days: int = 2555  # ~7 years
    ancient_temper: float = -55.0
    # Mid-age without PSIRT confirmation
    aging_no_psirt_days: int = 1825  # ~5 years
    aging_no_psirt_temper: float = -18.0

    # Buckets
    urgent_floor: float = 95.0  # non-KEV must clear a higher bar
    watch_floor: float = 35.0


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = date_parser.isoparse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError, OverflowError):
        return None


def _parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """Parse CVSS 3.x vector into metric→value map (AV, PR, UI, …)."""
    if not vector:
        return {}
    out: dict[str, str] = {}
    # e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    parts = vector.split("/")
    for part in parts:
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        if key.upper() == "CVSS":
            continue
        out[key.upper()] = val.upper()
    return out


def apply_levers(finding: Finding, cfg: RankerConfig | None = None) -> Finding:
    cfg = cfg or RankerConfig()
    levers: list[Lever] = []

    # --- CISA KEV (primary upward escalator) ---
    if finding.on_kev:
        levers.append(
            Lever(
                id="cisa_kev",
                source="CISA KEV",
                direction=LeverDirection.UP,
                weight=cfg.kev_weight,
                reason="Listed in CISA Known Exploited Vulnerabilities catalog (actively exploited).",
                evidence={
                    "date_added": finding.kev_date_added,
                    "required_action": finding.kev_required_action,
                },
            )
        )
        if finding.kev_ransomware:
            levers.append(
                Lever(
                    id="cisa_kev_ransomware",
                    source="CISA KEV",
                    direction=LeverDirection.UP,
                    weight=cfg.kev_ransomware_bonus,
                    reason="CISA flags known ransomware campaign use.",
                    evidence={"knownRansomwareCampaignUse": True},
                )
            )

    # --- FIRST EPSS (exploit likelihood; counterweight to raw CVSS) ---
    if finding.epss is not None:
        if finding.epss >= cfg.epss_hot:
            levers.append(
                Lever(
                    id="epss_hot",
                    source="FIRST EPSS",
                    direction=LeverDirection.UP,
                    weight=cfg.epss_hot_weight,
                    reason=f"High EPSS exploit probability ({finding.epss:.3f}).",
                    evidence={
                        "epss": finding.epss,
                        "percentile": finding.epss_percentile,
                    },
                )
            )
        elif finding.epss >= cfg.epss_warm:
            levers.append(
                Lever(
                    id="epss_warm",
                    source="FIRST EPSS",
                    direction=LeverDirection.UP,
                    weight=cfg.epss_warm_weight,
                    reason=f"Elevated EPSS exploit probability ({finding.epss:.3f}).",
                    evidence={
                        "epss": finding.epss,
                        "percentile": finding.epss_percentile,
                    },
                )
            )
        elif (
            finding.epss <= cfg.epss_cold
            and finding.cvss_score is not None
            and finding.cvss_score >= 7.0
            and not finding.on_kev
        ):
            # Classic counter-lever: paper-critical, empirically cold.
            levers.append(
                Lever(
                    id="epss_vs_cvss_temper",
                    source="FIRST EPSS",
                    direction=LeverDirection.DOWN,
                    weight=cfg.epss_vs_cvss_temper,
                    reason=(
                        f"CVSS is {finding.cvss_score} but EPSS is cold "
                        f"({finding.epss:.4f}) — temper severity-only urgency."
                    ),
                    evidence={
                        "epss": finding.epss,
                        "cvss": finding.cvss_score,
                    },
                )
            )

    # --- NVD CVSS severity ---
    if finding.cvss_score is not None:
        score = finding.cvss_score
        if score >= 9.0:
            w, label = cfg.cvss_critical, "Critical"
        elif score >= 7.0:
            w, label = cfg.cvss_high, "High"
        elif score >= 4.0:
            w, label = cfg.cvss_medium, "Medium"
        else:
            w, label = cfg.cvss_low, "Low"
        levers.append(
            Lever(
                id="nvd_cvss",
                source="NVD CVSS",
                direction=LeverDirection.UP,
                weight=w,
                reason=f"NVD CVSS {label} ({score}).",
                evidence={
                    "score": score,
                    "severity": finding.cvss_severity,
                    "vector": finding.cvss_vector,
                },
            )
        )

    # --- CVSS vector mechanics (AV / PR / UI) ---
    metrics = _parse_cvss_vector(finding.cvss_vector)
    av = metrics.get("AV")
    if av == "N":
        levers.append(
            Lever(
                id="cvss_av_network",
                source="NVD CVSS vector",
                direction=LeverDirection.UP,
                weight=cfg.network_av_boost,
                reason="Attack Vector is Network — remotely reachable flaw class.",
                evidence={"AV": av},
            )
        )
    elif av == "A":
        levers.append(
            Lever(
                id="cvss_av_adjacent",
                source="NVD CVSS vector",
                direction=LeverDirection.UP,
                weight=cfg.adjacent_av_boost,
                reason="Attack Vector is Adjacent — network-neighbour reachability.",
                evidence={"AV": av},
            )
        )
    elif av == "L":
        levers.append(
            Lever(
                id="cvss_av_local",
                source="NVD CVSS vector",
                direction=LeverDirection.DOWN,
                weight=cfg.local_av_temper,
                reason="Attack Vector is Local — temper vs remote-first prioritization.",
                evidence={"AV": av},
            )
        )
    elif av == "P":
        levers.append(
            Lever(
                id="cvss_av_physical",
                source="NVD CVSS vector",
                direction=LeverDirection.DOWN,
                weight=cfg.physical_av_temper,
                reason="Attack Vector is Physical — strong temper for remote triage queues.",
                evidence={"AV": av},
            )
        )

    if metrics.get("PR") in {"H", "L"} and metrics.get("UI") == "R":
        levers.append(
            Lever(
                id="cvss_priv_ui_temper",
                source="NVD CVSS vector",
                direction=LeverDirection.DOWN,
                weight=cfg.priv_and_ui_temper,
                reason="Requires privileges and user interaction — friction against mass exploit.",
                evidence={"PR": metrics.get("PR"), "UI": metrics.get("UI")},
            )
        )

    # --- OWASP Top 10 via CWE ---
    owasp = map_cwes_to_owasp(finding.cwes)
    finding.owasp_top10 = owasp
    if owasp:
        ow = strongest_owasp_weight(owasp) * cfg.owasp_scale
        levers.append(
            Lever(
                id="owasp_top10",
                source="OWASP Top 10 (2021)",
                direction=LeverDirection.UP,
                weight=ow,
                reason=f"CWE maps to OWASP Top 10: {', '.join(owasp)}.",
                evidence={"categories": owasp, "cwes": finding.cwes},
            )
        )

    # --- IBM PSIRT bulletin ---
    if finding.ibm_bulletin_status == "confirmed":
        levers.append(
            Lever(
                id="ibm_psirt_confirmed",
                source="IBM PSIRT",
                direction=LeverDirection.UP,
                weight=cfg.psirt_confirmed,
                reason="IBM Security Bulletin confirms product impact.",
                evidence={
                    "url": finding.ibm_bulletin_url,
                    "title": finding.ibm_bulletin_title,
                },
            )
        )
    elif finding.ibm_bulletin_status == "unconfirmed" and finding.platforms:
        # Soft temper only — PSIRT lag is common; do not punish hard.
        levers.append(
            Lever(
                id="ibm_psirt_unconfirmed",
                source="IBM PSIRT",
                direction=LeverDirection.DOWN,
                weight=cfg.psirt_missing_temper,
                reason=(
                    "No matched IBM Security Bulletin yet — keep on radar, "
                    "but do not equate NVD keyword hits with vendor confirmation."
                ),
                evidence={"status": "unconfirmed"},
            )
        )

    # --- Platform match confidence ---
    if finding.platforms:
        strengths = {p.match_strength for p in finding.platforms}
        if "cpe" in strengths:
            levers.append(
                Lever(
                    id="platform_cpe",
                    source="NVD CPE",
                    direction=LeverDirection.UP,
                    weight=cfg.cpe_match_boost,
                    reason="Strong CPE match to a Power-family platform.",
                    evidence={
                        "platforms": [p.platform.value for p in finding.platforms],
                    },
                )
            )
        elif strengths == {"keyword"}:
            levers.append(
                Lever(
                    id="platform_keyword_temper",
                    source="NVD keyword",
                    direction=LeverDirection.DOWN,
                    weight=cfg.keyword_match_temper,
                    reason="Platform association is keyword-only — lower confidence than CPE.",
                    evidence={
                        "platforms": [p.platform.value for p in finding.platforms],
                    },
                )
            )

    # --- Freshness vs stale-without-signal ---
    now = datetime.now(timezone.utc)
    pub = _parse_dt(finding.published) or _parse_dt(finding.last_modified)
    if pub is not None:
        age_days = max(0, (now - pub).days)
        if age_days <= cfg.recent_days:
            levers.append(
                Lever(
                    id="freshness_recent",
                    source="NVD chronology",
                    direction=LeverDirection.UP,
                    weight=cfg.recent_boost,
                    reason=f"Published/modified within {cfg.recent_days} days ({age_days}d).",
                    evidence={"age_days": age_days},
                )
            )
        elif (
            age_days >= cfg.stale_days
            and not finding.on_kev
            and (finding.epss is None or finding.epss <= cfg.epss_cold)
        ):
            levers.append(
                Lever(
                    id="freshness_stale_temper",
                    source="NVD chronology",
                    direction=LeverDirection.DOWN,
                    weight=cfg.stale_temper,
                    reason=(
                        f"Stale ({age_days}d) with no KEV and cold/missing EPSS — "
                        "deprioritize vs lived threats (still reviewable)."
                    ),
                    evidence={"age_days": age_days, "epss": finding.epss},
                )
            )

        # Counter-lever against "antique but still hot EPSS" crowding the Urgent queue
        # when there is no KEV and no IBM bulletin confirmation.
        if (
            age_days >= cfg.ancient_days
            and not finding.on_kev
            and finding.ibm_bulletin_status != "confirmed"
        ):
            levers.append(
                Lever(
                    id="ancient_unconfirmed_temper",
                    source="Operational recency",
                    direction=LeverDirection.DOWN,
                    weight=cfg.ancient_temper,
                    reason=(
                        f"Ancient finding ({age_days}d) with no CISA KEV and no IBM PSIRT "
                        "confirmation — temper so museum CVEs do not dominate modern Power triage."
                    ),
                    evidence={"age_days": age_days},
                )
            )
        elif (
            age_days >= cfg.aging_no_psirt_days
            and not finding.on_kev
            and finding.ibm_bulletin_status != "confirmed"
        ):
            levers.append(
                Lever(
                    id="aging_no_psirt_temper",
                    source="Operational recency",
                    direction=LeverDirection.DOWN,
                    weight=cfg.aging_no_psirt_temper,
                    reason=(
                        f"Aging finding ({age_days}d) without IBM PSIRT confirmation — "
                        "keep visible, but below actively governed issues."
                    ),
                    evidence={"age_days": age_days},
                )
            )

    finding.levers = levers
    finding.score = round(sum(lev.weight for lev in levers), 2)
    finding.bucket = bucketize(finding, cfg)

    # Hard demote: museum CVEs without KEV / PSIRT cannot lead Urgent or Watch,
    # even when CVSS + hot EPSS still clear the numeric floors after tempering.
    is_museum = any(lev.id == "ancient_unconfirmed_temper" for lev in levers)
    if is_museum and not finding.on_kev:
        finding.bucket = Bucket.LOW
        finding.score = min(finding.score, cfg.watch_floor - 0.01)

    if not finding.nvd_url:
        # Prefer CVE.org — NVD HTML detail pages often 502/timeout in browsers.
        finding.nvd_url = f"https://www.cve.org/CVERecord?id={finding.cve_id}"
    return finding


def bucketize(finding: Finding, cfg: RankerConfig | None = None) -> Bucket:
    cfg = cfg or RankerConfig()
    # KEV is an absolute escalator into Urgent (analyst non-negotiable).
    if finding.on_kev:
        return Bucket.URGENT
    if finding.score >= cfg.urgent_floor:
        return Bucket.URGENT
    if finding.score >= cfg.watch_floor:
        return Bucket.WATCH
    return Bucket.LOW


def rank_findings(
    findings: Iterable[Finding], cfg: RankerConfig | None = None
) -> list[Finding]:
    cfg = cfg or RankerConfig()
    ranked = [apply_levers(f, cfg) for f in findings]
    bucket_order = {Bucket.URGENT: 0, Bucket.WATCH: 1, Bucket.LOW: 2}
    ranked.sort(key=lambda f: (bucket_order[f.bucket], -f.score, f.cve_id))
    return ranked


def build_metrics(findings: list[Finding]) -> TriageMetrics:
    by_platform: dict[str, int] = {}
    lever_net: dict[str, float] = {}
    for f in findings:
        for p in f.platforms:
            by_platform[p.platform.value] = by_platform.get(p.platform.value, 0) + 1
        for lev in f.levers:
            lever_net[lev.id] = lever_net.get(lev.id, 0.0) + lev.weight

    return TriageMetrics(
        total=len(findings),
        urgent=sum(1 for f in findings if f.bucket == Bucket.URGENT),
        watch=sum(1 for f in findings if f.bucket == Bucket.WATCH),
        low=sum(1 for f in findings if f.bucket == Bucket.LOW),
        kev_hits=sum(1 for f in findings if f.on_kev),
        psirt_confirmed=sum(
            1 for f in findings if f.ibm_bulletin_status == "confirmed"
        ),
        high_epss=sum(1 for f in findings if f.epss is not None and f.epss >= 0.1),
        owasp_mapped=sum(1 for f in findings if f.owasp_top10),
        by_platform=by_platform,
        lever_net_contribution={k: round(v, 2) for k, v in lever_net.items()},
    )
