"""
Classify findings as platform-native vs supply-chain / TPRM surface,
and assign an action lane for actionable visual motion.
"""

from __future__ import annotations

import re
from typing import Literal

from app.models import Finding

RiskSurface = Literal["platform", "supply_chain", "mixed"]
ActionLane = Literal["apply", "contain", "monitor"]

# Third-party / open-source stack that commonly rides on IBM i.
SUPPLY_CHAIN_PATTERNS = [
    r"\bapache\b",
    r"\btomcat\b",
    r"\bopenssh\b",
    r"\bopenssl\b",
    r"\bopenjdk\b",
    r"\bjava\b",
    r"\bnodejs\b",
    r"\bnode\.js\b",
    r"\bpython\b",
    r"\bphp\b",
    r"\bnginx\b",
    r"\bcurl\b",
    r"\bgit\b",
    r"\bdocker\b",
    r"\bkubernetes\b",
    r"\blog4j\b",
    r"\bspring\b",
    r"\bwebkit\b",
    r"\bfirefox\b",
    r"\bchromium\b",
    r"\bpostgres\b",
    r"\bmysql\b",
    r"\bmariadb\b",
    r"\bredis\b",
    r"\bsamba\b",
    r"\bbind9?\b",
    r"\bsudo\b",
    r"\bglibc\b",
    r"\bdocker\b",
    r"\bkubernetes\b",
    r"\bpowershell\b",
    r"\bcisco\b",
    r"\bvmware\b",
    r"\borg\.apache\b",
]

PLATFORM_NATIVE_PATTERNS = [
    r"\bibm i\b",
    r"\bos/400\b",
    r"\bos400\b",
    r"\bdb2 for i\b",
    r"\bqsys\b",
    r"\bqsys2\b",
    r"\bpase\b",
]


def _blob(finding: Finding) -> str:
    parts = [
        finding.title or "",
        finding.description or "",
        " ".join(finding.cwes or []),
        " ".join(finding.owasp_top10 or []),
        " ".join(p.platform.value for p in finding.platforms),
        " ".join(
            prod
            for p in finding.platforms
            for prod in (p.products or [])
        ),
    ]
    return " ".join(parts).lower()


def classify_risk_surface(finding: Finding) -> RiskSurface:
    text = _blob(finding)
    supply = any(re.search(p, text) for p in SUPPLY_CHAIN_PATTERNS)
    # OWASP A06 is explicitly third-party / outdated components
    if any("A06" in o for o in finding.owasp_top10):
        supply = True
    native = any(re.search(p, text) for p in PLATFORM_NATIVE_PATTERNS)
    # CPE match for OS platforms alone doesn't force native if description is Java/Apache
    if supply and native:
        return "mixed"
    if supply:
        return "supply_chain"
    return "platform"


def _has_package_fix(finding: Finding) -> bool:
    for step in finding.resolution_steps or []:
        kind = str(step.get("kind", "")).lower()
        if kind in {"ptf", "apar", "bulletin", "summary"}:
            # "unknown" kinds don't count; bulletin alone is a package path
            if kind == "summary" and "no packaged" in str(step.get("detail", "")).lower():
                continue
            return True
        title = str(step.get("title", "")).lower()
        if title.startswith("ptf ") or title.startswith("apar "):
            return True
        if "security bulletin" in title:
            return True
    return False


def _has_useful_interim(finding: Finding) -> bool:
    for step in finding.interim_mitigations or []:
        if str(step.get("kind", "")) != "unknown":
            return True
    return bool(finding.interim_mitigations)


def assign_action_lane(finding: Finding) -> ActionLane:
    """
    Actionable destination — not an urgency color.

    apply   = packaged fix path known (PTF/APAR/bulletin)
    contain = no package yet, but interim controls exist (or KEV demands action)
    monitor = tempered / no immediate work product beyond watch
    """
    if _has_package_fix(finding):
        return "apply"
    if finding.on_kev or _has_useful_interim(finding):
        # KEV without extracted PTF still needs containment motion
        if finding.on_kev and not _has_package_fix(finding):
            return "contain"
        if _has_useful_interim(finding) and finding.bucket.value in {"urgent", "watch"}:
            return "contain"
        if _has_useful_interim(finding) and not _has_package_fix(finding):
            # Only "No packaged fix" style unknowns → still contain if interims exist
            only_unknown = all(
                str(s.get("kind")) == "unknown" for s in (finding.resolution_steps or [])
            )
            if only_unknown or not finding.resolution_steps:
                return "contain"
    if finding.bucket.value == "low":
        return "monitor"
    # Watch/urgent without package → contain if we have any interim, else monitor
    if _has_useful_interim(finding):
        return "contain"
    return "monitor"


def annotate_surfaces(findings: list[Finding]) -> None:
    for f in findings:
        f.risk_surface = classify_risk_surface(f)
        f.action_lane = assign_action_lane(f)
