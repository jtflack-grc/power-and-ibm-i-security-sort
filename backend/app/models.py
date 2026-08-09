from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Platform(str, Enum):
    IBM_I = "ibm_i"


class Bucket(str, Enum):
    URGENT = "urgent"
    WATCH = "watch"
    LOW = "low"


class LeverDirection(str, Enum):
    UP = "up"
    DOWN = "down"


class Lever(BaseModel):
    """One scoring counter-lever — a discrete signal that raises or lowers priority."""

    id: str
    source: str
    direction: LeverDirection
    weight: float
    reason: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class PlatformHit(BaseModel):
    platform: Platform
    match_strength: Literal["cpe", "keyword"] = "keyword"
    products: list[str] = Field(default_factory=list)


class BulletinApplicability(BaseModel):
    """One source-supported product/release row from an IBM bulletin."""

    applicability_id: str
    product_id: str | None = None
    product_name: str
    component_type: Literal[
        "operating_system",
        "licensed_internal_code",
        "licensed_program",
        "bundled_component",
        "unknown",
    ] = "unknown"
    release: str | None = None
    release_system: str | None = None
    individual_ptfs: list[str] = Field(default_factory=list)
    group_ptfs: list[str] = Field(default_factory=list)
    apars: list[str] = Field(default_factory=list)
    source_excerpt: str = ""
    source_url: str = ""
    confidence: Literal["structured", "heuristic", "unresolved"] = "unresolved"


class Bulletin(BaseModel):
    """IBM Security Bulletin as the remediation-work unit."""

    bulletin_id: str
    url: str
    title: str
    published: str | None = None
    last_modified: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    applicability: list[BulletinApplicability] = Field(default_factory=list)
    unassociated_individual_ptfs: list[str] = Field(default_factory=list)
    unassociated_group_ptfs: list[str] = Field(default_factory=list)
    unassociated_apars: list[str] = Field(default_factory=list)
    affected_source_text: str = ""


class Finding(BaseModel):
    cve_id: str
    title: str
    description: str
    published: str | None = None
    last_modified: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cwes: list[str] = Field(default_factory=list)
    platforms: list[PlatformHit] = Field(default_factory=list)
    on_kev: bool = False
    kev_ransomware: bool = False
    kev_date_added: str | None = None
    kev_required_action: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    ibm_bulletin_url: str | None = None
    ibm_bulletin_title: str | None = None
    ibm_bulletin_status: Literal["confirmed", "unconfirmed", "not_checked"] = "not_checked"
    bulletin_id: str | None = None
    owasp_top10: list[str] = Field(default_factory=list)
    nvd_url: str = ""
    score: float = 0.0
    bucket: Bucket = Bucket.LOW
    levers: list[Lever] = Field(default_factory=list)
    resolution_steps: list[dict[str, Any]] = Field(default_factory=list)
    interim_mitigations: list[dict[str, Any]] = Field(default_factory=list)
    risk_surface: Literal["platform", "supply_chain", "mixed"] = "platform"
    action_lane: Literal["apply", "contain", "monitor"] = "monitor"


class TriageMetrics(BaseModel):
    total: int = 0
    urgent: int = 0
    watch: int = 0
    low: int = 0
    kev_hits: int = 0
    psirt_confirmed: int = 0
    high_epss: int = 0
    owasp_mapped: int = 0
    by_platform: dict[str, int] = Field(default_factory=dict)
    lever_net_contribution: dict[str, float] = Field(default_factory=dict)


class TriageResult(BaseModel):
    schema_version: str = "2.0"
    job_id: str
    generated_at: str
    findings: list[Finding]
    bulletins: list[Bulletin] = Field(default_factory=list)
    metrics: TriageMetrics
    sources: list[str]
    mode: Literal["sample", "live"] = "live"
    feed_health: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    flagship_cve: str | None = None


class ProgressEvent(BaseModel):
    stage: str
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
    pct: int = 0
