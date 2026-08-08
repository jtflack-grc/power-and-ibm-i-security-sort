from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Platform(str, Enum):
    IBM_I = "ibm_i"
    AIX = "aix"
    LINUX_ON_POWER = "linux_on_power"
    ZOS = "zos"


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
    job_id: str
    generated_at: str
    findings: list[Finding]
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
