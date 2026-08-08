"""Unit tests for counter-lever ranking logic."""

from app.models import Finding, Platform, PlatformHit
from app.scoring.ranker import apply_levers, bucketize
from app.scoring.owasp_map import map_cwes_to_owasp


def test_kev_is_absolute_urgent():
    f = Finding(
        cve_id="CVE-2021-44228",
        title="Log4Shell",
        description="Remote code execution",
        cvss_score=10.0,
        on_kev=True,
        epss=0.97,
        platforms=[PlatformHit(platform=Platform.LINUX_ON_POWER, match_strength="keyword")],
    )
    apply_levers(f)
    assert f.bucket.value == "urgent"
    assert any(l.id == "cisa_kev" for l in f.levers)


def test_epss_tempers_high_cvss_without_kev():
    f = Finding(
        cve_id="CVE-2099-0001",
        title="Paper critical",
        description="Scary but unused",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        on_kev=False,
        epss=0.0005,
        published="2025-06-01T00:00:00.000",
        platforms=[PlatformHit(platform=Platform.AIX, match_strength="cpe")],
    )
    apply_levers(f)
    assert any(l.id == "epss_vs_cvss_temper" for l in f.levers)
    assert f.bucket.value != "urgent"


def test_owasp_injection_maps():
    cats = map_cwes_to_owasp(["CWE-89", "CWE-79"])
    assert any("Injection" in c for c in cats)


def test_local_vector_tempers():
    f = Finding(
        cve_id="CVE-2099-0002",
        title="Local only",
        description="Needs local access",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        epss=0.02,
        published="2025-01-01T00:00:00.000",
        platforms=[PlatformHit(platform=Platform.IBM_I, match_strength="cpe")],
    )
    apply_levers(f)
    assert any(l.id == "cvss_av_local" for l in f.levers)


def test_psirt_confirmed_boosts():
    f = Finding(
        cve_id="CVE-2099-0003",
        title="Bulletin backed",
        description="IBM confirmed",
        cvss_score=7.5,
        published="2025-01-01T00:00:00.000",
        ibm_bulletin_status="confirmed",
        ibm_bulletin_url="https://www.ibm.com/support/pages/node/1",
        platforms=[PlatformHit(platform=Platform.IBM_I, match_strength="cpe")],
        cwes=["CWE-427"],
    )
    apply_levers(f)
    assert any(l.id == "ibm_psirt_confirmed" for l in f.levers)
    assert any(l.id == "owasp_top10" for l in f.levers)


def test_bucketize_watch_band():
    f = Finding(cve_id="CVE-2099-0004", title="t", description="d", score=50)
    assert bucketize(f).value == "watch"


def test_ancient_temper_applies():
    f = Finding(
        cve_id="CVE-2001-0797",
        title="Ancient",
        description="Old news",
        published="2001-01-01T00:00:00.000",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss=0.9,
        on_kev=False,
        ibm_bulletin_status="unconfirmed",
        platforms=[PlatformHit(platform=Platform.AIX, match_strength="cpe")],
    )
    apply_levers(f)
    assert any(l.id == "ancient_unconfirmed_temper" for l in f.levers)
    # High EPSS alone should not keep museum CVE glued to Urgent without KEV/PSIRT.
    assert f.bucket.value == "low"


def test_ancient_seven_year_cutoff_hard_demotes():
    """~8yo unconfirmed museum CVE must not lead Urgent even with hot EPSS."""
    f = Finding(
        cve_id="CVE-2017-9999",
        title="Aging museum",
        description="Still scored hot on paper",
        published="2017-01-01T00:00:00.000",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss=0.97,
        on_kev=False,
        ibm_bulletin_status="unconfirmed",
        platforms=[PlatformHit(platform=Platform.IBM_I, match_strength="cpe")],
    )
    apply_levers(f)
    assert any(l.id == "ancient_unconfirmed_temper" for l in f.levers)
    assert f.bucket.value == "low"
    assert f.score < 35.0


def test_ancient_kev_still_urgent():
    f = Finding(
        cve_id="CVE-2014-0160",
        title="Heartbleed-class KEV",
        description="Old but actively catalogued",
        published="2014-04-07T00:00:00.000",
        cvss_score=7.5,
        on_kev=True,
        ibm_bulletin_status="unconfirmed",
        platforms=[PlatformHit(platform=Platform.LINUX_ON_POWER, match_strength="cpe")],
    )
    apply_levers(f)
    assert f.bucket.value == "urgent"
