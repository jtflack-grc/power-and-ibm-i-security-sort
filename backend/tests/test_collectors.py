from app.collectors.nvd import _keyword_text_match, _extract_ibm_bulletin
from app.models import Platform
from app.scoring.guidance import APAR_RE, GROUP_PTF_TOKEN_RE, PTF_TOKEN_RE, attach_guidance
from app.models import Finding, PlatformHit


def test_keyword_filter_rejects_unrelated_noise():
    item = {
        "cve": {
            "id": "CVE-2099-1000",
            "descriptions": [
                {"lang": "en", "value": "A vulnerability in an unrelated network appliance."}
            ],
            "configurations": [],
        }
    }
    assert _keyword_text_match(item, Platform.IBM_I) is False


def test_keyword_filter_accepts_ibm_i_signal():
    item = {
        "cve": {
            "id": "CVE-2099-1001",
            "descriptions": [
                {"lang": "en", "value": "IBM i allows an authenticated user to escalate privileges."}
            ],
            "configurations": [],
        }
    }
    assert _keyword_text_match(item, Platform.IBM_I) is True


def test_nvd_bulletin_prefers_node_over_seo_slug():
    # SEO slugs often dump into IBM support-search dead-ends; node IDs are durable.
    refs = [
        {
            "url": "https://www.ibm.com/support/pages/security-bulletin-cve-2099",
            "tags": ["Vendor Advisory"],
        },
        {"url": "https://www.ibm.com/support/pages/node/123", "tags": ["Third Party Advisory"]},
    ]
    url, title = _extract_ibm_bulletin(refs)
    assert url == "https://www.ibm.com/support/pages/node/123"
    assert "Bulletin" in (title or "")


def test_ptf_apar_token_parse():
    blob = "Apply PTF SI71234 or modern PTF SJ03022 and group SF99740; APAR IJ45678; also IV11222."
    assert "SI71234" in {t.upper() for t in PTF_TOKEN_RE.findall(blob)}
    assert "SJ03022" in {t.upper() for t in PTF_TOKEN_RE.findall(blob)}
    assert "SF99740" in {t.upper() for t in GROUP_PTF_TOKEN_RE.findall(blob)}
    apars = [(m.group(1) or m.group(0)).upper() for m in APAR_RE.finditer(blob)]
    assert "IJ45678" in apars
    assert "IV11222" in apars


def test_attach_guidance_always_has_fix_central():
    f = Finding(
        cve_id="CVE-2099-2000",
        title="Test",
        description="Test finding",
        platforms=[PlatformHit(platform=Platform.IBM_I, match_strength="cpe")],
    )
    out = attach_guidance(f, {})
    kinds = {str(s.get("kind")) for s in out.resolution_steps}
    assert "fixcentral" in kinds or "search" in kinds
    assert out.interim_mitigations
