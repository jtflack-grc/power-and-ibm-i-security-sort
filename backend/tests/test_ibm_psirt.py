from app.collectors.ibm_psirt import enrich_psirt_from_nvd, parse_psirt_bundle, parse_psirt_payload
from app.models import Finding, Platform, PlatformHit


def test_psirt_expands_grouped_bulletin_and_rejects_non_ibmi():
    payload = {
        "results": [
            {
                "title": "IBM i is affected [CVE-2026-10001, CVE-2026-10002]",
                "field_product": "IBM i",
                "field_affected_products": "<table><tr><td>IBM i</td><td>7.5</td></tr></table>",
                "field_cvss_desc": "Two vulnerabilities affect the product.",
                "field_cvss_base_score": "High",
                "field_pub_date": "2026-08-01T00:00:00Z",
                "field_published_url": "https://www.ibm.com/support/pages/node/1234567?x=y",
            },
            {
                "title": "Other product [CVE-2026-99999]",
                "field_product": "Unrelated appliance",
                "field_affected_products": "Unrelated appliance 1.0",
                "field_published_url": "https://www.ibm.com/support/pages/node/7654321",
            },
        ]
    }
    findings = parse_psirt_payload(payload)
    assert set(findings) == {"CVE-2026-10001", "CVE-2026-10002"}
    assert findings["CVE-2026-10001"].published == "2026-08-01"
    assert findings["CVE-2026-10001"].ibm_bulletin_url == "https://www.ibm.com/support/pages/node/1234567"


def test_nvd_enriches_but_cannot_add_a_finding():
    psirt = parse_psirt_payload({
        "results": [{
            "title": "IBM i bulletin CVE-2026-10001",
            "field_product": "IBM i",
            "field_affected_products": "IBM i 7.6",
            "field_published_url": "https://www.ibm.com/support/pages/node/123",
        }]
    })
    nvd = {
        "CVE-2026-10001": Finding(
            cve_id="CVE-2026-10001", title="NVD", description="NVD description",
            cvss_score=9.8, cwes=["CWE-79"],
            platforms=[PlatformHit(platform=Platform.IBM_I, match_strength="cpe")],
        ),
        "CVE-2026-99999": Finding(
            cve_id="CVE-2026-99999", title="Noise", description="Noise"
        ),
    }
    merged = enrich_psirt_from_nvd(psirt, nvd)
    assert set(merged) == {"CVE-2026-10001"}
    assert merged["CVE-2026-10001"].cvss_score == 9.8
    assert merged["CVE-2026-10001"].cwes == ["CWE-79"]
    assert merged["CVE-2026-10001"].platforms[0].match_strength == "cpe"


def test_psirt_can_apply_a_bulletin_publication_window():
    payload = {"results": [
        {
            "title": "Current IBM i bulletin CVE-2026-10001",
            "field_product": "IBM i",
            "field_affected_products": "IBM i 7.6",
            "field_pub_date": "2026-01-02",
            "field_published_url": "https://www.ibm.com/support/pages/node/1",
        },
        {
            "title": "Archived IBM i bulletin CVE-2020-10001",
            "field_product": "IBM i",
            "field_affected_products": "IBM i 7.3",
            "field_pub_date": "2020-01-02",
            "field_published_url": "https://www.ibm.com/support/pages/node/2",
        },
    ]}
    findings = parse_psirt_payload(payload, published_after="2025-01-01")
    assert set(findings) == {"CVE-2026-10001"}


def test_psirt_preserves_bulletin_membership_and_release_rows():
    payload = {"results": [{
        "title": "IBM i grouped bulletin [CVE-2026-10001, CVE-2026-10002]",
        "field_product": "IBM i 5770-SS1",
        "field_affected_products": """
            <table>
              <tr><th>Product</th><th>Release</th></tr>
              <tr><td>IBM i 5770-SS1</td><td>7.4</td></tr>
              <tr><td>IBM i 5770-SS1</td><td>7.5</td></tr>
            </table>
        """,
        "field_pub_date": "2026-08-01",
        "field_published_url": "https://www.ibm.com/support/pages/node/1234567",
    }]}
    bundle = parse_psirt_bundle(payload)
    assert len(bundle.bulletins) == 1
    bulletin = bundle.bulletins[0]
    assert bulletin.bulletin_id == "ibm-psirt-1234567"
    assert bulletin.cve_ids == ["CVE-2026-10001", "CVE-2026-10002"]
    assert [row.release for row in bulletin.applicability] == ["7.4", "7.5"]
    assert [row.release_system for row in bulletin.applicability] == ["V7R4M0", "V7R5M0"]
    assert all(row.product_id == "5770SS1" for row in bulletin.applicability)
    assert all(row.component_type == "operating_system" for row in bulletin.applicability)
    assert all(not row.individual_ptfs for row in bulletin.applicability)
    assert all(f.bulletin_id == bulletin.bulletin_id for f in bundle.findings.values())


def test_psirt_does_not_invent_release_when_source_is_ambiguous():
    payload = {"results": [{
        "title": "IBM i bulletin CVE-2026-10001",
        "field_product": "IBM i",
        "field_affected_products": "Supported IBM i environments",
        "field_published_url": "https://www.ibm.com/support/pages/node/42",
    }]}
    row = parse_psirt_bundle(payload).bulletins[0].applicability[0]
    assert row.release is None
    assert row.release_system is None
    assert row.individual_ptfs == []


def test_psirt_release_parser_does_not_treat_unrelated_digits_as_releases():
    payload = {"results": [{
        "title": "IBM i bulletin CVE-2026-10001",
        "field_product": "IBM i",
        "field_affected_products": "IBM i application with 4 affected components and CVSS 5",
        "field_published_url": "https://www.ibm.com/support/pages/node/43",
    }]}
    row = parse_psirt_bundle(payload).bulletins[0].applicability[0]
    assert row.release is None
    assert row.release_system is None
