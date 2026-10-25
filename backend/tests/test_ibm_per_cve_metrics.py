from app.collectors.ibm_psirt import enrich_psirt_from_nvd, parse_psirt_payload
from app.models import Finding


def bulletin(details):
    return {"results": [{
        "title": "IBM i Java [CVE-2026-18193, CVE-2026-18249, CVE-2026-17476]",
        "field_product": "IBM i",
        "field_affected_products": "IBM i 7.5",
        "field_published_url": "https://www.ibm.com/support/pages/node/7283283",
        "field_cvss_desc": "Multiple vulnerabilities affect Java.",
        "field_cvss_base_score": "Critical",
        "field_vulnerability_details": details,
    }]}


def test_bind_ibm_scores_and_prerequisites_to_the_exact_cve_section():
    # Distinct entries from the IBM bulletin's CVE-specific structure.
    findings = parse_psirt_payload(bulletin("""
        <p>CVEID: CVE-2026-18193</p>
        <p>DESCRIPTION: Remote attacker may bypass security restrictions.</p>
        <p>CWE: CWE-269</p><p>CVSS Source: IBM</p><p>CVSS Base score: 8.9</p>
        <p>CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L)</p>
        <p>CVEID: CVE-2026-18249</p>
        <p>DESCRIPTION: Remote authenticated attacker may gain elevated privileges.</p>
        <p>CWE: CWE-269</p><p>CVSS Source: IBM</p><p>CVSS Base score: 8.4</p>
        <p>CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L)</p>
        <p>CVEID: CVE-2026-17476</p><p>DESCRIPTION: Buffer write may cause denial of service.</p>
        <p>CWE: CWE-787</p><p>CVSS Base score: 4.8</p>
        <p>CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L)</p>
    """))
    assert findings["CVE-2026-18193"].ibm_cvss_score == 8.9
    assert findings["CVE-2026-18193"].cvss_score == 8.9
    assert findings["CVE-2026-18193"].cvss_source == "IBM"
    assert "/PR:N/" in findings["CVE-2026-18193"].ibm_cvss_vector
    assert findings["CVE-2026-18249"].ibm_cvss_score == 8.4
    assert "/PR:L/" in findings["CVE-2026-18249"].ibm_cvss_vector
    assert "authenticated" in findings["CVE-2026-18249"].ibm_vulnerability_description
    assert "Buffer write" not in findings["CVE-2026-18249"].ibm_vulnerability_description
    assert findings["CVE-2026-17476"].ibm_cvss_score == 4.8


def test_group_summary_and_adjacent_cve_metrics_do_not_leak():
    findings = parse_psirt_payload(bulletin("""
        CVEID: CVE-2026-18193 DESCRIPTION: Explicit first section.
        CVSS Base score: 8.9 CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L
        CVEID: CVE-2026-18249 DESCRIPTION: This section has no numeric metrics.
    """))
    assert findings["CVE-2026-18249"].ibm_cvss_score is None
    assert findings["CVE-2026-18249"].ibm_cvss_vector is None
    assert findings["CVE-2026-17476"].ibm_vulnerability_description is None
    unstructured = parse_psirt_payload(bulletin("CVSS Base score: 9.8 applies somewhere in the bulletin"))
    assert all(f.ibm_cvss_score is None for f in unstructured.values())
    assert all(f.cvss_severity is None for f in unstructured.values())


def test_nvd_enrichment_keeps_ibm_specific_metrics_separate():
    findings = parse_psirt_payload(bulletin("CVEID: CVE-2026-18193 DESCRIPTION: IBM-specific. CVSS Base score: 8.9 CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L"))
    extra = Finding(cve_id="CVE-2026-18193", title="NVD", description="Different general description", cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    result = enrich_psirt_from_nvd(findings, {extra.cve_id: extra})[extra.cve_id]
    assert result.cvss_score == 10.0
    assert result.ibm_cvss_score == 8.9
    assert "AC:H" in result.ibm_cvss_vector
    assert result.ibm_vulnerability_description == "IBM-specific."
    assert result.cvss_source == "NVD"


def test_missing_nvd_score_does_not_erase_ibm_public_score():
    findings = parse_psirt_payload(bulletin("CVEID: CVE-2026-18193 DESCRIPTION: IBM-specific. CVSS Base score: 8.9 CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L"))
    extra = Finding(cve_id="CVE-2026-18193", title="NVD", description="Unenriched NVD record")
    result = enrich_psirt_from_nvd(findings, {extra.cve_id: extra})[extra.cve_id]
    assert result.cvss_score == 8.9
    assert result.cvss_source == "IBM"
    assert result.cvss_vector == result.ibm_cvss_vector
