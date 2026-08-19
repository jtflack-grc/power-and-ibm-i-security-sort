from pathlib import Path


KIT = Path(__file__).parents[2] / "frontend" / "public" / "ibmi-cve-fix-evidence.sql"


def test_sql_evidence_kit_keeps_claims_separate():
    sql = KIT.read_text(encoding="utf-8").upper()
    assert "SYSTOOLS.CVE_INFO()" in sql
    assert "QSYS2.PTF_INFO" in sql
    assert "QSYS2.GROUP_PTF_INFO" in sql
    assert "SYSTOOLS.GROUP_PTF_CURRENCY" in sql
    assert "PTF_LOADED_STATUS" in sql
    assert "PTF_IPL_ACTION" in sql
    assert "PTF_SUPERCEDED_BY_PTF" in sql


def test_sql_evidence_kit_documents_74_boundary():
    sql = KIT.read_text(encoding="utf-8")
    assert "IBM i 7.4" in sql
    assert "skip statement 2" in sql
