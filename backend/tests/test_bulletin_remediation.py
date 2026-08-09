from bs4 import BeautifulSoup

from app.models import Bulletin, BulletinApplicability
from app.scoring.guidance import _extract_table_remediation_rows, attach_bulletin_remediation


def test_table_row_preserves_release_to_ptf_relationship():
    soup = BeautifulSoup("""
      <table>
        <tr><th>IBM i release</th><th>Product</th><th>PTF</th><th>APAR</th></tr>
        <tr><td>7.4</td><td>5770-SS1</td><td>SJ10866</td><td>APAR MA51234</td></tr>
        <tr><td>7.5</td><td>5770-SS1</td><td>SJ10925</td><td>APAR MA51235</td></tr>
      </table>
    """, "lxml")
    rows = _extract_table_remediation_rows(soup, "https://www.ibm.com/support/pages/node/1")
    assert [(row["release"], row["individual_ptfs"]) for row in rows] == [
        ("7.4", ["SJ10866"]),
        ("7.5", ["SJ10925"]),
    ]
    assert rows[0]["product_id"] == "5770SS1"
    assert rows[0]["apars"] == ["MA51234"]


def test_ambiguous_fix_tokens_remain_unassociated():
    bulletin = Bulletin(
        bulletin_id="ibm-psirt-1",
        url="https://www.ibm.com/support/pages/node/1",
        title="Example",
        applicability=[
            BulletinApplicability(
                applicability_id="a1", product_id="5770SS1", product_name="IBM i",
                release="7.4", release_system="V7R4M0"
            )
        ],
    )
    records = {bulletin.url: {
        "ptfs": ["SJ10866", "SJ99999"], "ptf_groups": [], "apars": [],
        "remediation_rows": [{
            "release": "7.4", "product_id": "5770SS1",
            "individual_ptfs": ["SJ10866"], "group_ptfs": [], "apars": [],
            "source_excerpt": "IBM i 7.4 5770-SS1 SJ10866",
        }],
    }}
    attach_bulletin_remediation([bulletin], records)
    assert bulletin.applicability[0].individual_ptfs == ["SJ10866"]
    assert bulletin.unassociated_individual_ptfs == ["SJ99999"]


def test_row_without_release_is_not_associated():
    soup = BeautifulSoup("<table><tr><td>IBM i</td><td>SJ10866</td></tr></table>", "lxml")
    row = _extract_table_remediation_rows(soup, "https://www.ibm.com/support/pages/node/1")[0]
    assert row["release"] is None
    assert row["confidence"] == "unresolved"
