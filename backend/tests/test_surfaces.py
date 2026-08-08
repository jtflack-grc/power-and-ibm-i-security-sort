from app.models import Bucket, Finding, Platform, PlatformHit
from app.scoring.surfaces import assign_action_lane, classify_risk_surface


def test_ibm_i_java_is_supply_chain():
    f = Finding(
        cve_id="CVE-2099-1001",
        title="IBM Java on IBM i",
        description="OpenJDK vulnerability affecting IBM i Java PASE.",
        platforms=[PlatformHit(platform=Platform.IBM_I, match_strength="keyword")],
    )
    assert classify_risk_surface(f) in {"supply_chain", "mixed"}


def test_aix_native_is_platform():
    f = Finding(
        cve_id="CVE-2099-1002",
        title="AIX kernel privilege issue",
        description="Privilege escalation in IBM AIX kernel subsystem.",
        platforms=[PlatformHit(platform=Platform.AIX, match_strength="cpe")],
    )
    assert classify_risk_surface(f) == "platform"


def test_action_lane_apply_with_ptf():
    f = Finding(
        cve_id="CVE-2099-1003",
        title="Fixable",
        description="Has a fix",
        platforms=[PlatformHit(platform=Platform.IBM_I)],
        resolution_steps=[
            {"title": "PTF SI12345", "detail": "Apply this", "kind": "ptf"}
        ],
        interim_mitigations=[{"title": "Temp", "detail": "x", "kind": "interim"}],
    )
    assert assign_action_lane(f) == "apply"


def test_action_lane_contain_without_package():
    f = Finding(
        cve_id="CVE-2099-1004",
        title="No package",
        description="Wait for PTF",
        bucket=Bucket.URGENT,
        platforms=[PlatformHit(platform=Platform.AIX)],
        resolution_steps=[
            {
                "title": "No packaged fix resolved yet",
                "detail": "None",
                "kind": "unknown",
            }
        ],
        interim_mitigations=[
            {"title": "Reduce exposure", "detail": "ACL", "kind": "interim"}
        ],
    )
    assert assign_action_lane(f) == "contain"
