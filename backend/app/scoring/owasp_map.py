"""
OWASP Top 10 (2021) ↔ CWE counter-lever map.

Not every CWE in a Top 10 category should auto-escalate priority; this map
is a *supporting* lever. High-severity categories (A01, A03, A07, A08) get
stronger upward weights; documentation / logging gaps (A09) get softer ones.
Absence from Top 10 is not itself a down-lever — many midrange issues live
outside web-app taxonomy.
"""

from __future__ import annotations

# CWE id (numeric string) → list of OWASP Top 10 2021 category codes
# Sourced from OWASP Top 10 2021 CWE mappings (subset of highest-signal CWEs).
CWE_TO_OWASP_2021: dict[str, list[str]] = {
    # A01 Broken Access Control
    "22": ["A01:2021-Broken Access Control"],
    "23": ["A01:2021-Broken Access Control"],
    "35": ["A01:2021-Broken Access Control"],
    "59": ["A01:2021-Broken Access Control"],
    "200": ["A01:2021-Broken Access Control"],
    "201": ["A01:2021-Broken Access Control"],
    "219": ["A01:2021-Broken Access Control"],
    "264": ["A01:2021-Broken Access Control"],
    "275": ["A01:2021-Broken Access Control"],
    "276": ["A01:2021-Broken Access Control"],
    "284": ["A01:2021-Broken Access Control"],
    "285": ["A01:2021-Broken Access Control"],
    "352": ["A01:2021-Broken Access Control"],
    "359": ["A01:2021-Broken Access Control"],
    "377": ["A01:2021-Broken Access Control"],
    "402": ["A01:2021-Broken Access Control"],
    "425": ["A01:2021-Broken Access Control"],
    "441": ["A01:2021-Broken Access Control"],
    "497": ["A01:2021-Broken Access Control"],
    "538": ["A01:2021-Broken Access Control"],
    "540": ["A01:2021-Broken Access Control"],
    "548": ["A01:2021-Broken Access Control"],
    "552": ["A01:2021-Broken Access Control"],
    "566": ["A01:2021-Broken Access Control"],
    "601": ["A01:2021-Broken Access Control"],
    "639": ["A01:2021-Broken Access Control"],
    "651": ["A01:2021-Broken Access Control"],
    "668": ["A01:2021-Broken Access Control"],
    "706": ["A01:2021-Broken Access Control"],
    "785": ["A01:2021-Broken Access Control"],
    "846": ["A01:2021-Broken Access Control"],
    "862": ["A01:2021-Broken Access Control"],
    "863": ["A01:2021-Broken Access Control"],
    "913": ["A01:2021-Broken Access Control"],
    "922": ["A01:2021-Broken Access Control"],
    "1275": ["A01:2021-Broken Access Control"],
    # A02 Cryptographic Failures
    "261": ["A02:2021-Cryptographic Failures"],
    "296": ["A02:2021-Cryptographic Failures"],
    "310": ["A02:2021-Cryptographic Failures"],
    "319": ["A02:2021-Cryptographic Failures"],
    "321": ["A02:2021-Cryptographic Failures"],
    "322": ["A02:2021-Cryptographic Failures"],
    "323": ["A02:2021-Cryptographic Failures"],
    "324": ["A02:2021-Cryptographic Failures"],
    "325": ["A02:2021-Cryptographic Failures"],
    "326": ["A02:2021-Cryptographic Failures"],
    "327": ["A02:2021-Cryptographic Failures"],
    "328": ["A02:2021-Cryptographic Failures"],
    "329": ["A02:2021-Cryptographic Failures"],
    "330": ["A02:2021-Cryptographic Failures"],
    "331": ["A02:2021-Cryptographic Failures"],
    "335": ["A02:2021-Cryptographic Failures"],
    "336": ["A02:2021-Cryptographic Failures"],
    "337": ["A02:2021-Cryptographic Failures"],
    "338": ["A02:2021-Cryptographic Failures"],
    "340": ["A02:2021-Cryptographic Failures"],
    "347": ["A02:2021-Cryptographic Failures"],
    "523": ["A02:2021-Cryptographic Failures"],
    "720": ["A02:2021-Cryptographic Failures"],
    "757": ["A02:2021-Cryptographic Failures"],
    "759": ["A02:2021-Cryptographic Failures"],
    "760": ["A02:2021-Cryptographic Failures"],
    "780": ["A02:2021-Cryptographic Failures"],
    "818": ["A02:2021-Cryptographic Failures"],
    "916": ["A02:2021-Cryptographic Failures"],
    # A03 Injection
    "20": ["A03:2021-Injection"],
    "74": ["A03:2021-Injection"],
    "75": ["A03:2021-Injection"],
    "77": ["A03:2021-Injection"],
    "78": ["A03:2021-Injection"],
    "79": ["A03:2021-Injection"],
    "80": ["A03:2021-Injection"],
    "83": ["A03:2021-Injection"],
    "87": ["A03:2021-Injection"],
    "88": ["A03:2021-Injection"],
    "89": ["A03:2021-Injection"],
    "90": ["A03:2021-Injection"],
    "91": ["A03:2021-Injection"],
    "93": ["A03:2021-Injection"],
    "94": ["A03:2021-Injection"],
    "95": ["A03:2021-Injection"],
    "96": ["A03:2021-Injection"],
    "97": ["A03:2021-Injection"],
    "98": ["A03:2021-Injection"],
    "99": ["A03:2021-Injection"],
    "113": ["A03:2021-Injection"],
    "116": ["A03:2021-Injection"],
    "138": ["A03:2021-Injection"],
    "184": ["A03:2021-Injection"],
    "470": ["A03:2021-Injection"],
    "471": ["A03:2021-Injection"],
    "564": ["A03:2021-Injection"],
    "610": ["A03:2021-Injection"],
    "643": ["A03:2021-Injection"],
    "644": ["A03:2021-Injection"],
    "652": ["A03:2021-Injection"],
    "917": ["A03:2021-Injection"],
    # A04 Insecure Design (selected)
    "73": ["A04:2021-Insecure Design"],
    "183": ["A04:2021-Insecure Design"],
    "209": ["A04:2021-Insecure Design"],
    "213": ["A04:2021-Insecure Design"],
    "235": ["A04:2021-Insecure Design"],
    "256": ["A04:2021-Insecure Design"],
    "257": ["A04:2021-Insecure Design"],
    "266": ["A04:2021-Insecure Design"],
    "269": ["A04:2021-Insecure Design"],
    "280": ["A04:2021-Insecure Design"],
    "311": ["A04:2021-Insecure Design"],
    "312": ["A04:2021-Insecure Design"],
    "313": ["A04:2021-Insecure Design"],
    "316": ["A04:2021-Insecure Design"],
    "419": ["A04:2021-Insecure Design"],
    "430": ["A04:2021-Insecure Design"],
    "434": ["A04:2021-Insecure Design"],
    "444": ["A04:2021-Insecure Design"],
    "451": ["A04:2021-Insecure Design"],
    "472": ["A04:2021-Insecure Design"],
    "501": ["A04:2021-Insecure Design"],
    "522": ["A04:2021-Insecure Design"],
    "525": ["A04:2021-Insecure Design"],
    "539": ["A04:2021-Insecure Design"],
    "579": ["A04:2021-Insecure Design"],
    "598": ["A04:2021-Insecure Design"],
    "602": ["A04:2021-Insecure Design"],
    "642": ["A04:2021-Insecure Design"],
    "646": ["A04:2021-Insecure Design"],
    "650": ["A04:2021-Insecure Design"],
    "653": ["A04:2021-Insecure Design"],
    "656": ["A04:2021-Insecure Design"],
    "657": ["A04:2021-Insecure Design"],
    "799": ["A04:2021-Insecure Design"],
    "807": ["A04:2021-Insecure Design"],
    "840": ["A04:2021-Insecure Design"],
    "841": ["A04:2021-Insecure Design"],
    "927": ["A04:2021-Insecure Design"],
    "1021": ["A04:2021-Insecure Design"],
    "1173": ["A04:2021-Insecure Design"],
    # A05 Security Misconfiguration
    "2": ["A05:2021-Security Misconfiguration"],
    "11": ["A05:2021-Security Misconfiguration"],
    "13": ["A05:2021-Security Misconfiguration"],
    "15": ["A05:2021-Security Misconfiguration"],
    "16": ["A05:2021-Security Misconfiguration"],
    "260": ["A05:2021-Security Misconfiguration"],
    "315": ["A05:2021-Security Misconfiguration"],
    "520": ["A05:2021-Security Misconfiguration"],
    "526": ["A05:2021-Security Misconfiguration"],
    "537": ["A05:2021-Security Misconfiguration"],
    "541": ["A05:2021-Security Misconfiguration"],
    "547": ["A05:2021-Security Misconfiguration"],
    "611": ["A05:2021-Security Misconfiguration"],
    "614": ["A05:2021-Security Misconfiguration"],
    "756": ["A05:2021-Security Misconfiguration"],
    "776": ["A05:2021-Security Misconfiguration"],
    "942": ["A05:2021-Security Misconfiguration"],
    "1004": ["A05:2021-Security Misconfiguration"],
    "1032": ["A05:2021-Security Misconfiguration"],
    "1174": ["A05:2021-Security Misconfiguration"],
    # A06 Vulnerable and Outdated Components — often meta; light up-lever only
    "937": ["A06:2021-Vulnerable and Outdated Components"],
    "1035": ["A06:2021-Vulnerable and Outdated Components"],
    "1104": ["A06:2021-Vulnerable and Outdated Components"],
    # A07 Identification and Authentication Failures
    "255": ["A07:2021-Identification and Authentication Failures"],
    "259": ["A07:2021-Identification and Authentication Failures"],
    "287": ["A07:2021-Identification and Authentication Failures"],
    "288": ["A07:2021-Identification and Authentication Failures"],
    "290": ["A07:2021-Identification and Authentication Failures"],
    "294": ["A07:2021-Identification and Authentication Failures"],
    "295": ["A07:2021-Identification and Authentication Failures"],
    "297": ["A07:2021-Identification and Authentication Failures"],
    "300": ["A07:2021-Identification and Authentication Failures"],
    "302": ["A07:2021-Identification and Authentication Failures"],
    "304": ["A07:2021-Identification and Authentication Failures"],
    "306": ["A07:2021-Identification and Authentication Failures"],
    "307": ["A07:2021-Identification and Authentication Failures"],
    "346": ["A07:2021-Identification and Authentication Failures"],
    "384": ["A07:2021-Identification and Authentication Failures"],
    "521": ["A07:2021-Identification and Authentication Failures"],
    "613": ["A07:2021-Identification and Authentication Failures"],
    "620": ["A07:2021-Identification and Authentication Failures"],
    "640": ["A07:2021-Identification and Authentication Failures"],
    "798": ["A07:2021-Identification and Authentication Failures"],
    "1216": ["A07:2021-Identification and Authentication Failures"],
    "1390": ["A07:2021-Identification and Authentication Failures"],
    # A08 Software and Data Integrity Failures
    "345": ["A08:2021-Software and Data Integrity Failures"],
    "353": ["A08:2021-Software and Data Integrity Failures"],
    "426": ["A08:2021-Software and Data Integrity Failures"],
    "427": ["A08:2021-Software and Data Integrity Failures"],
    "494": ["A08:2021-Software and Data Integrity Failures"],
    "502": ["A08:2021-Software and Data Integrity Failures"],
    "565": ["A08:2021-Software and Data Integrity Failures"],
    "784": ["A08:2021-Software and Data Integrity Failures"],
    "829": ["A08:2021-Software and Data Integrity Failures"],
    "830": ["A08:2021-Software and Data Integrity Failures"],
    "915": ["A08:2021-Software and Data Integrity Failures"],
    # A09 Security Logging and Monitoring Failures
    "117": ["A09:2021-Security Logging and Monitoring Failures"],
    "223": ["A09:2021-Security Logging and Monitoring Failures"],
    "778": ["A09:2021-Security Logging and Monitoring Failures"],
    # A10 SSRF
    "918": ["A10:2021-Server-Side Request Forgery"],
}

# Relative upward intensity for OWASP categories (used by ranker).
OWASP_CATEGORY_WEIGHT: dict[str, float] = {
    "A01:2021-Broken Access Control": 18.0,
    "A02:2021-Cryptographic Failures": 14.0,
    "A03:2021-Injection": 20.0,
    "A04:2021-Insecure Design": 10.0,
    "A05:2021-Security Misconfiguration": 12.0,
    "A06:2021-Vulnerable and Outdated Components": 8.0,
    "A07:2021-Identification and Authentication Failures": 18.0,
    "A08:2021-Software and Data Integrity Failures": 16.0,
    "A09:2021-Security Logging and Monitoring Failures": 6.0,
    "A10:2021-Server-Side Request Forgery": 14.0,
}


def normalize_cwe(cwe: str) -> str:
    cwe = cwe.strip().upper()
    if cwe.startswith("CWE-"):
        return cwe[4:]
    return cwe.lstrip("CWE")


def map_cwes_to_owasp(cwes: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for raw in cwes:
        key = normalize_cwe(raw)
        for cat in CWE_TO_OWASP_2021.get(key, []):
            if cat not in seen:
                seen.add(cat)
                found.append(cat)
    return found


def strongest_owasp_weight(categories: list[str]) -> float:
    if not categories:
        return 0.0
    return max(OWASP_CATEGORY_WEIGHT.get(c, 8.0) for c in categories)
