# Threat model

## Protected claims and assets

- PSIRT remains the admission authority.
- A PTF is not represented as release-applicable without source-supported structure.
- Synthetic 5250 output is not represented as production evidence.
- Credentials, private inventory, and shop context do not leave the browser.

| Threat | Control | Residual limitation |
|---|---|---|
| Malformed feed content | HTTPS allowlists, bounded streaming, limits, text sanitization | Public sources can still be inaccurate |
| NVD becomes discovery authority | PSIRT-only admission and publication assertions | Local degraded mode is intentionally narrower |
| Empty feed replaces healthy queue | CVE/bulletin floors and fail-before-deploy | Prior deployment can become stale; UI warns after 48 hours |
| PTF paired to wrong release | Same-row association; ambiguity remains unassociated | IBM table changes require parser maintenance |
| Arbitrary terminal or host access | Named fixtures, validated fields, fixed origin, no transport | Scenario is educational, not observed state |
| XSS from bulletin HTML | Text extraction, sanitization, React text rendering | External links still leave the application |
| Sensitive inventory disclosure | Session-local handling and no upload | Users must sanitize exported or shared material |

## Non-goals

This is not a scanner of record, Fix Central replacement, authenticated vulnerability-management platform, ticketing system, or proof that a production partition is compliant.
