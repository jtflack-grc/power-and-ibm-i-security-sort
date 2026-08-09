# Ranking model and calibration boundaries

The curator uses two separate decisions: queue order and risk scoring. IBM
bulletin publication date controls the queue. The counter-lever score explains
risk within that operational context; it does not override a newer disclosure
with an older, higher-scoring CVE.

Queue order is:

1. IBM bulletin publication date, newest first.
2. CISA KEV status within the same publication date.
3. Counter-lever score within the same date and KEV status.

## What the signals mean

| Signal | Why it is used | What it cannot prove |
| --- | --- | --- |
| IBM PSIRT confirmation | Establishes admission to the IBM i queue and ties a CVE to an IBM disclosure. | That a particular partition, release, or installed product is affected. |
| Bulletin publication date | Keeps current vendor work ahead of archive material. | Exploitability or business impact. |
| CISA KEV | Indicates known exploitation and creates urgent context. | Exposure in a specific shop or that an IBM i remedy applies there. |
| FIRST EPSS | Adds empirical exploit-likelihood context and tempers severity-only urgency. | Future exploitation, IBM i applicability, or local exposure. |
| NVD CVSS/vector | Describes vendor-neutral technical severity and attack conditions. | Actual exposure, exploit activity, or remediation status. |
| CWE/OWASP mapping | Connects weakness type to control context. | A complete control assessment or compensating-control effectiveness. |
| IBM product/release rows | Preserves source-supported applicability and remedy combinations. | Installed inventory, prerequisites, supersedence, or successful application unless IBM explicitly supplies that evidence. |
| Shop context | Reweights the presentation for user-entered exposure and change pressure. | Scanner-grade discovery or an authoritative asset inventory. |

## Calibration cases

Automated tests lock down these boundary judgments:

- Critical CVSS with cold EPSS does not become urgent on severity alone.
- A KEV-listed finding remains urgent even when it is old.
- An old KEV does not sort above a newly published IBM bulletin.
- KEV is a tie-breaker for findings from the same bulletin publication date.
- Findings sharing the same date and KEV state use score as the final tie-breaker.
- Missing or malformed publication dates sort after dated disclosures.
- PSIRT confirmation boosts confidence but does not admit NVD-only CVEs.
- A finding with no identified package routes to containment/research instead of claiming an applicable fix.

This is a maintained engineering calibration set, not expert validation. A
future reviewed set should record an IBM i practitioner's expected order,
action lane, applicability rationale, and acceptable evidence for each case.
