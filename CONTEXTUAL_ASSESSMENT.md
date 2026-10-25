# IBM i automatic OSINT assessment v0.2

The primary assessment is automatic. Every finding receives an IBM i estimated score range, endpoint assumptions, source coverage, and source links without a user record or form. CVSS remains the leading score and sort; existing filters are preserved. Partition-specific validation is available under an optional refinement drawer.

## Automatic source hierarchy

The scheduled collector extracts description, score, and vector from each explicitly identified CVEID section in the IBM bulletin feed. It does not spread a grouped bulletin's rating or one CVE's prerequisites across other CVEs. IBM-specific fields remain separate from NVD. Public CVSS uses the IBM numeric/vector pair when NVD numeric enrichment is unavailable, with source provenance; a present NVD score remains available separately from the IBM-specific estimate. Group-level severity is not treated as an individual CVE score.

The automatic engine prefers a valid IBM per-CVE vector, then a valid CVE vector. It combines those vulnerability facts with a curated platform-reference catalog. References include current IBM authority and Java documentation, IBM Redbooks Modernizing IBM i Applications, historical SG24-7680 paired with current documentation, and Fortra/Kisco guidance. Catalog review date and model version are visible. Daily feed changes regenerate finding estimates; general platform references are curated and reviewed, not silently fetched or interpreted by an LLM on every page load.

## Automatic range rules

These are explicit experimental scenario choices, not statistical probabilities, calibrated confidence intervals, or endpoints endorsed by the source publishers.

- **Application/service job:** where component text identifies a runtime/service and no authority-boundary warning applies, the lower scenario assumes limited effective job authority and limited confidentiality/integrity consequences. Modified C/I (or vulnerable/subsequent C/I in v4) move from High to Low where relevant. Availability and attack prerequisites remain as published. This is a conditional lower-impact deployment, not an assertion that controls are installed.
- **Authority-boundary flaw:** privilege escalation, authentication/authorization bypass, unqualified library calls, kernel/integrity context, or relevant CWE signals receive no generic authority discount. The lower scenario retains published impacts and prerequisites.
- **Other components:** retain the original vector for the lower scenario when public details do not support a narrower impact scenario.
- **Broad-impact endpoint:** calculate high C/I/A security requirements for a critical workload. No firewall, exit program, MFA, patch installation, or effective control is inferred.
- **Retained public inputs:** include the unmodified vector calculation and available IBM/public numeric scores inside the envelope. Higher public ratings are not hidden when sources differ.
- **Sparse records:** without a usable vector, show a clearly labeled provisional band from the available numeric anchor to 10; a trustworthy source-specific severity category can provide its lower boundary. With no numeric/vector/category basis, show a broad 0–10 unresolved band. These fallback bands are original policy bounds, not CVSS Environmental calculations. Known zero/no-impact vector cases remain valid zero-severity scenarios.

The range is the minimum and maximum of the disclosed endpoints. Scores use the vector's own version (3.0, 3.1, or 4.0). Network is never changed to Local/Adjacent because a server is believed to be internal. The original queue score stays visible. KEV keeps an expedited response emphasis; low EPSS and generic platform capabilities do not cancel it. A fix being published does not establish remediation.

## FAIR-CAM reference in the automatic view

A populated control-function narrative accompanies each estimate: the assumed resistance role, lack of known avoidance/network isolation, unresolved detection/response, and source/decision-support limitations. This explains the assumptions used in the envelope. It assigns no measured control efficacy, percent risk reduction, or monetary loss. Local measurements remain optional.

## Optional partition refinement (v0.1)

The following stricter evidence workflow is secondary. Its “Not assessed” state does not block or replace the automatic OSINT estimate. It does not query an IBM i partition or validate an assessor's observations automatically.

## Scope and persistence

Assess a CVE for a named partition pseudonym, release, component, threat scenario, assessor, and time. The browser stores up to 30 assessments per CVE and dataset mode; sample and live records are separate. Use sanitized references. Evidence stays in browser local storage and can be exported as Markdown or JSON. There is no server upload or cross-device synchronization. Storage failure is shown; the draft remains in memory for download. Changing scope invalidates evidence states. Changes to the source vector, last-modified date, or remedy guidance invalidate prior calculations.

The automatic OSINT range always supplies the secondary label in the CVSS listing. A valid selected local assessment adds a separately labeled refinement. Select another saved record in the detail editor to review other partitions. This label is never a fleet-wide aggregate.

## Severity envelope

Calculator: MIT-licensed `@pandatix/js-cvss` 0.4.4, bundled locally. Its license is retained in `frontend/public/licenses/js-cvss-MIT.txt`. No calculator request is sent to another service.

Support is CVSS 3.0, 3.1, and 4.0, without cross-version conversion. Validate the source vector, retain its intrinsic Base metrics, and apply only the selected Environmental metrics. Published Temporal/Threat metrics are not carried into this Environmental-only model. The original vector is preserved and exported. Missing/invalid/unsupported vectors remain unassessed.

The range is the minimum and maximum of up to two separately documented, observed or analyst-verified scenarios. Each needs a collection date and rationale/reference. Applicability and effective remedy state must be evidenced first. Unknown, stale, conflicting, or owner-attested protection cannot produce a numerical reduction. Even one conflicting scenario blocks the range. Equal endpoints are valid; they do not imply all uncertainty is resolved. This is a scenario severity envelope, not a probability/confidence interval, calibrated risk score, or monetary loss distribution.

Modified attack vector requires reachability evidence; complexity/attack requirements use relevant platform-protection evidence; privileges use effective-authority evidence; user interaction uses relevant interface/authentication evidence; impact/scope and security requirements use business-consequence evidence. These are original conservative workflow anchors, not FIRST-prescribed IBM i mappings. Every explicit metric override needs its relevant anchor. Reductions below the same version's unmodified score require analyst-verified anchors. The assessor must explain the causal relationship: the app does not automatically map a control checkbox to a metric or infer that internal access is local access. Requirements may increase severity above Base.

Source definitions: [FIRST v3.0](https://www.first.org/cvss/v3.0/specification-document), [FIRST v3.1](https://www.first.org/cvss/v3.1/specification-document), [FIRST v4.0](https://www.first.org/cvss/v4.0/specification-document). This app's evidence rules are original policy, not an endorsed scoring extension.

## Disposition rules

- Credible, current local exploitation evidence: Incident response, even if a remedy is applied.
- Analyst-verified non-applicability: Not applicable to the scoped scenario.
- Confirmed applicability and analyst-verified effective remedy: Remediated.
- KEV with missing local facts: Expedite validation. With confirmed applicability, unremediated/pending remedy, and evidenced reachable path: Expedite remediation.
- Confirmed applicability and unremediated/pending remedy without the above triggers: Schedule remediation.
- Otherwise: Investigate.

Terminal dispositions are not zero severity. Merely loaded fixes and pending activation remain actionable. A temporarily applied PTF may be effective according to the remedy instructions. No source establishes a universal evidence validity window; review-through dates are assessor-selected. Review after changes, even before that date. The view reevaluates expiry periodically while open.

## IBM i baseline and source provenance

Capabilities establish questions; observed settings establish local context. There is no generic IBM i discount, default posture score, survey-derived exploitation probability, or automated prevention credit for QSECURITY, installed tools, exit registration, MFA, logging, or backups.

Sources are available in the app:

- [IBM security levels](https://www.ibm.com/docs/en/i/7.5.0?topic=security-level): relevant integrity protections.
- [IBM authority collection](https://www.ibm.com/docs/en/i/7.5.0?topic=reference-authority-collection): user, group, public, and adopted authority.
- [IBM PTF_INFO](https://www.ibm.com/docs/en/i/7.5.0?topic=services-ptf-info-view): effective remedy and activation evidence.
- [IBM NETSTAT_INFO](https://www.ibm.com/support/pages/qsys2netstatinfo): connection information, alongside separately tested network paths.
- [Fortra security guidance](https://power.fortra.com/blog/6-pro-tips-2026-state-ibm-i-security-study): assessment domains, not a population prior.
- [Kisco exit points](https://www.kisco.com/u/content/ibm-i-exit-points-for-security.html) and [adopted authority](https://www.kisco.com/u/content/controlling-adopted-authority.html): interface coverage and execution-context questions.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/faq): separate threat context. EPSS is not a partition loss probability.

## FAIR and FAIR-CAM reference

The original control-evidence worksheet references FAIR-CAM™ functions published by the FAIR Institute. It records scoped measurements and supporting evidence for network/authority prevention, event telemetry and detection, containment, recovery, drift checks, and assessment-input review. The detection view checks whether observations and measurements exist for visibility, monitoring, and recognition; it does not assert effectiveness from their presence or multiply their values. A zero efficacy measurement remains a zero; documentation completeness is not risk reduction.

The worksheet also records a FAIR loss scenario and the analyst's calibrated frequency, susceptibility, loss, and dependency inputs. This release does not compute monetary loss, percent risk reduction, confidence percentiles, or a control maturity score. No CVSS-to-probability conversion is used. Overlapping CVEs must not be assumed to represent independent loss events.

[Open FAIR](https://www.opengroup.org/open-fair) provides the risk-analysis foundation. [FAIR-CAM™ official guidance](https://www.fairinstitute.org/resources/FAIR-CAM) and [standard v1.0, January 2025](https://www.fairinstitute.org/hubfs/Standards%20Artifacts/FAIR%20Controls%20Analytics%20Model%20%28FAIR-CAM%29%20Standard%20V1.0%20%28January%202025%29.pdf) provide the control-function reference. FAIR-CAM™ content is owned by the FAIR Institute; see [use terms](https://www.fairinstitute.org/frequently-asked-questions) and [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/). The application contains original code and IBM i assessment examples, links to the published model, and does not reproduce or distribute a modified ontology, model diagram, or standard. It is not a certified FAIR-CAM analytics implementation.

## Validation

Run `npm run test:context` and `npm run build` from `frontend/`. The deployment workflow runs the contextual tests before publishing. Tests cover known version-specific vectors, zero scores, input rejection, supported ranges, missing/unverified evidence, expiry/source changes, terminal gates, low EPSS plus KEV, detection evidence dependencies, and malformed/isolated persistence. Browser checks additionally exercise local editing, score creation, persistence, and mobile layout.
