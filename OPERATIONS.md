# Feed operations baseline

## Observed healthy baseline

The guarded Pages publisher was verified twice on 2026-08-09 after the
forced-refresh repair. The current successful run reported:

| Measure | Observed | Safety boundary |
| --- | ---: | ---: |
| PSIRT response | 11.1 MB | 32 MB hard ceiling |
| PSIRT transfer | 5,980 ms | 60-second request timeout |
| Bulletin records | 50 | 1,000-record parser cap; 20 publication floor |
| Admitted CVEs | 161 | 750-CVE parser cap; 75 publication floor |
| Bulletin bodies processed | 49/49 | IBM HTTPS allowlist and bounded concurrency |
| EPSS attachment | 160/161 | Enrichment may degrade without changing admission |

The response currently uses about 35% of the byte ceiling. The record and CVE
caps retain substantial headroom while still bounding an unexpected service
expansion. Raising any limit should require multiple observed healthy runs and a
review of Actions runtime, artifact size, and untrusted-text exposure.

## Change and failure semantics

- Publication age, not CVE age or modification churn, controls the rolling
  400-day admission window.
- A bulletin exactly on the cutoff date is included; an older or undated
  bulletin is excluded from the rolling queue.
- Snapshot comparison marks a bulletin `new`, `modified`, or `unchanged`
  against the previously deployed JSON. Modification includes structured
  applicability/remediation changes, not merely a title badge in the browser.
- Valid empty JSON, non-JSON IBM outage pages, schema drift, excessive response
  size, materially narrow results, and missing bulletin membership all prevent
  deployment.
- NVD fallback remains available for local degraded use but cannot overwrite the
  published PSIRT snapshot.

## Operational follow-up

Retain the 32 MB / 1,000-record / 750-CVE limits until scheduled observations
show sustained growth near a boundary. Review the workflow summary and live feed
strip after IBM Support platform changes. A sequence of healthy scheduled runs,
not a single successful request, is the contract-stability signal.
