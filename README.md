# IBM i Vulnerability Curator

A portfolio artifact that **correlates IBM's release-applicable CVEs and bulletin remedies with observed IBM i fix state**.

The curator is intentionally IBM i-only. IBM's `SYSTOOLS.CVE_INFO()` establishes which
published CVEs affect a 7.5 or 7.6 release, but does not report whether each correcting
PTF is applied. The curator closes that gap: it resolves IBM bulletin remedies, compares
them with browser-local `QSYS2.PTF_INFO` / `QSYS2.GROUP_PTF_INFO` exports, and preserves
the result as reviewable remediation evidence.

It live-pulls public intel, sorts with explainable **counter-levers** (so CVSS alone cannot drown the queue), then docks each finding into **Apply / Contain / Monitor** with Resolve (PTF / APAR / Fix Central) vs Interim controls.

Front door: [jtflack-grc.github.io/portfolio](https://jtflack-grc.github.io/portfolio/)

## The aisle it crosses

| GRC / security side | Systems side |
|---------------------|--------------|
| CISA KEV, EPSS, OWASP, CVSS | IBM i applicability and product/release evidence |
| Priority buckets | Work docks: Apply · Contain · Monitor |
| “Why does this matter?” levers | Resolve: bulletin / PTF / APAR / Fix Central / verify-on-box |
| Threat tempering | Interim: authority, exposure, TLS, PSP currency |
| IBM bulletin remedy | Observed SQL fix state and explicit indeterminate outcomes |

**This is not a scanner replacement.** It is the correlation and evidence layer between IBM's CVE claim, local fix state, and change work.

## What it does

1. Discovers IBM i issues from **IBM Product Security Central / PSIRT**, then enriches that IBM-curated set with **CISA KEV**, **NVD**, **FIRST EPSS**, and **OWASP Top 10** via CWE
2. Scores with up *and* down counter-levers ([`backend/app/scoring/ranker.py`](backend/app/scoring/ranker.py))
3. Distinguishes IBM i-native from supply-chain / TPRM surface
4. Builds Resolve + Interim cards (including Fix Central / support search when scrape is thin)
5. Groups remediation work by IBM bulletin while retaining individual CVE scoring
6. Provides an ACS-ready SQL collection kit and compares IBM's expected PTF/group remedy with a bounded, browser-local inventory export
7. Produces a Markdown evidence packet with optional owner, dates, disposition, reviewer, and observed-inventory status
8. UI: **Findings · Issue · Evidence**, with the green-screen method closed as a legacy fallback

## Why PSIRT-first changed the result

The earlier NVD-discovery prototype found only 20 current IBM i-looking CVEs. That
was not a defensible IBM i inventory: component vulnerabilities may be published
under OpenSSL, Java, Liberty, BIND, ACS, and other names without an IBM i CPE or
keyword. IBM PSIRT is now the admission authority, matching the source used by
IBM's `SYSTOOLS.CVE_INFO` service. The current guarded snapshot contains 161
PSIRT-confirmed CVEs across 49 processed bulletin bodies. NVD can enrich those
records, but it cannot add findings to the published queue.

## Evidence model

| Claim | Authority | Curator treatment |
|-------|-----------|-------------------|
| A CVE affects an IBM i release | IBM PSIRT / `SYSTOOLS.CVE_INFO()` | Admit and preserve the IBM support reference |
| A bulletin identifies a remedy | IBM Security Bulletin | Extract product, release, PTF, Group PTF, and APAR without inventing missing relationships |
| A fix exists on this partition | `QSYS2.PTF_INFO` / `QSYS2.GROUP_PTF_INFO` export | Parse locally and compare with the expected remedy |
| A group is current | `SYSTOOLS.GROUP_PTF_CURRENCY` | Preserve current, update-available, or PSP-unavailable state |
| Remediation is complete | Human-reviewed case record | Require disposition, ownership, change reference, and reviewer evidence |

The downloadable [`ibmi-cve-fix-evidence.sql`](frontend/public/ibmi-cve-fix-evidence.sql)
is the canonical collection path. It captures system context, `CVE_INFO`, individual
PTFs, Group PTFs, live group currency, and operational exceptions such as loaded fixes
or pending IPL action. IBM i 7.4 skips `CVE_INFO`; the curator's guarded PSIRT snapshot
provides the release-level CVE set while local QSYS2 views still provide observed state.

## Panels

| Panel | Purpose |
|-------|---------|
| Findings | Bulletin-first queue with expandable CVEs; release, product, remedy, priority, action, and snapshot-change filters |
| Issue | **Resolve** / **Interim**, local decision fields, and downloadable Markdown packet |
| Evidence | SQL-first CVE-to-fix comparison and case evidence; legacy command/5250 aid closed by default |

## Legacy 5250 scenario mode

The legacy accordion is retained for shops where SQL collection is unavailable. The Pages application does not connect to an IBM i, accept credentials, or run
websockify. It vendors the TN5250 implementation from
[bencz/IronTerm](https://github.com/bencz/IronTerm) at a pinned commit and replaces
the live WebSocket/Telnet lifecycle with a deterministic scenario boundary.

Retained IronTerm capabilities include the 5250 presentation space, EBCDIC codec,
inbound parser, outbound builder, field behavior, AID keys, cursor rules, renderer,
input controller, and OIA. The terminal remains locked and blank until a
source-validated PTF datastream fixture is supplied. No approximate PTF screen is
shipped as a placeholder.

See [`frontend/public/ironterm/SCENARIO_MODE.md`](frontend/public/ironterm/SCENARIO_MODE.md).
PTF screen provenance, LCL comparisons, IBM sources, and fixture release gates are
tracked in [`frontend/public/ironterm/fixtures/SCREEN_SOURCING.md`](frontend/public/ironterm/fixtures/SCREEN_SOURCING.md)
and the machine-readable `screen-sources.json` registry.

## Counter-lever scoring (summary)

KEV escalates hard. EPSS can raise *or* temper high CVSS. OWASP is context, not auto-urgency. IBM PSIRT confirmation raises. Ancient / unconfirmed findings are tempered so museum CVEs do not dominate. Full ledger: [`backend/app/scoring/ranker.py`](backend/app/scoring/ranker.py).

## Security / no-keys stance

- **Published feeds are the Pages default.** A daily GitHub Action uses IBM PSIRT as the discovery authority, enriches those findings from public CISA / NVD / FIRST data, and ships `live-triage.json` inside the static site. No open triage API. No keys in the SPA.
- **Sample remains an explicit offline walkthrough.** It never automatically replaces a healthy PSIRT snapshot.
- **Shop context stays in the browser** (`sessionStorage`). Personas and answers never POST to a server.
- **Inventory comparison stays in the browser.** CSV/text is limited to 200 KB / 5,000 lines, reduced to validated PTF/group identifiers and statuses, and never uploaded.
- **On-demand live feeds are local/Docker only** (FastAPI). They call the same public sources. Optional `NVD_API_KEY` may be set as a **repo Actions secret** for fuller scheduled NVD pulls, or in the local shell — never embedded in a public deploy.
- **Keyless NVD uses a slim recipe** (~8 queries, 1 page) so cold refreshes finish far faster; disk cache skips politeness delays on repeat. Successful local live runs persist a **last-good snapshot** served instantly on the next Live click while a refresh continues in the background.
- **Change packets** are generated client-side (copy / download Markdown).

## Local development

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt pytest
set PYTHONPATH=%CD%
uvicorn app.main:app --reload --port 8000
```

Optional self-host only: `NVD_API_KEY` for faster NVD quotas. Do **not** put keys in the frontend or a public GitHub Pages demo.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the app. On GitHub Pages, **Open published feeds** loads the scheduled snapshot. Locally, live buttons appear when `/api/health` responds; **Load sample** remains the offline walkthrough.

### Tests

```bash
cd backend
set PYTHONPATH=%CD%
.venv\Scripts\pytest -q
```

### Single-process portfolio build

```bash
cd frontend && npm run build && cd ..
cd backend
set PYTHONPATH=%CD%
uvicorn app.main:app --port 8000
```

Or: `docker build -t power-vuln-curator . && docker run --rm -p 8000:8000 power-vuln-curator`

Static hosting: serve `frontend/dist` (sample JSON included). Live feeds need a backend; sample does not.

## Flagship walkthrough (portfolio)

**CVE-2024-25050** — IBM i local privilege escalation with a published Security Bulletin.

1. **Open published feeds** (Pages) or **Start live** (local FastAPI) — fixture stays optional for offline demos.
2. Open a finding — counter-levers explain the sort.
3. Resolve → bulletin / Fix Central; Interim → privileged-profile hygiene.
4. Optional: guided routing / shop persona (answers stay in-browser); paste PSP tokens if you have them.
5. Run the supplied ACS SQL kit and compare a sanitized `QSYS2.PTF_INFO` / `QSYS2.GROUP_PTF_INFO` export.
6. Complete local owner/change/disposition fields and download the Markdown evidence packet.

Story in one line: IBM identifies the CVEs; the curator turns IBM's bulletin remedy and local SQL state into a reviewable remediation decision.

## Portfolio card copy

**IBM i Vulnerability Curator** — Joins IBM's release-applicable CVEs and bulletin remedies to observed IBM i PTF state. It supplies an ACS SQL evidence kit, compares sanitized browser-local PTF and Group PTF exports, explains every priority and applicability decision, and produces an evidence-ready Markdown packet. A closed legacy accordion retains DSPPTF guidance for constrained shops. Static Pages deployment; not a scanner of record.

## Static Pages deploy (scheduled live snapshot)

GitHub Action [`.github/workflows/pages.yml`](.github/workflows/pages.yml) runs daily (and on push / workflow_dispatch):

1. Refreshes public intel via `python -m app.scripts.refresh_live_snapshot` → `frontend/public/live-triage.json`
2. Builds `frontend/dist` with `vite --base=./`
3. Publishes to GitHub Pages

If PSIRT is unhealthy, materially narrow, or loses bulletin membership, the workflow stops before deployment. Pages retains the prior build rather than publishing an NVD fallback over a healthy PSIRT snapshot.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the data flow and trust boundaries. [`OPERATIONS.md`](OPERATIONS.md) records the observed PSIRT baseline, ceilings, and failure behavior. [`RANKING_MODEL.md`](RANKING_MODEL.md) records queue-order invariants, signal limitations, and the current engineering calibration set.

Optional: add repo secret `NVD_API_KEY` for a fuller NVD recipe in Actions (never baked into the SPA).

1. Repo → **Settings → Pages → Source: GitHub Actions**
2. Push to `main` (or run **Pages sample deploy** via workflow_dispatch)
3. Open the Pages URL — **Open published feeds** loads the snapshot; sample remains available

Artifact ships `.nojekyll` so GitHub does not strip paths. Local FastAPI is still the path for on-demand live refresh.

Generate a snapshot locally with:

```bash
cd backend
set PYTHONPATH=%CD%
python -m app.scripts.refresh_live_snapshot
```

## Design stance

IBM Plex + OLED black grounds. Green and amber stay on strokes and accents only — no green-washed panels. No glow, scanline grids, side-tab cards, hero kickers, or pulse dots — patterns the [impeccable](https://impeccable.style/slop) detector treats as AI slop. Substance lives in the pulls, docks, and Resolve / Interim steps.

## Current limitations

- Inventory comparison trusts locally supplied exports and is not scanner-grade discovery.
- Supersedence, prerequisites/co-requisites, IPL action, delayed application, and cover-letter warnings are shown only when a reliable IBM source can support them; the curator does not infer them.
- SQL exports are user-supplied observations, not authenticated scanner results; the curator cannot attest that an export is complete or untampered.
- `CVE_INFO()` is available only on IBM i 7.5 and 7.6 at IBM's required PTF levels and depends on network access to IBM. IBM i 7.4 uses the curator's guarded PSIRT snapshot for CVE scope.
- `DSPPTF` remains a legacy demonstration. `WRKPTFGRP` and additional-detail screens remain command coaching rather than the primary evidence path.
- Ranking has an automated engineering calibration set, not an independent expert-reviewed benchmark.
- No organizational workflow data is sent or synchronized; local fields disappear with the browser session.
- The rolling 400-day queue is operational curation, not a historical vulnerability archive.

The final project name is **IBM i Vulnerability Curator**. “Vuln Curator” remains only the compact header treatment.

## License and attribution

This repository is distributed under GPL-3.0 because it incorporates and modifies
GPL-3.0 IronTerm source. The upstream license and pinned commit are preserved under
`frontend/public/ironterm/`. Local modifications are documented in
`SCENARIO_MODE.md`.

## Honesty

Practice / portfolio demo. Public feeds only. External advisory text is sanitized and untrusted. PTF/APAR extraction is best-effort from public bulletins. Terminal fixtures must be validated against IBM-controlled documentation or clean IBM i reference output before release. Always confirm on Fix Central and your release matrix before change.

Pre-publish checklist: [`SHIP_SAFETY.md`](SHIP_SAFETY.md).
