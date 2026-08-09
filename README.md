# IBM i Vulnerability Curator

A portfolio artifact that **translates public vulnerability intelligence into IBM i remediation and verification work**.

The curator is intentionally IBM i-only. It preserves explainable prioritization and
Apply / Contain / Monitor routing, then introduces a source-validated 5250 verification
rail for findings with an applicable PTF path.

It live-pulls public intel, sorts with explainable **counter-levers** (so CVSS alone cannot drown the queue), then docks each finding into **Apply / Contain / Monitor** with Resolve (PTF / APAR / Fix Central) vs Interim controls.

Front door: [jtflack-grc.github.io/portfolio](https://jtflack-grc.github.io/portfolio/)

## The aisle it crosses

| GRC / security side | Systems side |
|---------------------|--------------|
| CISA KEV, EPSS, OWASP, CVSS | IBM i applicability and product/release evidence |
| Priority buckets | Work docks: Apply · Contain · Monitor |
| “Why does this matter?” levers | Resolve: bulletin / PTF / APAR / Fix Central / verify-on-box |
| Threat tempering | Interim: authority, exposure, TLS, PSP currency |
| Vendor remedy | Synthetic 5250 verification using validated PTF screen fixtures |

**This is not a scanner replacement.** It is a curator that sits between risk language and change work.

## What it does

1. Discovers IBM i issues from **IBM Product Security Central / PSIRT**, then enriches that IBM-curated set with **CISA KEV**, **NVD**, **FIRST EPSS**, and **OWASP Top 10** via CWE
2. Scores with up *and* down counter-levers ([`backend/app/scoring/ranker.py`](backend/app/scoring/ranker.py))
3. Distinguishes IBM i-native from supply-chain / TPRM surface
4. Builds Resolve + Interim cards (including Fix Central / support search when scrape is thin)
5. Groups remediation work by IBM bulletin while retaining individual CVE scoring
6. UI: **Findings · Issue · Actions + 5250 verification**

## Panels

| Panel | Purpose |
|-------|---------|
| Findings | Bulletin-first queue with expandable CVEs, release/remedy filters, and recent/new views |
| Issue | Overview + **Resolve** / **Interim** deep dive |
| Actions | Work docks plus a transport-free IronTerm TN5250 verification rail |

## 5250 scenario mode

The Pages application does not connect to an IBM i, accept credentials, or run
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
5. Copy change packet for a ticket-ready Markdown artifact.

Story in one line: GRC language (CVSS / OWASP access-control) becomes IBM i systems work (bulletin → PTF decision → 5250 verification → closure evidence).

## Portfolio card copy

**IBM i Vulnerability Curator** — Curates public vulnerability intelligence for IBM i into Apply, Contain, or Monitor, then carries supported PTF findings into a synthetic 5250 verification rail built on IronTerm’s protocol-grounded terminal core. Includes guided shop context, bulletin/PTF/Fix Central paths, interim controls, feed honesty, and ticket-ready change packets. Pages serves a scheduled public snapshot with no open API or live host connection. Flagship walkthrough: CVE-2024-25050. Not a scanner of record.

## Static Pages deploy (scheduled live snapshot)

GitHub Action [`.github/workflows/pages.yml`](.github/workflows/pages.yml) runs daily (and on push / workflow_dispatch):

1. Refreshes public intel via `python -m app.scripts.refresh_live_snapshot` → `frontend/public/live-triage.json`
2. Builds `frontend/dist` with `vite --base=./`
3. Publishes to GitHub Pages

If PSIRT is unhealthy, materially narrow, or loses bulletin membership, the workflow stops before deployment. Pages retains the prior build rather than publishing an NVD fallback over a healthy PSIRT snapshot.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the data flow, trust boundaries, and failure behavior. [`RANKING_MODEL.md`](RANKING_MODEL.md) records queue-order invariants, signal limitations, and the current engineering calibration set.

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

## License and attribution

This repository is distributed under GPL-3.0 because it incorporates and modifies
GPL-3.0 IronTerm source. The upstream license and pinned commit are preserved under
`frontend/public/ironterm/`. Local modifications are documented in
`SCENARIO_MODE.md`.

## Honesty

Practice / portfolio demo. Public feeds only. External advisory text is sanitized and untrusted. PTF/APAR extraction is best-effort from public bulletins. Terminal fixtures must be validated against IBM-controlled documentation or clean IBM i reference output before release. Always confirm on Fix Central and your release matrix before change.

Pre-publish checklist: [`SHIP_SAFETY.md`](SHIP_SAFETY.md).
