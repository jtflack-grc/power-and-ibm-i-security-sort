# IBM Power & Z Vulnerability Curator

A portfolio artifact that **translates GRC / vulnerability-management language into IBM enterprise systems work** across two distinct platform families:

- **IBM Power:** IBM i, AIX, Linux on Power
- **IBM Z:** z/OS

It live-pulls public intel, sorts with explainable **counter-levers** (so CVSS alone cannot drown the queue), then docks each finding into **Apply / Contain / Monitor** with Resolve (PTF / APAR / Fix Central) vs Interim controls.

Front door: [jtflack-grc.github.io/portfolio](https://jtflack-grc.github.io/portfolio/)

## The aisle it crosses

| GRC / security side | Systems side |
|---------------------|--------------|
| CISA KEV, EPSS, OWASP, CVSS | Platform filters: IBM Power (IBM i / AIX / Linux on Power) and IBM Z (z/OS) |
| Priority buckets | Work docks: Apply · Contain · Monitor |
| “Why does this matter?” levers | Resolve: bulletin / PTF / APAR / Fix Central / verify-on-box |
| Threat tempering | Interim: authority, exposure, TLS, PSP currency |

**This is not a scanner replacement.** It is a curator that sits between risk language and change work.

## What it does

1. Pulls **CISA KEV**, **NVD**, **FIRST EPSS**, maps **OWASP Top 10** via CWE, resolves **IBM Security Bulletins** when possible
2. Scores with up *and* down counter-levers ([`backend/app/scoring/ranker.py`](backend/app/scoring/ranker.py))
3. Tags platform-native vs supply-chain / TPRM surface
4. Builds Resolve + Interim cards (including Fix Central / support search when scrape is thin)
5. UI: **Findings · Issue · Work docks**

## Panels

| Panel | Purpose |
|-------|---------|
| Findings | Platform + priority filters; curated queue |
| Issue | Overview + **Resolve** / **Interim** deep dive |
| Visual | Work docks — click to filter by Apply / Contain / Monitor |

## Counter-lever scoring (summary)

KEV escalates hard. EPSS can raise *or* temper high CVSS. OWASP is context, not auto-urgency. IBM PSIRT confirmation raises. Ancient / unconfirmed findings are tempered so museum CVEs do not dominate. Full ledger: [`backend/app/scoring/ranker.py`](backend/app/scoring/ranker.py).

## Security / no-keys stance

- **Published feeds are the Pages default.** A daily GitHub Action pulls public CISA / NVD / FIRST / IBM intel and ships `live-triage.json` inside the static site. No open triage API. No keys in the SPA.
- **Sample remains the offline fallback.** `frontend/public/sample-triage.json` ships for walkthroughs when the snapshot step fails or you want the flagship story.
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

Story in one line: GRC language (CVSS / OWASP access-control) becomes systems work (bulletin → Apply dock → verify on box).

## Portfolio card copy

**IBM Power & Z Vulnerability Curator** — Curates public vulnerability intelligence for IBM Power (IBM i, AIX, Linux on Power) and IBM Z (z/OS) into Apply, Contain, or Monitor — with guided routing questions, PTF/APAR/Fix Central resolve paths, interim controls, optional browser-only shop context + paste, feed honesty, and ticket-ready change packets. Pages serves a scheduled live snapshot (no open API). Flagship walkthrough: CVE-2024-25050. Not a scanner of record.

## Static Pages deploy (scheduled live snapshot)

GitHub Action [`.github/workflows/pages.yml`](.github/workflows/pages.yml) runs daily (and on push / workflow_dispatch):

1. Refreshes public intel via `python -m app.scripts.refresh_live_snapshot` → `frontend/public/live-triage.json`
2. Builds `frontend/dist` with `vite --base=./`
3. Publishes to GitHub Pages

If the snapshot step fails, the site still deploys with the curated sample fixture only.

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

## Honesty

Practice / portfolio demo. Public feeds only. External advisory text is sanitized and untrusted. PTF/APAR extraction is best-effort from public bulletins — always confirm on Fix Central and your release matrix before change.

Pre-publish checklist: [`SHIP_SAFETY.md`](SHIP_SAFETY.md).
