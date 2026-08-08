# Power System Vulnerability Curator

A portfolio artifact that **translates GRC / vuln-management language into Power systems work** — IBM i, AIX, Linux on Power, and z/OS.

Live-pulls public intel, sorts with explainable **counter-levers** (so CVSS alone cannot drown the queue), then docks each finding into **Apply / Contain / Monitor** with Resolve (PTF / Fix Central) vs Interim controls.

Front door: [jtflack-grc.github.io/portfolio](https://jtflack-grc.github.io/portfolio/)

## The aisle it crosses

| GRC / security side | Systems side |
|---------------------|--------------|
| CISA KEV, EPSS, OWASP, CVSS | Baileywick filters (IBM i / AIX / z/OS / Linux on Power) |
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
| Findings | Baileywick + priority filters; curated queue |
| Issue | Overview + **Resolve** / **Interim** deep dive |
| Visual | Work docks — click to filter by Apply / Contain / Monitor |

## Counter-lever scoring (summary)

KEV escalates hard. EPSS can raise *or* temper high CVSS. OWASP is context, not auto-urgency. IBM PSIRT confirmation raises. Ancient / unconfirmed findings are tempered so museum CVEs do not dominate. Full ledger: [`backend/app/scoring/ranker.py`](backend/app/scoring/ranker.py).

## Security / no-keys stance

- **Sample is the portfolio default.** `frontend/public/sample-triage.json` ships in the static page. No API keys. No uploads.
- **Shop context stays in the browser** (`sessionStorage`). Personas and answers never POST to a server.
- **Live public feeds are optional** when FastAPI is running. They call public CISA / NVD / FIRST / IBM pages only. `NVD_API_KEY` is never required and must not be embedded in a public deploy.
- **Keyless NVD uses a slim recipe** (~8 queries, 1 page) so cold refreshes finish far faster; disk cache skips politeness delays on repeat. Successful live runs persist a **last-good snapshot** served instantly on the next Live click while a refresh continues in the background.
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

Open the app and use **Load sample** for a keyless demo. Live buttons appear only when `/api/health` responds.

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

1. **Start live** (or Route, then live) — fixture stays optional for offline demos.
2. Open a finding — counter-levers explain the sort.
3. Resolve → bulletin / Fix Central; Interim → privileged-profile hygiene.
4. Optional: guided routing / shop persona (answers stay in-browser); paste PSP tokens if you have them.
5. Copy change packet for a ticket-ready Markdown artifact.

Story in one line: GRC language (CVSS / OWASP access-control) becomes systems work (bulletin → Apply dock → verify on box).

## Portfolio card copy

**Power System Vulnerability Curator** — Curates public IBM i / AIX / Power / z/OS CVEs into Apply, Contain, or Monitor — with guided routing questions, PTF/Fix Central resolve paths, interim controls, optional browser-only shop context + paste, feed honesty, and ticket-ready change packets. Sample mode needs no keys. Flagship walkthrough: CVE-2024-25050. Not a scanner of record.

## Static Pages deploy (no secrets)

GitHub Action [`.github/workflows/pages.yml`](.github/workflows/pages.yml) builds `frontend/dist` with `vite --base=./` and publishes **fixture-only** sample mode (no API keys, no live backend).

1. Repo → **Settings → Pages → Source: GitHub Actions**
2. Push to `main` (or run **Pages sample deploy** via workflow_dispatch)
3. Open the Pages URL — welcome → curated fixture / route path works statically; live buttons stay hidden without `/api/health`

Artifact ships `.nojekyll` so GitHub does not strip paths. Local FastAPI is still the path for live feeds.

## Design stance

IBM Plex + OLED black grounds. Green and amber stay on strokes and accents only — no green-washed panels. No glow, scanline grids, side-tab cards, hero kickers, or pulse dots — patterns the [impeccable](https://impeccable.style/slop) detector treats as AI slop. Substance lives in the pulls, docks, and Resolve / Interim steps.

## Honesty

Practice / portfolio demo. Public feeds only. External advisory text is sanitized and untrusted. PTF extraction is best-effort from public bulletins — always confirm on Fix Central and your release matrix before change.

Pre-publish checklist: [`SHIP_SAFETY.md`](SHIP_SAFETY.md).
