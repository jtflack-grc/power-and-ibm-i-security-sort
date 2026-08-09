# Ship safety trainer — IBM Power & Z Vulnerability Curator

Run this before push / portfolio link. Public surface is **GitHub Pages with a scheduled live snapshot** (static JSON). FastAPI on-demand live feeds are for local/Docker demos only.

## 1. Never commit (debris / secrets)

| Path / pattern | Why |
|----------------|-----|
| `.env` (any real `NVD_API_KEY`) | Secret |
| `.cache/`, `backend/.cache/`, `.cache_debug/` | Raw NVD dumps + last-live snapshots |
| `backend/.venv/`, `frontend/node_modules/` | Huge + local |
| `frontend/dist/` | Rebuild in CI/Pages (Pages workflow builds fresh) |
| `frontend/public/live-triage.json` | Generated in CI; do not commit |
| `.pytest_cache/`, `__pycache__/` | Local test debris |
| IDE folders (`.idea/`, `.vscode/`) | Machine-local |

`.gitignore` already covers these. Spot-check with:

```bash
git status --ignored
# or before first commit: ensure those folders are not staged
```

`.env.example` may ship with an **empty** `NVD_API_KEY=` line only.

Optional Actions secret `NVD_API_KEY` is fine for scheduled snapshot quality — it must never be written into SPA source or `live-triage.json`.

## 2. What *is* safe to publish

- Source under `backend/app/`, `frontend/src/`, tests, README, Dockerfile, `.github/workflows/pages.yml`
- `frontend/public/sample-triage.json` — curated **public** CVEs only
- Pages artifact may include generated `live-triage.json` (public CVE intel only)
- Portfolio links to `jtflack-grc.github.io` (intentional public identity)

## 3. OWASP / threat model (honest)

| Area | Status | Notes |
|------|--------|--------|
| Secrets in frontend / Actions | OK | No keys in SPA; optional `NVD_API_KEY` is Actions secret only |
| XSS | OK | React text nodes; bulletin HTML scraped → `get_text` + sanitize, not raw HTML |
| Path traversal (SPA static) | Hardened | `_safe_dist_file` rejects escapes outside `frontend/dist` |
| SSRF (bulletin scrape) | Hardened | Fetch allowlist = `*.ibm.com`; reject post-redirect off-host |
| CORS | Hardened | Localhost origins only; `credentials=False` |
| CSRF / unauth triage | Acceptable for demo | `/api/triage/run` is open — **do not** expose API to the open internet without limits |
| Docker `0.0.0.0` | Documented | Container LAN bind; public path is Pages static snapshot |
| Dependency noise | Acceptable | Pin via lockfiles; no weird private packages |

## 4. Pre-push commands

```bash
# From repo root
# Confirm no env with a real key
# Confirm caches / live-triage.json are gitignored, not staged

cd backend
set PYTHONPATH=%CD%
.venv\Scripts\pytest -q

cd ..\frontend
npm run build
```

## 5. Deploy modes

1. **Portfolio (default):** GitHub Pages → scheduled `live-triage.json` snapshot (daily Action). Sample fixture fallback if snapshot fails. No open triage API.
2. **Local live:** `uvicorn` on `127.0.0.1:8000` with optional `NVD_API_KEY` in the **shell env**, never baked into the SPA.
3. **Docker:** fine for controlled demos; not the public internet without auth/rate limits.

## 6. Portfolio copy reminder

Footer/README claim: practice demo, public feeds, not a scanner of record. Keep that honesty. Platform taxonomy should remain explicit: **IBM Power = IBM i / AIX / Linux on Power; IBM Z = z/OS.**

## Sign-off

- [ ] No `.env` with a real key in the tree
- [ ] Caches / venv / `node_modules` / `dist` / `live-triage.json` not staged
- [ ] `pytest` green
- [ ] Pages workflow uses `vite --base=./`; optional `NVD_API_KEY` is Actions secret only
- [ ] Ready for push + portfolio card
