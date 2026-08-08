# Ship safety trainer — Power System Vulnerability Curator

Run this before `git init` / first push / portfolio link. Public surface is **GitHub Pages sample mode** (static). FastAPI live feeds are for local/Docker demos.

## 1. Never commit (debris / secrets)

| Path / pattern | Why |
|----------------|-----|
| `.env` (any real `NVD_API_KEY`) | Secret |
| `.cache/`, `backend/.cache/`, `.cache_debug/` | Raw NVD dumps + last-live snapshots |
| `backend/.venv/`, `frontend/node_modules/` | Huge + local |
| `frontend/dist/` | Rebuild in CI/Pages (Pages workflow builds fresh) |
| `.pytest_cache/`, `__pycache__/` | Local test debris |
| IDE folders (`.idea/`, `.vscode/`) | Machine-local |

`.gitignore` already covers these. Spot-check with:

```bash
git status --ignored
# or before first commit: ensure those folders are not staged
```

`.env.example` may ship with an **empty** `NVD_API_KEY=` line only.

## 2. What *is* safe to publish

- Source under `backend/app/`, `frontend/src/`, tests, README, Dockerfile, `.github/workflows/pages.yml`
- `frontend/public/sample-triage.json` — curated **public** CVEs only
- Portfolio links to `jtflack-grc.github.io` (intentional public identity)

## 3. OWASP / threat model (honest)

| Area | Status | Notes |
|------|--------|--------|
| Secrets in frontend / Actions | OK | No keys in SPA; Pages builds sample-only |
| XSS | OK | React text nodes; bulletin HTML scraped → `get_text` + sanitize, not raw HTML |
| Path traversal (SPA static) | Hardened | `_safe_dist_file` rejects escapes outside `frontend/dist` |
| SSRF (bulletin scrape) | Hardened | Fetch allowlist = `*.ibm.com`; reject post-redirect off-host |
| CORS | Hardened | Localhost origins only; `credentials=False` |
| CSRF / unauth triage | Acceptable for demo | `/api/triage/run` is open — **do not** expose API to the open internet without limits |
| Docker `0.0.0.0` | Documented | Container LAN bind; public path is Pages static |
| Dependency noise | Acceptable | Pin via lockfiles; no weird private packages |

## 4. Pre-push commands

```bash
# From repo root
# Confirm no env with a real key
# Confirm caches are gitignored, not staged

cd backend
set PYTHONPATH=%CD%
.venv\Scripts\pytest -q

cd ..\frontend
npm run build
```

## 5. Deploy modes

1. **Portfolio (default):** GitHub Pages → sample fixture only. Live buttons stay hidden without `/api/health`.
2. **Local live:** `uvicorn` on `127.0.0.1:8000` with optional empty `NVD_API_KEY` in the **shell env**, never baked into the SPA.
3. **Docker:** fine for controlled demos; not the public internet without auth/rate limits.

## 6. Portfolio copy reminder

Footer/README claim: practice demo, public feeds, not a scanner of record. Keep that honesty.

## Sign-off

- [ ] No `.env` with a real key in the tree
- [ ] Caches / venv / `node_modules` / `dist` not staged
- [ ] `pytest` green
- [ ] Pages workflow uses `vite --base=./` and no env secrets
- [ ] Ready for `git init` + first push + portfolio card
