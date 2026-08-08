from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.triage import router as triage_router

app = FastAPI(
    title="Power System Vulnerability Curator",
    description="Curate public Power / IBM i CVEs into what actually matters.",
    version="0.1.0",
)

# Local demos only. Pages hosting is static and never hits this API.
# Do not pair allow_origins=["*"] with allow_credentials=True.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(triage_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "power-system-vulnerability-curator"}


FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _safe_dist_file(full_path: str) -> Path | None:
    """Resolve a SPA asset only if it stays inside FRONTEND_DIST (no path escape)."""
    if not full_path or full_path.endswith("/"):
        return None
    dist_root = FRONTEND_DIST.resolve()
    candidate = (dist_root / full_path).resolve()
    try:
        candidate.relative_to(dist_root)
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    return None


if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        index = FRONTEND_DIST / "index.html"
        safe = _safe_dist_file(full_path)
        if safe is not None:
            return FileResponse(safe)
        return FileResponse(index)
