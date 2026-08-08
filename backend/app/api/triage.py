from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.triage_service import load_last_live, run_triage, store

router = APIRouter(prefix="/api/triage", tags=["triage"])

FRONTEND_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"
FRONTEND_PUBLIC = Path(__file__).resolve().parents[3] / "frontend" / "public"


class StartRequest(BaseModel):
    force_refresh: bool = False


class StartResponse(BaseModel):
    job_id: str


@router.get("/latest")
async def latest_live():
    """Last successful live triage (disk) — instant UX; refresh runs separately."""
    result = load_last_live()
    if result is None:
        raise HTTPException(status_code=404, detail="No cached live triage yet")
    return result


@router.get("/sample")
async def sample_triage():
    """Curated public fixture — no keys, safe for portfolio demos."""
    for path in (
        FRONTEND_DIST / "sample-triage.json",
        FRONTEND_PUBLIC / "sample-triage.json",
    ):
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="Sample fixture missing")


@router.post("/{job_id}/cancel")
async def cancel_triage(job_id: str):
    ok = await store.cancel(job_id)
    if not ok and store.get_result(job_id) is not None:
        return {"job_id": job_id, "cancelled": False, "reason": "already_complete"}
    return {"job_id": job_id, "cancelled": True}


@router.post("/run", response_model=StartResponse)
async def start_triage(body: StartRequest, background: BackgroundTasks) -> StartResponse:
    job_id = await store.create()
    background.add_task(run_triage, job_id, body.force_refresh)
    return StartResponse(job_id=job_id)


@router.get("/{job_id}/events")
async def triage_events(job_id: str) -> StreamingResponse:
    async def event_gen():
        q = await store.subscribe(job_id)
        try:
            while True:
                item = await q.get()
                if item is None:
                    yield "event: done\ndata: {}\n\n"
                    break
                payload = item.model_dump()
                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
        except asyncio.CancelledError:
            return

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.get("/{job_id}/result")
async def triage_result(job_id: str):
    result = store.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not ready")
    return result
