import { useEffect, useState } from "react";
import type { ProgressEvent } from "../types";

interface Props {
  liveRunning: boolean;
  progress: ProgressEvent[];
  startedAt: number | null;
  pendingLive: boolean;
  refreshingCached?: boolean;
  onCancel: () => void;
  onApplyPending: () => void;
  onDismissPending: () => void;
}

function formatEta(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "…";
  if (seconds < 60) return `~${Math.max(1, Math.round(seconds))}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `~${m}m ${s}s`;
}

export function LiveProgressBanner({
  liveRunning,
  progress,
  startedAt,
  pendingLive,
  refreshingCached = false,
  onCancel,
  onApplyPending,
  onDismissPending,
}: Props) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!liveRunning) return;
    const id = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [liveRunning]);

  const latest = progress[progress.length - 1];
  const pct = Math.max(2, latest?.pct ?? 2);
  const elapsedSec = startedAt ? (Date.now() - startedAt) / 1000 : 0;
  const etaSec =
    liveRunning && pct > 5 && pct < 100 ? (elapsedSec * (100 - pct)) / pct : null;
  const slow = liveRunning && elapsedSec >= 90;

  if (pendingLive && !liveRunning) {
    return (
      <div className="live-banner is-ready" role="status">
        <div className="live-banner-main">
          <strong>Live feeds ready</strong>
          <span>Public triage finished. Switch over, or keep the queue you already have open.</span>
        </div>
        <div className="live-banner-actions">
          <button type="button" className="button button-primary" onClick={onApplyPending}>
            Switch to live
          </button>
          <button type="button" className="button" onClick={onDismissPending}>
            Keep current
          </button>
        </div>
      </div>
    );
  }

  if (!liveRunning) return null;

  return (
    <div className={`live-banner ${slow ? "is-slow" : ""}`} role="status" aria-live="polite">
      <div className="live-banner-main">
        <strong>
          {refreshingCached ? "Refreshing live snapshot" : "Live feeds in background"}
        </strong>
        <span>
          {latest?.message || "Starting…"}
          {latest?.stage ? ` · ${latest.stage}` : ""}
          {etaSec != null ? ` · ETA ${formatEta(etaSec)}` : ""}
          {slow
            ? " · Running long — cancel anytime, or open the curated fixture from the findings rail"
            : ""}
        </span>
        <div className="live-banner-bar" aria-hidden>
          <div style={{ transform: `scaleX(${pct / 100})` }} />
        </div>
      </div>
      <div className="live-banner-actions">
        <span className="live-banner-pct">{pct}%</span>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
