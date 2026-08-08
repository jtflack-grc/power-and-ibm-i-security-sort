/** Collapsed wait / recover callouts for cold live — keep the findings rail honest. */
import { useEffect, useState } from "react";
import type { ProgressEvent } from "../types";

interface WaitProps {
  progress: ProgressEvent[];
  startedAt: number | null;
  onCancel: () => void;
  onFixture: () => void;
}

export function LiveWaitCallout({ progress, startedAt, onCancel, onFixture }: WaitProps) {
  const latest = progress[progress.length - 1];
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const elapsed = startedAt ? Math.round((now - startedAt) / 1000) : 0;
  const slow = elapsed >= 90;

  return (
    <div className="empty-state callout live-wait">
      <strong>Pulling public feeds</strong>
      <p>
        {latest?.message || "Starting NVD / KEV / EPSS / IBM lookups…"}
        {elapsed > 0 ? ` · ${elapsed}s` : ""}
      </p>
      <p className="callout-muted">
        {slow
          ? "Keyless NVD can run long on a cold cache. Stay here, cancel, or walk the fixture while it finishes."
          : "The findings rail stays empty until the first snapshot lands — that is expected on a cold start."}
      </p>
      <div className="callout-actions">
        <button type="button" className="button" onClick={onCancel}>
          Cancel live
        </button>
        <button type="button" className="button" onClick={onFixture}>
          Open curated fixture
        </button>
      </div>
    </div>
  );
}

interface FailProps {
  message: string;
  onRetry: () => void;
  onFixture: () => void;
}

export function LiveFailCallout({ message, onRetry, onFixture }: FailProps) {
  return (
    <div className="empty-state callout live-fail">
      <strong>Live pull did not land</strong>
      <p>{message}</p>
      <p className="callout-muted">
        Upstream rate limits and empty windows happen. Retry, or use the curated fixture for the
        portfolio walkthrough.
      </p>
      <div className="callout-actions">
        <button type="button" className="button button-primary" onClick={onRetry}>
          Retry live
        </button>
        <button type="button" className="button" onClick={onFixture}>
          Open curated fixture
        </button>
      </div>
    </div>
  );
}
