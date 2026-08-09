import type { FeedHealth } from "../types";

interface Props {
  health: FeedHealth[];
  notes?: string[];
  mode?: "sample" | "live";
  generatedAt?: string;
}

/**
 * Permanent quiet footing under the docks — breaks the three-rectangle mass
 * without competing for attention. Not a card; a ledger line.
 */
export function FeedHealthStrip({ health, notes, mode, generatedAt }: Props) {
  if (!health.length && !notes?.length) return null;

  const ok = health.filter((h) => h.status === "ok").length;
  const bad = health.filter((h) => h.status !== "ok").length;
  const generatedTime = generatedAt ? new Date(generatedAt).getTime() : Number.NaN;
  const staleHours = Number.isNaN(generatedTime) ? null : Math.floor((Date.now() - generatedTime) / 3_600_000);
  const stale = mode === "live" && staleHours != null && staleHours >= 48;

  return (
    <aside className="feed-health feed-health-aside" aria-label="Feed sources">
      <div className="feed-health-head">
        <span>Sources</span>
        <span className="feed-health-meta">
          {mode === "sample" ? "sample" : "live"}
          {health.length
            ? ` · ${bad > 0 ? `${ok} ok · ${bad} attention` : `${health.length} ok`}`
            : ""}
          {generatedAt ? ` · ${generatedAt.slice(0, 10)}` : ""}
        </span>
      </div>
      {stale && (
        <p className="feed-stale" role="status">
          Published snapshot is {Math.floor(staleHours / 24)} days old. Verify current IBM bulletins before change work.
        </p>
      )}
      {health.length > 0 && (
        <ul className="feed-health-list">
          {health.map((h) => (
            <li key={h.id} className={`feed-pill status-${h.status}`}>
              <span className="feed-pill-label">{h.label}</span>
              <span className="feed-pill-status">{h.status}</span>
              {h.detail && <span className="feed-pill-detail">{h.detail}</span>}
            </li>
          ))}
        </ul>
      )}
      {notes && notes.length > 0 && (
        <ul className="feed-notes">
          {notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </aside>
  );
}
