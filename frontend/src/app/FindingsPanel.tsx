import { useEffect, useMemo, useRef, useState } from "react";
import type { ActionLane } from "./ActionLanesFlow";
import type { Bucket, Finding } from "../types";
import { PLATFORM_LABELS } from "../types";

interface Props {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (f: Finding) => void;
  laneFilter: ActionLane | "all";
  onLaneFilter: (lane: ActionLane | "all") => void;
  pasteHitIds?: string[];
}

const BUCKETS: Array<Bucket | "all"> = ["all", "urgent", "watch", "low"];
const FOCUS_LIMIT = 40;
/** Match backend RankerConfig.ancient_days (~7y). */
const MUSEUM_AGE_DAYS = 2555;

function shortDate(value?: string | null): string | null {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

export function isMuseumFinding(f: Finding): boolean {
  if (f.on_kev) return false;
  if (f.levers?.some((l) => l.id === "ancient_unconfirmed_temper")) return true;
  // Prefer published age — last_modified churn must not keep museum rows in the default rail.
  const stamp = f.published;
  if (!stamp) return false;
  const t = new Date(stamp).getTime();
  if (Number.isNaN(t)) return false;
  const ageDays = (Date.now() - t) / 86_400_000;
  return ageDays >= MUSEUM_AGE_DAYS;
}

export function FindingsPanel({
  findings,
  selectedId,
  onSelect,
  laneFilter,
  onLaneFilter,
  pasteHitIds = [],
}: Props) {
  const [bucket, setBucket] = useState<Bucket | "all">("all");
  const [includeOlder, setIncludeOlder] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const skipAutoScroll = useRef(true);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (bucket !== "all" && f.bucket !== bucket) return false;
      if (laneFilter !== "all" && (f.action_lane ?? "monitor") !== laneFilter) {
        return false;
      }
      if (!includeOlder && isMuseumFinding(f)) {
        // Keep paste matches and the current selection reachable.
        if (selectedId === f.cve_id) return true;
        if (pasteHitIds.includes(f.cve_id)) return true;
        return false;
      }
      return true;
    });
  }, [findings, bucket, laneFilter, includeOlder, selectedId, pasteHitIds]);

  const olderHidden = useMemo(() => {
    if (includeOlder) return 0;
    return findings.filter((f) => {
      if (!isMuseumFinding(f)) return false;
      if (selectedId === f.cve_id) return false;
      if (pasteHitIds.includes(f.cve_id)) return false;
      if (bucket !== "all" && f.bucket !== bucket) return false;
      if (laneFilter !== "all" && (f.action_lane ?? "monitor") !== laneFilter) {
        return false;
      }
      return true;
    }).length;
  }, [findings, includeOlder, selectedId, pasteHitIds, bucket, laneFilter]);

  const visible = useMemo(() => {
    if (showAll || filtered.length <= FOCUS_LIMIT) return filtered;
    const head = filtered.slice(0, FOCUS_LIMIT);
    if (selectedId && !head.some((f) => f.cve_id === selectedId)) {
      const selected = filtered.find((f) => f.cve_id === selectedId);
      if (selected) return [...head, selected];
    }
    return head;
  }, [filtered, showAll, selectedId]);

  // New result or filter change: stay at the top of the findings panel.
  useEffect(() => {
    skipAutoScroll.current = true;
    setShowAll(false);
    const root = listRef.current;
    if (!root) return;
    root.scrollTo({ top: 0 });
    const pane = root.closest(".panel-body");
    if (pane instanceof HTMLElement) pane.scrollTo({ top: 0 });
  }, [findings, bucket, laneFilter, includeOlder]);

  // Only scroll a row into view after deliberate keyboard moves (not auto-select on load).
  useEffect(() => {
    if (skipAutoScroll.current) {
      skipAutoScroll.current = false;
      return;
    }
    if (!selectedId || !listRef.current) return;
    const el = listRef.current.querySelector(`[data-cve="${selectedId}"]`);
    if (el instanceof HTMLElement) {
      el.scrollIntoView({ block: "nearest" });
    }
  }, [selectedId]);

  if (!findings.length) {
    return (
      <div className="empty-state">
        No curated findings yet. Run live triage to pull public feeds.
      </div>
    );
  }

  return (
    <div
      ref={listRef}
      tabIndex={0}
      onKeyDown={(e) => {
        if (!visible.length) return;
        const idx = visible.findIndex((f) => f.cve_id === selectedId);
        if (e.key === "ArrowDown") {
          e.preventDefault();
          const next = visible[Math.min(visible.length - 1, Math.max(0, idx) + 1)];
          if (next) onSelect(next);
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          const prev = visible[Math.max(0, (idx < 0 ? 0 : idx) - 1)];
          if (prev) onSelect(prev);
        } else if (e.key === "Enter" && selectedId) {
          const cur = visible.find((f) => f.cve_id === selectedId);
          if (cur) onSelect(cur);
        }
      }}
    >
      <div className="findings-filters">
        <div className="filter-row-label">Priority</div>
        {BUCKETS.map((b) => (
          <button
            key={b}
            type="button"
            className={`chip ${bucket === b ? "active" : ""}`}
            onClick={() => setBucket(b)}
          >
            {b}
          </button>
        ))}
      </div>
      {laneFilter !== "all" && (
        <div className="findings-filters">
          <div className="filter-row-label">Dock filter</div>
          <button
            type="button"
            className="chip active"
            onClick={() => onLaneFilter("all")}
          >
            {laneFilter} ✕
          </button>
        </div>
      )}
      <div className="findings-focus-bar">
        <button
          type="button"
          className={`chip ${includeOlder ? "active" : ""}`}
          onClick={() => setIncludeOlder((v) => !v)}
          title="Museum CVEs without KEV / PSIRT stay out of the default rail"
        >
          {includeOlder ? "Older included" : "Include older findings"}
        </button>
        {filtered.length > FOCUS_LIMIT && (
          <button
            type="button"
            className={`chip ${showAll ? "active" : ""}`}
            onClick={() => setShowAll((v) => !v)}
          >
            {showAll ? `Show top ${FOCUS_LIMIT}` : `Show all ${filtered.length}`}
          </button>
        )}
      </div>
      <div className="filter-count">
        Showing {visible.length} of {findings.length}
        {!showAll && filtered.length > FOCUS_LIMIT ? ` · focus ${FOCUS_LIMIT}` : ""}
        {olderHidden > 0 ? ` · ${olderHidden} older hidden` : ""}
        {" · ↑↓ to move"}
      </div>
      {visible.map((f) => {
        const selected = selectedId === f.cve_id;
        const supply = f.risk_surface && f.risk_surface !== "platform";
        const published = shortDate(f.published);
        return (
          <button
            key={f.cve_id}
            type="button"
            data-cve={f.cve_id}
            className={`finding-row ${selected ? "selected" : ""}`}
            onClick={() => onSelect(f)}
          >
            <div className="finding-top">
              <span className="cve-id">{f.cve_id}</span>
              <span className="score-pill">{f.score.toFixed(0)}</span>
            </div>
            <div className="finding-title">{f.title}</div>
            <div className="finding-meta">
              {published && <span>{published}</span>}
              {f.cvss_score != null && <span>CVSS {f.cvss_score}</span>}
              {f.epss != null && <span>EPSS {(f.epss * 100).toFixed(1)}%</span>}
              {f.ibm_bulletin_status === "confirmed" && <span>PSIRT</span>}
            </div>
            <div className="badges">
              <span className={`badge ${f.bucket}`}>{f.bucket}</span>
              {f.action_lane && (
                <span className={`badge badge-lane lane-${f.action_lane}`}>
                  {f.action_lane}
                </span>
              )}
              {supply && <span className="badge badge-supply">Supply chain</span>}
              {f.on_kev && <span className="badge kev">KEV</span>}
              {pasteHitIds.includes(f.cve_id) && (
                <span className="badge badge-paste">paste match</span>
              )}
              {f.platforms.slice(0, 2).map((p) => (
                <span key={p.platform} className="badge badge-platform">
                  {PLATFORM_LABELS[p.platform]}
                </span>
              ))}
            </div>
          </button>
        );
      })}
      {filtered.length === 0 && (
        <div className="empty-state">No findings in this dock / priority cut.</div>
      )}
    </div>
  );
}
