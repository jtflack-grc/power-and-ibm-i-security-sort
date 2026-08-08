import { useEffect, useMemo, useRef, useState } from "react";
import type { ActionLane } from "./ActionLanesFlow";
import type { Bucket, Finding, Platform } from "../types";
import { PLATFORM_LABELS } from "../types";

interface Props {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (f: Finding) => void;
  platformFilter: Platform | "all";
  onPlatformFilter: (p: Platform | "all") => void;
  laneFilter: ActionLane | "all";
  onLaneFilter: (lane: ActionLane | "all") => void;
  pasteHitIds?: string[];
}

const BUCKETS: Array<Bucket | "all"> = ["all", "urgent", "watch", "low"];
const PLATFORMS: Array<Platform | "all"> = [
  "all",
  "ibm_i",
  "aix",
  "zos",
  "linux_on_power",
];

function shortDate(value?: string | null): string | null {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

export function FindingsPanel({
  findings,
  selectedId,
  onSelect,
  platformFilter,
  onPlatformFilter,
  laneFilter,
  onLaneFilter,
  pasteHitIds = [],
}: Props) {
  const [bucket, setBucket] = useState<Bucket | "all">("all");
  const listRef = useRef<HTMLDivElement>(null);
  const skipAutoScroll = useRef(true);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (bucket !== "all" && f.bucket !== bucket) return false;
      if (
        platformFilter !== "all" &&
        !f.platforms.some((p) => p.platform === platformFilter)
      ) {
        return false;
      }
      if (laneFilter !== "all" && (f.action_lane ?? "monitor") !== laneFilter) {
        return false;
      }
      return true;
    });
  }, [findings, bucket, platformFilter, laneFilter]);

  // New result or filter change: stay at the top of the findings panel.
  useEffect(() => {
    skipAutoScroll.current = true;
    const root = listRef.current;
    if (!root) return;
    root.scrollTo({ top: 0 });
    const pane = root.closest(".panel-body");
    if (pane instanceof HTMLElement) pane.scrollTo({ top: 0 });
  }, [findings, platformFilter, bucket, laneFilter]);

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
        if (!filtered.length) return;
        const idx = filtered.findIndex((f) => f.cve_id === selectedId);
        if (e.key === "ArrowDown") {
          e.preventDefault();
          const next = filtered[Math.min(filtered.length - 1, Math.max(0, idx) + 1)];
          if (next) onSelect(next);
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          const prev = filtered[Math.max(0, (idx < 0 ? 0 : idx) - 1)];
          if (prev) onSelect(prev);
        } else if (e.key === "Enter" && selectedId) {
          const cur = filtered.find((f) => f.cve_id === selectedId);
          if (cur) onSelect(cur);
        }
      }}
    >
      <div className="findings-filters">
        <div className="filter-row-label">Platform</div>
        {PLATFORMS.map((p) => (
          <button
            key={p}
            type="button"
            className={`chip chip-platform ${platformFilter === p ? "active" : ""}`}
            onClick={() => onPlatformFilter(p)}
          >
            {p === "all" ? "All platforms" : PLATFORM_LABELS[p]}
          </button>
        ))}
      </div>
      {platformFilter === "all" && (
        <div className="filter-hint">Start wide — chip a platform when you want the rail narrower.</div>
      )}
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
      <div className="filter-count">
        Showing {filtered.length} of {findings.length} · ↑↓ to move
      </div>
      {filtered.map((f) => {
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
        <div className="empty-state">No findings in this platform / dock / priority cut.</div>
      )}
    </div>
  );
}
