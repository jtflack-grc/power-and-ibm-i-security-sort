/**
 * Action docks — Apply / Contain / Monitor.
 * Selected CVE uses an amber rule under the dock; click filters the queue.
 */
import { useEffect, useMemo, useState } from "react";
import type { Finding } from "../types";

export type ActionLane = "apply" | "contain" | "monitor";

const LANES: ActionLane[] = ["apply", "contain", "monitor"];

const LANE_COPY: Record<
  ActionLane,
  { title: string; verb: string; hint: string }
> = {
  apply: {
    title: "Apply package",
    verb: "Change-ready",
    hint: "PTF / APAR / bulletin path extracted",
  },
  contain: {
    title: "Contain interim",
    verb: "Buy time",
    hint: "No package yet — interim controls available",
  },
  monitor: {
    title: "Monitor",
    verb: "Stay aware",
    hint: "Tempered by levers — watch, don’t thrash",
  },
};

function laneOf(f: Finding): ActionLane {
  return f.action_lane ?? "monitor";
}

function isSupply(f: Finding): boolean {
  return (f.risk_surface ?? "platform") !== "platform";
}

interface Props {
  findings: Finding[];
  selected?: Finding | null;
  settling?: boolean;
  laneFilter: ActionLane | "all";
  onLaneFilter: (lane: ActionLane | "all") => void;
  onSelect: (f: Finding) => void;
}

export function ActionLanesFlow({
  findings,
  selected,
  settling,
  laneFilter,
  onLaneFilter,
  onSelect,
}: Props) {
  const [settled, setSettled] = useState(false);

  useEffect(() => {
    setSettled(false);
    if (!findings.length || settling) return;
    const t = window.setTimeout(() => setSettled(true), 900);
    return () => window.clearTimeout(t);
  }, [findings, settling]);

  const byLane = useMemo(() => {
    const map: Record<ActionLane, Finding[]> = {
      apply: [],
      contain: [],
      monitor: [],
    };
    for (const f of findings) {
      map[laneOf(f)].push(f);
    }
    for (const lane of LANES) {
      map[lane].sort((a, b) => b.score - a.score);
    }
    return map;
  }, [findings]);

  const total = Math.max(1, findings.length);
  const selectedLane = selected ? laneOf(selected) : null;

  if (!findings.length) {
    return (
      <div className="empty-state" style={{ padding: "1.5rem" }}>
        After triage, Apply / Contain / Monitor fill here. Click a dock to filter the findings
        rail.
      </div>
    );
  }

  return (
    <div className={`docks-wrap ${settled ? "is-settled" : "is-settling"}`}>
      <div className="docks-header">
        <div>
          <h3 className="docks-title">Work docks</h3>
          <div className="docks-sub">Click a dock to filter the queue.</div>
        </div>
        {laneFilter !== "all" && (
          <button type="button" className="button" onClick={() => onLaneFilter("all")}>
            Clear filter
          </button>
        )}
      </div>

      <div className="docks-grid">
        {LANES.map((lane, idx) => {
          const items = byLane[lane];
          const share = items.length / total;
          const supply = items.filter(isSupply).length;
          const active = laneFilter === lane;
          const hasSelected = selectedLane === lane;
          const head = items[0];
          const delay = `${0.06 + idx * 0.1}s`;
          const scale = settled ? Math.max(0.04, share) : 0;

          return (
            <button
              key={lane}
              type="button"
              className={[
                "dock",
                `dock-${lane}`,
                active ? "is-active" : "",
                hasSelected ? "has-selected" : "",
              ]
                .filter(Boolean)
                .join(" ")}
              style={{ animationDelay: delay }}
              onClick={() => {
                onLaneFilter(active ? "all" : lane);
                if (head) onSelect(head);
              }}
            >
              <div className="dock-top">
                <span className="dock-title">{LANE_COPY[lane].title}</span>
                <span className="dock-verb">{LANE_COPY[lane].verb}</span>
              </div>

              <div className="dock-count" aria-label={`${items.length} findings`}>
                <span className="dock-count-num">{items.length}</span>
                <span className="dock-count-unit">findings</span>
              </div>

              <div className="dock-meter" aria-hidden>
                <div
                  className="dock-meter-fill"
                  style={{
                    transform: `scaleX(${scale})`,
                    transitionDelay: delay,
                  }}
                />
              </div>

              <div className="dock-meta">
                <span>{Math.round(share * 100)}% of view</span>
                {supply > 0 && (
                  <span className="dock-supply">{supply} supply-chain</span>
                )}
              </div>

              <div className="dock-hint">{LANE_COPY[lane].hint}</div>

              {hasSelected && selected ? (
                <div className="dock-selected">
                  <span className="dock-selected-label">Selected</span>
                  <span className="dock-selected-cve">{selected.cve_id}</span>
                </div>
              ) : head ? (
                <div className="dock-next">
                  <span className="dock-selected-label">Top of dock</span>
                  <span className="dock-selected-cve">{head.cve_id}</span>
                </div>
              ) : (
                <div className="dock-next muted">Empty</div>
              )}
            </button>
          );
        })}
      </div>

      <div className="docks-caption">
        Apply when a package path exists. Contain when interim controls are the honest next
        step. Monitor when levers temper the noise.
      </div>
    </div>
  );
}
