import { useEffect, useMemo, useRef, useState } from "react";
import type { ActionLane } from "./ActionLanesFlow";
import type { Bucket, Bulletin, Finding } from "../types";
import { PLATFORM_LABELS } from "../types";
import { hasIndividualPtfEvidence } from "../ptfEvidence";

interface Props {
  findings: Finding[];
  bulletins?: Bulletin[];
  selectedId: string | null;
  onSelect: (f: Finding) => void;
  laneFilter: ActionLane | "all";
  onLaneFilter: (lane: ActionLane | "all") => void;
  pasteHitIds?: string[];
}

const BUCKETS: Array<Bucket | "all"> = ["all", "urgent", "watch", "low"];
const LANES: Array<ActionLane | "all"> = ["all", "apply", "contain", "monitor"];
const FOCUS_LIMIT = 40;
/** Match backend RankerConfig.ancient_days (~7y). */
const MUSEUM_AGE_DAYS = 2555;
const SEEN_BULLETINS_KEY = "ibmi-curator-seen-bulletins-v1";

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

function hasPtfEvidence(f: Finding): boolean {
  return hasIndividualPtfEvidence(f);
}

export function FindingsPanel({
  findings,
  bulletins = [],
  selectedId,
  onSelect,
  laneFilter,
  onLaneFilter,
  pasteHitIds = [],
}: Props) {
  const [bucket, setBucket] = useState<Bucket | "all">("all");
  const [includeOlder, setIncludeOlder] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [ptfOnly, setPtfOnly] = useState(false);
  const [releaseFilter, setReleaseFilter] = useState("all");
  const [remedyFilter, setRemedyFilter] = useState("all");
  const [recentOnly, setRecentOnly] = useState(false);
  const [newOnly, setNewOnly] = useState(false);
  const [newBulletinIds, setNewBulletinIds] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const listRef = useRef<HTMLDivElement>(null);
  const skipAutoScroll = useRef(true);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (bucket !== "all" && f.bucket !== bucket) return false;
      if (ptfOnly && !hasPtfEvidence(f)) return false;
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
  }, [findings, bucket, laneFilter, includeOlder, selectedId, pasteHitIds, ptfOnly]);

  const ptfCount = useMemo(() => findings.filter(hasPtfEvidence).length, [findings]);

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
    // A source-extracted PTF unlocks the verification rail, so retain those
    // sparse rows in the focused queue even when rank places them below 40.
    for (const finding of filtered) {
      if (hasPtfEvidence(finding) && !head.some((f) => f.cve_id === finding.cve_id)) {
        head.push(finding);
      }
    }
    if (selectedId && !head.some((f) => f.cve_id === selectedId)) {
      const selected = filtered.find((f) => f.cve_id === selectedId);
      if (selected) return [...head, selected];
    }
    return head;
  }, [filtered, showAll, selectedId]);

  const bulletinIndex = useMemo(
    () => new Map(bulletins.map((bulletin) => [bulletin.bulletin_id, bulletin])),
    [bulletins]
  );
  useEffect(() => {
    if (!bulletins.length) return;
    const current = bulletins.map((bulletin) => bulletin.bulletin_id);
    try {
      const previous = JSON.parse(localStorage.getItem(SEEN_BULLETINS_KEY) || "[]") as string[];
      setNewBulletinIds(new Set(previous.length ? current.filter((id) => !previous.includes(id)) : []));
      localStorage.setItem(SEEN_BULLETINS_KEY, JSON.stringify(current));
    } catch {
      setNewBulletinIds(new Set());
    }
  }, [bulletins]);
  const releaseOptions = useMemo(
    () => [...new Set(bulletins.flatMap((bulletin) => bulletin.applicability.map((row) => row.release).filter(Boolean) as string[]))].sort(),
    [bulletins]
  );
  const visibleGroups = useMemo(() => {
    const groups = new Map<string, { id: string; title: string; published?: string | null; findings: Finding[] }>();
    for (const finding of visible) {
      const id = finding.bulletin_id || finding.ibm_bulletin_url || `cve-${finding.cve_id}`;
      const bulletin = bulletinIndex.get(id);
      const group = groups.get(id);
      if (group) group.findings.push(finding);
      else groups.set(id, {
        id,
        title: bulletin?.title || finding.ibm_bulletin_title || finding.title,
        published: bulletin?.published || finding.published,
        findings: [finding],
      });
    }
    return [...groups.values()].filter((group) => {
      const bulletin = bulletinIndex.get(group.id);
      if (newOnly && !newBulletinIds.has(group.id)) return false;
      if (recentOnly) {
        const stamp = new Date(group.published || "").getTime();
        if (Number.isNaN(stamp) || Date.now() - stamp > 30 * 86_400_000) return false;
      }
      if (releaseFilter !== "all" && !bulletin?.applicability.some((row) => row.release === releaseFilter)) return false;
      if (remedyFilter === "all") return true;
      const steps = group.findings.flatMap((finding) => finding.resolution_steps ?? []);
      if (remedyFilter === "ptf") return steps.some((step) => step.kind === "ptf");
      if (remedyFilter === "group") return steps.some((step) => step.kind === "ptf_group");
      if (remedyFilter === "apar") return steps.some((step) => step.kind === "apar");
      return !steps.some((step) => ["ptf", "ptf_group", "apar"].includes(String(step.kind)));
    });
  }, [visible, bulletinIndex, releaseFilter, remedyFilter, newOnly, newBulletinIds, recentOnly]);
  const visibleGroupFindings = useMemo(() => visibleGroups.flatMap((group) => group.findings), [visibleGroups]);

  useEffect(() => {
    if (!selectedId) return;
    const group = visibleGroups.find((item) => item.findings.some((finding) => finding.cve_id === selectedId));
    if (!group) return;
    setExpanded((current) => current.has(group.id) ? current : new Set([...current, group.id]));
  }, [selectedId, visibleGroups]);

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
        if (!visibleGroupFindings.length) return;
        const idx = visibleGroupFindings.findIndex((f) => f.cve_id === selectedId);
        if (e.key === "ArrowDown") {
          e.preventDefault();
          const next = visibleGroupFindings[Math.min(visibleGroupFindings.length - 1, Math.max(0, idx) + 1)];
          if (next) onSelect(next);
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          const prev = visibleGroupFindings[Math.max(0, (idx < 0 ? 0 : idx) - 1)];
          if (prev) onSelect(prev);
        } else if (e.key === "Enter" && selectedId) {
          const cur = visibleGroupFindings.find((f) => f.cve_id === selectedId);
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
        {ptfCount > 0 && (
          <button
            type="button"
            className={`chip ${ptfOnly ? "active" : ""}`}
            onClick={() => setPtfOnly((value) => !value)}
            title="Show findings with a PTF identifier extracted from IBM guidance"
          >
            PTF evidence ({ptfCount})
          </button>
        )}
      </div>
      <div className="findings-filters findings-filters-compact">
        <div className="filter-row-label">Action</div>
        {LANES.map((lane) => (
          <button
            key={lane}
            type="button"
            className={`chip ${laneFilter === lane ? "active" : ""}`}
            onClick={() => onLaneFilter(lane)}
          >
            {lane}
          </button>
        ))}
      </div>
      <div className="findings-focus-bar">
        <button type="button" className={`chip ${recentOnly ? "active" : ""}`} onClick={() => setRecentOnly((value) => !value)}>Recently published · 30d</button>
        {newBulletinIds.size > 0 && <button type="button" className={`chip ${newOnly ? "active" : ""}`} onClick={() => setNewOnly((value) => !value)}>New since last visit ({newBulletinIds.size})</button>}
        <label className="queue-select">Release
          <select value={releaseFilter} onChange={(event) => setReleaseFilter(event.target.value)}>
            <option value="all">All</option>
            {releaseOptions.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>
        <label className="queue-select">Remedy
          <select value={remedyFilter} onChange={(event) => setRemedyFilter(event.target.value)}>
            <option value="all">All</option><option value="ptf">Individual PTF</option><option value="group">Group PTF</option><option value="apar">APAR</option><option value="unresolved">Unresolved</option>
          </select>
        </label>
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
        Showing {visibleGroups.length} bulletins · {visibleGroupFindings.length} of {findings.length} CVEs
        {!showAll && filtered.length > FOCUS_LIMIT ? ` · focus ${FOCUS_LIMIT}` : ""}
        {olderHidden > 0 ? ` · ${olderHidden} older hidden` : ""}
        {" · ↑↓ to move"}
      </div>
      {visibleGroups.map((group) => {
        const isExpanded = expanded.has(group.id);
        const lead = group.findings.reduce((best, finding) => finding.score > best.score ? finding : best, group.findings[0]);
        const published = shortDate(group.published);
        return (
          <section key={group.id} className={`bulletin-group ${group.findings.some((finding) => finding.cve_id === selectedId) ? "selected" : ""}`}>
            <button type="button" className="bulletin-row" aria-expanded={isExpanded} onClick={() => setExpanded((current) => {
              const next = new Set(current);
              if (next.has(group.id)) next.delete(group.id); else next.add(group.id);
              return next;
            })}>
              <div className="finding-top"><span className="cve-id">{group.findings.length} CVE{group.findings.length === 1 ? "" : "s"}</span><span className="score-pill">{lead.score.toFixed(0)}</span></div>
              <div className="finding-title">{group.title}</div>
              <div className="finding-meta">{published && <span>{published}</span>}<span>PSIRT bulletin</span><span>{isExpanded ? "Collapse" : "Expand"}</span></div>
              <div className="badges"><span className={`badge ${lead.bucket}`}>{lead.bucket}</span>{group.findings.some((finding) => finding.on_kev) && <span className="badge kev">KEV</span>}{group.findings.some(hasPtfEvidence) && <span className="badge badge-ptf">PTF</span>}</div>
            </button>
            {isExpanded && <div className="bulletin-cves">{group.findings.map((f) => {
              const selected = selectedId === f.cve_id;
              return <button key={f.cve_id} type="button" data-cve={f.cve_id} className={`finding-row finding-row-child ${selected ? "selected" : ""}`} onClick={() => onSelect(f)}>
                <div className="finding-top"><span className="cve-id">{f.cve_id}</span><span className="score-pill">{f.score.toFixed(0)}</span></div>
                <div className="finding-meta">{f.cvss_score != null && <span>CVSS {f.cvss_score}</span>}{f.epss != null && <span>EPSS {(f.epss * 100).toFixed(1)}%</span>}<span className={`badge ${f.bucket}`}>{f.bucket}</span>{f.action_lane && <span className={`badge badge-lane lane-${f.action_lane}`}>{f.action_lane}</span>}{hasPtfEvidence(f) && <span className="badge badge-ptf">PTF</span>}{pasteHitIds.includes(f.cve_id) && <span className="badge badge-paste">paste match</span>}{f.platforms.slice(0, 1).map((p) => <span key={p.platform} className="badge badge-platform">{PLATFORM_LABELS[p.platform]}</span>)}</div>
              </button>;
            })}</div>}
          </section>
        );
      })}
      {filtered.length === 0 && (
        <div className="empty-state">No findings in this dock / priority cut.</div>
      )}
    </div>
  );
}
