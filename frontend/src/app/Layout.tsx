import { estimateOsint } from "../osintAssessment";
import { useEffect, useMemo, useState } from "react";
import type { Finding, ProgressEvent, TriageResult } from "../types";
import { assess, readStore, STORAGE_KEY, storeKey } from "../contextAssessment";
import type { Assessment, AssessmentStore } from "../contextAssessment";
import { cvssValue } from "../cvss";
import { FLAGSHIP_CVE, FlagshipWalkthrough } from "./FlagshipWalkthrough";
import type { ActionLane } from "./ActionLanesFlow";
import { FeedHealthStrip } from "./FeedHealthStrip";
import { FindingsPanel } from "./FindingsPanel";
import { IssueDetailPanel } from "./IssueDetailPanel";
import { LiveFailCallout, LiveWaitCallout } from "./LiveStatusCallouts";
import { LiveProgressBanner } from "./LiveProgressBanner";
import { VerificationRail } from "./VerificationRail";

type Pane = "findings" | "issue" | "flow";

interface Props {
  result: TriageResult | null;
  liveRunning: boolean;
  sampleLoading: boolean;
  publishedLoading?: boolean;
  progress: ProgressEvent[];
  liveStartedAt: number | null;
  pendingLive: boolean;
  refreshingCached?: boolean;
  onRun: (force: boolean) => void;
  onSample: () => void;
  onPublished: () => void;
  onCancelLive: () => void;
  onApplyPending: () => void;
  onDismissPending: () => void;
  backendAvailable: boolean;
  publishedAvailable: boolean;
  onOpenCredits?: () => void;
  liveError?: string | null;
  onClearError?: () => void;
}

function formatStamp(iso?: string): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function Layout({
  result,
  liveRunning,
  sampleLoading,
  publishedLoading = false,
  progress,
  liveStartedAt,
  pendingLive,
  refreshingCached = false,
  onRun,
  onSample,
  onPublished,
  onCancelLive,
  onApplyPending,
  onDismissPending,
  backendAvailable,
  publishedAvailable,
  onOpenCredits,
  liveError = null,
  onClearError,
}: Props) {
  const [assessmentClock, setAssessmentClock] = useState(Date.now());
  useEffect(() => { const timer = window.setInterval(() => setAssessmentClock(Date.now()), 60_000); return () => window.clearInterval(timer); }, []);
  const [contextStore, setContextStore] = useState<AssessmentStore>(() => {
    try { return readStore(localStorage.getItem(STORAGE_KEY)); } catch { return {}; }
  });
  const saveContext = (record: Assessment): boolean => {
    const key = storeKey(record.mode, record.cveId);
    const entries = contextStore[key] || [];
    const next = { ...contextStore, [key]: [record, ...entries.filter(item => item.id !== record.id)].slice(0, 30) };
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); setContextStore(next); return true; }
    catch { setContextStore(next); return false; }
  };
  const [pane, setPane] = useState<Pane>("findings");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [laneFilter, setLaneFilter] = useState<ActionLane | "all">("all");
  const [showFlagship, setShowFlagship] = useState(true);
  const [showFeedSources, setShowFeedSources] = useState(false);

  const findings = useMemo(() => result?.findings ?? [], [result?.findings]);
  const contextMode = result?.mode || "unknown";
  const contextLabels = useMemo(() => Object.fromEntries(findings.map(finding => {
    const estimate = estimateOsint(finding);
    const automatic = `IBM i OSINT ${estimate.low.toFixed(1)}–${estimate.high.toFixed(1)} · Estimated`;
    const record = contextStore[storeKey(contextMode, finding.cve_id)]?.[0];
    if (!record) return [finding.cve_id, automatic];
    const assessment = assess(record, finding, assessmentClock);
    return [finding.cve_id, automatic + (assessment.range ? ` · Local ${assessment.range.low.toFixed(1)}–${assessment.range.high.toFixed(1)} (${record.asset})` : "")];
  })), [findings, contextStore, contextMode, assessmentClock]);
  const publishedStamp = formatStamp(result?.generated_at);
  const modeLabel =
    result?.mode === "live"
      ? backendAvailable
        ? "live feeds"
        : publishedStamp
          ? `published · ${publishedStamp}`
          : "published feeds"
      : result
        ? "sample"
        : "idle";
  const flagship =
    findings.find((f) => f.cve_id === (result?.flagship_cve || FLAGSHIP_CVE)) ?? null;
  const emptyLive = result?.mode === "live" && findings.length === 0;
  const scopedFindings = useMemo(() => [...findings].sort((a, b) => (cvssValue(b) ?? -1) - (cvssValue(a) ?? -1) || b.score - a.score), [findings]);

  useEffect(() => {
    if (!scopedFindings.length) {
      setSelected(null);
      return;
    }
    setSelected((prev) => {
      if (prev && scopedFindings.some((f) => f.cve_id === prev.cve_id)) {
        return scopedFindings.find((f) => f.cve_id === prev.cve_id) ?? prev;
      }
      return scopedFindings[0];
    });
  }, [scopedFindings]);

  const selectedResolved =
    selected == null
      ? null
      : scopedFindings.find((f) => f.cve_id === selected.cve_id) ?? selected;
  const selectedBulletin = selectedResolved?.bulletin_id
    ? result?.bulletins?.find((bulletin) => bulletin.bulletin_id === selectedResolved.bulletin_id) ?? null
    : null;

  const openFinding = (f: Finding) => {
    setSelected(f);
    setPane("issue");
    setShowFlagship(false);
    requestAnimationFrame(() => document.getElementById("issue-workbench")?.focus());
  };

  return (
    <div className="app-shell cvss-first-layout">
      <header className="site-header">
        <a
          className="brand"
          href="https://jtflack-grc.github.io/portfolio/"
          target="_blank"
          rel="noreferrer"
        >
          <div className="brand-wordmark">
            <span>IBM i Fix Curator</span>
          </div>
          <div className="brand-sub">CVE-to-fix evidence · i on GRC</div>
        </a>
        <div className="header-actions">
          <button
            type="button"
            className="button"
            onClick={onSample}
            disabled={sampleLoading}
          >
            {sampleLoading ? "Loading sample…" : "Load sample"}
          </button>
          {onOpenCredits && (
            <button type="button" className="button" onClick={onOpenCredits}>
              Help &amp; credits
            </button>
          )}
          {publishedAvailable && !backendAvailable && (
            <button
              type="button"
              className="button button-primary"
              onClick={onPublished}
              disabled={publishedLoading}
              title={
                publishedStamp
                  ? `Published snapshot · ${publishedStamp}`
                  : "Scheduled public intel snapshot"
              }
            >
              {publishedLoading ? "Loading feeds…" : "Published feeds"}
            </button>
          )}
          {backendAvailable && (
            <>
              <button
                type="button"
                className="button"
                onClick={() => onRun(true)}
                disabled={liveRunning}
                title="Bypass local cache; still keyless public feeds"
              >
                Refresh live
              </button>
              <button
                type="button"
                className="button button-primary"
                onClick={() => onRun(false)}
                disabled={liveRunning}
              >
                {liveRunning ? "Live running…" : "Live in background"}
              </button>
            </>
          )}
        </div>
      </header>

      <LiveProgressBanner
        liveRunning={liveRunning}
        progress={progress}
        startedAt={liveStartedAt}
        pendingLive={pendingLive}
        refreshingCached={refreshingCached}
        onCancel={onCancelLive}
        onApplyPending={onApplyPending}
        onDismissPending={onDismissPending}
      />

      <div className="mobile-tabs">
        {(["findings", "issue", "flow"] as Pane[]).map((p) => (
          <button
            key={p}
            type="button"
            className={pane === p ? "active" : ""}
            onClick={() => setPane(p)}
          >
            {p === "issue" ? "Issue" : p === "flow" ? "Actions" : "Findings"}
          </button>
        ))}
      </div>

      <main className="panel-grid">
        <section id="cvss-listing" className={`panel findings-panel-shell ${pane !== "findings" ? "hidden-mobile" : ""}`}>
          <div className="panel-head">
            <h2>CVSS score listing</h2>
            <div className="meta">
              {scopedFindings.length} · {modeLabel}
              {liveRunning ? " · live bg" : ""}
            </div>
          </div>
          <div className="panel-body">
            {liveRunning && !result && (
              <LiveWaitCallout
                progress={progress}
                startedAt={liveStartedAt}
                onCancel={onCancelLive}
                onFixture={onSample}
              />
            )}
            {liveError && !result && !liveRunning && !sampleLoading && !publishedLoading && (
              <LiveFailCallout
                message={liveError}
                onRetry={() => {
                  onClearError?.();
                  if (backendAvailable) onRun(false);
                  else if (publishedAvailable) onPublished();
                  else onSample();
                }}
                onFixture={() => {
                  onClearError?.();
                  onSample();
                }}
              />
            )}
            {(sampleLoading || publishedLoading) && !result && !liveRunning && (
              <div className="empty-state callout" role="status">
                <strong>{publishedLoading ? "Loading published feeds…" : "Loading sample…"}</strong>
                <p className="callout-muted">Pulling the curated queue into this tab.</p>
              </div>
            )}
            {emptyLive && !liveRunning && (
              <div className="empty-state callout">
                <strong>Live returned an empty queue</strong>
                <p className="callout-muted">
                  Rate limit, empty window, or upstream hiccup — common on keyless NVD. Retry, or
                  walk the fixture.
                </p>
                <div className="callout-actions">
                  {backendAvailable ? (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={() => onRun(true)}
                    >
                      Retry live
                    </button>
                  ) : publishedAvailable ? (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={onPublished}
                    >
                      Reload published feeds
                    </button>
                  ) : null}
                  <button type="button" className="button" onClick={onSample}>
                    Open curated fixture
                  </button>
                </div>
              </div>
            )}
            {!result &&
              !liveRunning &&
              !sampleLoading &&
              !publishedLoading &&
              !liveError && (
              <div className="empty-state callout">
                Nothing loaded yet.
                <div className="callout-actions">
                  {backendAvailable ? (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={() => onRun(false)}
                    >
                      Start live
                    </button>
                  ) : publishedAvailable ? (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={onPublished}
                    >
                      Open published feeds
                    </button>
                  ) : (
                    <button type="button" className="button button-primary" onClick={onSample}>
                      Load sample
                    </button>
                  )}
                </div>
              </div>
            )}
            {!!findings.length && (
              <FindingsPanel
                findings={findings}
                bulletins={result?.bulletins}
                selectedId={selectedResolved?.cve_id ?? null}
                laneFilter={laneFilter}
                onLaneFilter={setLaneFilter}
                onSelect={openFinding}
                pasteHitIds={[]}
                contextLabels={contextLabels}
              />
            )}
            {result?.mode === "sample" && (
              <FlagshipWalkthrough
                finding={flagship}
                onOpen={openFinding}
                visible={showFlagship}
              />
            )}
          </div>
        </section>

        <section id="issue-workbench" tabIndex={-1} aria-label="Selected issue workbench" className={`panel issue-panel-shell ${pane !== "issue" ? "hidden-mobile" : ""}`}>
          <div className="panel-head">
            <h2>Issue</h2>
            <a className="panel-source-button" href="#cvss-listing" onClick={() => setPane("findings")}>Back to CVSS listing ↑</a>
            <div className="meta">{selectedResolved?.cve_id ?? "select one"}</div>
          </div>
          <div className="panel-body">
            <IssueDetailPanel finding={selectedResolved} bulletin={selectedBulletin} generatedAt={result?.generated_at} contextMode={contextMode} contextRecords={selectedResolved ? contextStore[storeKey(contextMode, selectedResolved.cve_id)] || [] : []} onSaveContext={saveContext} />
          </div>
        </section>

        <section className={`panel evidence-panel-shell ${pane !== "flow" ? "hidden-mobile" : ""}`}>
          <div className="panel-head">
            <h2>Evidence</h2>
            <div className="panel-head-actions">
              <span className="meta">IBM claim × local state</span>
              {result && (
                <button
                  type="button"
                  className="panel-source-button"
                  aria-expanded={showFeedSources}
                  onClick={() => setShowFeedSources((value) => !value)}
                >
                  Feed sources
                </button>
              )}
            </div>
          </div>
          <div className="panel-body panel-body-docks">
            {result && showFeedSources && (
              <div className="feed-source-drawer">
                <FeedHealthStrip
                  health={result.feed_health ?? []}
                  notes={result.notes}
                  mode={result.mode}
                  generatedAt={result.generated_at}
                />
              </div>
            )}
            <VerificationRail finding={selectedResolved} bulletin={selectedBulletin} />
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <span>
          IBM PSIRT scope · local SQL evidence · no uploads · transparent comparison · not a scanner
        </span>
        <a href="https://jtflack-grc.github.io/portfolio/" target="_blank" rel="noreferrer">
          Portfolio front door ↗
        </a>
      </footer>
    </div>
  );
}
