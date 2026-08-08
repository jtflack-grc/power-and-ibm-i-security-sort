import { useEffect, useMemo, useState } from "react";
import type { Finding, Platform, ProgressEvent, TriageResult } from "../types";
import {
  findingMatchesPaste,
  type ShopContext,
} from "../shopContext";
import { FLAGSHIP_CVE, FlagshipWalkthrough } from "./FlagshipWalkthrough";
import { ActionLanesFlow, type ActionLane } from "./ActionLanesFlow";
import { FeedHealthStrip } from "./FeedHealthStrip";
import { FindingsPanel } from "./FindingsPanel";
import { IssueDetailPanel } from "./IssueDetailPanel";
import { LiveFailCallout, LiveWaitCallout } from "./LiveStatusCallouts";
import { LiveProgressBanner } from "./LiveProgressBanner";
import { ShopContextPanel } from "./ShopContextPanel";

type Pane = "findings" | "issue" | "flow";

interface Props {
  result: TriageResult | null;
  liveRunning: boolean;
  sampleLoading: boolean;
  progress: ProgressEvent[];
  liveStartedAt: number | null;
  pendingLive: boolean;
  refreshingCached?: boolean;
  onRun: (force: boolean) => void;
  onSample: () => void;
  onCancelLive: () => void;
  onApplyPending: () => void;
  onDismissPending: () => void;
  liveAvailable: boolean;
  shop: ShopContext;
  onShopChange: (ctx: ShopContext) => void;
  platformFilter: Platform | "all";
  onPlatformFilter: (p: Platform | "all") => void;
  onStartIntake: () => void;
  liveError?: string | null;
  onClearError?: () => void;
}

export function Layout({
  result,
  liveRunning,
  sampleLoading,
  progress,
  liveStartedAt,
  pendingLive,
  refreshingCached = false,
  onRun,
  onSample,
  onCancelLive,
  onApplyPending,
  onDismissPending,
  liveAvailable,
  shop,
  onShopChange,
  platformFilter,
  onPlatformFilter,
  onStartIntake,
  liveError = null,
  onClearError,
}: Props) {
  const [pane, setPane] = useState<Pane>("findings");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [laneFilter, setLaneFilter] = useState<ActionLane | "all">("all");
  const [showFlagship, setShowFlagship] = useState(true);

  const findings = result?.findings ?? [];
  const modeLabel = result?.mode === "live" ? "live feeds" : result ? "sample" : "idle";
  const flagship =
    findings.find((f) => f.cve_id === (result?.flagship_cve || FLAGSHIP_CVE)) ?? null;
  const emptyLive = result?.mode === "live" && findings.length === 0;
  const pasteHits = useMemo(
    () => findings.filter((f) => findingMatchesPaste(f, shop.paste)).map((f) => f.cve_id),
    [findings, shop.paste]
  );

  const scopedFindings = useMemo(() => {
    if (platformFilter === "all") return findings;
    return findings.filter((f) =>
      f.platforms.some((p) => p.platform === platformFilter)
    );
  }, [findings, platformFilter]);

  useEffect(() => {
    if (!scopedFindings.length) {
      setSelected(null);
      return;
    }
    setSelected((prev) => {
      if (prev && scopedFindings.some((f) => f.cve_id === prev.cve_id)) {
        return scopedFindings.find((f) => f.cve_id === prev.cve_id) ?? prev;
      }
      // Always land on the top of the current rail. Shop/route re-weights ranking;
      // platform chips stay "All" until the user drills in.
      return scopedFindings[0];
    });
  }, [scopedFindings]);

  const selectedResolved =
    selected == null
      ? null
      : scopedFindings.find((f) => f.cve_id === selected.cve_id) ?? selected;

  const openFinding = (f: Finding) => {
    setSelected(f);
    setPane("issue");
    setShowFlagship(false);
  };

  const onShopChangeOnly = (ctx: ShopContext) => {
    onShopChange(ctx);
  };

  return (
    <div className="app-shell">
      <header className="site-header">
        <a
          className="brand"
          href="https://jtflack-grc.github.io/portfolio/"
          target="_blank"
          rel="noreferrer"
        >
          <div className="brand-wordmark">
            <span>Power Vuln Curator</span>
          </div>
          <div className="brand-sub">Power System Vulnerability Curator · i on GRC</div>
        </a>
        <div className="header-actions">
          <button type="button" className="button" onClick={onStartIntake}>
            Route queue
          </button>
          <button
            type="button"
            className="button"
            onClick={onSample}
            disabled={sampleLoading}
          >
            {sampleLoading ? "Loading sample…" : "Load sample"}
          </button>
          {liveAvailable && (
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
        <section className={`panel ${pane !== "findings" ? "hidden-mobile" : ""}`}>
          <div className="panel-head">
            <h2>Findings</h2>
            <div className="meta">
              {scopedFindings.length} · {modeLabel}
              {shop.enabled ? " · shop on" : ""}
              {pasteHits.length ? ` · ${pasteHits.length} paste hit` : ""}
              {liveRunning ? " · live bg" : ""}
            </div>
          </div>
          <div className="panel-body">
            {result?.mode === "sample" && (
              <FlagshipWalkthrough
                finding={flagship}
                onOpen={openFinding}
                visible={showFlagship}
              />
            )}
            <ShopContextPanel
              context={shop}
              onChange={onShopChangeOnly}
              onStartIntake={onStartIntake}
            />
            {shop.enabled && result && platformFilter === "all" && (
              <div className="route-cue" role="status">
                Shop ranking is on · viewing <strong>All platforms</strong> — chip a baileywick
                below to narrow the rail (IBM i, AIX, …). Ranking stays shop-weighted either way.
              </div>
            )}
            {liveRunning && !result && (
              <LiveWaitCallout
                progress={progress}
                startedAt={liveStartedAt}
                onCancel={onCancelLive}
                onFixture={onSample}
              />
            )}
            {liveError && !result && !liveRunning && (
              <LiveFailCallout
                message={liveError}
                onRetry={() => {
                  onClearError?.();
                  onRun(false);
                }}
                onFixture={() => {
                  onClearError?.();
                  onSample();
                }}
              />
            )}
            {emptyLive && !liveRunning && (
              <div className="empty-state callout">
                <strong>Live returned an empty queue</strong>
                <p className="callout-muted">
                  Rate limit, empty window, or upstream hiccup — common on keyless NVD. Retry, or
                  walk the fixture.
                </p>
                <div className="callout-actions">
                  <button
                    type="button"
                    className="button button-primary"
                    onClick={() => onRun(true)}
                  >
                    Retry live
                  </button>
                  <button type="button" className="button" onClick={onSample}>
                    Open curated fixture
                  </button>
                </div>
              </div>
            )}
            {!result && !liveRunning && !sampleLoading && !liveError && (
              <div className="empty-state callout">
                Nothing loaded yet.
                <div className="callout-actions">
                  {liveAvailable ? (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={() => onRun(false)}
                    >
                      Start live
                    </button>
                  ) : (
                    <button type="button" className="button button-primary" onClick={onStartIntake}>
                      Route my queue
                    </button>
                  )}
                  <button type="button" className="button" onClick={onSample}>
                    Curated fixture
                  </button>
                </div>
              </div>
            )}
            {!!findings.length && (
              <FindingsPanel
                findings={findings}
                selectedId={selectedResolved?.cve_id ?? null}
                platformFilter={platformFilter}
                onPlatformFilter={onPlatformFilter}
                laneFilter={laneFilter}
                onLaneFilter={setLaneFilter}
                onSelect={openFinding}
                pasteHitIds={pasteHits}
              />
            )}
          </div>
        </section>

        <section className={`panel ${pane !== "issue" ? "hidden-mobile" : ""}`}>
          <div className="panel-head">
            <h2>Issue</h2>
            <div className="meta">{selectedResolved?.cve_id ?? "select one"}</div>
          </div>
          <div className="panel-body">
            <IssueDetailPanel finding={selectedResolved} shop={shop} />
          </div>
        </section>

        <section className={`panel ${pane !== "flow" ? "hidden-mobile" : ""}`}>
          <div className="panel-head">
            <h2>Actions</h2>
            <div className="meta">Work docks</div>
          </div>
          <div className="panel-body panel-body-docks">
            <ActionLanesFlow
              findings={scopedFindings}
              selected={selectedResolved}
              settling={sampleLoading || liveRunning}
              laneFilter={laneFilter}
              onLaneFilter={setLaneFilter}
              onSelect={openFinding}
            />
            {result && (
              <div className="feed-aside-wrap">
                <FeedHealthStrip
                  health={result.feed_health ?? []}
                  notes={result.notes}
                  mode={result.mode}
                  generatedAt={result.generated_at}
                />
              </div>
            )}
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <span>
          No keys · live when available · route in-browser · fixture for offline demos · not a
          scanner
        </span>
        <a href="https://jtflack-grc.github.io/portfolio/" target="_blank" rel="noreferrer">
          Portfolio front door ↗
        </a>
      </footer>
    </div>
  );
}
