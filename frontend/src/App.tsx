import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  cancelTriage,
  fetchLatestLive,
  fetchResult,
  loadPublishedLive,
  loadSampleTriage,
  probeBackend,
  probePublishedLive,
  startTriage,
  subscribeProgress,
} from "./api";
import { GuidedIntake } from "./app/GuidedIntake";
import { Layout } from "./app/Layout";
import {
  applyShopContext,
  loadShopContext,
  saveShopContext,
  type ShopContext,
} from "./shopContext";
import type { Platform, ProgressEvent, TriageResult } from "./types";
import "./index.css";

type Gate = "welcome" | "intake" | "app";

export default function App() {
  const [rawResult, setRawResult] = useState<TriageResult | null>(null);
  const [pendingLiveResult, setPendingLiveResult] = useState<TriageResult | null>(null);
  const [liveRunning, setLiveRunning] = useState(false);
  const [refreshingCached, setRefreshingCached] = useState(false);
  const refreshingCachedRef = useRef(false);
  const [sampleLoading, setSampleLoading] = useState(false);
  const [publishedLoading, setPublishedLoading] = useState(false);
  const [progress, setProgress] = useState<ProgressEvent[]>([]);
  const [liveStartedAt, setLiveStartedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [gate, setGate] = useState<Gate>("welcome");
  const [backendAvailable, setBackendAvailable] = useState(false);
  const [publishedAvailable, setPublishedAvailable] = useState(false);
  const [shop, setShop] = useState<ShopContext>(() => loadShopContext());
  const [platformFilter, setPlatformFilter] = useState<Platform | "all">("all");
  const liveJobRef = useRef<string | null>(null);
  const stopLiveRef = useRef<(() => void) | null>(null);
  const rawResultRef = useRef<TriageResult | null>(null);
  rawResultRef.current = rawResult;

  const feedsPreferred = backendAvailable || publishedAvailable;

  useEffect(() => {
    void Promise.all([probeBackend(), probePublishedLive()]).then(([backend, published]) => {
      setBackendAvailable(backend);
      setPublishedAvailable(published);
    });
  }, []);

  useEffect(() => {
    saveShopContext(shop);
  }, [shop]);

  const result = useMemo(
    () => (rawResult ? applyShopContext(rawResult, shop) : null),
    [rawResult, shop]
  );

  const ensureSample = useCallback(async () => {
    if (rawResultRef.current) return;
    setSampleLoading(true);
    try {
      const data = await loadSampleTriage();
      setRawResult({ ...data, mode: data.mode ?? "sample" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sample load failed");
    } finally {
      setSampleLoading(false);
    }
  }, []);

  const onPublished = useCallback(async () => {
    setError(null);
    setGate("app");
    setPendingLiveResult(null);
    setPublishedLoading(true);
    try {
      const data = await loadPublishedLive();
      setRawResult({ ...data, mode: "live" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Published live load failed");
    } finally {
      setPublishedLoading(false);
    }
  }, []);

  const onSample = useCallback(async () => {
    setError(null);
    setGate("app");
    setPendingLiveResult(null);
    setSampleLoading(true);
    try {
      const data = await loadSampleTriage();
      setRawResult({ ...data, mode: data.mode ?? "sample" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sample load failed");
    } finally {
      setSampleLoading(false);
    }
  }, []);

  const stopLiveSubscription = useCallback(() => {
    stopLiveRef.current?.();
    stopLiveRef.current = null;
    liveJobRef.current = null;
    setLiveRunning(false);
    setLiveStartedAt(null);
  }, []);

  const onCancelLive = useCallback(async () => {
    const jobId = liveJobRef.current;
    if (jobId) {
      try {
        await cancelTriage(jobId);
      } catch {
        // Local stop still clears the banner
      }
    }
    stopLiveSubscription();
    setProgress((prev) => [
      ...prev,
      {
        stage: "cancelled",
        message: "Live triage cancelled.",
        pct: 100,
        detail: {},
      },
    ]);
  }, [stopLiveSubscription]);

  const onRun = useCallback(
    async (force: boolean) => {
      if (!backendAvailable) {
        if (publishedAvailable) {
          await onPublished();
        }
        return;
      }
      if (liveRunning) return;
      setError(null);
      setGate("app");
      setPendingLiveResult(null);
      setProgress([]);
      setLiveRunning(true);
      setLiveStartedAt(Date.now());
      setRefreshingCached(false);
      refreshingCachedRef.current = false;

      // Instant path: last successful live on disk. Never auto-seed the curated fixture —
      // that is opt-in so Live / Route don't silently become "sample mode".
      if (!force) {
        const latest = await fetchLatestLive();
        if (latest?.findings?.length) {
          setRawResult(latest);
          refreshingCachedRef.current = true;
          setRefreshingCached(true);
          setProgress([
            {
              stage: "cache",
              message: "Showing last live snapshot — refreshing feeds in background…",
              pct: 8,
              detail: {},
            },
          ]);
        }
      }

      try {
        const jobId = await startTriage(force);
        liveJobRef.current = jobId;
        await new Promise<void>((resolve, reject) => {
          const stop = subscribeProgress(
            jobId,
            (ev) => setProgress((prev) => [...prev, ev]),
            async () => {
              try {
                const data = await fetchResult(jobId);
                const live = { ...data, mode: "live" as const };
                const cancelled =
                  data.notes?.some((n) => n.toLowerCase().includes("cancelled")) ||
                  data.feed_health?.some((h) => h.detail === "cancelled");
                if (!cancelled) {
                  const current = rawResultRef.current;
                  if (!current || current.mode === "live" || refreshingCachedRef.current) {
                    setRawResult(live);
                    setPendingLiveResult(null);
                  } else {
                    setPendingLiveResult(live);
                  }
                }
                resolve();
              } catch (err) {
                reject(err);
              } finally {
                stop();
                stopLiveRef.current = null;
                liveJobRef.current = null;
                setLiveRunning(false);
                setLiveStartedAt(null);
                refreshingCachedRef.current = false;
                setRefreshingCached(false);
              }
            }
          );
          stopLiveRef.current = stop;
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Triage failed");
        stopLiveSubscription();
        refreshingCachedRef.current = false;
        setRefreshingCached(false);
      }
    },
    [backendAvailable, publishedAvailable, liveRunning, onPublished, stopLiveSubscription]
  );

  const applyPending = useCallback(() => {
    if (pendingLiveResult) {
      setRawResult(pendingLiveResult);
      setPendingLiveResult(null);
    }
  }, [pendingLiveResult]);

  const dismissPending = useCallback(() => {
    setPendingLiveResult(null);
  }, []);

  const startIntake = useCallback(() => {
    setError(null);
    setGate("intake");
  }, []);

  const finishIntake = useCallback(
    (ctx: ShopContext) => {
      setShop(ctx);
      setPlatformFilter("all");
      setGate("app");
      if (backendAvailable) {
        void onRun(false);
      } else if (publishedAvailable) {
        void onPublished();
      } else {
        void ensureSample();
      }
    },
    [backendAvailable, publishedAvailable, onRun, onPublished, ensureSample]
  );

  const skipIntake = useCallback(() => {
    setShop((prev) => ({ ...prev, enabled: false, routed: true, paste: null }));
    setPlatformFilter("all");
    setGate("app");
    if (backendAvailable) {
      void onRun(false);
    } else if (publishedAvailable) {
      void onPublished();
    } else {
      void ensureSample();
    }
  }, [backendAvailable, publishedAvailable, onRun, onPublished, ensureSample]);

  return (
    <>
      <Layout
        result={result}
        liveRunning={liveRunning}
        sampleLoading={sampleLoading}
        publishedLoading={publishedLoading}
        progress={progress}
        liveStartedAt={liveStartedAt}
        pendingLive={Boolean(pendingLiveResult)}
        refreshingCached={refreshingCached}
        onRun={onRun}
        onSample={onSample}
        onPublished={onPublished}
        onCancelLive={onCancelLive}
        onApplyPending={applyPending}
        onDismissPending={dismissPending}
        backendAvailable={backendAvailable}
        publishedAvailable={publishedAvailable}
        shop={shop}
        onShopChange={setShop}
        platformFilter={platformFilter}
        onPlatformFilter={setPlatformFilter}
        onStartIntake={startIntake}
        liveError={error}
        onClearError={() => setError(null)}
      />
      {gate === "welcome" && !liveRunning && !result && (
        <div className="overlay">
          <div className="overlay-card welcome-card">
            <h1>Power System Vulnerability Curator</h1>
            <p className="welcome-lead">
              Public CVE intel for IBM i, AIX, Linux on Power, and z/OS — sorted so systems and
              GRC can share one work queue.
            </p>
            <ul className="welcome-method">
              <li>
                <strong>Published feeds</strong> Scheduled public intel snapshot (Pages) or local
                live refresh
              </li>
              <li>
                <strong>Route</strong> A few answers re-weight that queue to your baileywick
              </li>
              <li>
                <strong>Fixture</strong> Small curated set for offline walkthroughs
              </li>
            </ul>
            <p className="welcome-honesty">
              Portfolio demo. No API keys in the page. Shop answers and optional PSP paste stay in
              this tab only. Not a scanner of record.
            </p>
            {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
            <div className="welcome-actions">
              {backendAvailable ? (
                <>
                  <button
                    type="button"
                    className="button button-primary"
                    onClick={() => onRun(false)}
                  >
                    Start live
                  </button>
                  <button type="button" className="button" onClick={startIntake}>
                    Route, then live
                  </button>
                </>
              ) : publishedAvailable ? (
                <>
                  <button
                    type="button"
                    className="button button-primary"
                    onClick={() => void onPublished()}
                    disabled={publishedLoading}
                  >
                    {publishedLoading ? "Loading feeds…" : "Open published feeds"}
                  </button>
                  <button type="button" className="button" onClick={startIntake}>
                    Route, then feeds
                  </button>
                </>
              ) : (
                <button type="button" className="button button-primary" onClick={startIntake}>
                  Route my queue
                </button>
              )}
            </div>
            <p className="welcome-alt">
              {backendAvailable
                ? "Backend offline later? "
                : publishedAvailable
                  ? "Want the short walkthrough? "
                  : "Published feeds refresh on a schedule. Meanwhile, "}
              <button type="button" className="linkish" onClick={() => void onSample()}>
                open the curated fixture
              </button>
              {backendAvailable || publishedAvailable
                ? " — offline walkthrough with the flagship CVE."
                : "."}
            </p>
          </div>
        </div>
      )}
      {gate === "intake" && (
        <GuidedIntake
          initial={shop}
          livePreferred={feedsPreferred}
          onComplete={finishIntake}
          onSkip={skipIntake}
        />
      )}
      {error && result && (
        <div className="site-footer" style={{ color: "var(--danger)" }}>
          {error}
        </div>
      )}
    </>
  );
}
