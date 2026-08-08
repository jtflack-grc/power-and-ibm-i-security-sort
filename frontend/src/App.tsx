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
import { AboutOverlay, hasSeenIntro } from "./app/AboutOverlay";
import { Layout } from "./app/Layout";
import {
  applyShopContext,
  loadShopContext,
  saveShopContext,
  type ShopContext,
} from "./shopContext";
import type { Platform, ProgressEvent, TriageResult } from "./types";
import "./index.css";

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
  const [showIntake, setShowIntake] = useState(false);
  const [showIntro, setShowIntro] = useState(() => !hasSeenIntro());
  const [showCredits, setShowCredits] = useState(false);
  const [backendAvailable, setBackendAvailable] = useState(false);
  const [publishedAvailable, setPublishedAvailable] = useState(false);
  const [shop, setShop] = useState<ShopContext>(() => loadShopContext());
  const [platformFilter, setPlatformFilter] = useState<Platform | "all">("all");
  const liveJobRef = useRef<string | null>(null);
  const stopLiveRef = useRef<(() => void) | null>(null);
  const rawResultRef = useRef<TriageResult | null>(null);
  const bootStartedRef = useRef(false);
  rawResultRef.current = rawResult;

  const feedsPreferred = backendAvailable || publishedAvailable;

  useEffect(() => {
    saveShopContext(shop);
  }, [shop]);

  const result = useMemo(
    () => (rawResult ? applyShopContext(rawResult, shop) : null),
    [rawResult, shop]
  );

  const onPublished = useCallback(async () => {
    setError(null);
    setPendingLiveResult(null);
    setPublishedLoading(true);
    try {
      const data = await loadPublishedLive();
      setRawResult({ ...data, mode: "live" });
      setPublishedAvailable(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Published live load failed");
    } finally {
      setPublishedLoading(false);
    }
  }, []);

  const onSample = useCallback(async () => {
    setError(null);
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
        } else {
          await onSample();
        }
        return;
      }
      if (liveRunning) return;
      setError(null);
      setPendingLiveResult(null);
      setProgress([]);
      setLiveRunning(true);
      setLiveStartedAt(Date.now());
      setRefreshingCached(false);
      refreshingCachedRef.current = false;

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
    [backendAvailable, publishedAvailable, liveRunning, onPublished, onSample, stopLiveSubscription]
  );

  // Boot straight into data — no welcome gate.
  useEffect(() => {
    if (bootStartedRef.current) return;
    bootStartedRef.current = true;
    let cancelled = false;

    void (async () => {
      const [backend, published] = await Promise.all([probeBackend(), probePublishedLive()]);
      if (cancelled) return;
      setBackendAvailable(backend);
      setPublishedAvailable(published);

      if (backend) {
        setError(null);
        setProgress([]);
        setLiveRunning(true);
        setLiveStartedAt(Date.now());
        try {
          const latest = await fetchLatestLive();
          if (cancelled) return;
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
          const jobId = await startTriage(false);
          if (cancelled) return;
          liveJobRef.current = jobId;
          await new Promise<void>((resolve, reject) => {
            const stop = subscribeProgress(
              jobId,
              (ev) => setProgress((prev) => [...prev, ev]),
              async () => {
                try {
                  const data = await fetchResult(jobId);
                  if (!cancelled) {
                    const live = { ...data, mode: "live" as const };
                    const cancelledRun =
                      data.notes?.some((n) => n.toLowerCase().includes("cancelled")) ||
                      data.feed_health?.some((h) => h.detail === "cancelled");
                    if (!cancelledRun) setRawResult(live);
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
          if (!cancelled) {
            setError(err instanceof Error ? err.message : "Triage failed");
            setLiveRunning(false);
            setLiveStartedAt(null);
            // Fall through to published/sample below if boot live failed empty
            if (!rawResultRef.current) {
              if (published) {
                setPublishedLoading(true);
                try {
                  const data = await loadPublishedLive();
                  if (!cancelled) setRawResult({ ...data, mode: "live" });
                } catch (pubErr) {
                  if (!cancelled) {
                    setError(pubErr instanceof Error ? pubErr.message : "Load failed");
                  }
                } finally {
                  setPublishedLoading(false);
                }
              } else {
                setSampleLoading(true);
                try {
                  const data = await loadSampleTriage();
                  if (!cancelled) setRawResult({ ...data, mode: data.mode ?? "sample" });
                } catch (sampleErr) {
                  if (!cancelled) {
                    setError(sampleErr instanceof Error ? sampleErr.message : "Sample load failed");
                  }
                } finally {
                  setSampleLoading(false);
                }
              }
            }
          }
        }
        return;
      }

      if (published) {
        setPublishedLoading(true);
        try {
          const data = await loadPublishedLive();
          if (!cancelled) setRawResult({ ...data, mode: "live" });
        } catch (err) {
          if (!cancelled) {
            setError(err instanceof Error ? err.message : "Published live load failed");
            setSampleLoading(true);
            try {
              const data = await loadSampleTriage();
              if (!cancelled) setRawResult({ ...data, mode: data.mode ?? "sample" });
            } catch (sampleErr) {
              if (!cancelled) {
                setError(sampleErr instanceof Error ? sampleErr.message : "Sample load failed");
              }
            } finally {
              setSampleLoading(false);
            }
          }
        } finally {
          if (!cancelled) setPublishedLoading(false);
        }
        return;
      }

      setSampleLoading(true);
      try {
        const data = await loadSampleTriage();
        if (!cancelled) setRawResult({ ...data, mode: data.mode ?? "sample" });
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Sample load failed");
      } finally {
        if (!cancelled) setSampleLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

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
    setShowCredits(false);
    setShowIntro(false);
    setShowIntake(true);
  }, []);

  const openCredits = useCallback(() => {
    setShowIntake(false);
    setShowIntro(false);
    setShowCredits(true);
  }, []);

  const replayIntro = useCallback(() => {
    setShowCredits(false);
    setShowIntake(false);
    setShowIntro(true);
  }, []);

  const finishIntake = useCallback((ctx: ShopContext) => {
    setShop(ctx);
    setPlatformFilter("all");
    setShowIntake(false);
  }, []);

  const skipIntake = useCallback(() => {
    setShop((prev) => ({ ...prev, enabled: false, routed: true, paste: null }));
    setPlatformFilter("all");
    setShowIntake(false);
  }, []);

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
        onOpenCredits={openCredits}
        liveError={error}
        onClearError={() => setError(null)}
      />
      {showIntro && (
        <AboutOverlay mode="intro" onClose={() => setShowIntro(false)} />
      )}
      {showCredits && (
        <AboutOverlay
          mode="credits"
          onClose={() => setShowCredits(false)}
          onReplayIntro={replayIntro}
        />
      )}
      {showIntake && (
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
