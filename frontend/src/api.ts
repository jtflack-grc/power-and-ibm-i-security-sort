import type { ProgressEvent, TriageResult } from "./types";

/**
 * Resolve API / static fixture URLs against Vite base.
 * Pages builds with `--base=./` so leading `/live-triage.json` would 404 on github.io root.
 */
function resolveBase(): string {
  const override = import.meta.env.VITE_API_BASE as string | undefined;
  if (override != null && override !== "") {
    return override.replace(/\/$/, "");
  }
  const base = (import.meta.env.BASE_URL as string | undefined) ?? "/";
  if (base === "/") return "";
  return base.replace(/\/$/, "");
}

const API_BASE = resolveBase();

function url(path: string): string {
  const cleaned = path.startsWith("/") ? path.slice(1) : path;
  if (!API_BASE) return `/${cleaned}`;
  return `${API_BASE}/${cleaned}`;
}

export async function probeBackend(): Promise<boolean> {
  try {
    const res = await fetch(url("api/health"), { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}

/** Pages ships a scheduled live-triage.json (no open API). */
export async function probePublishedLive(): Promise<boolean> {
  try {
    const res = await fetch(url("live-triage.json"), { method: "GET" });
    if (!res.ok) return false;
    const data = (await res.json()) as TriageResult;
    return Boolean(data?.findings?.length);
  } catch {
    return false;
  }
}

export async function loadPublishedLive(): Promise<TriageResult> {
  const paths = [url("live-triage.json")];
  let lastErr: Error | null = null;
  for (const path of paths) {
    try {
      const res = await fetch(path);
      if (!res.ok) throw new Error(`Published live load failed (${res.status})`);
      const data = (await res.json()) as TriageResult;
      if (!data?.findings?.length) throw new Error("Published live snapshot is empty");
      return { ...data, mode: "live" };
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
    }
  }
  throw lastErr ?? new Error("Published live snapshot unavailable");
}

export async function loadSampleTriage(): Promise<TriageResult> {
  const paths = [url("sample-triage.json"), url("api/triage/sample")];
  let lastErr: Error | null = null;
  for (const path of paths) {
    try {
      const res = await fetch(path);
      if (!res.ok) throw new Error(`Sample load failed (${res.status})`);
      return (await res.json()) as TriageResult;
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
    }
  }
  throw lastErr ?? new Error("Sample fixture unavailable");
}

export async function fetchLatestLive(): Promise<TriageResult | null> {
  try {
    const res = await fetch(url("api/triage/latest"));
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Latest live failed (${res.status})`);
    const data = (await res.json()) as TriageResult;
    return { ...data, mode: "live" };
  } catch {
    return null;
  }
}

export async function startTriage(forceRefresh = false): Promise<string> {
  const res = await fetch(url("api/triage/run"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force_refresh: forceRefresh }),
  });
  if (!res.ok) throw new Error(`Failed to start triage (${res.status})`);
  const data = (await res.json()) as { job_id: string };
  return data.job_id;
}

export async function cancelTriage(jobId: string): Promise<void> {
  await fetch(url(`api/triage/${jobId}/cancel`), { method: "POST" });
}

export function subscribeProgress(
  jobId: string,
  onEvent: (ev: ProgressEvent) => void,
  onDone: () => void,
  onError?: (err: Error) => void
): () => void {
  const es = new EventSource(url(`api/triage/${jobId}/events`));
  es.addEventListener("progress", (msg) => {
    try {
      const data = JSON.parse((msg as MessageEvent).data) as ProgressEvent;
      onEvent(data);
    } catch (err) {
      onError?.(err as Error);
    }
  });
  es.addEventListener("done", () => {
    es.close();
    onDone();
  });
  es.onerror = () => {
    // EventSource retries; consumer fetches result when done fires.
  };
  return () => es.close();
}

export async function fetchResult(jobId: string): Promise<TriageResult> {
  const res = await fetch(url(`api/triage/${jobId}/result`));
  if (!res.ok) throw new Error(`Result not ready (${res.status})`);
  return (await res.json()) as TriageResult;
}
