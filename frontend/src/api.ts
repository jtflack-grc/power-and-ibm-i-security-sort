import type { ProgressEvent, TriageResult } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export async function probeBackend(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/health`, { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}

export async function loadSampleTriage(): Promise<TriageResult> {
  const paths = [`${API_BASE}/sample-triage.json`, `${API_BASE}/api/triage/sample`];
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
    const res = await fetch(`${API_BASE}/api/triage/latest`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Latest live failed (${res.status})`);
    const data = (await res.json()) as TriageResult;
    return { ...data, mode: "live" };
  } catch {
    return null;
  }
}

export async function startTriage(forceRefresh = false): Promise<string> {
  const res = await fetch(`${API_BASE}/api/triage/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force_refresh: forceRefresh }),
  });
  if (!res.ok) throw new Error(`Failed to start triage (${res.status})`);
  const data = (await res.json()) as { job_id: string };
  return data.job_id;
}

export async function cancelTriage(jobId: string): Promise<void> {
  await fetch(`${API_BASE}/api/triage/${jobId}/cancel`, { method: "POST" });
}

export function subscribeProgress(
  jobId: string,
  onEvent: (ev: ProgressEvent) => void,
  onDone: () => void,
  onError?: (err: Error) => void
): () => void {
  const es = new EventSource(`${API_BASE}/api/triage/${jobId}/events`);
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
  const res = await fetch(`${API_BASE}/api/triage/${jobId}/result`);
  if (!res.ok) throw new Error(`Result not ready (${res.status})`);
  return (await res.json()) as TriageResult;
}
