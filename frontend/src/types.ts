export type Bucket = "urgent" | "watch" | "low";
export type Platform = "ibm_i";

export interface Lever {
  id: string;
  source: string;
  direction: "up" | "down";
  weight: number;
  reason: string;
  evidence?: Record<string, unknown>;
}

export interface PlatformHit {
  platform: Platform;
  match_strength: "cpe" | "keyword";
  products: string[];
}

export interface Finding {
  cve_id: string;
  title: string;
  description: string;
  published?: string | null;
  last_modified?: string | null;
  cvss_score?: number | null;
  cvss_severity?: string | null;
  cvss_vector?: string | null;
  cwes: string[];
  platforms: PlatformHit[];
  on_kev: boolean;
  kev_ransomware: boolean;
  kev_date_added?: string | null;
  epss?: number | null;
  epss_percentile?: number | null;
  ibm_bulletin_url?: string | null;
  ibm_bulletin_title?: string | null;
  ibm_bulletin_status: "confirmed" | "unconfirmed" | "not_checked";
  owasp_top10: string[];
  nvd_url: string;
  score: number;
  bucket: Bucket;
  levers: Lever[];
  resolution_steps?: Array<{
    title: string;
    detail: string;
    kind?: string;
    url?: string;
  }>;
  interim_mitigations?: Array<{
    title: string;
    detail: string;
    kind?: string;
  }>;
  risk_surface?: "platform" | "supply_chain" | "mixed";
  action_lane?: "apply" | "contain" | "monitor";
}

export interface TriageMetrics {
  total: number;
  urgent: number;
  watch: number;
  low: number;
  kev_hits: number;
  psirt_confirmed: number;
  high_epss: number;
  owasp_mapped: number;
  by_platform: Record<string, number>;
  lever_net_contribution: Record<string, number>;
}

export interface FeedHealth {
  id: string;
  label: string;
  status: "ok" | "degraded" | "empty" | string;
  detail?: string;
}

export interface TriageResult {
  job_id: string;
  generated_at: string;
  findings: Finding[];
  metrics: TriageMetrics;
  sources: string[];
  mode?: "sample" | "live";
  feed_health?: FeedHealth[];
  notes?: string[];
  flagship_cve?: string;
}

export interface ProgressEvent {
  stage: string;
  message: string;
  pct: number;
  detail: Record<string, unknown>;
}

export const PLATFORM_LABELS: Record<Platform, string> = {
  ibm_i: "IBM i",
};
