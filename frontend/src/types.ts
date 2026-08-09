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

export interface BulletinApplicability {
  applicability_id: string;
  product_id?: string | null;
  product_name: string;
  component_type:
    | "operating_system"
    | "licensed_internal_code"
    | "licensed_program"
    | "bundled_component"
    | "unknown";
  release?: string | null;
  release_system?: string | null;
  individual_ptfs: string[];
  group_ptfs: string[];
  group_ptf_levels?: Record<string, number>;
  apars: string[];
  prerequisite_ptfs?: string[];
  corequisite_ptfs?: string[];
  supersedes_ptfs?: string[];
  application_instructions?: string[];
  source_excerpt: string;
  source_url: string;
  confidence: "structured" | "heuristic" | "unresolved";
}

export interface Bulletin {
  bulletin_id: string;
  url: string;
  title: string;
  published?: string | null;
  last_modified?: string | null;
  cve_ids: string[];
  applicability: BulletinApplicability[];
  unassociated_individual_ptfs: string[];
  unassociated_group_ptfs: string[];
  unassociated_apars: string[];
  affected_source_text: string;
  change_status?: "new" | "modified" | "unchanged" | "unknown";
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
  bulletin_id?: string | null;
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
  schema_version?: string;
  job_id: string;
  generated_at: string;
  findings: Finding[];
  bulletins?: Bulletin[];
  metrics: TriageMetrics;
  sources: string[];
  mode?: "sample" | "live";
  feed_health?: FeedHealth[];
  notes?: string[];
  flagship_cve?: string;
  previous_snapshot_at?: string | null;
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
