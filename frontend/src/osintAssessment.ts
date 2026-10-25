import type { Finding } from "./types";
import { baseVector, scoreScenario } from "./contextAssessment";
import { normalizeIbmBulletinUrl } from "./links";

export const OSINT_MODEL = "ibmi-osint-0.2";
export const OSINT_REVIEWED = "2026-10-25";
export interface OsintSource { title: string; url: string; fact: string; applicability: string }
const authority: OsintSource = {
  title: "IBM Redbooks — Modernizing IBM i Applications: authority and adoption",
  url: "https://www.redbooks.ibm.com/docs/MD260020/MD260020-12.html",
  fact: "Execution authority depends on the profile and call stack; adopted authority can widen access.",
  applicability: "Current architectural reference. Supports alternative authority/blast-radius scenarios, not a claim about a partition's permissions.",
};
const securityGuide: OsintSource = {
  title: "IBM Redbooks SG24-7680 — Security Guide for IBM i V6.1, §§4.2 and 4.5",
  url: "https://www.redbooks.ibm.com/redbooks/pdfs/sg247680.pdf#page=80",
  fact: "Object authority and interface controls are distinct; exit programs do not cover every access path.",
  applicability: "Historical 2009 architectural guidance, paired with current IBM documentation. No legacy defaults are assumed for current releases.",
};
const resources: OsintSource = {
  title: "IBM i 7.5 — Resource security",
  url: "https://www.ibm.com/docs/en/i/7.5.0?topic=security-resource",
  fact: "Objects, libraries, directories, groups, public authority, and adopted authority determine accessible resources.",
  applicability: "Current mechanism reference; actual grants and business consequences remain unknown.",
};
const java: OsintSource = {
  title: "IBM i 7.6 — Java security",
  url: "https://www.ibm.com/docs/en/i/7.6.0?topic=java-security",
  fact: "Java applications run under user authority; the applet sandbox does not generally restrict ordinary server applications.",
  applicability: "Used only for Java/runtime findings. Java is not assigned an automatic security discount.",
};
const fortra: OsintSource = {
  title: "Fortra — IBM i security assessment guidance",
  url: "https://power.fortra.com/blog/6-pro-tips-2026-state-ibm-i-security-study",
  fact: "Privilege, public authority, interfaces, credentials, system values, and audit coverage need review.",
  applicability: "Prevents assuming that available platform protections are deployed. Survey observations are not a probability prior.",
};
const kisco: OsintSource = {
  title: "Kisco — IBM i exit points for security",
  url: "https://www.kisco.com/u/content/ibm-i-exit-points-for-security.html",
  fact: "Security exit points cover specific network interfaces and operations.",
  applicability: "Explains interface-specific control opportunities; neither installation nor effective coverage is inferred.",
};
export interface OsintEndpoint { name: string; score: number; vector?: string; assumption: string }
export interface OsintAssessment {
  model: string; reviewed: string; low: number; high: number;
  basis: string; coverage: string; profile: string; priority: string;
  facts: string[]; unknowns: string[]; endpoints: OsintEndpoint[]; sources: OsintSource[];
  controlMap: Array<{ role: string; inference: string }>;
}
const finiteScore = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 10;
const round = (value: number) => Math.round(value * 10) / 10;

/** Automatic OSINT scenario estimate. No local-storage or customer input is required. */
export function estimateOsint(f: Finding): OsintAssessment {
  const sources: OsintSource[] = [
    { title: `${f.cve_id} — IBM bulletin / support reference`, url: normalizeIbmBulletinUrl(f.ibm_bulletin_url, f.cve_id), fact: "Affected products, vulnerability prerequisites, and published remedies are the primary vulnerability-specific inputs.", applicability: f.ibm_bulletin_status === "confirmed" ? "IBM bulletin association is present in the feed; no local installation is inferred." : "Association needs confirmation; this is a lookup reference." },
    authority, securityGuide, resources, fortra,
  ];
  const specific = f.ibm_vulnerability_description || "";
  const description = specific || f.description || "";
  const componentText = `${f.title || ""} ${description}`;
  const boundary = (f.cwes || []).some(cwe => ["CWE-269", "CWE-287", "CWE-862", "CWE-863"].includes(cwe)) || /privilege escalation|gain.{0,30}(?:elevated|additional|higher).{0,15}privilege|bypass.{0,40}(?:security|authority|authorization|authentication)|improper (?:privilege|authorization|authentication)|unqualified.{0,30}(?:call|library)|library.{0,15}(?:list|call)|licensed internal code|system domain|kernel/i.test(componentText);
  const runtime = /\b(java|log4j|liberty|websphere|apache|tomcat|node\.?js|php|pase|openssl|ssh|sftp|ftp|odbc|ddm|drda)\b/i.test(componentText);
  const javaRelated = /\b(java|log4j|jdk|jre)\b/i.test(componentText);
  const networkService = /\b(ftp|sftp|odbc|ddm|drda|netserver|nfs|telnet|smtp|dns|bind)\b/i.test(componentText);
  if (javaRelated) sources.push(java);
  if (networkService) sources.push(kisco);
  const facts: string[] = [];
  if (specific) facts.push(`IBM's CVE-specific description: ${specific}`);
  else facts.push("Uses the CVE record and associated IBM bulletin/component text; a separately extracted IBM per-CVE description is unavailable.");
  if (finiteScore(f.ibm_cvss_score)) facts.push(`IBM bulletin score: ${f.ibm_cvss_score.toFixed(1)}. The published queue score remains ${finiteScore(f.cvss_score) ? f.cvss_score.toFixed(1) : "unrated"}.`);
  if (f.on_kev) facts.push("CISA KEV lists exploitation in the wild. The automatic estimate retains an expedited response signal.");
  if (f.epss != null) facts.push(`EPSS ${(f.epss * 100).toFixed(2)}% is a 30-day in-the-wild signal; it does not measure loss probability on this partition.`);
  const unknowns = ["Installed component/version and effective fix state", "Reachable paths and actual authentication coverage", "Job/profile/adopted authority and accessible data", "Business criticality, recovery capability, and control efficacy"];
  const endpoints: OsintEndpoint[] = [];
  let coverage = "CVE vector + platform references";
  let basis = "CVSS Environmental scenario calculations";
  let profile = boundary ? "Authority-boundary exposure" : runtime ? "Application / service-job exposure" : "Platform/component exposure";
  let selectedVector = "";
  for (const candidate of [f.ibm_cvss_vector, f.cvss_vector]) {
    if (!candidate) continue;
    try { baseVector(candidate); selectedVector = candidate; break; } catch { /* Broader fallbacks stay automatic and explicit. */ }
  }
  if (selectedVector) {
    const parsed = baseVector(selectedVector);
    if (selectedVector === f.ibm_cvss_vector) coverage = "IBM per-CVE vector + platform references";
    const metrics = Object.fromEntries(parsed.vector.split("/").slice(1).map(pair => pair.split(":")));
    const lower: Record<string, string> = {};
    // This is a conditional impact scenario, not an inferred installed control.
    // Never turn Network into Local/Adjacent merely because IBM i is usually internal.
    if (runtime && !boundary) {
      for (const metric of parsed.version === "4.0" ? ["VC", "VI", "SC", "SI"] : ["C", "I"]) {
        if (metrics[metric] === "H") lower[`M${metric}`] = "L";
      }
    }
    const high = { CR: "H", IR: "H", AR: "H" };
    const lowScore = scoreScenario(selectedVector, lower);
    const highScore = scoreScenario(selectedVector, high);
    endpoints.push({
      name: "Bounded-impact IBM i scenario", score: lowScore.score, vector: lowScore.vector,
      assumption: Object.keys(lower).length ? "Assumes the affected application/service job has limited effective authority and limited confidentiality/integrity consequences. Availability impact and attack prerequisites stay as published. This is a plausible OSINT scenario, not an observed configuration." : boundary ? "Retains published impacts and prerequisites: an authority/integrity-boundary flaw may defeat the protections that would otherwise limit a job. No generic IBM i mitigation is credited." : "Retains published impacts and prerequisites. Public component details do not justify a narrower lower-impact scenario.",
    });
    endpoints.push({ name: "Broad-impact / critical-workload scenario", score: highScore.score, vector: highScore.vector, assumption: "Assumes high confidentiality, integrity, and availability requirements for the affected workload. Broad service/adopted authority and business dependencies remain plausible. No firewall, exit program, MFA, or patch is assumed effective." });
    // Keep the unmodified assessment and public score inside the envelope, including source disagreement.
    const unchanged = scoreScenario(selectedVector, {});
    endpoints.push({ name: selectedVector === f.ibm_cvss_vector ? "IBM per-CVE baseline" : "CVE vector baseline", score: unchanged.score, vector: unchanged.vector, assumption: "No Environmental overrides; preserves the selected vector's intrinsic assessment." });
    sources.push({ title: `FIRST CVSS ${parsed.version} specification`, url: `https://www.first.org/cvss/v${parsed.version}/specification-document`, fact: "Defines the Environmental calculation used for these endpoint vectors.", applicability: "Scenario selection is this project's explicit inference; FIRST and IBM do not publish these endpoints as a partition score." });
  } else {
    basis = "Provisional source-score band — no Environmental calculation";
    coverage = "Limited — full usable vector unavailable";
    profile = "Broad provisional IBM i envelope";
    const score = finiteScore(f.ibm_cvss_score) ? f.ibm_cvss_score : finiteScore(f.cvss_score) ? f.cvss_score : null;
    const severity = ["IBM", "NVD"].includes(f.cvss_source || "") ? (f.cvss_severity || "").toLowerCase() : "";
    const floor = score ?? ({ critical: 9, high: 7, medium: 4, low: 0.1, none: 0 }[severity] ?? 0);
    endpoints.push({ name: "Available public severity basis", score: floor, assumption: score != null ? "Uses the available public numeric severity as a provisional lower anchor. No downward adjustment can be calculated without the vector." : severity ? `Uses the published ${severity} category's lower boundary. This is not a calculated CVSS Environmental score.` : "No reliable numeric/vector/category basis is available: retain the full 0–10 uncertainty band rather than invent precision." });
    endpoints.push({ name: "Unresolved critical-impact bound", score: score === 0 && severity === "none" ? 0 : 10, assumption: "A deliberately broad policy bound while component-specific prerequisites and impacts remain unresolved. This endpoint is a model assumption, not a measured probability or a vendor-published score." });
  }
  if (finiteScore(f.cvss_score)) endpoints.push({ name: "Published queue CVSS", score: f.cvss_score, assumption: "Preserved as a separate public input. The automatic envelope does not suppress a higher published score when sources disagree." });
  if (finiteScore(f.ibm_cvss_score)) endpoints.push({ name: "IBM bulletin numeric score", score: f.ibm_cvss_score, assumption: "IBM-specific public input, kept distinct from the queue's score." });
  const low = round(Math.min(...endpoints.map(e => e.score))), high = round(Math.max(...endpoints.map(e => e.score)));
  const priority = f.on_kev ? "Expedite applicability / remediation" : high >= 9 ? "Prioritize scope and fix review" : high >= 7 ? "Schedule applicability / fix review" : "Review with routine maintenance";
  return {
    model: OSINT_MODEL, reviewed: OSINT_REVIEWED, low, high, basis, coverage, profile, priority, facts, unknowns, endpoints, sources,
    controlMap: [
      { role: "Prevention / resistance", inference: boundary ? "Authority-boundary defect: platform access controls are not credited as a generic mitigation." : runtime ? "Lower endpoint assumes a bounded service/job authority path; upper endpoint retains broad impact. The authority sources explain why both scenarios are plausible." : "No component-specific prevention credit inferred from platform capabilities alone." },
      { role: "Prevention / avoidance", inference: "No network isolation or exit-control deployment is known from these public sources; attack-vector metrics are not reduced." },
      { role: "Detection and response", inference: "Telemetry, alert handling, containment, and recovery are unknown. They receive no automated severity deduction or fabricated loss reduction." },
      { role: "Variance and decision support", inference: "Source versions, bulletin details, model rules, and unresolved assumptions are visible. A published PTF is not evidence that a partition is remediated." },
    ],
  };
}
