import { CVSS30, CVSS31, CVSS40 } from "@pandatix/js-cvss";
import type { Finding } from "./types";

export const MODEL_VERSION = "ibmi-context-0.1";
export const STORAGE_KEY = "ibmi-context-assessments-v1";
export type EvidenceState = "unknown" | "attested" | "observed" | "verified" | "conflicting";
export interface Evidence { value: string; state: EvidenceState; note: string; observedAt: string }
export interface Scenario { name: string; metrics: Record<string, string>; evidence: Evidence }
export interface ControlObservation { function: string; measure: string; unit: string; evidence: Evidence }
export interface Assessment {
  id: string; modelVersion: string; cveId: string; sourceVector: string; sourceRevision: string; mode: string;
  asset: string; release: string; component: string; threat: string; assessor: string;
  assessedAt: string; validUntil: string;
  evidence: Record<string, Evidence>; scenarios: Scenario[]; controls: ControlObservation[];
  lossEffect: string; lossInputs: string;
}
export type AssessmentStore = Record<string, Assessment[]>;
export const SOURCES = [
  { name: "IBM security levels", url: "https://www.ibm.com/docs/en/i/7.5.0?topic=security-level", use: "Integrity protections depend on active configuration and the exploit path." },
  { name: "IBM authority collection", url: "https://www.ibm.com/docs/en/i/7.5.0?topic=reference-authority-collection", use: "Effective authority includes user, group, public, and adopted authority." },
  { name: "IBM PTF_INFO", url: "https://www.ibm.com/docs/en/i/7.5.0?topic=services-ptf-info-view", use: "Check remedy state and next-IPL action against the bulletin." },
  { name: "IBM NETSTAT_INFO", url: "https://www.ibm.com/support/pages/qsys2netstatinfo", use: "Connection data is one input; validate network paths separately." },
  { name: "Fortra IBM i security guidance", url: "https://power.fortra.com/blog/6-pro-tips-2026-state-ibm-i-security-study", use: "Review privilege, public authority, interfaces, credentials, system values, and audit coverage." },
  { name: "Kisco exit points", url: "https://www.kisco.com/u/content/ibm-i-exit-points-for-security.html", use: "Check interface-specific coverage and enforcement behavior." },
  { name: "Kisco adopted authority", url: "https://www.kisco.com/u/content/controlling-adopted-authority.html", use: "Review owner-adopting programs in the actual execution path." },
  { name: "FIRST CVSS v3.1", url: "https://www.first.org/cvss/v3.1/specification-document", use: "Environmental score definitions and calculation." },
  { name: "FIRST CVSS v3.0", url: "https://www.first.org/cvss/v3.0/specification-document", use: "Version-specific Environmental score definitions." },
  { name: "FIRST CVSS v4.0", url: "https://www.first.org/cvss/v4.0/specification-document", use: "CVSS-BE Environmental metrics; no conversion from v3 vectors." },
  { name: "FIRST EPSS", url: "https://www.first.org/epss/faq", use: "30-day exploitation-in-the-wild signal; not partition loss probability." },
  { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", use: "Documented exploitation informs urgency; it is not proof of local compromise." },
  { name: "Open FAIR", url: "https://www.opengroup.org/open-fair", use: "Define the threat, asset, loss effect, timeframe, and calibrated inputs." },
  { name: "FAIR-CAM™ — FAIR Institute", url: "https://www.fairinstitute.org/resources/FAIR-CAM", use: "Reference for how controls affect loss frequency, magnitude, reliability, and decisions." },
];
export const DIMENSIONS = [
  { id: "applicability", label: "Applicability", options: [["unknown", "Unknown"], ["confirmed", "Affected component confirmed"], ["not-applicable", "Not applicable — evidence required"]], hint: "Match IBM's bulletin to this partition, release, component, and configuration. A release-level CVE list is a candidate set." },
  { id: "remedy", label: "Effective remedy", options: [["unknown", "Unknown"], ["vulnerable", "Remedy not effective"], ["pending", "Loaded / pending activation"], ["remediated", "Effective remedy verified"]], hint: "Record package mapping, supersedence, prerequisites, and activation. A temporarily applied PTF can be effective; loaded alone is not enough." },
  { id: "reachability", label: "Attack-path reachability", options: [["unknown", "Unknown"], ["reachable", "Relevant threat can reach function"], ["restricted", "Path restriction tested"]], hint: "Combine service state with routing/firewall evidence and a scoped test. Internal does not mean unreachable." },
  { id: "authority", label: "Effective authority", options: [["unknown", "Unknown"], ["broad", "Broad or elevated authority"], ["restricted", "Scoped least authority demonstrated"]], hint: "Include direct, primary/supplemental group, public, adopted, and service/job authority. Menus do not establish effective access." },
  { id: "integrity", label: "Relevant platform protection", options: [["unknown", "Unknown"], ["effective", "Relevant protection tested"], ["ineffective", "Protection absent or insufficient"]], hint: "Record the active security level and the specific prerequisite it blocks. No blanket credit for QSECURITY 40/50." },
  { id: "network", label: "Exit controls / authentication", options: [["unknown", "Unknown"], ["enforcing", "Relevant path enforcement tested"], ["logging", "Logging only / partial coverage"], ["absent", "No relevant enforcement"]], hint: "A purchased product or registered exit is not proof of enforcement. Check alternate interfaces and authentication paths." },
  { id: "business", label: "Business consequences", options: [["unknown", "Unknown"], ["documented", "Owner-confirmed requirements"]], hint: "Record affected data, dependent processes, confidentiality/integrity/availability requirements, and outage tolerance." },
  { id: "exploitation", label: "Local exploitation", options: [["unknown", "Not investigated"], ["none-observed", "No local exploitation observed"], ["observed", "Credible local exploitation"]], hint: "No observation is not proof of absence. KEV is a separate in-the-wild signal; low EPSS never cancels KEV." },
] as const;

export function emptyEvidence(value = "unknown"): Evidence { return { value, state: "unknown", note: "", observedAt: "" }; }
export function sourceRevision(f: Finding): string { return JSON.stringify([f.cvss_vector || "", f.last_modified || "", f.ibm_bulletin_url || "", f.resolution_steps || []]); }
export function newAssessment(f: Finding, mode: string): Assessment {
  return {
    id: crypto.randomUUID(), modelVersion: MODEL_VERSION, cveId: f.cve_id,
    sourceVector: f.cvss_vector || "", sourceRevision: sourceRevision(f), mode, asset: "", release: "", component: "", threat: "", assessor: "",
    assessedAt: "", validUntil: "", evidence: Object.fromEntries(DIMENSIONS.map(d => [d.id, emptyEvidence()])),
    scenarios: ["Observed deployment", "Supported alternative"].map(name => ({ name, metrics: {}, evidence: emptyEvidence() })),
    controls: [
      ["Prevention / Avoidance", "Relevant network-path restriction", "% of scoped path tests blocked"],
      ["Prevention / Resistance", "Authority and interface enforcement", "% of scoped unauthorized attempts blocked"],
      ["Detection / Visibility", "Required event telemetry", "% of scoped test events captured"],
      ["Detection / Monitoring", "Telemetry processing", "% of captured test events processed"],
      ["Detection / Recognition", "Actionable detection", "% of processed test events correctly recognized"],
      ["Response / Containment", "Terminate the relevant activity", "hours to contain"],
      ["Response / Resilience", "Restore the business function", "hours to restore"],
      ["Variance management reference", "Change and drift validation", "validation frequency / time to correct"],
      ["Decision support reference", "Assessment inputs and ownership", "input freshness / review interval"],
    ].map(([fn, value, unit]) => ({ function: fn, measure: "", unit, evidence: emptyEvidence(value) })),
    lossEffect: "", lossInputs: "",
  };
}
export const storeKey = (mode: string, cveId: string) => `${mode}:${cveId}`;

const v3base: Record<string, string[]> = { AV: ["N", "A", "L", "P"], AC: ["L", "H"], PR: ["N", "L", "H"], UI: ["N", "R"], S: ["U", "C"], C: ["N", "L", "H"], I: ["N", "L", "H"], A: ["N", "L", "H"] };
const v4base: Record<string, string[]> = { AV: ["N", "A", "L", "P"], AC: ["L", "H"], AT: ["N", "P"], PR: ["N", "L", "H"], UI: ["N", "P", "A"], VC: ["N", "L", "H"], VI: ["N", "L", "H"], VA: ["N", "L", "H"], SC: ["N", "L", "H"], SI: ["N", "L", "H"], SA: ["N", "L", "H"] };
export interface Metric { id: string; label: string; values: string[] }
const metricNames: Record<string, string> = { AV: "attack vector", AC: "attack complexity", AT: "attack requirements", PR: "privileges required", UI: "user interaction", S: "scope", C: "confidentiality impact", I: "integrity impact", A: "availability impact", VC: "vulnerable-system confidentiality", VI: "vulnerable-system integrity", VA: "vulnerable-system availability", SC: "subsequent-system confidentiality", SI: "subsequent-system integrity", SA: "subsequent-system availability" };
export function metricValueLabel(id: string, value: string): string {
  if (value === "X") return "X · inherit / not defined";
  if (id === "MAV") return `${value} · ${{ N: "Network", A: "Adjacent", L: "Local", P: "Physical" }[value]}`;
  if (id === "MUI") return `${value} · ${{ N: "None", R: "Required", P: "Passive", A: "Active" }[value]}`;
  if (id === "MS") return `${value} · ${value === "U" ? "Unchanged" : "Changed"}`;
  if (id === "MAT") return `${value} · ${value === "P" ? "Present" : "None"}`;
  return `${value} · ${{ N: "None / negligible", L: "Low", M: "Medium", H: "High", S: "Safety" }[value]}`;
}
export function environmentalMetrics(version: string): Metric[] {
  const base = version === "4.0" ? v4base : v3base;
  return [
    ...Object.entries(base).map(([key, values]) => ({ id: `M${key}`, label: `Modified ${metricNames[key]} (M${key})`, values: ["X", ...values, ...((version === "4.0" && ["SI", "SA"].includes(key)) ? ["S"] : [])] })),
    ...["CR", "IR", "AR"].map(id => ({ id, label: `${id === "CR" ? "Confidentiality" : id === "IR" ? "Integrity" : "Availability"} requirement (${id})`, values: ["X", "L", "M", "H"] })),
  ];
}
export function baseVector(vector: string): { version: string; vector: string } {
  const parts = vector.trim().split("/");
  const version = parts.shift()?.replace("CVSS:", "");
  if (!version || !["3.0", "3.1", "4.0"].includes(version) || !vector.startsWith(`CVSS:${version}/`)) throw Error("A valid CVSS 3.0, 3.1, or 4.0 vector is required. Other versions stay unassessed.");
  const metrics: Record<string, string> = {};
  for (const part of parts) {
    const pair = part.split(":");
    if (pair.length !== 2 || metrics[pair[0]] !== undefined) throw Error("Duplicate or malformed vector metric.");
    metrics[pair[0]] = pair[1];
  }
  // Validate the full source before selecting its intrinsic Base metrics.
  if (version === "4.0") new CVSS40(vector); else if (version === "3.1") new CVSS31(vector); else new CVSS30(vector);
  const required = version === "4.0" ? v4base : v3base;
  for (const [id, values] of Object.entries(required)) if (!values.includes(metrics[id])) throw Error(`Missing or invalid Base metric ${id}.`);
  return { version, vector: `CVSS:${version}/` + Object.keys(required).map(id => `${id}:${metrics[id]}`).join("/") };
}
export function scoreScenario(source: string, metrics: Record<string, string>): { score: number; vector: string; version: string } {
  const base = baseVector(source);
  const allowed = environmentalMetrics(base.version);
  for (const [key, value] of Object.entries(metrics)) if (!allowed.some(m => m.id === key && m.values.includes(value))) throw Error(`Invalid Environmental metric ${key}:${value}.`);
  const additions = Object.entries(metrics).filter(([, v]) => v !== "X").map(([k, v]) => `${k}:${v}`);
  const vector = base.vector + (additions.length ? "/" + additions.join("/") : "");
  const score = base.version === "4.0" ? new CVSS40(vector).Score() : base.version === "3.1" ? new CVSS31(vector).EnvironmentalScore() : new CVSS30(vector).EnvironmentalScore();
  if (!Number.isFinite(score) || score < 0 || score > 10) throw Error("Calculator returned an invalid score.");
  return { score, vector, version: base.version };
}

export function usableEvidence(e: Evidence | undefined, assessedAt: string, now = Date.now(), verifiedOnly = false): boolean {
  if (!e || !(verifiedOnly ? e.state === "verified" : ["observed", "verified"].includes(e.state)) || !e.note.trim()) return false;
  const observed = Date.parse(e.observedAt);
  const assessed = Date.parse(assessedAt + "T23:59:59Z");
  return Number.isFinite(observed) && observed <= now && observed <= assessed;
}
export function scopeProblem(a: Assessment, f: Finding, now = Date.now()): string | null {
  if (!a.asset.trim() || !a.release.trim() || !a.component.trim() || !a.threat.trim() || !a.assessor.trim()) return "Complete the partition, release, component, threat scenario, and assessor.";
  if (a.modelVersion !== MODEL_VERSION || a.cveId !== f.cve_id || a.sourceVector !== (f.cvss_vector || "") || a.sourceRevision !== sourceRevision(f)) return "The source vector, remedy guidance, or model changed; reassess this record.";
  const assessed = Date.parse(a.assessedAt + "T00:00:00Z"), until = Date.parse(a.validUntil + "T23:59:59Z");
  if (!Number.isFinite(assessed) || !Number.isFinite(until) || assessed > now || until < now || until < assessed) return "Set a current assessment date and a valid review-through date. Expired records receive no credit.";
  return null;
}
export function assess(a: Assessment, f: Finding, now = Date.now()) {
  const problem = scopeProblem(a, f, now);
  const reliable = (id: string, verified = false) => !problem && usableEvidence(a.evidence[id], a.assessedAt, now, verified);
  const app = a.evidence.applicability, remedy = a.evidence.remedy;
  let disposition = "Investigate";
  if (reliable("exploitation") && a.evidence.exploitation.value === "observed") disposition = "Incident response";
  else if (reliable("applicability", true) && app.value === "not-applicable") disposition = "Not applicable";
  else if (reliable("applicability") && app.value === "confirmed" && reliable("remedy", true) && remedy.value === "remediated") disposition = "Remediated";
  else if (f.on_kev) disposition = "Expedite validation";
  else if (reliable("applicability") && app.value === "confirmed" && reliable("remedy") && ["vulnerable", "pending"].includes(remedy.value)) disposition = "Schedule remediation";
  if (disposition === "Expedite validation" && reliable("applicability") && app.value === "confirmed" && reliable("remedy") && ["vulnerable", "pending"].includes(remedy.value) && reliable("reachability") && a.evidence.reachability.value === "reachable") disposition = "Expedite remediation";
  const errors: string[] = [];
  if (problem) errors.push(problem);
  if (!reliable("applicability") || app.value !== "confirmed") errors.push("Confirm applicability with scoped evidence before scoring.");
  if (!reliable("remedy") || !["vulnerable", "pending"].includes(remedy.value)) errors.push("Establish the effective remedy state before scoring an unremediated scenario.");
  const scores: Array<{ score: number; vector: string; version: string; name: string; note: string }> = [];
  const hasUnresolved = Object.values(a.evidence).some(e => e.state === "conflicting");
  if (hasUnresolved) errors.push("Resolve conflicting evidence before calculating a range.");
  if (!errors.length) for (const scenario of a.scenarios) {
    if (!usableEvidence(scenario.evidence, a.assessedAt, now)) continue;
    try {
      // Every adjusted endpoint requires a causal rationale, not an automatic control deduction.
      const calculated = scoreScenario(f.cvss_vector || "", scenario.metrics);
      const baseline = scoreScenario(f.cvss_vector || "", {}).score;
      const protective = calculated.score < baseline;
      const anchors: Record<string, string> = { MAV: "reachability", MAC: "integrity", MAT: "integrity", MPR: "authority", MUI: "network" };
      for (const [metric, value] of Object.entries(scenario.metrics)) {
        if (value === "X") continue;
        const anchor = anchors[metric] || "business";
        if (!reliable(anchor, protective) || a.evidence[anchor].value === "unknown") throw Error(`${scenario.name}: ${metric} needs ${protective ? "analyst-verified" : "observed"} ${anchor} evidence. Unknown controls receive no mitigation credit.`);
      }
      scores.push({ ...calculated, name: scenario.name || "Unnamed scenario", note: scenario.evidence.note });
    } catch (error) { errors.push(error instanceof Error ? error.message : "Invalid vector."); }
  }
  if (!scores.length && !errors.length) errors.push("Document at least one observed or analyst-verified scenario, including metric rationale, source, and collection time.");
  if (a.scenarios.some(s => s.evidence.state === "conflicting")) errors.push("Resolve the conflicting scenario evidence.");
  const range = errors.length || !scores.length ? null : { low: Math.min(...scores.map(s => s.score)), high: Math.max(...scores.map(s => s.score)), version: scores[0].version };
  const detectionComplete = [2, 3, 4].every(i => !problem && usableEvidence(a.controls[i]?.evidence, a.assessedAt, now, true) && a.controls[i].measure.trim());
  return { disposition, range, scores, errors: [...new Set(errors)], detectionComplete, problem };
}

// Validate stored records before they can contribute to a result.
export function readStore(raw: string | null): AssessmentStore {
  try {
    const parsed = JSON.parse(raw || "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const result: AssessmentStore = {};
    for (const [key, entries] of Object.entries(parsed)) {
      if (!Array.isArray(entries)) continue;
      result[key] = entries.filter((a: Assessment) => a && typeof a.id === "string" && typeof a.cveId === "string" && typeof a.mode === "string" && a.modelVersion === MODEL_VERSION && typeof a.asset === "string" && typeof a.release === "string" && typeof a.component === "string" && typeof a.threat === "string" && typeof a.assessor === "string" && typeof a.sourceVector === "string" && typeof a.sourceRevision === "string" && typeof a.assessedAt === "string" && typeof a.validUntil === "string" && typeof a.lossEffect === "string" && typeof a.lossInputs === "string" && a.evidence && DIMENSIONS.every(d => validEvidence(a.evidence[d.id])) && Array.isArray(a.scenarios) && a.scenarios.length === 2 && a.scenarios.every(s => typeof s.name === "string" && validEvidence(s.evidence) && s.metrics && Object.entries(s.metrics).every(([k, v]) => /^[A-Z]+$/.test(k) && typeof v === "string")) && Array.isArray(a.controls) && a.controls.length === 9 && a.controls.every(c => typeof c.function === "string" && typeof c.measure === "string" && typeof c.unit === "string" && validEvidence(c.evidence)) && key === storeKey(a.mode, a.cveId)).slice(0, 30);
    }
    return result;
  } catch { return {}; }
}
function validEvidence(e: Evidence): boolean {
  return !!e && typeof e.value === "string" && ["unknown", "attested", "observed", "verified", "conflicting"].includes(e.state) && typeof e.note === "string" && typeof e.observedAt === "string";
}
