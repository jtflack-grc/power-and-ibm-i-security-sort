import { useState } from "react";
import type { Finding } from "../types";
import { assess, baseVector, DIMENSIONS, environmentalMetrics, metricValueLabel, MODEL_VERSION, newAssessment, sourceRevision, SOURCES } from "../contextAssessment";
import type { Assessment, Evidence, EvidenceState } from "../contextAssessment";
import { normalizeIbmBulletinUrl } from "../links";

interface Props { finding: Finding; mode: string; records: Assessment[]; onSave: (record: Assessment) => boolean }
const STATES: Array<[EvidenceState, string]> = [["unknown", "Unknown"], ["attested", "Owner-attested"], ["observed", "Observed export / configuration"], ["verified", "Analyst-verified behavior"], ["conflicting", "Conflicting evidence"]];
function EvidenceFields({ value, onChange, prefix }: { value: Evidence; onChange: (value: Evidence) => void; prefix: string }) {
  return <div className="context-evidence-fields">
    <label>Evidence state<select aria-label={`${prefix} evidence state`} value={value.state} onChange={e => onChange({ ...value, state: e.target.value as EvidenceState })}>{STATES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
    <label>Observed / tested on<input aria-label={`${prefix} observation date`} type="date" value={value.observedAt} onChange={e => onChange({ ...value, observedAt: e.target.value })} onInput={e => onChange({ ...value, observedAt: e.currentTarget.value })} onBlur={e => onChange({ ...value, observedAt: e.currentTarget.value })} /></label>
    <label className="context-wide">Evidence and source<textarea aria-label={`${prefix} evidence and source`} rows={2} value={value.note} placeholder="What was observed, how it was tested, source/reference, scope, and limitations. Use sanitized identifiers." onChange={e => onChange({ ...value, note: e.target.value })} /></label>
  </div>;
}

export function ContextAssessmentPanel({ finding, mode, records, onSave }: Props) {
  const [record, setRecord] = useState<Assessment>(() => records[0] || newAssessment(finding, mode));
  const [saved, setSaved] = useState(!!records.length);
  const [storageFailed, setStorageFailed] = useState(false);
  const result = assess(record, finding);
  let version = "";
  try { version = baseVector(finding.cvss_vector || "").version; } catch { /* Keep assessment available without numeric scoring. */ }
  const update = (next: Assessment) => {
    setRecord(next);
    const ok = onSave(next);
    setSaved(ok); setStorageFailed(!ok);
  };
  const scopeChange = (key: "asset" | "release" | "component" | "threat", value: string) => update({
    ...record, [key]: value,
    evidence: Object.fromEntries(Object.entries(record.evidence).map(([id, e]) => [id, { ...e, state: "unknown" as const }])),
    scenarios: record.scenarios.map(s => ({ ...s, evidence: { ...s.evidence, state: "unknown" } })),
    controls: record.controls.map(c => ({ ...c, evidence: { ...c.evidence, state: "unknown" } })),
  });
  const download = (format: "json" | "md") => {
    const payload = { assessment: record, result, publishedCvss: { score: finding.cvss_score, vector: finding.cvss_vector, bulletinUrl: normalizeIbmBulletinUrl(finding.ibm_bulletin_url, finding.cve_id), lastModified: finding.last_modified }, sources: SOURCES, exportedAt: new Date().toISOString() };
    const content = format === "json" ? JSON.stringify(payload, null, 2) : [
      `# ${finding.cve_id} — IBM i contextual assessment`, `Model: ${MODEL_VERSION} · mode: ${mode}`,
      `Published CVSS: ${finding.cvss_score ?? "Unrated"}`, `Source vector: ${finding.cvss_vector || "Unavailable"}`,
      `Scope: ${record.asset || "Unspecified"} / ${record.release || "Unspecified"} / ${record.component || "Unspecified"}`,
      `Threat scenario: ${record.threat || "Unspecified"}`, `Assessor: ${record.assessor || "Unspecified"}; assessed: ${record.assessedAt || "Unknown"}; review through: ${record.validUntil || "Unknown"}`,
      `Disposition: ${result.disposition}`, `Contextual range: ${result.range ? `${result.range.low.toFixed(1)}–${result.range.high.toFixed(1)} (CVSS ${result.range.version})` : "Not assessed"}`,
      "Range is a documented-scenario severity envelope, not a confidence interval or monetary loss estimate.",
      ...DIMENSIONS.map(d => `## ${d.label}\n${record.evidence[d.id].value} · ${record.evidence[d.id].state} · ${record.evidence[d.id].observedAt || "Undated"}\n${record.evidence[d.id].note || "No evidence"}`),
      "## Endpoint calculations", ...result.scores.map(s => `${s.name}: ${s.score.toFixed(1)}\n${s.vector}\n${s.note}`),
      ...result.errors.map(error => `Unresolved: ${error}`),
      "## Control observations — FAIR-CAM reference", ...record.controls.map(c => `${c.function}: ${c.evidence.value}\nMeasurement: ${c.measure || "Not measured"} ${c.unit}\nEvidence: ${c.evidence.state}; ${c.evidence.observedAt || "Undated"}\n${c.evidence.note}`),
      "## FAIR scenario worksheet", record.lossEffect || "Loss effect not specified", record.lossInputs || "Frequency, susceptibility, and loss inputs not calibrated; no dollar estimate calculated.",
      "## Sources and method", ...SOURCES.map(s => `- [${s.name}](${s.url}): ${s.use}`),
      "Original experimental IBM i assessment workflow. FAIR-CAM is referenced for control function concepts; no certified analytics or measured risk reduction is claimed.",
    ].join("\n\n");
    const url = URL.createObjectURL(new Blob([content], { type: format === "json" ? "application/json" : "text/markdown;charset=utf-8" }));
    const link = document.createElement("a"); link.href = url; link.download = `${finding.cve_id}-ibmi-context.${format}`; link.click(); URL.revokeObjectURL(url);
  };
  return <section className="context-panel" aria-labelledby="context-title">
    <header className="context-heading"><div><p className="queue-eyebrow">Optional local validation</p><h3 id="context-title">Partition-specific refinement</h3></div><span className="badge">Experimental v0.1</span></header>
    <div className="context-result" aria-live="polite">
      <div><span>IBM i contextual range</span><strong>{result.range ? `${result.range.low.toFixed(1)}–${result.range.high.toFixed(1)}` : "Not assessed"}</strong><small>{result.range ? `CVSS ${result.range.version}${result.range.version === "4.0" ? " scenario envelope" : " Environmental"} · / 10` : "Published CVSS stays unchanged"}</small></div>
      <div><span>Response priority</span><strong className="context-disposition">{result.disposition}</strong><small>{mode === "sample" ? "Sample context · separate from live assessments" : "Local partition context"}</small></div>
    </div>
    {record.asset && <p className="context-muted">Scope: <strong>{record.asset}</strong> · {record.release || "release unknown"} · {record.component || "component unknown"}. Assessor: {record.assessor || "unassigned"}. Review through: {record.validUntil || "not set"}.</p>}
    <p className="context-muted">A range spans documented deployment scenarios. It is not a probability interval. Unknown controls earn no mitigation credit; the upper endpoint can exceed the published Base score.</p>
    <details className="context-editor"><summary>Assess a partition · evidence and scenarios</summary>
      <div className="context-toolbar"><label>Saved assessments<select aria-label="Saved contextual assessments" value={records.some(r => r.id === record.id) ? record.id : "new"} onChange={e => { const chosen = records.find(r => r.id === e.target.value); if (chosen) { update(chosen); } }}><option value="new" disabled>New assessment</option>{records.map(r => <option key={r.id} value={r.id}>{r.asset || "Unscoped draft"} · {r.release || "Release unknown"} · {r.threat || "Scenario unknown"}</option>)}</select></label><button type="button" className="button" onClick={() => { setRecord(newAssessment(finding, mode)); setSaved(false); setStorageFailed(false); }}>New partition / scenario</button></div>
      <p className="context-muted">Changes save in this browser only. Changing the scope resets evidence states to Unknown and retains notes for review. Use pseudonyms; no inventory is uploaded.</p>
      <p className="context-muted">Assessment, evidence, and review dates use UTC calendar days.</p>
      <p role="status" className={storageFailed ? "context-error" : "context-muted"}>{storageFailed ? "Browser storage is unavailable or full. This draft is only in memory; download it before leaving." : saved ? "Saved locally" : "New draft — not yet saved"}</p>
      <div className="context-fields">
        <label>Partition pseudonym<input value={record.asset} onChange={e => scopeChange("asset", e.target.value)} placeholder="PROD-A" /></label>
        <label>IBM i release<input value={record.release} onChange={e => scopeChange("release", e.target.value)} placeholder="7.5 · relevant level" /></label>
        <label>Affected component<input value={record.component} onChange={e => scopeChange("component", e.target.value)} placeholder="Product, option, installed version" /></label>
        <label>Assessor<input value={record.assessor} onChange={e => update({ ...record, assessor: e.target.value })} placeholder="Name or team alias" /></label>
        <label className="context-wide">Threat scenario<input value={record.threat} onChange={e => scopeChange("threat", e.target.value)} placeholder="Which threat acts against which function, through which path?" /></label>
        <label>Assessment date<input type="date" value={record.assessedAt} onChange={e => update({ ...record, assessedAt: e.target.value })} onInput={e => update({ ...record, assessedAt: e.currentTarget.value })} onBlur={e => update({ ...record, assessedAt: e.currentTarget.value })} /></label>
        <label>Review through<input type="date" value={record.validUntil} onChange={e => update({ ...record, validUntil: e.target.value })} onInput={e => update({ ...record, validUntil: e.currentTarget.value })} onBlur={e => update({ ...record, validUntil: e.currentTarget.value })} /></label>
      </div>
      {record.sourceRevision !== sourceRevision(finding) && <div className="context-error"><p>The published vector or remedy guidance changed. Revalidate evidence for the new source.</p><button type="button" className="button" onClick={() => { const next = newAssessment(finding, mode); update({ ...next, id: record.id, asset: record.asset, release: record.release, component: record.component, threat: record.threat, assessor: record.assessor }); }}>Start reassessment with current vector</button></div>}
      <h4>Partition evidence</h4>
      {DIMENSIONS.map(d => <details className="context-dimension" key={d.id}><summary>{d.label}<span>{record.evidence[d.id].state === "verified" ? "Analyst-verified" : record.evidence[d.id].state}</span></summary><p className="context-muted">{d.hint}</p><label>{d.label} finding<select value={record.evidence[d.id].value} onChange={e => update({ ...record, evidence: { ...record.evidence, [d.id]: { ...record.evidence[d.id], value: e.target.value, state: "unknown" } } })}>{d.options.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label><EvidenceFields prefix={d.label} value={record.evidence[d.id]} onChange={e => update({ ...record, evidence: { ...record.evidence, [d.id]: e } })} /></details>)}
      <h4>Calculate the scenario envelope</h4>
      <p className="context-muted">Use the same CVSS version as the published vector. X inherits the Base metric. Changed metrics need relevant partition evidence and a written causal rationale; score reductions require analyst-verified evidence. Changing a metric resets that scenario to Unknown for revalidation. Threat/Temporal adjustments are excluded from this version.</p>
      {!version && <p className="context-error">Numeric scoring needs a valid CVSS 3.0, 3.1, or 4.0 vector. Evidence and control assessment are still available.</p>}
      {record.scenarios.map((s, i) => <details className="context-dimension" key={i}><summary>{s.name || `Scenario ${i + 1}`}<span>{s.evidence.state}</span></summary><label>Scenario name<input value={s.name} onChange={e => update({ ...record, scenarios: record.scenarios.map((item, index) => index === i ? { ...s, name: e.target.value } : item) })} /></label><EvidenceFields prefix={`Scenario ${i + 1}`} value={s.evidence} onChange={e => update({ ...record, scenarios: record.scenarios.map((item, index) => index === i ? { ...s, evidence: e } : item) })} />
        {version && <div className="context-metrics">{environmentalMetrics(version).map(m => <label key={m.id}>{m.label}<select aria-label={`Scenario ${i + 1} ${m.id}`} value={s.metrics[m.id] || "X"} onChange={e => update({ ...record, scenarios: record.scenarios.map((item, index) => index === i ? { ...s, metrics: { ...s.metrics, [m.id]: e.target.value }, evidence: { ...s.evidence, state: "unknown" } } : item) })}>{m.values.map(v => <option key={v} value={v}>{metricValueLabel(m.id, v)}</option>)}</select></label>)}</div>}
        <p className="context-muted"><a href={`https://www.first.org/cvss/v${version || "3.1"}/specification-document`} target="_blank" rel="noreferrer">Metric definitions from FIRST ↗</a>. MAV: attack vector; MAC: complexity; MAT: attack requirements (v4); MPR: privileges; MUI: interaction; MS: scope (v3); C/I/A: impacts and requirements. No automatic metric mapping from a control checkbox.</p>
      </details>)}
      {result.errors.length > 0 && <div className="context-gaps"><h4>Next evidence needed</h4><ul>{result.errors.map(error => <li key={error}>{error}</li>)}</ul></div>}
    </details>
    {result.range && <details className="context-editor"><summary>Range calculation and endpoint evidence</summary>{result.scores.map((s, index) => <article className="context-calculation" key={index}><h4>{s.name} · {s.score.toFixed(1)} / 10</h4><code>{s.vector}</code><p>{s.note}</p></article>)}<p className="context-muted">Calculated with @pandatix/js-cvss 0.4.4. Two matching endpoints mean the assessed scenarios have the same severity, not that all uncertainty has disappeared.</p></details>}
    <details className="context-editor"><summary>Control evidence · FAIR-CAM™ reference</summary>
      <p>Map the role of each control in this loss scenario, then record what was actually measured. A control inventory alone does not establish effectiveness.</p>
      <p className="context-muted">Original IBM i examples reference FAIR-CAM™ functions published by the FAIR Institute. Mappings are analyst judgments. No control-reduction percentages or monetary risk are calculated here. <a href="https://www.fairinstitute.org/resources/FAIR-CAM" target="_blank" rel="noreferrer">Official FAIR-CAM guidance ↗</a></p>
      <div className="context-gaps">Detection evidence chain: {result.detectionComplete ? "All three functions have current analyst-verified observations and measurements; review their joint dependencies." : "Incomplete — visibility, monitoring, and recognition each need scoped, analyst-verified evidence and measurements."}</div>
      {record.controls.map((c, i) => <details key={i} className="context-dimension"><summary>{c.function}<span>{c.evidence.state}</span></summary><p>{c.evidence.value}</p><label>Measurement ({c.unit})<input value={c.measure} placeholder="Measured value, test count/scope, and limitations" onChange={e => update({ ...record, controls: record.controls.map((item, index) => index === i ? { ...c, measure: e.target.value } : item) })} /></label><EvidenceFields prefix={c.function} value={c.evidence} onChange={e => update({ ...record, controls: record.controls.map((item, index) => index === i ? { ...c, evidence: e } : item) })} /></details>)}
      <label>FAIR loss scenario<textarea rows={3} value={record.lossEffect} placeholder="Threat community → action against the partition/component → business loss effect, over a stated timeframe." onChange={e => update({ ...record, lossEffect: e.target.value })} /></label>
      <label>Calibrated inputs and dependencies<textarea rows={3} value={record.lossInputs} placeholder="Frequency per year, susceptibility evidence, loss per event and currency, recovery duration, input ranges, sources, and dependencies. No default dollar values." onChange={e => update({ ...record, lossInputs: e.target.value })} /></label>
    </details>
    <details className="context-editor"><summary>Method, baseline, and sources</summary><p>Experimental {MODEL_VERSION}. IBM i capabilities establish assessment questions; current partition evidence supports local adjustments. Unknown, stale, conflicting, or merely attested protection earns no numeric reduction. Remediated and not applicable are evidence-backed dispositions, not zero CVSS scores.</p><p>Scope is CVE × partition × component × threat scenario × observation time. Review-through dates are assessor-selected; configuration changes can invalidate evidence sooner. Revalidate after changes. Model decisions and IBM i control mappings are original analyst policy, not vendor-endorsed weights.</p><p>FAIR-CAM™ is published by the FAIR Institute. This worksheet references the published model; it does not reproduce or modify the ontology. <a href="https://www.fairinstitute.org/frequently-asked-questions" target="_blank" rel="noreferrer">FAIR Institute use terms</a>. <a href="https://creativecommons.org/licenses/by-nc-nd/4.0/" target="_blank" rel="noreferrer">Model-content license</a>.</p><p><a href={normalizeIbmBulletinUrl(finding.ibm_bulletin_url, finding.cve_id)} target="_blank" rel="noreferrer">IBM bulletin / support reference for {finding.cve_id} ↗</a></p><ul className="context-sources">{SOURCES.map(s => <li key={s.url}><a href={s.url} target="_blank" rel="noreferrer">{s.name} ↗</a><p>{s.use}</p></li>)}</ul></details>
    <div className="context-toolbar"><button className="button" type="button" onClick={() => download("md")}>Download assessment .md</button><button className="button" type="button" onClick={() => download("json")}>Download evidence .json</button></div>
  </section>;
}
