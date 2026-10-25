import type { Finding } from "../types";
import { estimateOsint } from "../osintAssessment";

export function OsintAssessmentPanel({ finding, generatedAt }: { finding: Finding; generatedAt?: string | null }) {
  const result = estimateOsint(finding);
  const download = () => {
    const content = { cve: finding.cve_id, publishedCvss: finding.cvss_score, publishedVector: finding.cvss_vector, ibmCvss: finding.ibm_cvss_score, ibmVector: finding.ibm_cvss_vector, feedGeneratedAt: generatedAt, assessment: result };
    const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${finding.cve_id}-ibmi-osint-estimate.json`; link.click(); URL.revokeObjectURL(url);
  };
  return <section className="context-panel osint-assessment" aria-labelledby="osint-title">
    <header className="context-heading"><div><p className="queue-eyebrow">IBM i · the source-backed view</p><h3 id="osint-title">IBM i assessment score range</h3></div><span className="badge">OSINT estimate</span></header>
    <div className="context-result"><div><span>Automatic IBM i estimate</span><strong>{result.low.toFixed(1)}–{result.high.toFixed(1)}<small> / 10</small></strong><small>{result.coverage}</small></div><div><span>Response emphasis</span><strong className="context-disposition">{result.priority}</strong><small>{result.profile}</small></div></div>
    <p className="context-muted">Generated from the CVE, IBM bulletin, and documented IBM i behavior. Updates with the published feed; partition evidence can optionally refine it. Endpoints describe explicit assumed deployments; they are not a measured partition score or a probability interval.</p>
    <details className="context-editor"><summary>Why this range · facts and inferred scenarios</summary>
      <h4>What the public sources establish</h4><ul>{result.facts.map(fact => <li key={fact}>{fact}</li>)}</ul>
      <p className="context-muted">Method: {result.basis}. Model {result.model}; platform-reference review {result.reviewed}. Feed snapshot: {generatedAt || "not supplied"}.</p>
      {result.endpoints.map((endpoint, index) => <article className="context-calculation" key={index}><h4>{endpoint.name} · {endpoint.score.toFixed(1)} / 10</h4>{endpoint.vector && <code>{endpoint.vector}</code>}<p>{endpoint.assumption}</p></article>)}
      <h4>Uncertainty included in the estimate</h4><ul>{result.unknowns.map(unknown => <li key={unknown}>{unknown}</li>)}</ul>
      <p className="context-muted">The interval is an experimental scenario envelope. A narrow or unchanged range does not prove the partition is safe. Sparse records keep a broad provisional band. Higher published scores stay inside the envelope when sources differ.</p>
    </details>
    <details className="context-editor"><summary>IBM / Redbooks / specialist sources</summary><ul className="context-sources">{result.sources.map(source => <li key={source.url}><a href={source.url} target="_blank" rel="noreferrer">{source.title} ↗</a><p>{source.fact}</p><p>{source.applicability}</p></li>)}</ul><p className="context-muted">Sources establish platform mechanisms and vulnerability facts. This project's scenario choices are explicit analyst inferences, not score ranges endorsed by IBM, FIRST, Fortra, or Kisco.</p></details>
    <details className="context-editor"><summary>FAIR-CAM™ lens · automatic control assumptions</summary>{result.controlMap.map(control => <article key={control.role}><h4>{control.role}</h4><p>{control.inference}</p></article>)}<p className="context-muted">References <a href="https://www.fairinstitute.org/resources/FAIR-CAM" target="_blank" rel="noreferrer">FAIR-CAM™ guidance from the FAIR Institute ↗</a>. These original IBM i mappings explain the estimate; they do not claim measured control efficacy or quantified financial loss.</p></details>
    <div className="context-toolbar"><button type="button" className="button" onClick={download}>Download OSINT estimate + sources</button></div>
  </section>;
}
