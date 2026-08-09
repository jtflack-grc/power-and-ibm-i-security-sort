import type { CaseWorkflow, Disposition } from "../caseWorkflow";

interface Props {
  value: CaseWorkflow;
  onChange: (value: CaseWorkflow) => void;
}

export function CaseWorkflowPanel({ value, onChange }: Props) {
  return (
    <details className="case-workflow">
      <summary>Local decision fields</summary>
      <p>Optional. Stored only in this browser tab and included in the change packet.</p>
      <div className="case-workflow-grid">
        <label>Owner<input value={value.owner} maxLength={120} onChange={(event) => onChange({ ...value, owner: event.target.value })} /></label>
        <label>Target date<input type="date" value={value.targetDate} onChange={(event) => onChange({ ...value, targetDate: event.target.value })} /></label>
        <label>Change record<input value={value.changeRecord} maxLength={120} onChange={(event) => onChange({ ...value, changeRecord: event.target.value })} /></label>
        <label>Disposition<select value={value.disposition} onChange={(event) => onChange({ ...value, disposition: event.target.value as Disposition })}>
          <option value="unreviewed">Unreviewed</option><option value="remediate">Remediate</option><option value="mitigate">Mitigate</option><option value="accept">Accept / exception</option><option value="not_affected">Not affected</option>
        </select></label>
        <label>Exception expiry<input type="date" value={value.exceptionExpiry} onChange={(event) => onChange({ ...value, exceptionExpiry: event.target.value })} /></label>
        <label>Reviewer<input value={value.reviewer} maxLength={120} onChange={(event) => onChange({ ...value, reviewer: event.target.value })} /></label>
      </div>
    </details>
  );
}
