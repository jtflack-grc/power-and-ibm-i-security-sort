import type { Finding } from "../types";

/** Flagship portfolio walkthrough — CVE-2024-25050 */
export const FLAGSHIP_CVE = "CVE-2024-25050";

interface Props {
  finding: Finding | null;
  onOpen: (f: Finding) => void;
  visible: boolean;
}

export function FlagshipWalkthrough({ finding, onOpen, visible }: Props) {
  if (!visible) return null;

  return (
    <div className="flagship">
      <div className="flagship-title">Flagship walkthrough</div>
      <p className="flagship-body">
        <strong>{FLAGSHIP_CVE}</strong> — IBM i local privilege escalation with a published
        Security Bulletin. GRC signals (CVSS / OWASP access-control) meet systems work (bulletin →
        Fix Central → DSPPTF verify) on the <strong>Apply</strong> dock.
      </p>
      <ol className="flagship-steps">
        <li>Open the finding — levers show why it ranks.</li>
        <li>Resolve tab — bulletin + Fix Central path.</li>
        <li>Use the evidence rail to verify the published fix path.</li>
        <li>Copy the change packet for ticket-ready Markdown.</li>
      </ol>
      {finding ? (
        <button type="button" className="button button-primary" onClick={() => onOpen(finding)}>
          Open {FLAGSHIP_CVE}
        </button>
      ) : (
        <p className="flagship-missing">Load sample to walk this CVE.</p>
      )}
    </div>
  );
}
