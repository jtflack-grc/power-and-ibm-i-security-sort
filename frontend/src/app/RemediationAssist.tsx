import { useMemo, useState } from "react";
import { extractPtfEvidence } from "../ptfEvidence";
import type { Finding } from "../types";

interface Props {
  finding: Finding | null;
}

export function RemediationAssist({ finding }: Props) {
  const evidence = useMemo(() => extractPtfEvidence(finding), [finding]);
  const [copied, setCopied] = useState<string | null>(null);

  const copy = async (label: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(label);
    window.setTimeout(() => setCopied((current) => current === label ? null : current), 1600);
  };

  const route = evidence.groups.length
    ? "group"
    : evidence.apars.length
      ? "apar"
      : evidence.summaries.length
        ? "vendor"
        : "research";

  return (
    <div className="remediation-assist" aria-label="Remediation evidence assistance">
      <div className="remediation-assist-lead">
        <p className="verification-kicker">Evidence route · {route}</p>
        <h4>
          {route === "group"
            ? "Group PTF verification"
            : route === "apar"
              ? "APAR / iFix handoff"
              : route === "vendor"
                ? "Vendor remediation worksheet"
                : "Fix-resolution work queue"}
        </h4>
        <p>
          {route === "group"
            ? "This is not an individual DSPPTF selection. Verify the group and its installed level."
            : route === "apar"
              ? "Preserve the APAR reference, then resolve its applicable iFix or fix pack for the installed product level."
              : route === "vendor"
                ? "The bulletin has remediation text but no individual IBM i PTF was resolved. Capture the product-specific change target."
                : "The collector confirmed the finding but did not recover a packaged fix. Keep this in research/containment until resolved."}
        </p>
      </div>

      {route === "group" && (
        <div className="remediation-token-grid">
          {evidence.groups.map((group) => {
            const command = `WRKPTFGRP PTFGRP(${group})`;
            return (
              <div className="remediation-token" key={group}>
                <span>IBM i group PTF</span>
                <code>{command}</code>
                <button type="button" onClick={() => void copy(group, command)}>
                  {copied === group ? "Copied" : "Copy command"}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {route === "apar" && (
        <div className="remediation-token-grid">
          {evidence.apars.map((apar) => (
            <div className="remediation-token" key={apar}>
              <span>Vendor APAR</span>
              <code>{apar}</code>
              <button type="button" onClick={() => void copy(apar, apar)}>
                {copied === apar ? "Copied" : "Copy APAR"}
              </button>
            </div>
          ))}
        </div>
      )}

      {evidence.summaries.length > 0 && (
        <div className="remediation-summary">
          <span>IBM remediation captured</span>
          <p>{evidence.summaries[0]}</p>
        </div>
      )}

      <ol className="remediation-checklist">
        <li>Match affected product, release, option, and installed level.</li>
        <li>Resolve the exact downloadable package in the IBM bulletin or Fix Central.</li>
        <li>Record current state, planned change, validation command, and rollback evidence.</li>
      </ol>
      <div className="remediation-links">
        {finding?.ibm_bulletin_url && (
          <a href={finding.ibm_bulletin_url} target="_blank" rel="noreferrer">IBM bulletin ↗</a>
        )}
        <a href={`https://www.ibm.com/support/pages/search?q=${encodeURIComponent(finding?.cve_id ?? "IBM i")}`} target="_blank" rel="noreferrer">
          IBM Support search ↗
        </a>
        <a href="https://www.ibm.com/support/fixcentral" target="_blank" rel="noreferrer">Fix Central ↗</a>
      </div>
    </div>
  );
}
