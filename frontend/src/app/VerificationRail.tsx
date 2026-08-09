import { useEffect, useMemo, useRef, useState } from "react";
import type { Bulletin, Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";
import { RemediationAssist } from "./RemediationAssist";

interface Props {
  finding: Finding | null;
  bulletin?: Bulletin | null;
}

export function VerificationRail({ finding, bulletin = null }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const channelTokenRef = useRef(crypto.randomUUID());
  const [showSources, setShowSources] = useState(false);
  const applicableRows = useMemo(
    () => (bulletin?.applicability ?? []).filter((row) => row.product_id && row.release_system && row.individual_ptfs.length),
    [bulletin]
  );
  const [applicabilityId, setApplicabilityId] = useState("");
  useEffect(() => {
    setApplicabilityId(applicableRows.length === 1 ? applicableRows[0].applicability_id : "");
  }, [finding?.cve_id, applicableRows]);
  const selectedApplicability = applicableRows.find((row) => row.applicability_id === applicabilityId);
  const fallbackMeta = useMemo(() => extractPtfEvidence(finding), [finding]);
  const scenarioMeta = useMemo(() => selectedApplicability ? {
    ptfs: selectedApplicability.individual_ptfs.slice(0, 1),
    groups: selectedApplicability.group_ptfs,
    apars: selectedApplicability.apars,
    summaries: [],
    productId: selectedApplicability.product_id || "",
    release: selectedApplicability.release_system || "",
  } : fallbackMeta, [selectedApplicability, fallbackMeta]);
  const ptfs = scenarioMeta.ptfs;
  const hasPtfPath = ptfs.length > 0 && Boolean(scenarioMeta.productId && scenarioMeta.release);

  useEffect(() => {
    const load = () => {
      if (!hasPtfPath) return;
      frameRef.current?.contentWindow?.postMessage({
        type: "ironterm:load",
        scenario: "dspptf-status",
        channelToken: channelTokenRef.current,
        ptfs,
        productId: scenarioMeta.productId,
        release: scenarioMeta.release,
      }, window.location.origin);
    };
    const receive = (event: MessageEvent) => {
      if (
        event.source === frameRef.current?.contentWindow &&
        event.origin === window.location.origin &&
        event.data?.type === "ironterm:ready"
      ) load();
    };
    window.addEventListener("message", receive);
    load();
    return () => window.removeEventListener("message", receive);
  }, [finding?.cve_id, hasPtfPath, ptfs, scenarioMeta]);

  return (
    <section className="verification-rail" aria-labelledby="verification-title">
      <div className="verification-head">
        <div>
          <p className="verification-kicker">System verification</p>
          <h3 id="verification-title">Legacy Control Lab evidence check</h3>
        </div>
        <div className="verification-head-actions">
          <button
            type="button"
            className="verification-source-button"
            aria-expanded={showSources}
            onClick={() => setShowSources((value) => !value)}
          >
            Sources &amp; boundary
          </button>
          <span className="verification-state">
            {hasPtfPath ? "DSPPTF status validated" : "Guided evidence route"}
          </span>
        </div>
      </div>
      {showSources && (
        <div className="verification-source-panel">
          <a
            href="https://www.ibm.com/docs/en/was-nd/9.0.5?topic=installation-determining-proper-cumulative-ptf-level-i"
            target="_blank"
            rel="noreferrer"
          >
            IBM Display PTF Status example ↗
          </a>
          <span>IronTerm TN5250 · GPL-3.0 · transport and credentials disabled</span>
          <span>Option 5 remains gated until its destination screens have coordinate evidence.</span>
        </div>
      )}
      <p className="verification-copy">
        {finding
          ? hasPtfPath
            ? `${finding.cve_id} has a PTF path. The IBM-sourced DSPPTF status panel is interactive; detail navigation remains source-gated.`
            : `${finding.cve_id} does not resolve to an individual PTF. The evidence workspace below is routed by the remediation type IBM published.`
          : "Select a finding to assess whether an IBM i verification scenario applies."}
      </p>
      {applicableRows.length > 1 && (
        <label className="verification-applicability">
          Applicable IBM i fix row
          <select value={applicabilityId} onChange={(event) => setApplicabilityId(event.target.value)}>
            <option value="">Select release and product</option>
            {applicableRows.map((row) => (
              <option key={row.applicability_id} value={row.applicability_id}>
                IBM i {row.release} · {row.product_id} · {row.individual_ptfs.join(", ")}
              </option>
            ))}
          </select>
        </label>
      )}
      {hasPtfPath ? (
        <div className="verification-frame-wrap">
          <iframe
            ref={frameRef}
            className="verification-frame"
            src="./ironterm/index.html"
            title="IronTerm TN5250 scenario terminal"
            sandbox="allow-scripts allow-same-origin"
            referrerPolicy="no-referrer"
          />
        </div>
      ) : (
        <div className="verification-frame-wrap verification-assist-wrap">
          <RemediationAssist finding={finding} />
        </div>
      )}
    </section>
  );
}
