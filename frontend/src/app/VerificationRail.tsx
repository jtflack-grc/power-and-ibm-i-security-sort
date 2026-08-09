import { useEffect, useMemo, useRef, useState } from "react";
import type { Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";
import { RemediationAssist } from "./RemediationAssist";

interface Props {
  finding: Finding | null;
}

export function VerificationRail({ finding }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const channelTokenRef = useRef(crypto.randomUUID());
  const [showSources, setShowSources] = useState(false);
  const scenarioMeta = useMemo(() => extractPtfEvidence(finding), [finding]);
  const ptfs = scenarioMeta.ptfs;
  const hasPtfPath = ptfs.length > 0;

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
