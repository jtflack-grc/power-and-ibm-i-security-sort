import { useEffect, useMemo, useRef, useState } from "react";
import type { Finding } from "../types";

interface Props {
  finding: Finding | null;
}

export function VerificationRail({ finding }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const channelTokenRef = useRef(crypto.randomUUID());
  const [showSources, setShowSources] = useState(false);
  const ptfs = useMemo(() => {
    const tokens = (finding?.resolution_steps ?? [])
      .filter((step) => String(step.kind ?? "").toLowerCase() === "ptf")
      .flatMap((step) => `${step.title} ${step.detail}`.match(/\b[A-Z]{2}\d{5,7}\b/g) ?? [])
      .map((token) => token.toUpperCase());
    return [...new Set(tokens)].slice(0, 7);
  }, [finding]);
  const scenarioMeta = useMemo(() => {
    const guidance = (finding?.resolution_steps ?? [])
      .map((step) => `${step.title} ${step.detail}`)
      .join(" ");
    const productId = guidance.match(/\b\d{4}[A-Z0-9]{3}\b/)?.[0] ?? "5770SS1";
    const releaseMatch = guidance.match(/\b(?:IBM i\s+)?([1-9])\.([0-9])\b/i);
    const release = releaseMatch ? `V${releaseMatch[1]}R${releaseMatch[2]}M0` : "V7R4M0";
    return { productId, release };
  }, [finding]);
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
          <span className="verification-state">DSPPTF status validated</span>
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
            : `${finding.cve_id} does not yet have an extracted PTF identifier, so no terminal verification is offered.`
          : "Select a finding to assess whether an IBM i verification scenario applies."}
      </p>
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
    </section>
  );
}
