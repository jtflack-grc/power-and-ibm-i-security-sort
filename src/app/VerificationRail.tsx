import { useEffect, useRef } from "react";
import type { Finding } from "../types";

interface Props {
  finding: Finding | null;
}

export function VerificationRail({ finding }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const channelTokenRef = useRef(crypto.randomUUID());
  const hasPtfPath = Boolean(
    finding?.resolution_steps?.some((step) => String(step.kind ?? "") === "ptf")
  );

  useEffect(() => {
    const load = () => {
      if (!hasPtfPath) return;
      frameRef.current?.contentWindow?.postMessage({
        type: "ironterm:load",
        scenario: "dspptf-status",
        channelToken: channelTokenRef.current,
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
  }, [finding?.cve_id, hasPtfPath]);

  return (
    <section className="verification-rail" aria-labelledby="verification-title">
      <div className="verification-head">
        <div>
          <p className="verification-kicker">System verification</p>
          <h3 id="verification-title">Synthetic 5250 evidence check</h3>
        </div>
        <span className="verification-state">DSPPTF status validated</span>
      </div>
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
      <p className="verification-source">
        Terminal core: IronTerm TN5250, GPL-3.0. Live hosts, credentials, and websockify are disabled.
      </p>
    </section>
  );
}
