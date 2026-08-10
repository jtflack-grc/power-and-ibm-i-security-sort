import { useEffect, useMemo, useRef, useState } from "react";
import type { Bulletin, Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";
import { RemediationAssist } from "./RemediationAssist";
import { InventoryComparison } from "./InventoryComparison";

interface Props {
  finding: Finding | null;
  bulletin?: Bulletin | null;
}

export function VerificationRail({ finding, bulletin = null }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const channelTokenRef = useRef(crypto.randomUUID());
  const [showSources, setShowSources] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const applicableRows = useMemo(
    () => (bulletin?.applicability ?? []).filter((row) =>
      row.product_id && row.release_system && (row.individual_ptfs.length || row.group_ptfs.length)
    ),
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
  const groups = scenarioMeta.groups;
  const hasPtfPath = ptfs.length > 0 && Boolean(scenarioMeta.productId && scenarioMeta.release);
  const hasGroupPath = groups.length > 0;
  const hasTerminalPath = hasPtfPath || hasGroupPath;
  const [terminalScenario, setTerminalScenario] = useState<"dspptf-status" | "wrkptfgrp">("dspptf-status");

  useEffect(() => {
    setTerminalScenario(hasPtfPath ? "dspptf-status" : "wrkptfgrp");
  }, [finding?.cve_id, applicabilityId, hasPtfPath]);

  useEffect(() => {
    const load = () => {
      if (!hasTerminalPath) return;
      frameRef.current?.contentWindow?.postMessage({
        type: "ironterm:load",
        scenario: terminalScenario,
        channelToken: channelTokenRef.current,
        ptfs,
        groups,
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
  }, [finding?.cve_id, hasTerminalPath, terminalScenario, ptfs, groups, scenarioMeta]);

  useEffect(() => {
    if (!fullscreen) return;
    const close = (event: KeyboardEvent) => { if (event.key === "Escape") setFullscreen(false); };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [fullscreen]);

  return (
    <section className={`verification-rail ${fullscreen ? "verification-fullscreen" : ""}`} aria-labelledby="verification-title">
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
          <button type="button" className="verification-source-button" aria-pressed={fullscreen} onClick={() => setFullscreen((value) => !value)}>
            {fullscreen ? "Exit full screen" : "Full screen"}
          </button>
          <span className="verification-state">
            {hasTerminalPath ? "IBM-sourced PTF displays" : "Guided evidence route"}
          </span>
        </div>
      </div>
      {showSources && (
        <div className="verification-source-panel">
          <a
            href={terminalScenario === "wrkptfgrp"
              ? "https://www.ibm.com/support/pages/changing-number-levels-shown-wrkptfgrp"
              : "https://www.ibm.com/docs/en/was-nd/9.0.5?topic=installation-determining-proper-cumulative-ptf-level-i"}
            target="_blank"
            rel="noreferrer"
          >
            {terminalScenario === "wrkptfgrp" ? "IBM WRKPTFGRP examples ↗" : "IBM Display PTF Status example ↗"}
          </a>
          <span>IronTerm TN5250 · GPL-3.0 · transport and credentials disabled</span>
          <span>Fixture levels use IBM's public 7.4 group table; system statuses are synthetic.</span>
          <span>Option 5 remains gated until its destination screen has coordinate evidence.</span>
        </div>
      )}
      <p className="verification-copy">
        {finding
          ? hasTerminalPath
            ? `${finding.cve_id} has a ${hasPtfPath ? "PTF" : "group PTF"} path. Walk the source-validated status display, then use the SQL evidence route beneath it for repeatable collection.`
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
                IBM i {row.release} · {row.product_id} · {[...row.individual_ptfs, ...row.group_ptfs].join(", ")}
              </option>
            ))}
          </select>
        </label>
      )}
      {!fullscreen && <InventoryComparison bulletin={bulletin} />}
      {hasTerminalPath ? (
        <>
          {hasPtfPath && hasGroupPath && (
            <div className="verification-scenario-tabs" aria-label="PTF display">
              <button type="button" aria-pressed={terminalScenario === "dspptf-status"} onClick={() => setTerminalScenario("dspptf-status")}>Individual PTF</button>
              <button type="button" aria-pressed={terminalScenario === "wrkptfgrp"} onClick={() => setTerminalScenario("wrkptfgrp")}>PTF groups</button>
            </div>
          )}
          <div className="verification-frame-wrap">
            <iframe
              ref={frameRef}
              className="verification-frame"
              src="./ironterm/index.html"
              title={terminalScenario === "wrkptfgrp" ? "IronTerm Work with PTF Groups scenario" : "IronTerm Display PTF Status scenario"}
              sandbox="allow-scripts allow-same-origin"
              referrerPolicy="no-referrer"
            />
          </div>
          {!fullscreen && (
            <details className="sql-evidence-route">
              <summary>
                <span>Evidence engineering route</span>
                <strong>Collect the same state with IBM i SQL services</strong>
              </summary>
              <div className="sql-evidence-grid">
                <article>
                  <p>Group PTF evidence</p>
                  <pre><code>{`SELECT PTF_GROUP_NAME,
       PTF_GROUP_DESCRIPTION,
       PTF_GROUP_LEVEL,
       PTF_GROUP_STATUS,
       PTF_GROUP_TARGET_RELEASE
  FROM QSYS2.GROUP_PTF_INFO
 ORDER BY PTF_GROUP_NAME,
          PTF_GROUP_LEVEL DESC;`}</code></pre>
                </article>
                <article>
                  <p>Individual PTF evidence</p>
                  <pre><code>{`SELECT PTF_IDENTIFIER,
       PTF_PRODUCT_ID,
       PTF_PRODUCT_RELEASE_LEVEL,
       PTF_LOADED_STATUS,
       PTF_IPL_ACTION,
       PTF_ACTION_PENDING,
       PTF_IPL_REQUIRED
  FROM QSYS2.PTF_INFO
 ORDER BY PTF_IDENTIFIER;`}</code></pre>
                </article>
              </div>
              <p className="sql-evidence-note">
                Run through ACS Run SQL Scripts or your approved Db2 for i client. Export sanitized results and retain the query, collection timestamp, partition identity, and job identity with the evidence packet.
              </p>
              <a href="https://www.ibm.com/docs/en/i/7.4.0?topic=services-group-ptf-info-view" target="_blank" rel="noreferrer">IBM GROUP_PTF_INFO reference ↗</a>
              <a href="https://www.ibm.com/docs/en/i/7.4.0?topic=services-ptf-info-view" target="_blank" rel="noreferrer">IBM PTF_INFO reference ↗</a>
            </details>
          )}
        </>
      ) : (
        <div className="verification-frame-wrap verification-assist-wrap">
          <RemediationAssist finding={finding} />
        </div>
      )}
    </section>
  );
}
