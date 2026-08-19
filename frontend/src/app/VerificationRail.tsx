import { useEffect, useMemo, useRef, useState } from "react";
import type { Bulletin, Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";
import { RemediationAssist } from "./RemediationAssist";
import { InventoryComparison } from "./InventoryComparison";
import { PtfCommandCoach } from "./PtfCommandCoach";

interface Props {
  finding: Finding | null;
  bulletin?: Bulletin | null;
}

function sqlLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

export function VerificationRail({ finding, bulletin = null }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const channelTokenRef = useRef(crypto.randomUUID());
  const [showSources, setShowSources] = useState(false);
  const [showSql, setShowSql] = useState(false);
  const [copiedSql, setCopiedSql] = useState<"group" | "ptf" | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [showLegacy, setShowLegacy] = useState(false);
  const applicableRows = useMemo(
    () => (bulletin?.applicability ?? []).filter((row) =>
      row.product_id && row.release_system && (row.individual_ptfs.length || row.group_ptfs.length)
    ),
    [bulletin]
  );
  const [applicabilityId, setApplicabilityId] = useState("");
  useEffect(() => {
    setApplicabilityId(applicableRows.length === 1 ? applicableRows[0].applicability_id : "");
    setShowSql(false);
  }, [finding?.cve_id, applicableRows]);
  const selectedApplicability = applicableRows.find((row) => row.applicability_id === applicabilityId);
  const fallbackMeta = useMemo(() => extractPtfEvidence(finding), [finding]);
  const scenarioMeta = useMemo(() => selectedApplicability ? {
    ptfs: selectedApplicability.individual_ptfs,
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
  const groupSql = useMemo(() => {
    const filters: string[] = [];
    if (groups.length) filters.push(`PTF_GROUP_NAME IN (${groups.map(sqlLiteral).join(", ")})`);
    if (scenarioMeta.release) filters.push(`PTF_GROUP_TARGET_RELEASE = ${sqlLiteral(scenarioMeta.release)}`);
    return `SELECT PTF_GROUP_NAME,
       PTF_GROUP_DESCRIPTION,
       PTF_GROUP_LEVEL,
       PTF_GROUP_STATUS,
       PTF_GROUP_TARGET_RELEASE
  FROM QSYS2.GROUP_PTF_INFO${filters.length ? `\n WHERE ${filters.join("\n   AND ")}` : ""}
 ORDER BY PTF_GROUP_NAME,
          PTF_GROUP_LEVEL DESC;`;
  }, [groups, scenarioMeta.release]);
  const ptfSql = useMemo(() => {
    const filters: string[] = [];
    if (scenarioMeta.productId) filters.push(`PTF_PRODUCT_ID = ${sqlLiteral(scenarioMeta.productId)}`);
    if (scenarioMeta.release) filters.push(`PTF_PRODUCT_RELEASE_LEVEL = ${sqlLiteral(scenarioMeta.release)}`);
    if (ptfs.length) filters.push(`PTF_IDENTIFIER IN (${ptfs.map(sqlLiteral).join(", ")})`);
    return `SELECT PTF_IDENTIFIER,
       PTF_PRODUCT_ID,
       PTF_PRODUCT_RELEASE_LEVEL,
       PTF_LOADED_STATUS,
       PTF_IPL_ACTION,
       PTF_ACTION_PENDING,
       PTF_IPL_REQUIRED
  FROM QSYS2.PTF_INFO${filters.length ? `\n WHERE ${filters.join("\n   AND ")}` : ""}
 ORDER BY PTF_IDENTIFIER;`;
  }, [ptfs, scenarioMeta.productId, scenarioMeta.release]);
  const [terminalScenario, setTerminalScenario] = useState<"dspptf-status" | "wrkptfgrp">("dspptf-status");

  useEffect(() => {
    setTerminalScenario(hasGroupPath ? "wrkptfgrp" : "dspptf-status");
  }, [finding?.cve_id, applicabilityId, hasGroupPath]);

  useEffect(() => {
    const load = () => {
      if (!hasTerminalPath || (!showLegacy && !fullscreen)) return;
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
  }, [finding?.cve_id, hasTerminalPath, terminalScenario, ptfs, groups, scenarioMeta, showLegacy, fullscreen]);

  useEffect(() => {
    if (!fullscreen) return;
    const close = (event: KeyboardEvent) => { if (event.key === "Escape") setFullscreen(false); };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [fullscreen]);

  const copySql = async (kind: "group" | "ptf") => {
    await navigator.clipboard.writeText(kind === "group" ? groupSql : ptfSql);
    setCopiedSql(kind);
    window.setTimeout(() => setCopiedSql((current) => current === kind ? null : current), 1400);
  };

  const terminalFrame = hasTerminalPath && (showLegacy || fullscreen) ? (
    <div className="verification-frame-wrap verification-frame-wide">
      <iframe
        ref={frameRef}
        className="verification-frame"
        src="./ironterm/index.html"
        title={terminalScenario === "wrkptfgrp" ? "IronTerm Work with PTF Groups scenario" : "IronTerm Display PTF Status scenario"}
        sandbox="allow-scripts allow-same-origin"
        referrerPolicy="no-referrer"
      />
    </div>
  ) : null;

  return (
    <section className={`verification-rail ${fullscreen ? "verification-fullscreen" : ""}`} aria-labelledby="verification-title">
      <div className="verification-controls">
      <div className="verification-head verification-head-compact">
        <div>
          <p className="verification-kicker">CVE-to-fix evidence</p>
          <h3 id="verification-title">IBM claim × local system state</h3>
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
          <span className="verification-state">{hasTerminalPath ? "SQL comparison ready" : "Remediation route"}</span>
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
          <a href="https://www.ibm.com/docs/en/i/7.6.0?topic=services-cve-info-table-function" target="_blank" rel="noreferrer">IBM CVE_INFO documentation ↗</a>
          <span>SQL exports and case fields remain browser-local; no partition connection or upload.</span>
          <span>IronTerm TN5250 is a legacy aid; fixture system statuses are synthetic.</span>
        </div>
      )}
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
          {!fullscreen && (
            <section className="sql-evidence-route" aria-label="SQL evidence engineering route">
              <div className="sql-evidence-actions">
                <div><span>IBM i SQL services</span><strong>Repeatable PTF evidence</strong></div>
                <button type="button" onClick={() => void copySql("group")}>{copiedSql === "group" ? "Copied" : "Copy group SQL"}</button>
                <button type="button" onClick={() => void copySql("ptf")}>{copiedSql === "ptf" ? "Copied" : "Copy PTF SQL"}</button>
                <button type="button" aria-expanded={showSql} onClick={() => setShowSql((value) => !value)}>{showSql ? "Hide queries" : "Preview queries"}</button>
              </div>
              <div className="sql-evidence-target">
                <span>Selected scope</span>
                <code>{scenarioMeta.productId || "select product"} · {scenarioMeta.release || "select release"} · {[...ptfs, ...groups].join(", ") || "select fix row"}</code>
              </div>
              {showSql && (
                <div className="sql-evidence-body">
                  <div className="sql-evidence-grid">
                    <article>
                      <p>Group PTF evidence</p>
                      <pre><code>{groupSql}</code></pre>
                    </article>
                    <article>
                      <p>Individual PTF evidence</p>
                      <pre><code>{ptfSql}</code></pre>
                    </article>
                  </div>
                  <p className="sql-evidence-note">Focused queries use the selected bulletin remedy. Run in ACS or an approved Db2 for i client; retain timestamp and partition identity.</p>
                  <a href="https://www.ibm.com/docs/en/i/7.4.0?topic=services-group-ptf-info-view" target="_blank" rel="noreferrer">IBM GROUP_PTF_INFO reference ↗</a>
                  <a href="https://www.ibm.com/docs/en/i/7.4.0?topic=services-ptf-info-view" target="_blank" rel="noreferrer">IBM PTF_INFO reference ↗</a>
                </div>
              )}
            </section>
          )}
        </>
      ) : (
        <div className="verification-assist-wrap">
          <RemediationAssist finding={finding} />
        </div>
      )}
      </div>
      <details className="legacy-verification" open={fullscreen || showLegacy} onToggle={(event) => setShowLegacy(event.currentTarget.open)}>
        <summary>Legacy collection method · DSPPTF / WRKPTFGRP</summary>
        <p>Use this route only when SQL collection is unavailable. The deterministic screen demonstrates command navigation; it does not connect to a partition or prove local status.</p>
        <PtfCommandCoach finding={finding} evidenceOverride={scenarioMeta} />
        {hasPtfPath && hasGroupPath && (
          <div className="verification-scenario-tabs" aria-label="PTF display">
            <button type="button" aria-pressed={terminalScenario === "dspptf-status"} onClick={() => setTerminalScenario("dspptf-status")}>Individual PTF</button>
            <button type="button" aria-pressed={terminalScenario === "wrkptfgrp"} onClick={() => setTerminalScenario("wrkptfgrp")}>PTF groups</button>
          </div>
        )}
        {hasTerminalPath && <button type="button" className="verification-source-button" aria-pressed={fullscreen} onClick={() => setFullscreen((value) => !value)}>
          {fullscreen ? "Exit full screen" : "Open terminal full screen"}
        </button>}
        {terminalFrame || <p className="callout-muted">No source-associated PTF or Group PTF is available for a legacy scenario.</p>}
      </details>
    </section>
  );
}
