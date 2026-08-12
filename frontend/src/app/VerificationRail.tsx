import { useEffect, useMemo, useRef, useState } from "react";
import type { Bulletin, Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";
import { RemediationAssist } from "./RemediationAssist";
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
  const [showSql, setShowSql] = useState(true);
  const [copiedSql, setCopiedSql] = useState<"group" | "ptf" | null>(null);
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
    setShowSql(true);
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

  const copySql = async (kind: "group" | "ptf") => {
    await navigator.clipboard.writeText(kind === "group" ? groupSql : ptfSql);
    setCopiedSql(kind);
    window.setTimeout(() => setCopiedSql((current) => current === kind ? null : current), 1400);
  };

  return (
    <section className={`verification-rail ${fullscreen ? "verification-fullscreen" : ""}`} aria-labelledby="verification-title">
      <div className="verification-head verification-head-compact">
        <div>
          <p className="verification-kicker">Evidence engineering</p>
          <h3 id="verification-title">Collect SQL, then verify on IBM i</h3>
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
          <span>Individual-PTF option 5 opens a bounded General Information fixture; group details and alternate pages remain gated.</span>
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
      <PtfCommandCoach finding={finding} evidenceOverride={scenarioMeta} />
      {hasTerminalPath ? (
        <>
          {hasPtfPath && hasGroupPath && (
            <div className="verification-scenario-tabs" aria-label="PTF display">
              <button type="button" aria-pressed={terminalScenario === "dspptf-status"} onClick={() => setTerminalScenario("dspptf-status")}>Individual PTF</button>
              <button type="button" aria-pressed={terminalScenario === "wrkptfgrp"} onClick={() => setTerminalScenario("wrkptfgrp")}>PTF groups</button>
            </div>
          )}
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
                  <p className="sql-evidence-note">Run in ACS or an approved Db2 for i client; retain timestamp and partition identity.</p>
                  <a href="https://www.ibm.com/docs/en/i/7.4.0?topic=services-group-ptf-info-view" target="_blank" rel="noreferrer">IBM GROUP_PTF_INFO reference ↗</a>
                  <a href="https://www.ibm.com/docs/en/i/7.4.0?topic=services-ptf-info-view" target="_blank" rel="noreferrer">IBM PTF_INFO reference ↗</a>
                </div>
              )}
            </section>
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
        </>
      ) : (
        <div className="verification-frame-wrap verification-assist-wrap">
          <RemediationAssist finding={finding} />
        </div>
      )}
    </section>
  );
}
