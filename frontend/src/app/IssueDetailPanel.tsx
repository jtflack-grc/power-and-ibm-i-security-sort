import { useEffect, useState } from "react";
import type { Bulletin, Finding } from "../types";
import { PLATFORM_LABELS } from "../types";
import {
  cveRecordUrl,
  nvdDetailUrl,
  normalizeIbmBulletinUrl,
} from "../links";
import { changePacketMarkdown, type ShopContext } from "../shopContext";
import { loadCaseWorkflow, saveCaseWorkflow, type CaseWorkflow } from "../caseWorkflow";
import { CaseWorkflowPanel } from "./CaseWorkflowPanel";

interface Props {
  finding: Finding | null;
  shop?: ShopContext | null;
  bulletin?: Bulletin | null;
  generatedAt?: string | null;
}

type IssueSection = "act" | "resolve" | "interim";

function cleanSentence(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  const text = value.replace(/https?:\/\/\S+/g, "").replace(/\s+/g, " ").trim();
  return text.length > 220 ? `${text.slice(0, 217).trim()}…` : text;
}

export function IssueDetailPanel({ finding, shop, bulletin, generatedAt }: Props) {
  const [openSections, setOpenSections] = useState<Set<IssueSection>>(() => new Set());
  const [copied, setCopied] = useState(false);
  const [workflow, setWorkflow] = useState<CaseWorkflow>(() => finding ? loadCaseWorkflow(finding.cve_id) : loadCaseWorkflow("none"));

  useEffect(() => {
    if (finding) {
      setOpenSections(new Set());
      setWorkflow(loadCaseWorkflow(finding.cve_id));
    }
    setCopied(false);
  }, [finding]);

  if (!finding) {
    return (
      <div className="empty-state">
        Select a finding. Resolve is the package path; Interim is what to do before the PTF
        lands.
      </div>
    );
  }

  const steps = finding.resolution_steps ?? [];
  const interims = finding.interim_mitigations ?? [];
  const hasPackage = steps.some((s) =>
    ["ptf", "apar", "bulletin"].includes(String(s.kind ?? ""))
  );
  const resolveSummary = cleanSentence(
    steps.find((step) => ["ptf", "ptf_group", "apar", "bulletin"].includes(String(step.kind)))?.detail,
    "Confirm your product and release in IBM's bulletin, then identify the matching fix package."
  );
  const interimSummary = cleanSentence(
    interims[0]?.detail,
    "If the fix cannot be applied yet, reduce exposure and monitor the affected service until the change is complete."
  );
  const actSummary = finding.on_kev
    ? "Confirm whether the affected component is exposed and open an expedited change: exploitation is documented in CISA KEV."
    : finding.action_lane === "contain"
      ? "Validate exposure now, reduce the reachable attack surface, and hold the item open until the permanent fix is verified."
      : "Confirm the affected product and release, assign an owner, and route the matching IBM fix through change control.";
  const standardCues = [
    ...(finding.owasp_top10 ?? []).map((category) => ({
      label: "OWASP",
      text: `${category}: use the mapped weakness to focus code, configuration, access-control, or dependency review.`,
      url: "https://owasp.org/Top10/",
    })),
    {
      label: "NIST CSF 2.0",
      text: "RS.MI / PR.PS: contain exposure where necessary, remediate through controlled platform maintenance, and retain verification evidence.",
      url: "https://www.nist.gov/cyberframework",
    },
  ];

  const downloadPacket = () => {
    const md = changePacketMarkdown(finding, shop, { bulletin, generatedAt, workflow });
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${finding.cve_id}-change-packet.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyPacket = async () => {
    const md = changePacketMarkdown(finding, shop, { bulletin, generatedAt, workflow });
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      downloadPacket();
    }
  };

  const ibmUrl = normalizeIbmBulletinUrl(finding.ibm_bulletin_url, finding.cve_id);
  const toggle = (section: IssueSection) => {
    setOpenSections((current) => {
      const next = new Set(current);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  return (
    <div className="issue-panel">
      <div className="issue-hero">
        <div className="finding-top">
          <span className="cve-id">{finding.cve_id}</span>
          <span className={`badge ${finding.bucket}`}>{finding.bucket}</span>
        </div>
      </div>

      <div className="issue-brief">
        <p className="issue-plain-title">{finding.title}</p>
        <div className="badges">
          {finding.on_kev && <span className="badge kev">KEV</span>}
          {finding.action_lane && <span className={`badge badge-lane lane-${finding.action_lane}`}>{finding.action_lane}</span>}
          {finding.cvss_score != null && <span className="badge">CVSS {finding.cvss_score}</span>}
          {finding.epss != null && <span className="badge">EPSS {(finding.epss * 100).toFixed(1)}%</span>}
          {finding.platforms.map((p) => <span key={p.platform} className="badge badge-platform">{PLATFORM_LABELS[p.platform]}</span>)}
        </div>
      </div>

      <div className="issue-accordions">
        <button type="button" className="issue-accordion-toggle" aria-expanded={openSections.has("act")} onClick={() => toggle("act")}>
          <span>Act</span><strong>{actSummary}</strong>
        </button>
        {openSections.has("act") && <div className="issue-accordion-body">
          <p className="dive-lead">Establish applicability, exposure, ownership, urgency, and the evidence required to close the decision.</p>
          <div className="issue-links">
            <a href={cveRecordUrl(finding.cve_id)} target="_blank" rel="noreferrer">CVE Record ↗</a>
            <a href={nvdDetailUrl(finding.cve_id)} target="_blank" rel="noreferrer">NVD ↗</a>
            <a href={ibmUrl} target="_blank" rel="noreferrer">IBM Support ↗</a>
            <button type="button" className="linkish" onClick={() => void copyPacket()}>{copied ? "Copied" : "Copy packet"}</button>
            <button type="button" className="linkish" onClick={downloadPacket}>Download .md</button>
          </div>
          <CaseWorkflowPanel value={workflow} onChange={(next) => { setWorkflow(next); saveCaseWorkflow(finding.cve_id, next); }} />
          <div className="issue-guidance-grid">
            {standardCues.map((cue, index) => <article key={`${cue.label}-${index}`}><span>{cue.label}</span><p>{cue.text}</p><a href={cue.url} target="_blank" rel="noreferrer">Reference ↗</a></article>)}
          </div>
        </div>}

        <button type="button" className="issue-accordion-toggle" aria-expanded={openSections.has("resolve")} onClick={() => toggle("resolve")}>
          <span>Resolve</span><strong>{resolveSummary}</strong>
        </button>
      {openSections.has("resolve") && (
        <div className="dive-list">
          <p className="dive-lead">
            {hasPackage
              ? "Bulletin, PTF/APAR ids, then verify on the box."
              : "No packaged id extracted yet. Search Fix Central; keep interim controls until a bulletin package is confirmed."}
          </p>
          {steps.map((s, i) => (
            <div key={`${s.title}-${i}`} className={`dive-card kind-${s.kind ?? "unknown"}`}>
              <strong>{s.title}</strong>
              <p>{s.detail}</p>
              {s.url && (
                <a
                  href={
                    String(s.url).includes("ibm.com")
                      ? normalizeIbmBulletinUrl(s.url, finding.cve_id)
                      : s.url.includes("nvd.nist.gov")
                        ? nvdDetailUrl(finding.cve_id)
                        : s.url
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  Open ↗
                </a>
              )}
            </div>
          ))}
        </div>
      )}

        <button type="button" className="issue-accordion-toggle" aria-expanded={openSections.has("interim")} onClick={() => toggle("interim")}>
          <span>Interim</span><strong>{interimSummary}</strong>
        </button>
      {openSections.has("interim") && (
        <div className="dive-list">
          <p className="dive-lead">
            Authority, exposure, TLS, and verify steps that buy time without closing the CVE.
          </p>
          {interims.length === 0 && (
            <div className="empty-state">No interim guidance for this item.</div>
          )}
          {interims.map((s, i) => (
            <div key={`${s.title}-${i}`} className={`dive-card kind-${s.kind ?? "interim"}`}>
              <strong>{s.title}</strong>
              <p>{s.detail}</p>
            </div>
          ))}
        </div>
      )}
      </div>
    </div>
  );
}
