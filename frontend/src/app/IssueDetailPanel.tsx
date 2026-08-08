import { useEffect, useState } from "react";
import type { Finding } from "../types";
import { PLATFORM_LABELS } from "../types";
import {
  cveRecordUrl,
  nvdDetailUrl,
  normalizeIbmBulletinUrl,
} from "../links";
import { changePacketMarkdown, type ShopContext } from "../shopContext";

interface Props {
  finding: Finding | null;
  shop?: ShopContext | null;
}

type DiveTab = "fix" | "interim";

function defaultTab(finding: Finding): DiveTab {
  if (finding.action_lane === "contain") return "interim";
  return "fix";
}

export function IssueDetailPanel({ finding, shop }: Props) {
  const [tab, setTab] = useState<DiveTab>("fix");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (finding) setTab(defaultTab(finding));
    setCopied(false);
  }, [finding?.cve_id]);

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

  const downloadPacket = () => {
    const md = changePacketMarkdown(finding, shop);
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${finding.cve_id}-change-packet.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyPacket = async () => {
    const md = changePacketMarkdown(finding, shop);
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      downloadPacket();
    }
  };

  const ibmUrl = normalizeIbmBulletinUrl(finding.ibm_bulletin_url, finding.cve_id);

  return (
    <div className="issue-panel">
      <div className="issue-hero">
        <div className="finding-top">
          <span className="cve-id">{finding.cve_id}</span>
          <span className={`badge ${finding.bucket}`}>{finding.bucket}</span>
        </div>
        <h3 className="issue-title">{finding.title}</h3>
        <p className="issue-desc">{finding.description}</p>
        <div className="badges">
          {finding.on_kev && <span className="badge kev">KEV</span>}
          {finding.action_lane && (
            <span className={`badge badge-lane lane-${finding.action_lane}`}>
              {finding.action_lane}
            </span>
          )}
          {finding.risk_surface && finding.risk_surface !== "platform" && (
            <span className="badge badge-supply">
              {finding.risk_surface === "mixed" ? "Mixed / TPRM" : "Supply chain"}
            </span>
          )}
          {finding.cvss_score != null && (
            <span className="badge">CVSS {finding.cvss_score}</span>
          )}
          {finding.epss != null && (
            <span className="badge">EPSS {(finding.epss * 100).toFixed(1)}%</span>
          )}
          {finding.platforms.map((p) => (
            <span key={p.platform} className="badge badge-platform">
              {PLATFORM_LABELS[p.platform]}
            </span>
          ))}
          {finding.owasp_top10.slice(0, 2).map((o) => (
            <span key={o} className="badge">
              {o.split(":")[0]}
            </span>
          ))}
        </div>
        <div className="issue-links">
          <a href={cveRecordUrl(finding.cve_id)} target="_blank" rel="noreferrer">
            CVE Record ↗
          </a>
          <a href={nvdDetailUrl(finding.cve_id)} target="_blank" rel="noreferrer" title="NVD pages often 502 — CVE Record is the durable link">
            NVD ↗
          </a>
          <a href={ibmUrl} target="_blank" rel="noreferrer">
            IBM Support ↗
          </a>
          <button type="button" className="linkish" onClick={() => void copyPacket()}>
            {copied ? "Copied" : "Copy change packet"}
          </button>
          <button type="button" className="linkish" onClick={downloadPacket}>
            Download .md
          </button>
        </div>
      </div>

      <div className="dive-tabs">
        <button
          type="button"
          className={`chip ${tab === "fix" ? "active" : ""}`}
          onClick={() => setTab("fix")}
        >
          Resolve
        </button>
        <button
          type="button"
          className={`chip ${tab === "interim" ? "active" : ""}`}
          onClick={() => setTab("interim")}
        >
          Interim
        </button>
      </div>

      {tab === "fix" && (
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

      {tab === "interim" && (
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
  );
}
