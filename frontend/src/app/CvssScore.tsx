import type { Finding } from "../types";
import { cvssValue } from "../cvss";

export function CvssScore({ finding, maximum = false }: { finding: Pick<Finding, "cvss_score" | "cvss_vector">; maximum?: boolean }) {
  const score = cvssValue(finding);
  const severity = score == null ? "Unrated" : score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : score > 0 ? "Low" : "None";
  const version = finding.cvss_vector?.match(/^CVSS:(\d+\.\d+)\//)?.[1];
  return <span className={`cvss-score cvss-${severity.toLowerCase()}`}>
    <span className="cvss-label">{maximum ? "Max CVSS" : "CVSS"}{version ? ` ${version}` : ""}</span>
    <strong>{score == null ? "—" : score.toFixed(1)}<small> / 10</small></strong>
    <span>{severity}</span>
  </span>;
}
