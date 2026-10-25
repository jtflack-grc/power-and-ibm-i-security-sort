import type { Finding } from "./types";

export function cvssValue(finding: Pick<Finding, "cvss_score">): number | null {
  const score = finding.cvss_score;
  return typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10 ? score : null;
}

