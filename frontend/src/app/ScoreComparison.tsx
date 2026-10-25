import { memo } from "react";
import type { Finding } from "../types";
import { estimateOsint } from "../osintAssessment";
import { CvssScore } from "./CvssScore";

export const ScoreComparison = memo(function ScoreComparison({ finding }: { finding: Finding }) {
  const estimate = estimateOsint(finding);
  return <span className="score-comparison" aria-label="Published CVSS and estimated IBM i range">
    <CvssScore finding={finding} />
    <span className="osint-score">
      <span className="cvss-label">IBM i OSINT</span>
      <strong>{estimate.low.toFixed(1)}–{estimate.high.toFixed(1)}<small> / 10</small></strong>
      <span>Estimated range</span>
    </span>
  </span>;
});
