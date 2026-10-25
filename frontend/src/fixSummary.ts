import type { Bulletin, Finding } from "./types";
import { extractPtfEvidence } from "./ptfEvidence";

export function fixSummary(finding: Finding, bulletin?: Bulletin | null) {
  const rows = bulletin?.applicability ?? [];
  const evidence = extractPtfEvidence(finding);
  const packages = [...new Set(rows.flatMap(row => [...row.individual_ptfs, ...row.group_ptfs]))];
  const available = packages.length > 0 || evidence.ptfs.length > 0 || evidence.groups.length > 0;
  const releases = [...new Set(rows.map(row => row.release || row.release_system).filter(Boolean))];
  return {
    available,
    label: available ? "IBM fix available" : "Fix package needs review",
    scope: releases.length ? `Bulletin releases: ${releases.join(", ")}` : "Affected releases: confirm in IBM bulletin",
    detail: available ? "Match the package to your product and release; installation is unverified." : "An APAR or bulletin link alone does not establish an available fix package.",
  };
}
