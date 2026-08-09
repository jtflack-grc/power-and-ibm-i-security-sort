import type { Finding } from "./types";

// Individual IBM i PTF identifiers accepted by DSPPTF. SF identifiers are PTF
// groups and intentionally stay out of the individual-PTF terminal scenario.
const INDIVIDUAL_PTF_RE = /\b(?:SI|SJ|MF|UJ|UI|SE|UA|UB|UC)\d{4,7}\b/gi;
const TRUSTED_FIX_KINDS = new Set(["ptf", "summary", "snippet", "bulletin"]);

export interface PtfEvidence {
  ptfs: string[];
  productId: string;
  release: string;
}

export function extractPtfEvidence(finding: Finding | null): PtfEvidence {
  const trustedText = (finding?.resolution_steps ?? [])
    .filter((step) => TRUSTED_FIX_KINDS.has(String(step.kind ?? "").toLowerCase()))
    .map((step) => `${step.title} ${step.detail}`)
    .join(" ");
  const ptfs = [...new Set((trustedText.match(INDIVIDUAL_PTF_RE) ?? []).map((v) => v.toUpperCase()))];
  const productMatch = trustedText.match(/\b(\d{4})-?([A-Z0-9]{3})\b/i);
  const productId = productMatch
    ? `${productMatch[1]}${productMatch[2]}`.toUpperCase()
    : "5770SS1";
  const releaseMatch = trustedText.match(/\b(?:IBM i\s+)?([1-9])\.([0-9])\b/i);
  const release = releaseMatch ? `V${releaseMatch[1]}R${releaseMatch[2]}M0` : "V7R4M0";
  return { ptfs: ptfs.slice(0, 7), productId, release };
}

export function hasIndividualPtfEvidence(finding: Finding): boolean {
  return extractPtfEvidence(finding).ptfs.length > 0;
}
