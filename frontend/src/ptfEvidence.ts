import type { Finding } from "./types";

// Individual IBM i PTF identifiers accepted by DSPPTF. SF identifiers are PTF
// groups and intentionally stay out of the individual-PTF terminal scenario.
const INDIVIDUAL_PTF_RE = /\b(?:SI|SJ|MF|MJ|UJ|UI|SE|UA|UB|UC)\d{4,7}\b/gi;
const TRUSTED_FIX_KINDS = new Set(["ptf", "summary", "snippet", "bulletin"]);

export interface PtfEvidence {
  ptfs: string[];
  groups: string[];
  apars: string[];
  summaries: string[];
  productId: string;
  release: string;
}

export function extractPtfEvidence(finding: Finding | null): PtfEvidence {
  const trustedText = (finding?.resolution_steps ?? [])
    .filter((step) => TRUSTED_FIX_KINDS.has(String(step.kind ?? "").toLowerCase()))
    .map((step) => `${step.title} ${step.detail}`)
    .join(" ");
  const ptfs = [...new Set((trustedText.match(INDIVIDUAL_PTF_RE) ?? []).map((v) => v.toUpperCase()))];
  const groups = [...new Set((trustedText.match(/\bSF\d{5}\b/gi) ?? []).map((v) => v.toUpperCase()))];
  const apars = [...new Set(
    (finding?.resolution_steps ?? [])
      .filter((step) => String(step.kind ?? "").toLowerCase() === "apar")
      .flatMap((step) => `${step.title} ${step.detail}`.match(/\b[A-Z]{2}\d{5,7}\b/g) ?? [])
      .map((value) => value.toUpperCase())
  )];
  const summaries = (finding?.resolution_steps ?? [])
    .filter((step) => String(step.kind ?? "").toLowerCase() === "summary")
    .map((step) => step.detail.trim())
    .filter(Boolean);
  const productMatch = trustedText.match(/\b(\d{4})-?([A-Z0-9]{3})\b/i);
  const productId = productMatch ? `${productMatch[1]}${productMatch[2]}`.toUpperCase() : "";
  const releaseMatch = trustedText.match(/\b(?:IBM i\s+)?([1-9])\.([0-9])\b/i);
  const release = releaseMatch ? `V${releaseMatch[1]}R${releaseMatch[2]}M0` : "";
  return {
    // Bulletin tables commonly contain one row per IBM i release. Until those
    // rows are stored structurally, render only the first summary-ordered PTF
    // so one DSPPTF release header never claims cross-release identifiers.
    ptfs: ptfs.slice(0, 1),
    groups: groups.slice(0, 7),
    apars: apars.slice(0, 12),
    summaries: summaries.slice(0, 3),
    productId,
    release,
  };
}

export function hasIndividualPtfEvidence(finding: Finding): boolean {
  return extractPtfEvidence(finding).ptfs.length > 0;
}
