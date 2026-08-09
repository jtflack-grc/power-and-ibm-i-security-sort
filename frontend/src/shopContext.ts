/**
 * Shop context — optional, session-only, never uploaded.
 * Answers live in sessionStorage and only re-weight the local result.
 */
import type { Bulletin, Finding, TriageMetrics, TriageResult } from "./types";

export type Exposure = "internet" | "internal" | "restricted";
export type Privilege = "elevated" | "standard";
export type ChangePressure = "this_week" | "this_month" | "backlog";

export interface PasteTokens {
  /** Free-text snippet — session only, never POSTed */
  raw: string;
  ptfs: string[];
  apars: string[];
}

export interface ShopContext {
  enabled: boolean;
  exposure: Exposure;
  privilege: Privilege;
  changePressure: ChangePressure;
  personaId?: string;
  /** Optional paste (PSP / DSPPTF excerpt). Session-only. */
  paste?: PasteTokens | null;
  /** True after guided routing finished this session */
  routed?: boolean;
}

export interface ShopPersona {
  id: string;
  label: string;
  blurb: string;
  context: Omit<ShopContext, "enabled" | "personaId">;
}

export const DEFAULT_SHOP: ShopContext = {
  enabled: false,
  exposure: "internal",
  privilege: "standard",
  changePressure: "this_month",
  paste: null,
  routed: false,
};

const PTF_RE = /\b(?:SI|SJ|MF|MJ|UJ|UI|SE|UA|UB|UC)\d{4,7}\b/gi;
const APAR_RE = /\b(?:APAR\s+)?([A-Z]{2}\d{5,7})\b/gi;

/** Parse PSP / DSPPTF paste client-side. Never leaves the browser. */
export function parseShopPaste(raw: string): PasteTokens {
  const text = raw.trim();
  const ptfs = [...new Set((text.match(PTF_RE) ?? []).map((t) => t.toUpperCase()))];
  const apars: string[] = [];
  for (const m of text.matchAll(APAR_RE)) {
    const token = (m[1] || m[0]).toUpperCase().replace(/^APAR\s+/, "");
    // Skip false-positives that look like PTFs already captured
    if (/^(SI|SJ|MF|MJ|UJ|UI|SE|UA|UB|UC)\d/.test(token)) continue;
    if (/^[A-Z]{2}\d{5,7}$/.test(token)) apars.push(token);
  }
  return {
    raw: text,
    ptfs,
    apars: [...new Set(apars)],
  };
}

export function findingMatchesPaste(f: Finding, paste?: PasteTokens | null): boolean {
  if (!paste || (!paste.ptfs.length && !paste.apars.length)) return false;
  const blob = [
    f.cve_id,
    ...(f.resolution_steps ?? []).flatMap((s) => [s.title, s.detail, s.url ?? ""]),
    ...(f.interim_mitigations ?? []).flatMap((s) => [s.title, s.detail]),
  ]
    .join(" ")
    .toUpperCase();
  return (
    paste.ptfs.some((t) => blob.includes(t)) || paste.apars.some((t) => blob.includes(t))
  );
}

export const PERSONAS: ShopPersona[] = [
  {
    id: "ibm_i_edge",
    label: "IBM i · exposed services",
    blurb: "Prod LPAR, ODBC/SSH reachable from broader networks, privileged profiles in play.",
    context: {
      exposure: "internet",
      privilege: "elevated",
      changePressure: "this_week",
    },
  },
  {
    id: "ibm_i_internal",
    label: "IBM i · internal core",
    blurb: "Production LPARs on restricted internal networks with a standard change calendar.",
    context: {
      exposure: "internal",
      privilege: "standard",
      changePressure: "this_month",
    },
  },
  {
    id: "ibm_i_restricted",
    label: "IBM i · restricted posture",
    blurb: "Segmented LPARs where non-KEV findings can wait for a confirmed package path.",
    context: {
      exposure: "restricted",
      privilege: "standard",
      changePressure: "backlog",
    },
  },
];

const STORAGE_KEY = "psvc.shopContext.v1";

export function loadShopContext(): ShopContext {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SHOP };
    return { ...DEFAULT_SHOP, ...(JSON.parse(raw) as ShopContext) };
  } catch {
    return { ...DEFAULT_SHOP };
  }
}

export function saveShopContext(ctx: ShopContext): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(ctx));
}

export function clearShopContext(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}

function vectorMap(vector?: string | null): Record<string, string> {
  if (!vector) return {};
  const out: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (k && v && k.toUpperCase() !== "CVSS") out[k.toUpperCase()] = v.toUpperCase();
  }
  return out;
}

/**
 * Re-weights a triage result using shop answers. Pure client transform.
 * Does not call any network API.
 */
export function applyShopContext(result: TriageResult, ctx: ShopContext): TriageResult {
  if (!ctx.enabled) {
    return {
      ...result,
      findings: result.findings.map((f) => ({
        ...f,
        levers: (f.levers ?? []).filter((l) => !String(l.id).startsWith("shop_")),
      })),
    };
  }

  const findings = result.findings.map((f) => {
    const baseLevers = (f.levers ?? []).filter((l) => !String(l.id).startsWith("shop_"));
    const shopLevers: Finding["levers"] = [];
    let delta = 0;
    const metrics = vectorMap(f.cvss_vector);

    if (ctx.exposure === "internet" && metrics.AV === "N") {
      const w = 16;
      delta += w;
      shopLevers.push({
        id: "shop_exposure",
        source: "Shop context",
        direction: "up",
        weight: w,
        reason: "Shop reports broader network exposure + Network attack vector",
      });
    } else if (ctx.exposure === "restricted" && metrics.AV === "N") {
      const w = -8;
      delta += w;
      shopLevers.push({
        id: "shop_exposure_quiet",
        source: "Shop context",
        direction: "down",
        weight: w,
        reason: "Restricted exposure posture — network CVEs temper slightly",
      });
    }

    if (ctx.privilege === "elevated") {
      const authCwe = f.cwes.some((c) =>
        ["CWE-284", "CWE-862", "CWE-863", "CWE-250", "CWE-269"].includes(c.toUpperCase())
      );
      const local = metrics.AV === "L" || metrics.AV === "P";
      if (authCwe || local) {
        const w = 12;
        delta += w;
        shopLevers.push({
          id: "shop_privilege",
          source: "Shop context",
          direction: "up",
          weight: w,
          reason: "Elevated privilege surface heightens local/authority-class findings",
        });
      }
    }

    if (ctx.changePressure === "this_week" && (f.bucket === "urgent" || f.bucket === "watch")) {
      const w = 8;
      delta += w;
      shopLevers.push({
        id: "shop_pressure",
        source: "Shop context",
        direction: "up",
        weight: w,
        reason: "Change pressure this week — pull watch/urgent items forward",
      });
    } else if (ctx.changePressure === "backlog" && !f.on_kev) {
      const w = -6;
      delta += w;
      shopLevers.push({
        id: "shop_backlog",
        source: "Shop context",
        direction: "down",
        weight: w,
        reason: "Backlog posture — non-KEV items yield to higher-pressure work",
      });
    }

    const hasPackage = (f.resolution_steps ?? []).some((s) =>
      ["ptf", "apar", "bulletin"].includes(String(s.kind ?? ""))
    );

    if (findingMatchesPaste(f, ctx.paste)) {
      const w = 10;
      delta += w;
      shopLevers.push({
        id: "shop_paste_hit",
        source: "Shop paste",
        direction: "up",
        weight: w,
        reason: "PTF/APAR token from your session paste appears on this finding",
      });
    }

    const score = Math.max(0, Number((f.score + delta).toFixed(1)));
    let bucket = f.bucket;
    if (f.on_kev) bucket = "urgent";
    else if (score >= 70) bucket = "urgent";
    else if (score >= 40) bucket = "watch";
    else bucket = "low";

    let action_lane = f.action_lane ?? "monitor";
    if (hasPackage) action_lane = "apply";
    else if (f.on_kev || (f.interim_mitigations ?? []).length) {
      if (bucket !== "low") action_lane = "contain";
    } else if (bucket === "low") action_lane = "monitor";

    // Contain tilt when exposed + no package
    if (!hasPackage && ctx.exposure === "internet" && bucket !== "low") {
      action_lane = "contain";
    }

    return {
      ...f,
      score,
      bucket,
      action_lane,
      levers: [...baseLevers, ...shopLevers],
    };
  });

  findings.sort((a, b) => b.score - a.score);

  const metrics: TriageMetrics = {
    total: findings.length,
    urgent: findings.filter((f) => f.bucket === "urgent").length,
    watch: findings.filter((f) => f.bucket === "watch").length,
    low: findings.filter((f) => f.bucket === "low").length,
    kev_hits: findings.filter((f) => f.on_kev).length,
    psirt_confirmed: findings.filter((f) => f.ibm_bulletin_status === "confirmed").length,
    high_epss: findings.filter((f) => (f.epss ?? 0) >= 0.1).length,
    owasp_mapped: findings.filter((f) => f.owasp_top10.length > 0).length,
    by_platform: { ...result.metrics.by_platform },
    lever_net_contribution: { ...result.metrics.lever_net_contribution },
  };

  return {
    ...result,
    findings,
    metrics,
  };
}

export function changePacketMarkdown(
  f: Finding,
  ctx?: ShopContext | null,
  meta?: { bulletin?: Bulletin | null; generatedAt?: string | null }
): string {
  const lines: string[] = [
    `# Change packet — ${f.cve_id}`,
    "",
    `**Title:** ${f.title}`,
    `**Bucket:** ${f.bucket} · **Dock:** ${f.action_lane ?? "monitor"} · **Score:** ${f.score}`,
    `**Surface:** ${f.risk_surface ?? "platform"}`,
    "",
    "## Summary",
    f.description,
    "",
    "## Links",
    `- CVE Record: https://www.cve.org/CVERecord?id=${f.cve_id}`,
    `- NVD: https://nvd.nist.gov/vuln/detail/${f.cve_id}`,
  ];
  const ibmNode = f.ibm_bulletin_url?.match(/\/support\/pages\/node\/\d+/i)
    ? f.ibm_bulletin_url.split("?")[0]
    : null;
  lines.push(
    `- IBM Support: ${
      ibmNode ?? `https://www.ibm.com/support/pages/search?q=${encodeURIComponent(f.cve_id)}`
    }`
  );
  if (f.on_kev) lines.push("- CISA KEV: yes");
  if (meta?.generatedAt) lines.push(`- Curator snapshot: ${meta.generatedAt}`);
  if (meta?.bulletin) {
    lines.push("", "## IBM i applicability");
    for (const row of meta.bulletin.applicability) {
      lines.push(
        `- ${row.product_name}${row.product_id ? ` (${row.product_id})` : ""} · ${row.release ?? "release unresolved"}`,
        `  - Individual PTFs: ${row.individual_ptfs.join(", ") || "none source-associated"}`,
        `  - Group PTFs: ${row.group_ptfs.join(", ") || "none source-associated"}`,
        `  - APARs: ${row.apars.join(", ") || "none source-associated"}`,
        `  - Extraction confidence: ${row.confidence}`
      );
    }
  }
  lines.push("", "## Counter-levers");
  for (const l of f.levers ?? []) {
    lines.push(`- (${l.direction} ${l.weight}) **${l.source}** — ${l.reason}`);
  }
  lines.push("", "## Resolve");
  for (const s of f.resolution_steps ?? []) {
    lines.push(`- **${s.title}:** ${s.detail}${s.url ? ` (${s.url})` : ""}`);
  }
  lines.push("", "## Interim");
  for (const s of f.interim_mitigations ?? []) {
    lines.push(`- **${s.title}:** ${s.detail}`);
  }
  lines.push(
    "",
    "## Verification evidence checklist",
    "- [ ] Confirm affected product and IBM i release against the IBM bulletin.",
    "- [ ] Confirm the selected PTF/APAR or group level in Fix Central.",
    "- [ ] Capture pre-change PTF status.",
    "- [ ] Capture change record and application result.",
    "- [ ] Capture post-change DSPPTF or WRKPTFGRP status.",
    "- [ ] Record reviewer and closure decision.",
    "",
    "**Observed evidence:** none recorded by this static curator. The checklist describes expected evidence only."
  );
  if (ctx?.enabled) {
    lines.push(
      "",
      "## Shop context (browser session only — not uploaded)",
      "- Platform focus: IBM i",
      `- Exposure: ${ctx.exposure}`,
      `- Privilege: ${ctx.privilege}`,
      `- Change pressure: ${ctx.changePressure}`
    );
  }
  lines.push(
    "",
    "---",
    "_Generated by IBM i Vulnerability Curator. Confirm PTF/APAR ids on Fix Central before change._"
  );
  return lines.join("\n");
}
