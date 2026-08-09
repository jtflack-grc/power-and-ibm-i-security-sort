import type { Bulletin } from "./types";

export type InventoryStatus = "loaded" | "temporarily_applied" | "permanently_applied" | "superseded" | "not_applied" | "unknown";

export interface InventoryRecord {
  kind: "ptf" | "group";
  id: string;
  status: InventoryStatus;
  level?: number;
}

export interface ParsedInventory {
  records: InventoryRecord[];
  rejectedLines: number;
  truncated: boolean;
}

export interface RemedyComparison {
  kind: "ptf" | "group";
  id: string;
  expectedLevel?: number;
  observed?: InventoryRecord;
}

export const MAX_INVENTORY_BYTES = 200_000;
const MAX_LINES = 5_000;
const STORAGE_KEY = "ibmi-curator-inventory-v1";
const PTF_RE = /\b(?:SI|SJ|MF|MJ|UJ|UI|SE|UA|UB|UC)\d{4,7}\b/i;
const GROUP_RE = /\bSF\d{5}\b/i;

function statusFrom(line: string): InventoryStatus {
  const value = line.toUpperCase().replace(/[_-]+/g, " ");
  if (/PERMANENT(?:LY)?\s+APPLIED|PERM\s+APPLIED/.test(value)) return "permanently_applied";
  if (/TEMPORAR(?:Y|ILY)\s+APPLIED|TEMP\s+APPLIED/.test(value)) return "temporarily_applied";
  if (/SUPERSEDED/.test(value)) return "superseded";
  if (/NOT\s+APPLIED|NOT\s+INSTALLED/.test(value)) return "not_applied";
  if (/LOADED|INSTALLED/.test(value)) return "loaded";
  return "unknown";
}

export function parseInventory(raw: string): ParsedInventory {
  const bounded = [...raw.slice(0, MAX_INVENTORY_BYTES)].filter((char) => char.charCodeAt(0) !== 0).join("");
  const allLines = bounded.split(/\r?\n/);
  const lines = allLines.slice(0, MAX_LINES);
  const records = new Map<string, InventoryRecord>();
  let rejectedLines = 0;
  for (const rawLine of lines) {
    const line = [...rawLine].map((char) => {
      const code = char.charCodeAt(0);
      return (code > 0 && code < 32) || code === 127 ? " " : char;
    }).join("").trim().slice(0, 2_000);
    if (!line) continue;
    const ptf = line.match(PTF_RE)?.[0]?.toUpperCase();
    const group = line.match(GROUP_RE)?.[0]?.toUpperCase();
    const id = ptf || group;
    if (!id) {
      rejectedLines += 1;
      continue;
    }
    const levelMatch = group ? line.match(/(?:LEVEL|LVL|,|\s)(\d{1,4})(?:\D|$)/i) : null;
    const record: InventoryRecord = {
      kind: ptf ? "ptf" : "group",
      id,
      status: statusFrom(line),
      ...(levelMatch ? { level: Number(levelMatch[1]) } : {}),
    };
    const key = `${record.kind}:${record.id}`;
    const existing = records.get(key);
    if (!existing || existing.status === "unknown") records.set(key, record);
  }
  return {
    records: [...records.values()],
    rejectedLines,
    truncated: raw.length > MAX_INVENTORY_BYTES || allLines.length > MAX_LINES,
  };
}

export function loadInventory(): ParsedInventory {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return { records: [], rejectedLines: 0, truncated: false };
    const parsed = JSON.parse(raw) as ParsedInventory;
    return { records: Array.isArray(parsed.records) ? parsed.records.slice(0, MAX_LINES) : [], rejectedLines: Number(parsed.rejectedLines) || 0, truncated: Boolean(parsed.truncated) };
  } catch {
    return { records: [], rejectedLines: 0, truncated: false };
  }
}

export function saveInventory(value: ParsedInventory): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(value));
}

export function clearInventory(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}

export function compareInventory(bulletin: Bulletin | null | undefined, inventory: ParsedInventory): RemedyComparison[] {
  if (!bulletin) return [];
  const expected = new Map<string, RemedyComparison>();
  for (const row of bulletin.applicability) {
    for (const id of row.individual_ptfs) expected.set(`ptf:${id}`, { kind: "ptf", id });
    for (const id of row.group_ptfs) {
      const cleanId = id.match(GROUP_RE)?.[0]?.toUpperCase() || id;
      const level = row.group_ptf_levels?.[cleanId];
      expected.set(`group:${cleanId}`, { kind: "group", id: cleanId, ...(level != null ? { expectedLevel: level } : {}) });
    }
  }
  const index = new Map(inventory.records.map((item) => [`${item.kind}:${item.id}`, item]));
  return [...expected.values()].map((item) => ({ ...item, observed: index.get(`${item.kind}:${item.id}`) }));
}
