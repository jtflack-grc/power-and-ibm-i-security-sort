import { useState } from "react";
import type { Bulletin } from "../types";
import { clearInventory, compareInventory, loadInventory, MAX_INVENTORY_BYTES, parseInventory, saveInventory, type ParsedInventory } from "../inventory";

interface Props { bulletin?: Bulletin | null }

function statusLabel(value?: string): string {
  return value ? value.replaceAll("_", " ") : "not observed";
}

export function InventoryComparison({ bulletin }: Props) {
  const [inventory, setInventory] = useState<ParsedInventory>(() => loadInventory());
  const [raw, setRaw] = useState("");
  const [targetRelease, setTargetRelease] = useState("");
  const comparison = compareInventory(bulletin, inventory);
  const releaseRows = bulletin?.applicability.filter((row) => !targetRelease || row.release === targetRelease) ?? [];
  const releaseListed = !targetRelease || releaseRows.length > 0;

  const apply = (text: string) => {
    const parsed = parseInventory(text);
    setInventory(parsed);
    saveInventory(parsed);
  };

  return (
    <details className="inventory-comparison">
      <summary>Local PTF inventory comparison</summary>
      <p>Paste or load sanitized output from <code>QSYS2.PTF_INFO</code> or <code>QSYS2.GROUP_PTF_INFO</code>. Processing stays in this browser tab; files are never uploaded.</p>
      <label className="verification-applicability inventory-release">Partition release
        <select value={targetRelease} onChange={(event) => setTargetRelease(event.target.value)}>
          <option value="">Not selected</option>{["7.2", "7.3", "7.4", "7.5", "7.6"].map((value) => <option key={value} value={value}>IBM i {value}</option>)}
        </select>
      </label>
      {targetRelease && <p className={releaseListed ? "route-cue" : "empty-state"}>{releaseListed ? `IBM lists ${releaseRows.length} applicability row(s) for IBM i ${targetRelease}.` : `IBM i ${targetRelease} is not listed in this bulletin's parsed applicability rows. Treat applicability as unsupported or unresolved; do not infer that the partition is unaffected.`}</p>}
      <textarea aria-label="PTF inventory text" value={raw} maxLength={MAX_INVENTORY_BYTES} rows={6} placeholder="PTF_IDENTIFIER,PTF_STATUS&#10;SI12345,PERMANENTLY APPLIED&#10;SF99950,LEVEL 12,INSTALLED" onChange={(event) => setRaw(event.target.value)} />
      <div className="callout-actions">
        <button type="button" className="button" onClick={() => apply(raw)}>Parse inventory</button>
        <label className="button inventory-file">Load .csv/.txt<input type="file" accept=".csv,.txt,text/csv,text/plain" onChange={async (event) => {
          const file = event.target.files?.[0];
          if (!file || file.size > MAX_INVENTORY_BYTES) return;
          const text = await file.text();
          setRaw(text);
          apply(text);
          event.target.value = "";
        }} /></label>
        <button type="button" className="button" onClick={() => { clearInventory(); setInventory({ records: [], rejectedLines: 0, truncated: false }); setRaw(""); }}>Clear</button>
      </div>
      <p role="status">{inventory.records.length} validated inventory records · {inventory.rejectedLines} non-record lines ignored{inventory.truncated ? " · input truncated at safety limit" : ""}</p>
      {comparison.length > 0 && <div className="inventory-results">
        {comparison.map((item) => <div key={`${item.kind}-${item.id}`} className={`inventory-result ${item.observed ? "observed" : "missing"}`}>
          <strong>{item.id}</strong><span>{item.kind === "group" ? `Group PTF${item.expectedLevel != null ? ` · expected level ${item.expectedLevel}` : ""}` : "Individual PTF"}</span><span>{statusLabel(item.observed?.status)}{item.observed?.level != null ? ` · observed level ${item.observed.level}` : ""}{item.expectedLevel != null && item.observed?.level != null ? item.observed.level >= item.expectedLevel ? " · meets/exceeds expected" : " · below expected" : ""}</span>
        </div>)}
      </div>}
      {bulletin && comparison.length === 0 && <p>No source-associated PTF identifiers are available for comparison in this bulletin.</p>}
      <p className="callout-muted">An observed token is evidence supplied by the user, not proof that the remedy applies to this release or that application completed successfully.</p>
    </details>
  );
}
