import { test } from "node:test";
import assert from "node:assert/strict";
import { estimateOsint } from "../src/osintAssessment.ts";
import type { Finding } from "../src/types.ts";
import { readFileSync } from "node:fs";

const base = { cve_id: "CVE-TEST-1234", title: "IBM i Java application vulnerability", description: "Remote code execution in a Java application", cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwes: [], on_kev: false, ibm_bulletin_status: "confirmed", ibm_bulletin_url: "https://www.ibm.com/support/pages/node/123" } as Finding;
test("automatic assessment is populated without any partition record or form", () => {
  const result = estimateOsint(base);
  assert.ok(result.low < result.high);
  assert.equal(result.high, 9.8);
  assert.ok(result.sources.some(s => s.title.includes("Redbooks")));
  assert.ok(result.sources.some(s => s.title.includes("Java security")));
  assert.ok(result.endpoints.every(e => e.assumption.length > 20));
  assert.ok(result.controlMap.length > 0);
});
test("IBM per-CVE vector takes precedence; a higher queue score remains visible", () => {
  // IBM bulletin 7283283: source-specific Java security-boundary prerequisites.
  const f = { ...base, cvss_score: 10, ibm_cvss_score: 8.9, ibm_cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L", ibm_vulnerability_description: "IBM i could allow a remote attacker to bypass security restrictions due to improper validation of user-controlled addresses." };
  const result = estimateOsint(f);
  assert.equal(result.coverage, "IBM per-CVE vector + platform references");
  assert.equal(result.profile, "Authority-boundary exposure");
  assert.equal(result.high, 10);
  assert.ok(result.endpoints.find(e => e.name === "Bounded-impact IBM i scenario")!.vector!.includes("AC:H"));
  assert.ok(!result.endpoints[0].vector!.includes("/MC:"));
});
test("privilege and authentication defects receive no generic authority discount", () => {
  for (const f of [{ ...base, description: "Local privilege escalation via unqualified library call" }, { ...base, cwes: ["CWE-269"] }, { ...base, cwes: ["CWE-287"] }]) {
    const result = estimateOsint(f);
    assert.equal(result.profile, "Authority-boundary exposure");
    assert.ok(!result.endpoints[0].vector!.includes("/MC:"));
    assert.ok(!result.endpoints[0].vector!.includes("/MI:"));
  }
});
test("runtime lower-impact assumptions do not change attack vector or availability", () => {
  const result = estimateOsint(base);
  const lower = result.endpoints[0];
  assert.ok(lower.vector!.includes("/AV:N/"));
  assert.ok(!lower.vector!.includes("/MAV:"));
  assert.ok(!lower.vector!.includes("/MA:"));
  assert.ok(lower.assumption.includes("not an observed configuration"));
});
test("sparse sources still produce an explicit provisional envelope", () => {
  const numeric = estimateOsint({ ...base, cvss_vector: null });
  assert.equal(numeric.low, 9.8); assert.equal(numeric.high, 10);
  assert.ok(numeric.basis.includes("Provisional"));
  const category = estimateOsint({ ...base, cvss_vector: null, cvss_score: null, cvss_severity: "HIGH", cvss_source: "NVD" });
  assert.equal(category.low, 7); assert.equal(category.high, 10);
  const unknown = estimateOsint({ ...base, cvss_vector: null, cvss_score: null });
  assert.equal(unknown.low, 0); assert.equal(unknown.high, 10);
  assert.ok(unknown.coverage.includes("Limited"));
  const grouped = estimateOsint({ ...base, cvss_vector: null, cvss_score: null, cvss_severity: "HIGH" });
  assert.equal(grouped.low, 0, "An unproven grouped-bulletin category is not an individual CVE rating");
});
test("malformed vectors fall back without crashing a queue row", () => {
  const result = estimateOsint({ ...base, ibm_cvss_vector: "broken", cvss_vector: "CVSS:3.1/AV:Z" });
  assert.equal(result.low, 9.8); assert.equal(result.high, 10);
});
test("zero and CVSS v4 are handled without changing score versions", () => {
  const zero = estimateOsint({ ...base, cvss_score: 0, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" });
  assert.equal(zero.low, 0); assert.equal(zero.high, 0);
  const v4 = estimateOsint({ ...base, cvss_score: 10, cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" });
  assert.equal(v4.high, 10);
  assert.ok(v4.endpoints.filter(e => e.vector).every(e => e.vector!.startsWith("CVSS:4.0/")));
});
test("KEV keeps priority even when EPSS is low; no deployed control is invented", () => {
  const result = estimateOsint({ ...base, on_kev: true, epss: 0.0001 });
  assert.equal(result.priority, "Expedite applicability / remediation");
  assert.ok(result.controlMap.some(c => c.inference.includes("unknown")));
  assert.ok(result.unknowns.some(u => u.includes("fix state")));
});
if (process.env.OSINT_SNAPSHOT_PATH) test("every current public-feed finding gets a finite automatic estimate", () => {
  const data = JSON.parse(readFileSync(process.env.OSINT_SNAPSHOT_PATH!, "utf8"));
  assert.ok(data.findings.length > 0);
  for (const finding of data.findings as Finding[]) {
    const result = estimateOsint(finding);
    assert.ok(Number.isFinite(result.low) && Number.isFinite(result.high), finding.cve_id);
    assert.ok(result.low >= 0 && result.high <= 10 && result.low <= result.high, finding.cve_id);
    assert.ok(result.sources.length > 0 && result.endpoints.length > 0, finding.cve_id);
  }
});
