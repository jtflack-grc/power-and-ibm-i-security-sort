import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, baseVector, newAssessment, readStore, scoreScenario, storeKey } from "../src/contextAssessment.ts";
import type { Finding } from "../src/types.ts";

const finding = { cve_id: "CVE-TEST-0001", cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", on_kev: false } as Finding;
const now = Date.parse("2026-10-25T16:00:00Z");
function fixture(f = finding) {
  const a = newAssessment(f, "live");
  Object.assign(a, { asset: "PARTITION-A", release: "7.5", component: "Scoped component", threat: "Network actor against affected service", assessor: "Test assessor", assessedAt: "2026-10-25", validUntil: "2026-11-01" });
  for (const d of Object.values(a.evidence)) Object.assign(d, { state: "verified", note: "Scoped source and test result", observedAt: "2026-10-24" });
  a.evidence.applicability.value = "confirmed";
  a.evidence.remedy.value = "vulnerable";
  a.evidence.reachability.value = "reachable";
  a.evidence.authority.value = "restricted";
  a.evidence.integrity.value = "effective";
  a.evidence.network.value = "enforcing";
  a.evidence.business.value = "documented";
  Object.assign(a.scenarios[0].evidence, { state: "observed", note: "Current deployment, unmodified intrinsic metrics", observedAt: "2026-10-24" });
  return a;
}
test("standard known vectors and a local-attack Environmental adjustment", () => {
  assert.equal(scoreScenario(finding.cvss_vector!, {}).score, 9.8);
  assert.equal(scoreScenario(finding.cvss_vector!, { MAV: "L" }).score, 8.4);
  assert.equal(scoreScenario(finding.cvss_vector!.replace("3.1", "3.0"), { MAV: "L" }).score, 8.4);
  assert.equal(scoreScenario("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", {}).score, 5.4);
  assert.equal(scoreScenario("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", {}).score, 7.2);
  assert.equal(scoreScenario("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", {}).score, 10);
});
test("v4 uses its own calculator and preserves valid zero", () => {
  const zero = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N";
  assert.equal(scoreScenario(zero, {}).score, 0);
  const high = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
  assert.equal(scoreScenario(high, {}).score, 10);
  assert.equal(scoreScenario(high, { MSA: "S" }).version, "4.0");
});
test("malformed, missing, duplicate, unsupported and cross-version metrics fail closed", () => {
  for (const vector of ["", "9.8", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N", finding.cvss_vector + "/AV:L", finding.cvss_vector!.replace("AV:N", "AV:Z")]) assert.throws(() => baseVector(vector));
  assert.throws(() => scoreScenario(finding.cvss_vector!, { MAT: "P" }));
  assert.throws(() => scoreScenario(finding.cvss_vector!, { MAV: "Z" }));
});
test("range spans only documented supported scenarios; source stays immutable", () => {
  const a = fixture();
  a.scenarios[1].metrics = { MAV: "L" };
  a.scenarios[1].evidence = { ...a.scenarios[0].evidence, note: "Alternate validated local-only execution path" };
  const result = assess(a, finding, now);
  assert.deepEqual(result.range, { low: 8.4, high: 9.8, version: "3.1" });
  assert.equal(finding.cvss_score, 9.8);
  assert.equal(result.scores.length, 2);
});
test("unknown and attested controls cannot support a lower endpoint", () => {
  for (const state of ["unknown", "attested", "observed"] as const) {
    const a = fixture();
    a.evidence.reachability.state = state;
    a.scenarios[0].metrics = { MAV: "L" };
    assert.equal(assess(a, finding, now).range, null);
  }
});
test("missing scope, stale or future dates, changed sources and conflicts block numerical credit", () => {
  const mutations = [
    (a: ReturnType<typeof fixture>) => { a.asset = ""; },
    (a: ReturnType<typeof fixture>) => { a.validUntil = "2026-10-24"; },
    (a: ReturnType<typeof fixture>) => { a.assessedAt = "2026-10-26"; },
    (a: ReturnType<typeof fixture>) => { a.evidence.remedy.observedAt = "2026-10-26"; },
    (a: ReturnType<typeof fixture>) => { a.sourceVector = "stale"; },
    (a: ReturnType<typeof fixture>) => { a.evidence.authority.state = "conflicting"; },
    (a: ReturnType<typeof fixture>) => { a.scenarios[1].evidence.state = "conflicting"; },
  ];
  for (const mutate of mutations) { const a = fixture(); mutate(a); assert.equal(assess(a, finding, now).range, null); }
  assert.equal(assess(fixture(), { ...finding, last_modified: "2026-10-25" }, now).range, null);
});
test("no evidence and missing vector never fabricate a range", () => {
  assert.equal(assess(newAssessment(finding, "live"), finding, now).range, null);
  const noVector = { ...finding, cvss_vector: null };
  assert.equal(assess(fixture(noVector), noVector, now).range, null);
});
test("remediation gates need verified evidence; loaded/pending remains actionable", () => {
  const a = fixture();
  a.evidence.remedy.value = "pending";
  assert.equal(assess(a, finding, now).disposition, "Schedule remediation");
  a.evidence.remedy.value = "remediated";
  a.evidence.remedy.state = "attested";
  assert.notEqual(assess(a, finding, now).disposition, "Remediated");
  a.evidence.remedy.state = "verified";
  assert.equal(assess(a, finding, now).disposition, "Remediated");
  assert.equal(assess(a, finding, now).range, null);
  a.evidence.applicability.value = "not-applicable";
  assert.equal(assess(a, finding, now).disposition, "Not applicable");
});
test("KEV survives low EPSS and unknown controls; local incident outranks terminal gates", () => {
  const f = { ...finding, on_kev: true, epss: 0.0001 };
  assert.equal(assess(newAssessment(f, "live"), f, now).disposition, "Expedite validation");
  const a = fixture(f);
  assert.equal(assess(a, f, now).disposition, "Expedite remediation");
  a.evidence.exploitation.value = "observed";
  a.evidence.remedy.value = "remediated";
  assert.equal(assess(a, f, now).disposition, "Incident response");
});
test("detection requires evidence AND measurements for visibility, monitoring, recognition", () => {
  const a = fixture();
  for (const i of [2, 3, 4]) { a.controls[i].measure = "8/10 scoped test events"; a.controls[i].evidence = { ...a.evidence.business }; }
  assert.equal(assess(a, finding, now).detectionComplete, true);
  a.controls[3].evidence.state = "unknown";
  assert.equal(assess(a, finding, now).detectionComplete, false);
  assert.equal(assess(a, finding, now).range?.high, 9.8);
});
test("local persistence validates shape and separates live from sample", () => {
  const a = fixture();
  const key = storeKey("live", finding.cve_id);
  assert.equal(readStore(JSON.stringify({ [key]: [a] }))[key].length, 1);
  assert.deepEqual(readStore("invalid"), {});
  assert.deepEqual(readStore("null"), {});
  assert.deepEqual(readStore(JSON.stringify({ [key]: [{ ...a, controls: [] }] }))[key], []);
  assert.deepEqual(readStore(JSON.stringify({ [storeKey("sample", finding.cve_id)]: [a] }))[storeKey("sample", finding.cve_id)], []);
});
