import { test } from "node:test";
import assert from "node:assert/strict";
import { fixSummary } from "../src/fixSummary";
import type { Finding, Bulletin } from "../src/types";

test("bulletin or APAR links alone do not claim a fix package", () => {
  assert.equal(fixSummary({ resolution_steps: [{ kind: "apar", title: "APAR", detail: "SE123456" }, { kind: "bulletin", title: "IBM", detail: "Review bulletin" }] } as Finding).available, false);
});
test("structured group fixes expose bulletin scope without claiming installation", () => {
  const result = fixSummary({} as Finding, { applicability: [{ group_ptfs: ["SF99999"], individual_ptfs: [], release: "7.5" }] } as unknown as Bulletin);
  assert.equal(result.available, true);
  assert.match(result.scope, /7.5/);
  assert.match(result.detail, /unverified/);
});
