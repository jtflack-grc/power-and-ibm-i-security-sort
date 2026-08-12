import { useMemo } from "react";
import type { Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";

interface Props {
  finding: Finding | null;
  evidenceOverride?: ReturnType<typeof extractPtfEvidence>;
}

export function PtfCommandCoach({ finding, evidenceOverride }: Props) {
  const extracted = useMemo(() => extractPtfEvidence(finding), [finding]);
  const evidence = evidenceOverride ?? extracted;
  const ptf = evidence.ptfs[0] ?? null;
  const group = evidence.groups[0] ?? null;
  const apar = evidence.apars[0] ?? null;
  const product = evidence.productId;
  const displayCommand = ptf
    ? `DSPPTF LICPGM(${product}) SELECT(${ptf})`
    : group
      ? `WRKPTFGRP PTFGRP(${group})`
      : apar
        ? apar
        : `DSPPTF LICPGM(${product}) SELECT(*NOTAPY)`;
  const route = ptf ? "individual PTF" : group ? "group PTF" : apar ? "APAR / iFix" : "fix research";

  return (
    <section className="command-coach" aria-labelledby="command-coach-title">
      <div className="command-coach-intro">
        <div>
          <p className="command-coach-kicker">LCL command coach</p>
          <h3 id="command-coach-title">From finding to partition evidence</h3>
        </div>
        <p>
          {finding ? `${finding.cve_id}: ${route} route.` : "Select a finding to hydrate its evidence route."}
        </p>
      </div>
      <p className="command-coach-help">
        Start by choosing the IBM i release and product from the fix-row selector below. Run the shown command on that partition, compare the installed state with IBM&apos;s bulletin, and retain the result with the partition name and collection time.
      </p>
      <div className="command-coach-steps">
        <article className="command-coach-step is-primary">
          <span className="command-coach-number">01 · Locate</span>
          <code>{displayCommand}</code>
          <p>
            {ptf
              ? "Run this on the selected partition. Confirm the licensed product and release match the bulletin, then note whether the PTF is loaded, applied, superseded, or waiting for an IPL."
              : group
                ? "Run this on the selected partition. Confirm the group identifier, installed level, target release, and whether the group is current or has an action pending."
                : apar
                  ? "Use the exact APAR in IBM Support to identify the downloadable iFix or fix pack for your installed product level."
                  : "Use this as a starting inventory only. The exact bulletin package still needs to be resolved before you can claim remediation."}
          </p>
        </article>
        <article className="command-coach-step">
          <span className="command-coach-number">02 · Inspect</span>
          <code>{ptf ? `Enter 5 beside ${ptf}, then press Enter` : group ? `Enter 5 beside ${group}, then press Enter` : "Match product · release · installed level"}</code>
          <p>{ptf ? "Use option 5 to inspect status details and cover-letter instructions. Record any prerequisites, delayed apply, or IPL requirement before scheduling the change." : "Match the installed product and release exactly. A CVE, APAR, PTF group, and downloadable fix identify different parts of the remediation chain."}</p>
        </article>
        <article className="command-coach-step">
          <span className="command-coach-number">03 · Widen</span>
          <code>{group ? `WRKPTFGRP PTFGRP(${group})` : "WRKPTFGRP PTFGRP(*ALL)"}</code>
          <p>{group ? "Review the selected group and its level. A group can contain the required fix even when the individual PTF is superseded." : "Review all installed PTF groups for the release. One applied PTF does not prove that the cumulative, HIPER, or product group is current."}</p>
        </article>
      </div>
    </section>
  );
}
