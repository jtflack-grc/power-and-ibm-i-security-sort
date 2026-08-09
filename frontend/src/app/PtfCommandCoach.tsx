import { useMemo } from "react";
import type { Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";

interface Props {
  finding: Finding | null;
}

export function PtfCommandCoach({ finding }: Props) {
  const evidence = useMemo(() => extractPtfEvidence(finding), [finding]);
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
      <div className="command-coach-steps">
        <article className="command-coach-step is-primary">
          <span className="command-coach-number">01 · Locate</span>
          <code>{displayCommand}</code>
          <p>
            {ptf
              ? "Confirm product, release, PTF status, and IPL action."
              : group
                ? "Confirm group level, target release, and installed status."
                : apar
                  ? "Carry the exact APAR into IBM Support and resolve its iFix or fix-pack target."
                  : "List unapplied PTFs while the exact bulletin package is being resolved."}
          </p>
        </article>
        <article className="command-coach-step">
          <span className="command-coach-number">02 · Inspect</span>
          <code>{ptf ? "5=Display PTF details" : "Match product · release · installed level"}</code>
          <p>{ptf ? "Read general information and cover-letter instructions; detail navigation remains source-gated below." : "Do not treat a CVE, APAR, group, and downloadable fix as interchangeable identifiers."}</p>
        </article>
        <article className="command-coach-step">
          <span className="command-coach-number">03 · Widen</span>
          <code>{group ? "5=Display PTF group" : "WRKPTFGRP PTFGRP(*ALL)"}</code>
          <p>{group ? "Use option 5 on the selected group; its full screen remains source-gated." : "Check group context. One applied fix does not establish group currency."}</p>
        </article>
      </div>
    </section>
  );
}
