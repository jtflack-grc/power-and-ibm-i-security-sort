import { useMemo } from "react";
import type { Finding } from "../types";
import { extractPtfEvidence } from "../ptfEvidence";

interface Props {
  finding: Finding | null;
}

export function PtfCommandCoach({ finding }: Props) {
  const evidence = useMemo(() => extractPtfEvidence(finding), [finding]);
  const ptf = evidence.ptfs[0] ?? null;
  const product = evidence.productId;
  const displayCommand = ptf
    ? `DSPPTF LICPGM(${product}) SELECT(${ptf})`
    : `DSPPTF LICPGM(${product}) SELECT(*NOTAPY)`;

  return (
    <section className="command-coach" aria-labelledby="command-coach-title">
      <div className="command-coach-intro">
        <div>
          <p className="command-coach-kicker">LCL command coach</p>
          <h3 id="command-coach-title">From finding to partition evidence</h3>
        </div>
        <p>
          {ptf
            ? `${finding?.cve_id}: start with ${ptf}, then widen the check.`
            : "Select a PTF-tagged finding to hydrate the individual check."}
        </p>
      </div>
      <div className="command-coach-steps">
        <article className="command-coach-step is-primary">
          <span className="command-coach-number">01 · Locate</span>
          <code>{displayCommand}</code>
          <p>{ptf ? "Confirm product, release, PTF status, and IPL action." : "List PTFs not applied or superseded for this product."}</p>
        </article>
        <article className="command-coach-step">
          <span className="command-coach-number">02 · Inspect</span>
          <code>5=Display PTF details</code>
          <p>Read general information and cover-letter instructions; detail navigation remains source-gated below.</p>
        </article>
        <article className="command-coach-step">
          <span className="command-coach-number">03 · Widen</span>
          <code>WRKPTFGRP PTFGRP(*ALL)</code>
          <p>Check group level and status. One applied PTF does not establish group currency.</p>
        </article>
      </div>
    </section>
  );
}
