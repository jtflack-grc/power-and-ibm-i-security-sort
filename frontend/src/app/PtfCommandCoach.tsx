import { useMemo } from "react";
import type { Finding } from "../types";

interface Props {
  finding: Finding | null;
}

function commandContext(finding: Finding | null) {
  const guidance = (finding?.resolution_steps ?? [])
    .map((step) => `${step.title} ${step.detail}`)
    .join(" ");
  const ptfs = [...new Set((guidance.match(/\b[A-Z]{2}\d{5,7}\b/g) ?? []).map((v) => v.toUpperCase()))];
  const product = guidance.match(/\b\d{4}[A-Z0-9]{3}\b/)?.[0] ?? "5770SS1";
  return { ptf: ptfs[0] ?? null, product };
}

export function PtfCommandCoach({ finding }: Props) {
  const { ptf, product } = useMemo(() => commandContext(finding), [finding]);
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
