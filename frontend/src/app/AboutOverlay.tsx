import { useEffect, useRef } from "react";

const INTRO_SEEN_KEY = "psvc-intro-seen-v2";

export function hasSeenIntro(): boolean {
  try {
    return localStorage.getItem(INTRO_SEEN_KEY) === "1";
  } catch {
    return false;
  }
}

export function markIntroSeen(): void {
  try {
    localStorage.setItem(INTRO_SEEN_KEY, "1");
  } catch {
    // private mode / blocked storage — treat as session-only
  }
}

type Mode = "intro" | "credits";

interface Props {
  mode: Mode;
  onClose: () => void;
  onReplayIntro?: () => void;
}

export function AboutOverlay({ mode, onClose, onReplayIntro }: Props) {
  const isIntro = mode === "intro";
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusable = dialogRef.current?.querySelector<HTMLElement>("button, a[href], select, [tabindex]:not([tabindex='-1'])");
    focusable?.focus();
    return () => previous?.focus();
  }, [mode]);

  const enter = () => {
    markIntroSeen();
    onClose();
  };

  return (
    <div
      className="overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="about-title"
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          onClose();
          return;
        }
        if (event.key !== "Tab" || !dialogRef.current) return;
        const items = [...dialogRef.current.querySelectorAll<HTMLElement>("button, a[href], select, [tabindex]:not([tabindex='-1'])")]
          .filter((item) => !item.hasAttribute("disabled"));
        if (!items.length) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }}
    >
      <div ref={dialogRef} className={`overlay-card welcome-card about-card ${isIntro ? "about-intro" : "about-credits"}`}>
        {isIntro ? (
          <>
            <p className="about-kicker">Before the queue</p>
            <h1 id="about-title">Turn IBM&apos;s CVE list into fix evidence</h1>
            <p className="welcome-lead">
              IBM&apos;s <code>SYSTOOLS.CVE_INFO()</code> identifies CVEs affecting a release, but it does
              not prove that the correcting fix is applied. This curator resolves IBM&apos;s bulletins,
              compares the expected remedy with local SQL evidence, and preserves the decision.
            </p>

            <div className="welcome-source-line">
              <strong>Discovery authority</strong>
              <span>IBM Product Security Central / PSIRT</span>
              <small>NVD, CISA KEV, EPSS, CVSS, and OWASP add context; they do not define the queue.</small>
            </div>

            <div className="welcome-rail-map" aria-label="The three application rails">
              <section>
                <span className="welcome-rail-number">01</span>
                <h2>Findings</h2>
                <p>Start with IBM&apos;s newest published issues and narrow the queue with direct filters.</p>
              </section>
              <section>
                <span className="welcome-rail-number">02</span>
                <h2>Issue workbench</h2>
                <p>See why the issue ranks, what IBM says to apply, and what to contain while change work proceeds.</p>
              </section>
              <section>
                <span className="welcome-rail-number">03</span>
                <h2>Fix evidence</h2>
                <p>Compare the IBM remedy with QSYS2 PTF state; use the legacy 5250 path only when SQL is unavailable.</p>
              </section>
            </div>

            <div className="welcome-first-pass">
              <strong>Your first pass</strong>
              <ol>
                <li>Select a recent finding in the left rail.</li>
                <li>Review its ranking levers and IBM remediation path.</li>
                <li>Run the ACS SQL kit and compare sanitized local fix state.</li>
              </ol>
            </div>
            <p className="welcome-honesty">
              This is a decision and evidence companion, not a scanner of record, Fix Central,
              or a live connection to an IBM i partition.
            </p>
            <div className="welcome-actions">
              <button type="button" className="button button-primary" onClick={enter}>
                Enter current queue
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="about-kicker">Credits</p>
            <h1 id="about-title">IBM i Vulnerability Curator</h1>
            <p className="welcome-lead">
              Built by <strong>John Flack</strong> (jtflack-grc) as a portfolio artifact that
                joins IBM&apos;s CVE claims to transparent IBM i fix-state evidence.
            </p>
            <ul className="welcome-method">
              <li>
                <strong>What it is</strong> A curator between risk language and change work — KEV,
                NVD, EPSS, OWASP context, IBM bulletin remedies, and local SQL state → Apply / Contain / Monitor
              </li>
              <li>
                <strong>Platform scope</strong> IBM i only, including operating-system and
                supply-chain findings with a defensible IBM i applicability signal
              </li>
              <li>
                <strong>What it isn&apos;t</strong> A scanner of record, an authenticated enterprise
                service, a live IBM i terminal, or a replacement for Fix Central / your change board
              </li>
              <li>
                <strong>How Pages works</strong> Daily scheduled public intel snapshot, no open API,
                no keys in the SPA
              </li>
            </ul>
            <p className="welcome-honesty">
              Public-feed evidence remains in this browser tab only.
            </p>
            <div className="welcome-actions">
              <a
                className="button button-primary"
                href="https://jtflack-grc.github.io/portfolio/"
                target="_blank"
                rel="noreferrer"
              >
                Portfolio front door
              </a>
              {onReplayIntro && (
                <button
                  type="button"
                  className="button"
                  onClick={() => {
                    onClose();
                    onReplayIntro();
                  }}
                >
                  Replay first-time card
                </button>
              )}
              <button type="button" className="button" onClick={onClose}>
                Close
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
