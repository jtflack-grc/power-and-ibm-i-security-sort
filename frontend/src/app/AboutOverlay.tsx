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
  onStartIntake?: () => void;
}

export function AboutOverlay({ mode, onClose, onReplayIntro, onStartIntake }: Props) {
  const isIntro = mode === "intro";

  const enter = () => {
    markIntroSeen();
    onClose();
  };

  const route = () => {
    markIntroSeen();
    onClose();
    onStartIntake?.();
  };

  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-labelledby="about-title">
      <div className={`overlay-card welcome-card about-card ${isIntro ? "about-intro" : "about-credits"}`}>
        {isIntro ? (
          <>
            <p className="about-kicker">Before the queue</p>
            <h1 id="about-title">Turn IBM i security bulletins into system work</h1>
            <p className="welcome-lead">
              IBM publishes the affected product and remedy. This curator organizes those current
              IBM i bulletins into an explainable <strong>Apply / Contain / Monitor</strong> queue,
              then carries the operator from risk signal to PTF or APAR evidence and verification.
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
                <p>Start with IBM&apos;s newest published issues. Filters and shop context help narrow the queue.</p>
              </section>
              <section>
                <span className="welcome-rail-number">02</span>
                <h2>Issue workbench</h2>
                <p>See why the issue ranks, what IBM says to apply, and what to contain while change work proceeds.</p>
              </section>
              <section>
                <span className="welcome-rail-number">03</span>
                <h2>LCL evidence check</h2>
                <p>Use command coaching and source-validated 5250 screens to verify resolved PTF evidence.</p>
              </section>
            </div>

            <div className="welcome-first-pass">
              <strong>Your first pass</strong>
              <ol>
                <li>Select a recent finding in the left rail.</li>
                <li>Review its ranking levers and IBM remediation path.</li>
                <li>Use the evidence rail when a validated PTF scenario is available.</li>
              </ol>
            </div>
            <p className="welcome-honesty">
              This is a decision and evidence companion, not a scanner of record, Fix Central,
              or a live connection to an IBM i partition. Optional shop answers stay in this tab.
            </p>
            <div className="welcome-actions">
              <button type="button" className="button button-primary" onClick={enter}>
                Enter current queue
              </button>
              {onStartIntake && (
                <button type="button" className="button" onClick={route}>
                  Route for my shop first
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            <p className="about-kicker">Credits</p>
            <h1 id="about-title">IBM i Vulnerability Curator</h1>
            <p className="welcome-lead">
              Built by <strong>John Flack</strong> (jtflack-grc) as a portfolio artifact that
              translates GRC / vulnerability-management language into IBM i systems work and
              verification evidence.
            </p>
            <ul className="welcome-method">
              <li>
                <strong>What it is</strong> A curator between risk language and change work — KEV,
                NVD, EPSS, OWASP context, IBM bulletin hints → Apply / Contain / Monitor
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
              Shop answers and optional PSP paste stay in this browser tab only.
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
