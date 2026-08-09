const INTRO_SEEN_KEY = "psvc-intro-seen-v1";

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

  const enter = () => {
    markIntroSeen();
    onClose();
  };

  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-labelledby="about-title">
      <div className={`overlay-card welcome-card about-card ${isIntro ? "about-intro" : "about-credits"}`}>
        {isIntro ? (
          <>
            <p className="about-kicker">Before the queue</p>
            <h1 id="about-title">IBM i Vulnerability Curator</h1>
            <p className="welcome-lead">
              This is a curator, not a scanner. It turns public CVE intelligence for IBM i into an
              Apply / Contain / Monitor queue with explainable counter-levers and an explicit path
              from vendor remedy to system verification.
            </p>
            <ul className="welcome-method">
              <li>
                <strong>Feeds</strong> A scheduled public snapshot loads next (focused modern rail —
                museum CVEs stay out unless you ask)
              </li>
              <li>
                <strong>Route</strong> Optional shop answers re-weight this tab only; nothing is
                uploaded
              </li>
              <li>
                <strong>Work</strong> Open a finding for Resolve (bulletin / PTF / APAR), Interim
                controls, and source-validated 5250 verification when a scenario exists
              </li>
            </ul>
            <p className="welcome-honesty">
              Portfolio demo by John Flack · i on GRC. Public feeds only. Not a scanner of record.
            </p>
            <div className="welcome-actions">
              <button type="button" className="button button-primary" onClick={enter}>
                Enter the queue
              </button>
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
