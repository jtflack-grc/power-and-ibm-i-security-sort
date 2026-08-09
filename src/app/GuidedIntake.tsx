import { useMemo, useState } from "react";
import {
  PERSONAS,
  parseShopPaste,
  type ChangePressure,
  type Exposure,
  type Privilege,
  type ShopContext,
} from "../shopContext";
type Step = "exposure" | "privilege" | "pressure" | "paste";

const STEPS: Step[] = ["exposure", "privilege", "pressure", "paste"];

interface Props {
  initial: ShopContext;
  livePreferred?: boolean;
  onComplete: (ctx: ShopContext) => void;
  onSkip: () => void;
}

export function GuidedIntake({ initial, livePreferred = false, onComplete, onSkip }: Props) {
  const [stepIdx, setStepIdx] = useState(0);
  const [draft, setDraft] = useState<ShopContext>({
    ...initial,
    enabled: true,
    personaId: undefined,
  });
  const [pasteText, setPasteText] = useState(initial.paste?.raw ?? "");

  const step = STEPS[stepIdx];
  const progress = ((stepIdx + 1) / STEPS.length) * 100;

  const pastePreview = useMemo(() => {
    if (!pasteText.trim()) return null;
    return parseShopPaste(pasteText);
  }, [pasteText]);

  const applyPersona = (id: string) => {
    const p = PERSONAS.find((x) => x.id === id);
    if (!p) return;
    onComplete({
      ...draft,
      ...p.context,
      enabled: true,
      personaId: p.id,
      paste: pastePreview?.ptfs.length || pastePreview?.apars.length ? pastePreview : null,
      routed: true,
    });
  };

  const finish = (withPaste: boolean) => {
    const paste =
      withPaste && pastePreview && (pastePreview.ptfs.length || pastePreview.apars.length)
        ? pastePreview
        : null;
    onComplete({
      ...draft,
      enabled: true,
      personaId: undefined,
      paste,
      routed: true,
    });
  };

  const next = () => {
    if (stepIdx >= STEPS.length - 1) {
      finish(true);
      return;
    }
    setStepIdx((i) => i + 1);
  };

  const back = () => setStepIdx((i) => Math.max(0, i - 1));

  return (
    <div className="overlay">
      <div className="overlay-card intake-card">
        <div className="intake-head">
          <h1>Route your queue</h1>
          <p className="welcome-lead">
            {livePreferred
              ? "Three answers re-weight the IBM i queue already loading in this tab. An optional PTF/APAR paste stays local."
              : "Three answers re-weight the IBM i queue in this browser tab. An optional PTF/APAR paste stays local."}
          </p>
          <div className="intake-bar" aria-hidden>
            <div style={{ transform: `scaleX(${progress / 100})` }} />
          </div>
          <div className="intake-step-meta">
            Step {stepIdx + 1} of {STEPS.length}
          </div>
        </div>

        {step === "exposure" && (
          <fieldset className="intake-field">
            <legend>How exposed is the interesting surface?</legend>
            <div className="intake-options">
              {(
                [
                  ["internet", "Broader network / edge"],
                  ["internal", "Internal VLAN"],
                  ["restricted", "Restricted / segmented"],
                ] as Array<[Exposure, string]>
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  className={`chip ${draft.exposure === id ? "active" : ""}`}
                  onClick={() => setDraft({ ...draft, exposure: id })}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>
        )}

        {step === "privilege" && (
          <fieldset className="intake-field">
            <legend>What is the privileged-profile surface?</legend>
            <div className="intake-options">
              {(
                [
                  ["elevated", "Elevated (*ALLOBJ / root-class)"],
                  ["standard", "Standard"],
                ] as Array<[Privilege, string]>
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  className={`chip ${draft.privilege === id ? "active" : ""}`}
                  onClick={() => setDraft({ ...draft, privilege: id })}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>
        )}

        {step === "pressure" && (
          <fieldset className="intake-field">
            <legend>Change pressure this cycle?</legend>
            <div className="intake-options">
              {(
                [
                  ["this_week", "This week"],
                  ["this_month", "This month"],
                  ["backlog", "Backlog"],
                ] as Array<[ChangePressure, string]>
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  className={`chip ${draft.changePressure === id ? "active" : ""}`}
                  onClick={() => setDraft({ ...draft, changePressure: id })}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>
        )}

        {step === "paste" && (
          <fieldset className="intake-field">
            <legend>Optional — paste a PSP / DSPPTF snippet</legend>
            <p className="intake-hint">
              Parsed in-browser for PTF / APAR tokens. Cleared when the tab closes. Skip if you
              have nothing handy.
            </p>
            <textarea
              className="intake-paste"
              rows={5}
              placeholder="e.g. SI81234  APAR IJ45678  group SF99740…"
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
            />
            {pastePreview && (pastePreview.ptfs.length > 0 || pastePreview.apars.length > 0) && (
              <p className="intake-paste-preview">
                Found{" "}
                {[...pastePreview.ptfs, ...pastePreview.apars].slice(0, 8).join(", ")}
                {pastePreview.ptfs.length + pastePreview.apars.length > 8 ? "…" : ""}
              </p>
            )}
          </fieldset>
        )}

        {step === "exposure" && (
          <div className="intake-personas">
            <div className="intake-personas-label">Or jump a persona</div>
            <div className="intake-options">
              {PERSONAS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  className="chip"
                  title={p.blurb}
                  onClick={() => applyPersona(p.id)}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="welcome-actions intake-actions">
          {stepIdx > 0 ? (
            <button type="button" className="button" onClick={back}>
              Back
            </button>
          ) : (
            <button type="button" className="button" onClick={onSkip}>
              Skip — public ranking
            </button>
          )}
          {step === "paste" ? (
            <>
              <button type="button" className="button" onClick={() => finish(false)}>
                Skip paste
              </button>
              <button type="button" className="button button-primary" onClick={() => finish(true)}>
                Apply route
              </button>
            </>
          ) : (
            <button type="button" className="button button-primary" onClick={next}>
              Next
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
