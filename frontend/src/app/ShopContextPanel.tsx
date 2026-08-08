import { useMemo, useState } from "react";
import {
  PERSONAS,
  type ChangePressure,
  type Exposure,
  type Privilege,
  type ShopContext,
} from "../shopContext";
import type { Platform } from "../types";

interface Props {
  context: ShopContext;
  onChange: (ctx: ShopContext) => void;
  onStartIntake?: () => void;
}

export function ShopContextPanel({ context, onChange, onStartIntake }: Props) {
  const [open, setOpen] = useState(false);

  const summary = useMemo(() => {
    if (!context.enabled) return "Off — public ranking only";
    const persona = PERSONAS.find((p) => p.id === context.personaId);
    const pasteBits =
      context.paste && (context.paste.ptfs.length || context.paste.apars.length)
        ? ` · ${context.paste.ptfs.length + context.paste.apars.length} paste tokens`
        : "";
    if (persona) return `${persona.label}${pasteBits}`;
    return `${context.primaryPlatform} · ${context.exposure} · ${context.changePressure}${pasteBits}`;
  }, [context]);

  return (
    <div className="shop-strip">
      <button type="button" className="shop-toggle" onClick={() => setOpen((v) => !v)}>
        <span className="shop-toggle-label">Shop context</span>
        <span className="shop-toggle-summary">{summary}</span>
        <span className="shop-toggle-hint">{open ? "Hide" : "Optional"}</span>
      </button>

      {open && (
        <div className="shop-body">
          <p className="shop-privacy">
            Answers stay in this browser tab (sessionStorage). Nothing is uploaded — no inventory
            file, no keys.
          </p>

          {onStartIntake && (
            <button type="button" className="button" onClick={onStartIntake}>
              Re-run guided routing
            </button>
          )}

          <label className="shop-check">
            <input
              type="checkbox"
              checked={context.enabled}
              onChange={(e) => onChange({ ...context, enabled: e.target.checked })}
            />
            Apply shop context to ranking
          </label>

          <div className="shop-personas">
            {PERSONAS.map((p) => (
              <button
                key={p.id}
                type="button"
                className={`chip ${context.personaId === p.id && context.enabled ? "active" : ""}`}
                onClick={() =>
                  onChange({
                    ...context,
                    ...p.context,
                    enabled: true,
                    personaId: p.id,
                  })
                }
                title={p.blurb}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="shop-grid">
            <label>
              Platform focus
              <select
                value={context.primaryPlatform}
                disabled={!context.enabled}
                onChange={(e) =>
                  onChange({
                    ...context,
                    primaryPlatform: e.target.value as Platform | "multi",
                    personaId: undefined,
                  })
                }
              >
                <option value="ibm_i">IBM i</option>
                <option value="aix">AIX</option>
                <option value="linux_on_power">Linux on Power</option>
                <option value="zos">z/OS</option>
                <option value="multi">Multi / all</option>
              </select>
            </label>
            <label>
              Exposure
              <select
                value={context.exposure}
                disabled={!context.enabled}
                onChange={(e) =>
                  onChange({
                    ...context,
                    exposure: e.target.value as Exposure,
                    personaId: undefined,
                  })
                }
              >
                <option value="internet">Broader network / edge</option>
                <option value="internal">Internal VLAN</option>
                <option value="restricted">Restricted / segmented</option>
              </select>
            </label>
            <label>
              Privilege surface
              <select
                value={context.privilege}
                disabled={!context.enabled}
                onChange={(e) =>
                  onChange({
                    ...context,
                    privilege: e.target.value as Privilege,
                    personaId: undefined,
                  })
                }
              >
                <option value="elevated">Elevated (*ALLOBJ / root-class)</option>
                <option value="standard">Standard</option>
              </select>
            </label>
            <label>
              Change pressure
              <select
                value={context.changePressure}
                disabled={!context.enabled}
                onChange={(e) =>
                  onChange({
                    ...context,
                    changePressure: e.target.value as ChangePressure,
                    personaId: undefined,
                  })
                }
              >
                <option value="this_week">This week</option>
                <option value="this_month">This month</option>
                <option value="backlog">Backlog</option>
              </select>
            </label>
          </div>
        </div>
      )}
    </div>
  );
}
