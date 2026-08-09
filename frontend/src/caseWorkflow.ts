export type Disposition = "unreviewed" | "remediate" | "mitigate" | "accept" | "not_affected";

export interface CaseWorkflow {
  owner: string;
  targetDate: string;
  changeRecord: string;
  disposition: Disposition;
  exceptionExpiry: string;
  reviewer: string;
}

export const EMPTY_CASE_WORKFLOW: CaseWorkflow = {
  owner: "",
  targetDate: "",
  changeRecord: "",
  disposition: "unreviewed",
  exceptionExpiry: "",
  reviewer: "",
};

const STORAGE_PREFIX = "ibmi-curator-case-v1:";

function clean(value: unknown, limit = 120): string {
  return [...String(value ?? "")].map((char) => {
    const code = char.charCodeAt(0);
    return code < 32 || code === 127 ? " " : char;
  }).join("").trim().slice(0, limit);
}

export function loadCaseWorkflow(cveId: string): CaseWorkflow {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(`${STORAGE_PREFIX}${cveId}`) || "{}") as Partial<CaseWorkflow>;
    const disposition: Disposition = ["unreviewed", "remediate", "mitigate", "accept", "not_affected"].includes(String(parsed.disposition))
      ? parsed.disposition as Disposition
      : "unreviewed";
    return {
      owner: clean(parsed.owner),
      targetDate: clean(parsed.targetDate, 10),
      changeRecord: clean(parsed.changeRecord),
      disposition,
      exceptionExpiry: clean(parsed.exceptionExpiry, 10),
      reviewer: clean(parsed.reviewer),
    };
  } catch {
    return { ...EMPTY_CASE_WORKFLOW };
  }
}

export function saveCaseWorkflow(cveId: string, value: CaseWorkflow): void {
  sessionStorage.setItem(`${STORAGE_PREFIX}${cveId}`, JSON.stringify(value));
}
