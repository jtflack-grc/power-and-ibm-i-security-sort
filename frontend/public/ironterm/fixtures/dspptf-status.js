import { Ebcdic } from "../shared/src/proto/Ebcdic.js";

const cp037 = Ebcdic.get("CP037");
const ESC = 0x04;
const WTD = 0x11;
const CU = 0x40;
const CFT = 0x50;
const RMDT = 0x52;
const SBA = 0x11;
const SOH = 0x01;
const SF = 0x1d;

export const DSPPTF_STATUS = "dspptf-status";

const fallbackRows = [
  ["SI76195", "Permanently applied", "None"],
  ["SI76201", "Temporarily applied", "None"],
  ["SI75840", "Superseded", "None"],
  ["SI75572", "Permanently applied", "None"],
  ["SI75469", "Permanently applied", "None"],
  ["SI74829", "Superseded", "None"],
  ["SI74612", "Superseded", "None"],
];

function ebcdic(text) {
  return Array.from(text, (char) => cp037.fromCharCode(char.charCodeAt(0)));
}

function sba(row, col) {
  return [SBA, row, col];
}

// A basic attribute consumes one presentation-space cell. Put it in the
// column immediately before the first visible glyph, as an IBM i display
// file does. All coordinates below are therefore explicit 1-based 5250
// row/column coordinates, not CSS positions.
function text(row, col, value, attr = 0x20) {
  if (col < 2) throw new Error("fixture text requires an attribute cell");
  return [...sba(row, col - 1), attr, ...ebcdic(value)];
}

function input(row, col, length) {
  // SF at col-1: FFW present, uppercase input, green underline.
  return [...sba(row, col - 1), SF, 0x40, 0x20, 0x24, 0x00, length];
}

function assertFits(row, col, value) {
  if (row < 1 || row > 24 || col < 1 || col + value.length - 1 > 80) {
    throw new Error(`DSPPTF fixture overflow at ${row},${col}: ${value}`);
  }
}

export function buildDspptfStatusRecords({
  system = "CURATOR",
  ptfs = [],
  productId = "5770SS1",
  release = "V7R4M0",
} = {}) {
  const scenarioRows = ptfs.length
    ? ptfs.slice(0, 7).map((ptf, index) => [
        ptf,
        index === 0 ? "Permanently applied" : "Temporarily applied",
        "None",
      ])
    : fallbackRows;
  const stream = [ESC, CU, ESC, CFT, ESC, WTD, 0x00, 0x08];
  // SOH length 7; disable every PF key except PF3 and PF12. F11/F17 remain legible because
  // IBM's source panel shows them, but the terminal will reject their AIDs
  // until their destination layouts pass the same source gate.
  stream.push(SOH, 0x07, 0x00, 0x00, 0x00, 0x24, 0xdf, 0xef, 0xff);

  const writes = [
    [1, 33, "Display PTF Status", 0x22],
    [2, 61, `System:   ${system}`.slice(0, 20), 0x22],
    [3, 2, `Product ID  . . . . . . . . . . . . . :   ${productId}`],
    [4, 2, "IPL source  . . . . . . . . . . . . . :   ##MACH#B"],
    [5, 2, `Release of base option  . . . . . . . :   ${release}    L00`],
    [7, 2, "Type options, press Enter."],
    [8, 4, "5=Display PTF details   6=Print cover letter   8=Display cover letter", 0x30],
    [9, 4, "10=Display PTF apply information", 0x30],
    [11, 7, "PTF                                                   IPL", 0x22],
    [12, 2, "Opt  ID       Status                                       Action", 0x22],
    [21, 73, "More...", 0x22],
    [23, 2, "F3=Exit   F11=Display alternate view   F17=Position to   F12=Cancel", 0x30],
  ];

  for (const [row, col, value, attr] of writes) {
    assertFits(row, col, value);
    stream.push(...text(row, col, value, attr));
  }

  scenarioRows.forEach(([ptf, status, action], index) => {
    const row = 13 + index;
    stream.push(...input(row, 2, 2));
    stream.push(...text(row, 7, ptf));
    stream.push(...text(row, 16, status));
    stream.push(...text(row, 61, action));
  });

  stream.push(ESC, RMDT, 0x00, 0x08);
  return [stream];
}

export const fallbackDspptfRows = fallbackRows.map(([ptf, status, action]) => ({ ptf, status, action }));
