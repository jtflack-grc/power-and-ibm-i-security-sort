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

export const WRKPTFGRP = "wrkptfgrp";

// Public IBM i 7.4 group levels retrieved from IBM's "IBM i Group PTFs with
// level" table on 2026-08-10. Statuses represent a synthetic training
// partition; the fixture never claims to observe the visitor's system.
const ibmi74Groups = [
  ["SF99740", "26183", "Installed", "V7R4M0", "Cumulative PTF package"],
  ["SF99739", "176", "Not installed", "V7R4M0", "Group HIPER"],
  ["SF99738", "97", "Apply at next IPL", "V7R4M0", "Group Security"],
  ["SF99737", "12", "Installed", "V7R4M0", "Technology Refresh"],
  ["SF99704", "33", "Installed", "V7R4M0", "Db2 for IBM i"],
  ["SF99665", "33", "Installed", "V7R4M0", "Java"],
  ["SF99662", "52", "Installed", "V7R4M0", "IBM HTTP Server for i"],
];

function ebcdic(value) {
  return Array.from(value, (char) => cp037.fromCharCode(char.charCodeAt(0)));
}

function sba(row, col) {
  return [SBA, row, col];
}

function text(row, col, value, attr = 0x20) {
  if (col < 2) throw new Error("fixture text requires an attribute cell");
  return [...sba(row, col - 1), attr, ...ebcdic(value)];
}

function input(row, col, length) {
  return [...sba(row, col - 1), SF, 0x40, 0x20, 0x24, 0x00, length];
}

function assertFits(row, col, value) {
  if (row < 1 || row > 24 || col < 1 || col + value.length - 1 > 80) {
    throw new Error(`WRKPTFGRP fixture overflow at ${row},${col}: ${value}`);
  }
}

function scenarioRows(groups) {
  const requested = new Set(groups.map((group) => group.toUpperCase()));
  const known = ibmi74Groups.filter(([group]) => requested.has(group));
  const unknown = groups
    .filter((group) => !ibmi74Groups.some(([knownGroup]) => knownGroup === group.toUpperCase()))
    .map((group) => [group.toUpperCase(), "1", "Not installed", "V7R4M0", "Bulletin-linked PTF group"]);
  const remaining = ibmi74Groups.filter(([group]) => !requested.has(group));
  return [...known, ...unknown, ...remaining].slice(0, 7);
}

export function buildWrkptfgrpRecords({ system = "CURATOR", groups = [], descriptionView = false } = {}) {
  const rows = scenarioRows(groups);
  const stream = [ESC, CU, ESC, CFT, ESC, WTD, 0x00, 0x08];
  // PF3, PF11, and PF12 are enabled. Other destinations remain source-gated.
  stream.push(SOH, 0x07, 0x00, 0x00, 0x00, 0x24, 0xdf, 0xcf, 0xff);

  const writes = [
    [1, 29, "Work with PTF Groups", 0x22],
    [2, 61, `System:   ${system}`.slice(0, 20), 0x22],
    [3, 2, "Type options, press Enter."],
    [4, 4, "4=Delete   5=Display   8=Display special handling PTFs", 0x30],
    [5, 4, "9=Display related PTF groups", 0x30],
    [7, 2, descriptionView
      ? "Opt  PTF Group  Level  Status               Text"
      : "Opt  PTF Group  Level  Status               Target release", 0x22],
    [21, 73, "Bottom", 0x22],
    [23, 2, descriptionView
      ? "F3=Exit   F6=Print   F11=Display release   F12=Cancel   F22=Display list"
      : "F3=Exit   F6=Print   F11=Display text   F12=Cancel   F22=Display list", 0x30],
  ];

  for (const [row, col, value, attr] of writes) {
    assertFits(row, col, value);
    stream.push(...text(row, col, value, attr));
  }

  rows.forEach(([group, level, status, release, description], index) => {
    const row = 9 + index;
    stream.push(...input(row, 2, 1));
    stream.push(...text(row, 7, group));
    stream.push(...text(row, 18, String(level).padStart(5)));
    stream.push(...text(row, 26, status));
    stream.push(...text(row, 47, descriptionView ? description.slice(0, 34) : release));
  });

  stream.push(ESC, RMDT, 0x00, 0x08);
  return [stream];
}

export const wrkptfgrpReferenceRows = ibmi74Groups.map(
  ([group, level, status, release, description]) => ({ group, level, status, release, description })
);
