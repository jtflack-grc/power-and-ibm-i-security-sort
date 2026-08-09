import { Ebcdic } from "./shared/src/proto/Ebcdic.js";
import { ScreenBuffer } from "./tn5250/src/display/ScreenBuffer.js";
import { InboundParser } from "./tn5250/src/proto/InboundParser.js";
import { OutboundBuilder } from "./tn5250/src/proto/OutboundBuilder.js";
import { Aid, Models } from "./tn5250/src/proto/Constants.js";
import { Renderer } from "./tn5250/src/ui/Renderer.js";
import { InputController } from "./tn5250/src/ui/InputController.js";
import { DSPPTF_STATUS, buildDspptfStatusRecords } from "./fixtures/dspptf-status.js";

const canvas = document.querySelector("#screen");
const status = document.querySelector("#status");
const empty = document.querySelector("#fixture-empty");
const model = Models["5292-2"];
const screen = new ScreenBuffer(model.rows, model.cols, Ebcdic.get("CP037"));
const parser = new InboundParser(screen);
const builder = new OutboundBuilder(screen);
const renderer = new Renderer(canvas, screen);
const MAX_RECORDS = 4;
const MAX_RECORD_BYTES = 16_384;
let channelToken = null;
let activePtfs = [];

function draw() {
  renderer.draw();
  if (screen.alarm) {
    screen.alarm = false;
  }
}

function emitAid(aid) {
  const pf = (aid >= Aid.PF1 && aid <= Aid.PF12)
    ? aid - Aid.PF1 + 1
    : (aid >= Aid.PF13 && aid <= Aid.PF24)
      ? aid - Aid.PF13 + 13
      : null;
  if (pf !== null && !screen.isPfEnabled(pf)) {
    status.textContent = `F${pf} DESTINATION NOT YET SOURCE-VALIDATED`;
    screen.alarm = true;
    draw();
    return;
  }
  const response = builder.buildAidResponse(aid);
  window.parent.postMessage({
    type: "ironterm:aid",
    channelToken,
    aid,
    payload: Array.from(response),
  }, window.location.origin);
  if (aid === Aid.PF3 || aid === Aid.PF12) {
    screen.clearUnit();
    screen.keyboardLocked = true;
    empty.classList.remove("hidden");
    empty.querySelector("strong").textContent = aid === Aid.PF3 ? "DSPPTF exited" : "DSPPTF cancelled";
    empty.querySelector("span").textContent = "Choose another finding to begin a new verification scenario.";
    status.textContent = aid === Aid.PF3 ? "EXIT" : "CANCEL";
    draw();
    return;
  }
  if (aid === Aid.ENTER) {
    const selected = screen.fields
      .map((field, index) => ({
        index,
        value: Array.from({ length: field.length }, (_, offset) =>
          screen.cells[(field.start + 1 + offset) % screen.size]?.glyph || " "
        ).join("").trim(),
      }))
      .find((field) => field.value === "5");
    if (selected) {
      status.textContent = `${activePtfs[selected.index] || "PTF"}: OPTION 5 DESTINATION CAPTURE REQUIRED`;
      screen.alarm = true;
    } else {
      status.textContent = "TYPE 5 BESIDE A PTF, THEN PRESS ENTER";
      screen.alarm = true;
    }
    screen.keyboardLocked = false;
    parser.readPending = true;
    draw();
    return;
  }
  // Disabled PF AIDs are ignored by a real host. Keep the presentation
  // stable and surface the source gate in the scenario status strip.
  status.textContent = "FUNCTION NOT AVAILABLE IN VALIDATED FIXTURE";
  screen.alarm = true;
  screen.keyboardLocked = false;
  draw();
}

new InputController({
  canvas,
  renderer,
  screen,
  onAid: emitAid,
  onType: (value) => {
    if (screen.keyboardLocked) return;
    for (const char of value) screen.typeByte(screen.ebcdic.fromCharCode(char.charCodeAt(0)));
    draw();
  },
  onBackspace: () => { screen.backspace(); draw(); },
  onTab: () => { screen.tab(); draw(); },
  onBackTab: () => { screen.backTab(); draw(); },
  onMoveCursor: (position) => { screen.cursor = position; draw(); },
  onFlash: (message) => { status.textContent = String(message).toUpperCase(); },
  allowClipboardPaste: false,
});

function loadScenario(message) {
  if (message.scenario !== DSPPTF_STATUS) return;
  if (typeof message.channelToken !== "string" || message.channelToken.length > 64) return;
  if (!Array.isArray(message.ptfs) || message.ptfs.length === 0 || message.ptfs.length > 7) return;
  const ptfs = message.ptfs.map((value) => String(value).toUpperCase());
  if (ptfs.some((value) => !/^[A-Z]{2}\d{5,7}$/.test(value))) return;
  const productId = String(message.productId ?? "").toUpperCase();
  const release = String(message.release ?? "").toUpperCase();
  if (!/^\d{4}[A-Z0-9]{3}$/.test(productId) || !/^V[1-9]R\dM\d$/.test(release)) return;
  channelToken = message.channelToken;
  activePtfs = ptfs;
  const records = buildDspptfStatusRecords({ system: "CURATOR", ptfs, productId, release });
  if (
    records.length === 0 ||
    records.length > MAX_RECORDS ||
    records.some((record) => !Array.isArray(record) || record.length > MAX_RECORD_BYTES)
  ) throw new Error("Scenario fixture exceeds terminal safety limits");
  screen.clearUnit();
  for (const record of records) parser.process(Uint8Array.from(record));
  if (screen.pendingCursor >= 0) {
    screen.cursor = screen.pendingCursor;
    screen.pendingCursor = -1;
  } else {
    const first = screen.firstFocusable();
    if (first !== null) screen.cursor = first;
  }
  screen.keyboardLocked = false;
  empty.classList.add("hidden");
  status.textContent = "";
  draw();
}

window.addEventListener("message", (event) => {
  if (event.source !== window.parent || event.origin !== window.location.origin) return;
  if (event.data?.type === "ironterm:load") loadScenario(event.data);
});

window.addEventListener("resize", () => renderer.resize());
new ResizeObserver(() => renderer.resize()).observe(canvas);
renderer.resize();
draw();
window.parent.postMessage({ type: "ironterm:ready" }, window.location.origin);

// Parser internals are available only on an explicitly local development host.
if (location.hostname === "localhost" || location.hostname === "127.0.0.1") {
  Object.defineProperty(window, "scenarioTerminal", {
    value: Object.freeze({ screen, parser, builder, loadScenario, Aid, buildDspptfStatusRecords }),
    configurable: false,
    writable: false,
  });
}
