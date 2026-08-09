# IronTerm TN5250 scenario-mode integration

This directory vendors the TN5250 implementation from
[bencz/IronTerm](https://github.com/bencz/IronTerm) at the commit recorded in
`UPSTREAM_COMMIT`.

IronTerm is licensed under GPL-3.0. The upstream license is preserved as
`LICENSE`. The vendored source remains available under `tn5250/src` and
`shared/src`.

## Local modification

`scenario-main.js` replaces the live WebSocket/Telnet session lifecycle with a
deterministic scenario boundary. It retains IronTerm's presentation space,
EBCDIC codec, inbound datastream parser, outbound builder, field handling,
renderer, input controller, AID keys, cursor rules, and OIA.

The first bundled IBM i fixture is the source-gated DSPPTF status panel. A
scenario selects a validated, named fixture through `postMessage`; the terminal
generates its datastream locally. Production messages do
not accept caller-supplied datastream records. Both frames validate the exact
message source and origin, and the parent supplies a per-load channel token for
terminal replies. Unknown scenario names are ignored, fixture record counts and
sizes are bounded, and clipboard reads are disabled in scenario mode. The
terminal remains locked and blank until a known fixture is selected.

PTF screen provenance and release gates are maintained under `fixtures/`.

The live-host connection UI, credentials, connection profiles, and websockify
path are not loaded by the portfolio application.
