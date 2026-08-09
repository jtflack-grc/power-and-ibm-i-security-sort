# PTF screen sourcing decision

The source registry is `screen-sources.json`. It separates three questions that
must not be collapsed:

1. Is the IBM i workflow and vocabulary documented?
2. Is the exact 24x80 screen layout documented or captured?
3. Has the screen been encoded as a 5250 datastream fixture and accepted by John?

## Current result

| Screen | LCL starting point | IBM evidence | Fixture decision |
|---|---|---|---|
| WRKPTFGRP | Strong structural candidate | Command, behavior, and IBM-hosted screenshots identified | Hold for image/layout comparison |
| DSPPTFGRP | Strong structural candidate | Navigation, F19, F6, and status behavior identified | Hold for full-panel capture |
| Display PTF Status | Missing as a distinct LCL panel | Two IBM technotes contain preformatted screen output | Ready to encode |
| Display PTF Details menu | LCL currently skips it | IBM confirms the menu and option 1 | Hold for full-panel capture |
| General Information | LCL has useful fields but flattened navigation | IBM confirms the full field inventory and exact dotted labels for key fields | Hold for full-panel capture/paging decision |

## Correction to the LCL flow

LCL currently represents `DSPPTF` as one detailed panel. IBM's documented
interactive flow is:

```text
DSPPTF LICPGM(...) SELECT(...)
  -> Display PTF Status
  -> option 5
  -> Display PTF Details menu
  -> option 1
  -> General Information
```

The Curator fixtures will implement the separated IBM flow. LCL content may
supply synthetic values and candidate coordinates, but it will not be treated
as proof of IBM's actual navigation.

## First fixture to build

`DSPPTF_STATUS` is the first safe fixture. IBM Support provides a nearly complete
preformatted 5250 panel, including:

- Product ID, IPL source, and release of base option
- option 5, 6, and 8 legend
- PTF ID, Status, and IPL Action columns
- representative Temporary, Permanent, Superseded, and Not Applied states
- F3, F11, F17, and F12 function keys

The public fixture must replace the IBM example's system name and obsolete
product/release/PTF identifiers with synthetic values while preserving the
documented layout and status semantics.

## Acceptance record required for every enabled fixture

- source URLs and retrieval date
- applicable IBM i release or version-independent designation
- reference image or preformatted panel hash
- expected 24x80 text matrix
- field and protected-field map
- enabled AID keys and navigation targets
- scenario values marked public or synthetic
- IronTerm render comparison result
- John Flack acceptance date
