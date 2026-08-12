# PTF screen sourcing decision

The source registry is `screen-sources.json`. It separates three questions that
must not be collapsed:

1. Is the IBM i workflow and vocabulary documented?
2. Is the exact 24x80 screen layout documented or captured?
3. Has the screen been encoded as a 5250 datastream fixture and accepted by John?

## Current result

| Screen | LCL starting point | IBM evidence | Fixture decision |
|---|---|---|---|
| WRKPTFGRP | Strong structural candidate | Complete IBM Redbook initial/F11 panels, December 2024 IBM screen examples, current 7.4 group levels, and current command/SQL-service semantics | Implemented for preview; hold public enablement for John visual acceptance |
| DSPPTFGRP | Strong structural candidate | Navigation, F19, F6, and status behavior identified | Hold for full-panel capture |
| Display PTF Status | Missing as a distinct LCL panel | Two IBM technotes contain preformatted screen output | Ready to encode |
| DSPPTF option 5 / General Information | Bounded selected-PTF fixture enabled | IBM field inventory and published fix metadata | Alternate pages remain gated |
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

## WRKPTFGRP source breakthrough

IBM Redbook SG24-7311 pages 18–19 publishes complete preformatted 24x80 text for
both the initial Work with PTF Groups panel and its F11 description view. It
establishes the option legend, group/level/status and group/text columns, example
row placement, Bottom marker, and F3/F6/F11/F12/F22 labels. Because the example
is from the i5/OS V5R3 era, it is coordinate evidence rather than proof by
itself. IBM's December 2024 WRKPTFGRP technote confirms the modern `*ALL`,
`*LATEST`, and `*INSTALLED` presentations, while IBM's current Group PTF table
supplies the public IBM i 7.4 group/level pairs. The implemented fixture combines
those sources, marks its partition statuses synthetic, and remains preview-only
until John Flack visually accepts the initial and F11 views.

## SQL evidence route

The terminal is the interactive teaching surface. The evidence-engineering route
beneath it uses `QSYS2.GROUP_PTF_INFO` and `QSYS2.PTF_INFO` so a practitioner can
collect the same state repeatably, export sanitized rows, and retain the query,
collection timestamp, partition identity, and job identity with the decision
packet. The SQL results are not uploaded by Curator.

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
