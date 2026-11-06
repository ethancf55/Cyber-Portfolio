# NEXUS VORTEX 11.1 — Incident Reconstruction

Browser workspace for turning imported security logs into an investigation. The public edition and the local edition are the same page; only the local edition can reach the companion.

## What is real

Incident Reconstruction (`#/investigate`) imports Suricata EVE JSON, Zeek TSV and JSON, syslog authentication logs, authentication CSV, and Windows Security logon JSON. Every file gets a receipt: accepted, rejected, duplicate, timestamp assumptions, conflicts, and any limit that stopped it. Nothing is discarded quietly.

Findings come from versioned rules (`NV-RULESET 2026.11-1`). Each one cites the supporting records, the window, the thresholds, the assets, other explanations, and what the logs cannot show. Severity, evidence completeness, and confidence are separate. Confidence is a level, not a percentage, and a finding is not a confirmed compromise.

The Neural Threat Mesh keeps the holographic lattice. Evidence assets and relationships are drawn on top of it. Solid lines are stated by a record. Dashed lines are inferred by a finding. Dim slate nodes are the training lattice.

The timeline selects a window and can play or scrub it. Event time and ingestion time are separate. Records with no usable time stay in an explicit bucket. Order is not causation.

Cases are schema 2 in IndexedDB (localStorage if IndexedDB is unavailable, memory if both fail — the failure is shown). Export writes a JSON file with SHA-256 of the canonical content and of each raw line. Re-import checks both. A digest detects a later edit; it does not prove who created the file. The export dialog lists the addresses, accounts, hostnames, and credential-like patterns in the file before anything is written. Nothing is uploaded.

Older investigations under `nexus-investigations-v1` are copied forward on first open. The original key is left in place.

## Editions

`npm run build` writes:

- `dist/public/index.html` — companion buttons disabled, no credentials accepted.
- `dist/local/index.html` — same workspace, companion buttons enabled. Serve it from the existing local companion at `127.0.0.1` and inject `window.NEXUS_COMPANION` the way the current local edition does. This tree does not include or modify the companion, and it does not start one.

Nmap, Nessus, OpenVAS, Trivy, SARIF, and ZAP reports still use the previous adapter. That path does not report per-record rejections; the receipt says so.

## Limits

- 150,000 records in a tab. A file stops at the limit and the receipt names the line.
- 1 MiB per record. Longer lines are rejected and the next line is still read.
- Raw text over 16 KiB is stored as an excerpt. The SHA-256 is of the full line.
- JSON array files up to 128 MiB. Larger ones must be JSON lines.
- 10,000 live companion records, oldest dropped, and the drop is reported.
- A case holds 2,000 records, 8 MiB of raw text, and 200 notes.
- The mesh draws at most 120 assets and 360 relationships. The explorer and the dossiers include the rest, and the mesh says what was left out.

Timestamps without a zone use the zone selected at import (UTC by default). Syslog dates without a year use the year selected at import. Slash dates such as 05/06/2026 stay unknown until month-first or day-first is chosen.

## Verify

```bash
cd nexus-vortex
npm install
npm test          # parser, rule, and case tests
npm run test:e2e  # Chrome: import, finding, mesh, timeline, case, reload, export, re-import
npm run perf      # 50,000-event import; prints measured times
```

Synthetic fixtures live in `fixtures/` and are also embedded for the in-page buttons (Benign, Suspicious, Malformed, Timestamps, Hostile HTML, Generate 50,000 events). Addresses are documentation ranges. Names are `.example` / `.test`. Regenerate with `npm run fixtures`.

Open `dist/public/index.html`, press Esc to skip the boot sequence, and use `#/investigate`. The suspicious set should produce an authentication finding, a regular-connection finding, and a DNS finding. The benign set should produce none. The malformed set should list rejected lines. A `<script>` in a log line is shown as text.

## Trade-offs

Parsing and rules run in a worker. If workers are unavailable, the same code runs on the page thread in chunks and the header says so. The mesh is still drawn on the main thread and is capped, so a large import does not mean tens of thousands of nodes. Case storage is unencrypted browser storage; export is the copy you can keep. The training modules (detection-feed scoring, memory theater, exploit chains, C2 chamber) are unchanged and are labelled training when Evidence mode is on.
