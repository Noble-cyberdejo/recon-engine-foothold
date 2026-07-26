# Continuity Record

## Previous-stage commit and component reused

This is Advanced Project 1 (Ethical Hacking track) — the first Advanced-tier
project. Per the Portfolio Continuity Contract, Advanced Project 1 establishes
the common interface that later Ethical Hacking projects (exploit, IAM,
directory, estate) will extend, rather than reusing a component from an
earlier project itself.

No prior Advanced-stage commit is reused here. Foundation-stage work
(UBI Stages 0-4) was orientation/induction and did not produce a
carried-forward code component per the programme structure.

## Interface consumed and backward-compatible extension

N/A for this project — establishing interface, not consuming one.

## Evidence that prior raw-to-result provenance remains intact

N/A — no prior-stage raw evidence chain exists to preserve for this project.

## Migration record for every incompatible change

N/A — no prior component being migrated or replaced.

## Component, schema, evidence, or decision record handed to the next stage

The following become the common interface for subsequent Ethical Hacking
Advanced projects, per the Portfolio Continuity Contract's track
progression note ("Scope-safe discovery becomes the common interface;
exploit, IAM, directory, and estate projects extend the same runtime
identifier, evidence, cleanup, and remediation model"):

- **`recon_engine.scope`** — `ScopeEngine` (generic CIDR/hostname/port
  allow-list matcher) and `CompositeScope`/`LoopbackGuard` (hard
  loopback-only policy layer). Future projects extending scope beyond
  loopback will need to adapt `LoopbackGuard`'s hard-coded constraint —
  documented here as the expected extension point, not a limitation to
  route around silently.
- **`recon_engine.schema.NormalizedRecord`** — the versioned record
  format (schema_version "1.0") that all discovery output normalizes
  into. See `schemas/normalized-record.schema.json`.
- **`recon_engine.checkpoint`** — the 4-stage resumable pipeline model
  (`dns -> probe -> ports -> fingerprint`), reusable as a pattern for
  any future multi-stage runtime.
- **`recon_engine.ledger.RequestLedger`** — the append-only,
  crash-durable evidence-of-scope-compliance pattern.
- **`recon_engine.tools.adapter_base`** — the list-args-only subprocess
  wrapper pattern (never shell string concatenation) for invoking
  external tools safely, plus the fallback-on-missing-tool pattern.

This project hands forward to Stage 6: the `Orchestrator._attempt_foothold`
adaptive-discovery pattern (capability-probe -> route-proof -> breadcrumb-follow
-> authenticated-fetch) as a reusable model for chaining a non-HTTP service to
an HTTP one; the `recon_engine.tools.signal_protocol` and
`recon_engine.tools.http_discovery` adapters as examples of protocol-adaptive
discovery modules built against the `adapter_base` interface; and the
`run/normalized/assets.jsonl` evidence ledger produced by this run as the
runtime-identifier record for evidence marker UBI-A5-7A05BB4E73AC.