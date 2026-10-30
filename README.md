# Shield

Shield is a Windows-first security controller for application admission and
tightly scoped AI-assisted workflows. It combines native Windows execution
controls, isolated AI workers, broker-held credentials, and explicit task
permissions with separate approval before publishing changes. The goal is to
limit unauthorized actions even when an approved AI worker is manipulated,
rather than relying on the model to follow instructions.

The problem is the gap between allowing software to run and controlling what
it is authorized to do. Compromised applications and prompt-injected AI
workflows can misuse legitimate access to files, credentials, networks, and
connected accounts without launching a new malicious executable. Application
admission alone cannot govern every subsequent action, and model instructions
are not an authorization boundary.

**Experimental Windows/Rust prototype. Not a completed endpoint-security
product, an accepted integrated pilot, or a solution to every intrusion.
Do not use production credentials or data.**

## What is implemented

- **Worker isolation:** an unelevated controller, a narrowly scoped typed-stdio
  worker, verified zero-capability less-privileged AppContainer (LPAC) identities,
  job resource limits, deadlines, cancellation, and coordinated child-process
  creation to avoid leaking temporary worker pipe handles to other helpers.
  Cancellation still attempts owned-job termination on journal-write failure
  and reports unverified revocation rather than claiming success. Worker frame
  reads and self-test output have absolute pipe deadlines, even if a writer
  remains open.
- **Explicit authority:** frozen enrollment profiles, task grants and epochs,
  transactional allowances, protected local state, and no automatic replay of
  uncertain effects. Journal page/retention settings are reapplied on every
  connection rather than lost after initialization.
- **Controlled publication:** captured inputs, artifact digests, separate one-use
  approvals, changed-original rejection, readback, and reviewed restoration.
- **Brokered providers:** fixed OpenAI Responses and read-only Microsoft Graph
  adapters with bounded requests and credentials held outside the worker.
- **Native enforcement foundations:** owned Windows Filtering Platform (WFP)
  filters, App Control policy authoring/lifecycle code, an opt-in protected
  read-only verifier service, and pinned Authenticode publisher verification.
- **Diagnostics:** read-only inventory, scoped native canaries, local audit
  verification/export, and an offline manual fixture workflow.

The worker is a small custom client, **not Codex CLI or a wrapper for arbitrary
agents**. It cannot choose URLs, credentials, file destinations, commands, or
tools.

## Build and test

Use Windows with the pinned Rust toolchain and MSVC build tools. From the
project directory:

```powershell
cargo build --release --locked
cargo test --locked --all-targets
cargo test --release --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
```

The [Windows workflow](.github/workflows/windows.yml) performs formatting,
strict Clippy, debug/release builds, and native regression checks. Native tests
run under a fresh standard-user identity on a disposable GitHub-hosted VM,
with an independent elevation check.

Published software baseline `84ff512` has a
[passing hosted run](https://github.com/k0jir0/Shield/actions/runs/40979275471):
**148 tests passed in each debug/release configuration**, with no failures or
ignored tests, plus eight scoped LPAC observations per binary. Formatting,
strict all-feature Clippy and builds passed.

The [2026-10-30 functional QA report](reports/functional-qa-2026-10-30.txt)
records fresh local runs of all 148 tests per configuration, plus **62 independent
black-box checks across 66 actual CLI invocations**. The pass covers exercised
offline prototype functionality, not full-product protection or release
acceptance. Raw machine-local evidence remains local; the published report
includes the case matrix, executable hashes and explicit coverage gaps.

Earlier Application Control-blocked attempts remain in the
[technical paper](paper.txt); later passes do not erase them. Software checks
do not certify deployment or protection. Do not weaken security or execution
policy to make a check pass.

## Current limits

- No Shield App Control policy or WFP setup has been deployment/effect-qualified
  in an authorized disposable lab. The protected verifier is not
  deployment-qualified either. Never elevate the broker to bypass a refusal.
- The LPAC network probe reports **Winsock initialization failure 10107**, not a
  proven firewall rejection or complete egress isolation. An earlier ordinary
  AppContainer baseline successfully connected to an owned loopback listener.
- No live model/Graph workflow, independent provider ceiling/revocation test,
  integrated attack chain, qualified recovery, or representative-user pilot has
  passed. All twelve protection milestones remain unverified.
- Publication writes **in place, not crash-atomically**. Local cancellation
  cannot recall disclosed data, remote requests, tokens, or completed effects.
  Dispatch-journal failures explicitly require reconciliation before a fresh
  approval; they do not automatically replay a write or restore the original.
- The journal's **64 MiB limit covers main database pages**. Its 1 MiB retained
  WAL setting is not a hard peak-WAL or total-storage cap.
- There is no production signed release, authenticated updater, product
  installer, qualified deployment/recovery process, or public support commitment.

Live execution requires verified native enforcement and scoped canaries; missing
or unverifiable protection refuses execution. The offline manual fixture tests
staging, review, and publication only and cannot establish live readiness.

## Audit evidence bounds

`audit` and `audit --export <new-file>` verify and collect each event from the
same SQLite read snapshot. Export is limited to **1,024 records**, **1 MiB of
compact event-array JSON**, and **4 MiB of final file or terminal JSON**,
including pretty formatting and terminal-safe Unicode expansion.

An over-budget export fails explicitly: no silent truncation, partial output,
overwriting an existing file, audit deletion or authority reset. Longer valid
chains remain verifiable, but segmented export is not implemented. These are
engineering byte/record bounds, not a measured total-RAM, retention, privacy or
independent-observer qualification.

User-facing SQLite/JSON errors withhold raw messages and rejected input,
retaining SQLite failure codes and JSON category/location where available.
This does not sanitize arbitrary application messages, debug formatting or
the typed errors' retained internal source chains.

## Record an ordinary-launch baseline

From an unelevated Windows session, after building all three executables:

```powershell
& .\target\release\shield.exe endpoint baseline --output "$env:TEMP\Shield-baseline-$([guid]::NewGuid())"
```

This runs the adjacent inert allow/deny controls once each through ordinary
process creation, checks their exact nonce markers, and retains a local
`report.json` with executable hashes, launch outcomes, and read-only native
prerequisites. Existing output directories are refused. Failed controls invalidate
the baseline; missing native prerequisites remain explicit stop decisions.
Neither a valid baseline nor an absent marker establishes Shield enforcement.
See the [technical paper](paper.txt) for the report contract and limits.

## Test-driven feature architecture

The [acceptance catalog](tests/acceptance/catalog.rs) maps the intended scope to
**100 named contracts**: 82 pilot scenarios across all twelve gates, 8 release
scenarios, 5 conditional controls, and 5 future-feature scenarios. The
[evidence checker](tests/acceptance/evidence.rs) enforces frozen plans, explicit
budgets, valid controls, observer coverage, profile bindings, and prerequisites.
Its 24 regression tests use synthetic fixtures **only to test the checker**.

```powershell
cargo test --locked --test acceptance
cargo test --locked --features acceptance --test acceptance -- --list
```

Real-observer contract tests require a separately reviewed evidence bundle and
are intentionally **red without it**, not ignored or counted as protection
passes. They replay evidence; they do not themselves install policies, call
providers, authenticate observers, or certify Shield. See the [technical paper](paper.txt)
for the red/green workflow, bundle schema, scope selections, and limitations.
The four R0 contracts were executed and remain red: no reviewed scope,
authority matrix, budgets/stop rules, or admission/disclosure bundle has been
supplied. Code changes and green software tests cannot substitute for those
operator decisions or the authorized Windows/provider lab.

## Documentation

- **[Technical paper and complete implementation record](paper.txt):** preserves
  the full detailed README, including architecture, limitations, validation
  evidence, commands, offline fixture walkthrough, publisher verification,
  authorized-lab procedures, cleanup/recovery behavior, and primary references.
- **[Product scope and acceptance contract](start.txt):** the governing design,
  milestone graph, and requirements before Shield can be called complete.

Read the technical paper before attempting any lab setup. Privileged policy or
service installation belongs only in an explicitly authorized disposable
Windows lab, not on a development workstation.
