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
  job resource limits, deadlines, and cancellation.
- **Explicit authority:** frozen enrollment profiles, task grants and epochs,
  transactional allowances, protected local state, and no automatic replay of
  uncertain effects.
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
cargo clippy --locked --all-targets -- -D warnings
```

The [Windows workflow](.github/workflows/windows.yml) performs formatting,
strict Clippy, debug/release builds, and native regression checks. Native tests
run under a fresh standard-user identity on a disposable GitHub-hosted VM,
with an independent elevation check.

Recorded validation: **82 tests passed in both debug and release**, and both
builds passed eight scoped native observations bound to their executable
hashes. These are software checks, not deployment or protection certification.
Do not weaken Windows security or execution policy to make a check pass.

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
- There is no production signed release, authenticated updater, product
  installer, qualified deployment/recovery process, or public support commitment.

Live execution requires verified native enforcement and scoped canaries; missing
or unverifiable protection refuses execution. The offline manual fixture tests
staging, review, and publication only and cannot establish live readiness.

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
