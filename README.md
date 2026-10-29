# Shield

Shield is a Windows-first security controller for application admission and
tightly scoped AI-assisted workflows. It is designed to combine native Windows
execution controls, isolated AI workers, broker-held credentials, and explicit
task permissions with separate approval before publishing changes. The goal is
to limit unauthorized actions even when an approved AI worker is manipulated,
rather than relying on the model to follow instructions.

The problem Shield targets is the gap between allowing software to run and
controlling what it is authorized to do. A compromised application, hijacked AI
workflow, or prompt injection in untrusted content can misuse legitimate access
to files, credentials, networks, and connected accounts to disclose data or make
unauthorized changes. These attacks may use an existing process or account
without launching a new malicious executable. Application admission alone cannot
govern every subsequent action, and instructions to an AI model are not an
authorization boundary.

Experimental Windows/Rust implementation of part of the integrated pilot defined
in [start.txt](start.txt). **This is not a completed endpoint-security product,
an accepted integrated pilot, or a solution to every intrusion. Do not deploy it
with production credentials or data.**

## What exists

- An unelevated controller, a small typed-stdio AI worker, fresh zero-capability
  less-privileged AppContainer (LPAC) identities, an explicit inherited-handle list, atomic job assignment at process
  creation, one-process/memory/CPU limits, deadlines, and named-job cancellation.
  Before resume, native effective-access checks distinguish LPAC from ordinary
  AppContainer in addition to checking the package SID and zero capabilities.
- Frozen owner/Windows build-and-revision/executable profiles; separate task
  grants and epochs; protected local SQLite state; atomic operation/allowance
  reservations; bounded cached-result release; no automatic replay of uncertain
  inference or publication.
- Captured UTF-8 note/reference inputs, artifact digests, separate one-use
  publication approvals, changed-original rejection, exact readback, retained
  original snapshots, and explicitly approved local restoration.
- Fixed-route OpenAI Responses and read-only Microsoft Graph adapters. Requests
  have finite byte/time bounds, no proxy inheritance, no automatic redirects or
  inference retries, and no model tools. Inference explicitly requests
  `store: false`; that is not a promise of zero provider retention. Requested and
  returned model identifiers are recorded on completed calls.
- Windows Credential Manager custody outside the worker. Graph download
  capabilities remain broker-private; redirects are limited to exact configured
  HTTPS hosts and never receive the Graph bearer header.
- An explicit elevated lab setup/removal implementation for persistent,
  exact-worker-image WFP deny filters at IPv4/IPv6 ALE connect, accept and listen
  layers, separate from ordinary application admission.
- An owned App Control backend: native DefaultWindows baseline plus explicit
  application/DLL and fixed authoring-asset hash rules; reviewed revisions;
  separate lab-only installation/removal; native-state/byte checks; and durable
  no-replay reconciliation. Native enforcement is not yet qualified.
- An explicitly opted-in, protected read-only App Control verifier service,
  separate from the unelevated broker. It has a fixed profile/plan/owner binding,
  protected image/configuration, authenticated local IPC, and explicit lab-only
  installation, removal, no-replay reconciliation and separately reviewed
  cleanup with retained retirement evidence. It has not been installed or
  deployment-qualified.
- Exact whole-file SHA-256 plus pinned native Authenticode publisher verification,
  with an explicit frozen profile opt-in for broker, protected verifier and
  recovery image checks. This authenticates neither update metadata nor the
  suitability of the program; the development binaries remain unsigned.
- Read-only inventory, deterministic owned canaries, local audit-chain
  verification/export, honest status, and a clearly marked manual fixture mode.

The worker is a narrowly scoped custom client, not Codex CLI or support for
arbitrary existing agents. The host builds the one supported inference request;
the worker cannot choose URLs, credentials, file destinations, commands or tools.

## Critical current limits

The earlier ordinary zero-capability AppContainer canary **connected to an owned
IPv4 loopback listener**, which independently accepted it. That failed baseline
is retained. The launcher now requires zero-capability LPAC and verifies its
effective ordinary/restricted-package access before resume. Its worker exits
normally and the current eight scoped observations pass: tested file/process/
credential/child access is denied and the owned listener accepts no connection.

The network observation is specifically **Winsock initialization failed with
10107**, not a proven firewall rejection of a connect. The host positive control
uses the same native probe and successfully connects to that listener. Microsoft
defines 10107 as a generic system-call failure; do not treat it as an authorization
error or proof that raw, brokered, indirect, LAN, Internet or IPv6 egress is blocked.
Rust's standard TCP initialization previously panicked on this return value and
terminated the diagnostic worker with exit 101. The bounded native probe records
the failing operation/error instead; it does not add a capability or exemption.
An actual LPAC worker also completed the offline Start/Infer/InferenceResult/
Complete stdio exchange with exact owned fixture bytes. That is not a real model
call or M1 certification.

Consequently, AppContainer alone is not used as a sufficient network boundary.
Live execution requires the owned App Control policy and exact persistent WFP
objects to be readable and verified, then reruns the scoped native canaries
before granting a live worker.
Missing policy, inability to verify it, or a failed canary refuses execution.
The controller uses a 100 ms local lease-poll interval and a one-second interval
between native/profile checks. Those checks are still serialized: native CiTool
inventory can itself consume up to five seconds, and native API/SQLite latency
also matters. A separate monotonic-deadline monitor, which does not query SQLite
or native policy, terminates the owned worker job at its deadline or if its
controller signal disappears before verified worker completion. Final successful
output closure rechecks the host, WFP, owned App Control policy, task authority
and deadline; an earlier green check cannot substitute for that recheck.
These are not accepted worst-case termination or containment-time guarantees.

**The WFP setup/removal implementation has not been exercised in an authorized
elevated disposable lab.** Setup now supplies administrator-owned, protected
object ACLs: SYSTEM/Administrators retain control and the enrolled daily-user SID
receives only object read and security-descriptor read access. Verification checks
those permissions on the provider, sublayer and all six filters. No engine-wide
permissions are changed. Windows in-memory Authz checks allow that identity's
read and deny policy add/link/write, delete, ownership and ACL changes; they do
not prove installed-object behavior. A fresh unelevated read-only probe opened
WFP but reported that its required owned provider did not exist.
Actual installed-object standard-user verification, indirect/brokered
egress, Internet/LAN and IPv6 effects, reboot, controller-loss behavior and
enforcer faults still require actual validation. Never run the entire broker
elevated to bypass a failed verification.

Microsoft documents `NetworkIsolationSetupAppContainerBinaries` as supplying
image-path information to third-party firewalls, not as evidence that these
worker connections are blocked. No loopback exemption or machine-wide firewall
change was added to conceal the failed canary.

Ordinary application-admission authoring/deployment code now exists, but
**no Shield App Control policy has been deployed or effect-qualified**.
This Core workstation lacks ConfigCI and the native example template. Its
read-only support command reports the missing prerequisites explicitly.
Native inventory is not Shield enforcement, and launching something through
Shield cannot satisfy E1. No live model/Graph workflow, independent direct-provider
ceiling/revocation test, integrated attack chain, O1 recovery qualification or
representative-user P0 pilot has passed. All twelve milestone statuses remain
unverified. There is no authenticated updater, product installer/signing
pipeline, qualified administrator-protected controller/service deployment,
or public support commitment.

## Build and software checks

Use the pinned toolchain from the Shield directory on Windows:

```powershell
cargo check --locked --all-targets
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo test --release --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

The [Windows workflow](.github/workflows/windows.yml) runs formatting, strict
all-target Clippy and debug/release builds on `windows-2025`, with read-only
repository permissions and a commit-pinned checkout action. The hosted runner's
administrator token is used only for builds and ephemeral test-account setup.
The [hosted wrapper](.github/scripts/hosted-native-tests.ps1) refuses execution
outside a GitHub-hosted Windows VM, creates a fresh standard-user identity,
grants it workspace access and read/execute access to the installed toolchain,
and launches native tests with that identity's loaded profile. The native helper
independently checks the actual process elevation before running tests.
The wrapper removes the test account on exit; GitHub disposes of the VM,
including on cancellation. No production credentials or self-hosted runner
are required. Checkout does not persist Git credentials.

The [native-check script](.github/scripts/native-tests.ps1) can also be run locally
from an authorized unelevated development session:

```powershell
& .\.github\scripts\native-tests.ps1 -ReportDirectory 'C:\lab\Shield-checks-new'
```

It refuses an elevated process or an existing report directory, runs both
debug/release test suites and verifies both eight-observation LPAC reports
against independently computed executable hashes. It does not install services,
change security policy, provision provider credentials or bypass a failed check.
These are software regressions and scoped observations, not deployment,
complete-egress or provider/account qualification. Native reports stay on the
runner; no executable, report or credential is automatically uploaded.
The helper uses the machine's normal execution policy; do not bypass or weaken
workstation policy to execute it.

Recorded source validation on 2026-10-29: all 82 tests passed in both debug and
optimized release (74 library,
4 command-parsing and 4 actual native/CLI workflows), formatting passed, and all-target
Clippy passed with warnings denied. New checks include independently observed
termination of owned suspended processes, loss of a deadline-monitor owner,
final native-health/deadline output refusal, and Windows in-memory WFP ACL
evaluation, strict single-response probe framing, bounded terminal-safe native
failure diagnostics, the offline LPAC worker exchange, and verifier binding,
ACL/Authz, actual bounded named-pipe exchange/cancellation/client identity,
peer refusal, hidden-service/direct-launch refusal, and review-bound cleanup.
Cleanup checks cover retirement/replay binding, stale review digests,
interrupted remaining-object validation, actual NTFS by-handle file/directory
deletion, changed-object/hardlink/nonempty-directory refusal, rejection of
user-owned targets, and ordinary-user authorization refusal with otherwise
valid exact profile/plan bindings. Publisher checks cover canonical pins,
exact-zero native success, bounded signer metadata, SHA-2 artifact digests,
unsigned/hardlinked-file refusal, legacy profile digest preservation and
opt-in host/service/recovery enforcement, including refusal before creating
state or a pinned template. The normal locked
release build and current-source execution succeeded without changing native
policy after the earlier error-4551 blocks, including the `quote` build script.
Both current debug and release executables reran the LPAC canaries: all eight scoped
observations passed, with Winsock startup failure and no listener acceptance
recorded explicitly, not reclassified as a complete network-denial proof.
Both debug and release versions of the inert ordinary-launch controls
ran directly from PowerShell and produced independently checked exact marker
bytes before any Shield admission policy was installed; this is baseline
evidence, not a Shield denial or E1 pass.

The application is Windows-only. The note workflow supports ordinary absolute
local-drive paths and single-link regular files on NTFS. UNC/device/verbatim
paths, reparse points, alternate streams, ambiguous aliases and unsupported
text are rejected. The owner, Windows edition/build/revision and executable
digest are frozen at enrollment. Rebuilding/updating is not an implicit
authorization to continue an old profile.

Windows Code Integrity blocked a test executable, the formatter helper, and a
release dependency build script during development with error 4551. Normal
formatter/test/release build and execution later succeeded without policy changes; that does not
establish distribution/signing compatibility. If a normal command is blocked,
retain its failure and use the authorized lab/signing process. Do not disable
App Control/Smart App Control/Defender, add broad exclusions, rename binaries
to evade policy, or elevate the runtime.

## Pinned package publisher verification

This is a read-only check, not an installer or an updater. Set `$artifact` to a
normal absolute local NTFS file path, `$reviewedArtifactSha256` to the independently
reviewed complete-file digest, and `$trustedPublisherCertificateSha256` to an
independently authenticated publisher pin. Both pins must be exactly 64 lowercase
hexadecimal characters:

```powershell
& .\target\release\shield.exe release verify $artifact `
  --expected-sha256 $reviewedArtifactSha256 `
  --publisher-cert-sha256 $trustedPublisherCertificateSha256
```

The publisher pin is **SHA-256 of the DER-encoded leaf signing certificate**,
not a SHA-1 thumbprint, subject/issuer string, CA pin or permission for any
Windows-trusted publisher. Extracting a certificate from the candidate itself
does not establish the trusted pin or authorize an update.

The check pins the single-link, non-reparse regular file against normal
write/delete sharing, checks its complete bytes, verifies primary Authenticode
signature index 0 with native WinTrust, checks the exact verified certificate
and a SHA-256/384/512 artifact-signature digest, closes native verification state,
then rechecks the held file's fingerprint. The input bound is 128 MiB.
No catalog discovery, alternate-signer selection, trust enrollment or
unsigned fallback is implemented. Cargo build outputs can be hardlinked;
inspect an owned normal copy of the exact bytes instead of weakening the
single-link guard. Copying an unsigned binary does not make it signed.

WinTrust is resolved lazily from System32, like the verifier's role-only
Shell/COM APIs, so it is not eagerly initialized in the LPAC worker. Only native
return value zero is success. Whole-chain revocation checking uses cached data
only, with no UI or online retrieval fallback; unavailable/unknown revocation
is a failure, not a bypass. Certificate/timestamp handling otherwise follows
current Windows trust policy. Cache availability and native API latency are
not qualified whole-call timing guarantees.

`template --publisher-cert-sha256 <pin>` explicitly opts a new frozen profile
into the check and verifies the current image before writing the template.
The optional `publisher_cert_sha256` field is omitted when unset, preserving
old profile digest shapes and experimental hash-only behavior, **not** claiming
an authenticated publisher. When set, normal host/platform checks, protected
verifier image checks, state initialization and endpoint/verifier/WFP recovery
authorization enforce it. Recovery under OS revision drift does not waive
publisher verification. Certificate renewal/rotation changes the binding;
old profiles do not silently migrate. Current unsigned development builds
intentionally cannot create or operate a successfully publisher-pinned profile.

Actual debug and release experiments accepted an owned copy of a Microsoft-signed
fixture with its exact pins and rejected a different publisher pin. Changing
only the owned fixture's PE checksum rejected the old complete-file hash but
still passed native Authenticode with the new complete-file hash: Authenticode
intentionally excludes that checksum and certificate-related regions. Hence
the separate complete-file digest is necessary. Neither fixture was executed;
both original and modified temporary copies were removed. The Microsoft
certificate is a test fixture, **not Shield's signing identity**.

Success explicitly returns `update_authorized: false` and `effect_gate_pass: false`.
Package publisher authentication is distinct from TUF metadata authorization,
App Control signer rights, malware safety, SmartScreen reputation and deployment
qualification. There is still no production signed Shield release, authenticated
updater/protected version floor, qualified signing/key-rotation/recovery process,
or qualified first-download/native-consumer compatibility.

Primary references: Microsoft's [WinVerifyTrust return contract](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
[verification-state/revocation flags](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data),
and [PE Authenticode hash exclusions](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash).

## Safe local manual fixture

This tests local staging, review and publication only. It never calls a model
or Graph, does not install WFP/App Control policies, and cannot pass a live gate.
Use the normally built release binary. A separately built debug binary is also
available for development; it has a different frozen image identity and does not
authorize reuse of a release profile:

```powershell
$shield = (Resolve-Path .\target\release\shield.exe).Path
$lab = Join-Path $env:TEMP ("Shield-demo-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $lab | Out-Null
$state = Join-Path $lab 'state'
$note = Join-Path $lab 'note.txt'
$reference = Join-Path $lab 'reference.txt'
$proposal = Join-Path $lab 'proposal.txt'
Set-Content -LiteralPath $note -Value 'Original note' -Encoding ascii
Set-Content -LiteralPath $reference -Value 'Explicit local fixture' -Encoding ascii
Set-Content -LiteralPath $proposal -Value 'Human-reviewed replacement note' -Encoding ascii

& $shield --state $state init
$prepared = & $shield --state $state prepare --note $note --instruction 'Edit this manual fixture' --fixture-reference $reference | ConvertFrom-Json
$task = $prepared.task
& $shield --state $state inspect $task
& $shield --state $state stage-lab $task --proposal $proposal
& $shield --state $state review $task --approve
```

The last command shows literal, untrusted proposal text and asks for a fresh
trusted-host challenge. Copy the returned approval UUID into the following
command; there is no unrestricted `--yes`:

```powershell
& $shield --state $state publish $task --approval 'REPLACE-WITH-RETURNED-APPROVAL-UUID'
Get-Content -LiteralPath $note
& $shield --state $state status --require-ready
```

`status --require-ready` deliberately exits nonzero: manual success is not
integrated protection. `inspect` returns one JSON object with `disclosure` and
`disclosure_digest`. Automation that has independently reviewed the exact
artifact may use `review --reviewed-digest <lowercase-SHA256>`; that form returns
one JSON approval object without interleaving untrusted proposal text. Digests
bind content; they do not prove benign intent.

## Ordinary application admission: authorized lab only

The additional base policy uses the installed native
`DefaultWindows_Enforced.xml` and native ConfigCI hash rules. Its enforcement
does not depend on a Shield launcher or any AI agent running. Existing native
policies are retained; enforced base policies intersect. This policy cannot
make another policy allow blocked code. The baseline intentionally trusts a
Windows/driver/Store-app set, not just the explicitly selected artifacts.
Admission is not malware classification or behavior isolation for admitted code.

First run the read-only, state-independent prerequisite check:

```powershell
& $shield endpoint authoring-support
```

Missing ConfigCI/template support is an explicit unsupported authoring profile.
Do not substitute an unverified module, disable native protection, or treat a
made-up policy as equivalent. In a compatible disposable lab, initialize private
state normally and prepare the full desired application/DLL set:

```powershell
$admission = & $shield --state $state endpoint prepare --application .\target\release\shield-admission-allow.exe | ConvertFrom-Json
$plan = $admission.plan.id
$planDigest = $admission.plan_digest
& $shield --state $state endpoint inspect $plan
```

The current Shield image is included automatically. The fixed authoring script
is also admitted by its native hash so future admissions do not require
disabling script enforcement. Input files are pinned against ordinary
write/delete changes during generation; approved native source/XML/CIP digests
and all declared input identities are bound to the review. Native PE/script
hash matching is not the same as the whole-file release digest shown for
provenance. Necessary third-party helper executables/DLLs must be declared;
installer and ordinary-user usability remain unqualified.

Only the separate, explicitly authorized elevated **same-owner** lab helper
may install. Obtain the profile digest from enrollment/status and supply both
exact review bindings; installation plans expire after one hour:

```powershell
& $shield --state $state endpoint install $plan --authorized-lab --expected-profile-digest $profileDigest --expected-plan-digest $planDigest
```

This is computer-wide policy. Verify a disposable-machine restore and native
boot recovery before installation. There is no automatic elevation, reboot,
policy overwrite, baseline removal or retry. Signed/system/supplemental or
changed owned-policy objects are refused. Unrelated native policy state is
compared before/after; unexpected drift prevents a success result.

From the daily-user context, `endpoint verify` requires the confirmed owned
enrollment, exact native ID/base/version/name, unsigned non-system status,
on-disk digest and active/authorized flags. Access denied is not converted into
healthy status. Current unelevated CiTool inventory is denied on this
workstation. The opt-in protected verifier below supplies a source implementation
for this gap, but actual installation and standard-user operation remain
unqualified. Never elevate the broker to conceal a failed verification.

To admit changed application versions, prepare the **full** desired set again
with `--previous <prior-plan-UUID>`, inspect its new digest and install that next
native revision. This is not an authenticated Shield software updater.
Old application hashes not retained in the new explicit set are no longer
authorized by those explicit rules; the native baseline's trust still applies.

Use the same review-binding flags for `endpoint reconcile <plan>` or
`endpoint remove <plan>`. Reconciliation queries actual state without replaying
mutation. A known staged policy can be recorded as `staged_not_active`, permitting
explicit owned removal without forcing it to become active; it never becomes
live authority merely because the journal says its dispatch is confirmed.
Pending reboot/removal or unknown outcomes remain visible. Missing/corrupt
state and broader reinstall/update/boot recovery are not automatically repaired.

Two separately built, inert native executables support independent ordinary
launch tests: `shield-admission-allow.exe` and `shield-admission-deny.exe`.
They contain no AI/controller integration and only create a new marker with
their distinct compiled identity and nonce. Use a fresh owned directory per
case, outside the Shield launcher:

```powershell
$nonce = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$probeDirectory = Join-Path $env:TEMP "Shield-admission-$nonce"
New-Item -ItemType Directory -Path $probeDirectory | Out-Null
$marker = Join-Path $probeDirectory 'marker.txt'
& .\target\release\shield-admission-allow.exe $marker $nonce
Get-Content -LiteralPath $marker
```

Repeat with a new nonce/directory for the unapproved executable. Before Shield
policy both controls must demonstrate legitimate execution. After the owned
policy is active, require the allowed marker plus independent observations of
the denied effect and the correct owned-policy Windows event; absence of a
marker or another native policy's block alone is insufficient. Exercise ordinary
and alternate launch, scripts/delegation, updates, reboot/removal and final
composed helpers before E0/E1 acceptance. No such post-install pass exists.

## Opt-in protected read-only verifier

**Source implementation, not a deployed or qualified boundary.** This service
runs as LocalSystem and therefore extends the trusted computing base. It is not
an elevated AI broker, credential service, installer for arbitrary software, or
general command executor. Do not install it on the development workstation to
make a demonstration pass.

Select it **before enrollment and policy preparation**, using the same final
binary that will run:

```powershell
& $shield template --output .\pilot-profile.json --protected-verifier
```

The frozen profile records `endpoint_verifier: "protected_service"`. Existing
profiles default to direct verification without changing their serialized
digest shape. There is no automatic mode migration, elevation, service
installation, or fallback to disk-only/cached/coarse policy status.

After reviewing and activating the exact owned App Control plan in an
authorized compatible disposable lab, the separate elevated **same-owner**
operator may explicitly install its verifier:

```powershell
& $shield --state $state verifier install $plan --authorized-lab --expected-profile-digest $profileDigest --expected-plan-digest $planDigest
```

The installer verifies the active policy first. Its per-profile/per-plan
Program Files directory, copied frozen image, binding and lifecycle markers
are created with administrator ownership and protected ACLs, not created as
user-owned objects and subsequently permission-repaired. The daily SID has
read/execute only. The SCM object grants that SID only configuration/status
query and security-descriptor read; it cannot start, stop, reconfigure or delete
the service. Creation uses an administrator-default-owner token, followed by
explicit SCM security/configuration readback before startup. The broker never
elevates and the service never opens the user-owned SQLite store.

The SCM command fixes only profile UUID, plan UUID and enrolled owner SID.
Startup verifies protected directory/file ownership and permissions **before**
capturing/parsing configuration bytes. Configuration binds the exact frozen
profile, plan digest, policy UUID/revision and installed-CIP digest. No request
can choose a policy, filesystem path, executable, URL, credential or command.

The local-only first-instance pipe accepts strict length-bounded messages
(4 KiB maximum) with a fresh nonce and exact binding digest. The server verifies
the actual client's enrolled SID and non-AppContainer token through pipe
impersonation, then reverts before privileged work. It performs only the existing
fixed native CiTool inventory and exact owned metadata/installed-byte checks.
The client verifies protected files and SCM configuration/DACL/account/SID mode,
holds the actual process handle, checks its image and LocalSystem token, and
matches the pipe's server PID before accepting its nonce-bound response.
Pipe name, PID or self-reported JSON alone is not authentication.

The service grants the daily identity only query-limited/synchronize access to
its own process and `TOKEN_QUERY` to its own token so that authentication can
work without making the broker an administrator. No process memory/termination/
duplication or token duplication/adjustment rights are granted. In-memory
Windows Authz checks exercise these masks; actual installed-object access still
requires lab qualification.

Transactions have a ten-second pipe-I/O budget, SCM state waits a fifteen-second
budget, and cancellation a one-second completion-drain grace. Pending native
I/O storage is never freed/reused before completion; unconfirmed cancellation
logs a failure and aborts the owned process. Native metadata, DLL loading,
hashing and OS latency are not a qualified whole-call worst-case guarantee.
Acknowledgments ensure a response was consumed before server disconnection.
Startup/termination failures are reflected in SCM status; request failures are
returned explicitly and/or logged through bounded Event Log/stderr diagnostics.
These engineering bounds are not accepted R0 containment budgets.

Return to the standard-user context for fresh verification:

```powershell
& $shield --state $state verifier status $plan
& $shield --state $state endpoint verify
```

Opted-in runtime startup, periodic health checks and final output closure use
this path. Missing, stopped, pending, drifted, differently bound or unauthenticated
service state fails closed. Elevated endpoint authoring/setup/recovery continues
to use direct native checks, avoiding a circular dependency on the service.

Close/reconcile work before explicitly removing or reconciling the service:

```powershell
& $shield --state $state verifier remove $plan --authorized-lab --expected-profile-digest $profileDigest --expected-plan-digest $planDigest
& $shield --state $state verifier reconcile $plan --authorized-lab --expected-profile-digest $profileDigest --expected-plan-digest $planDigest
```

These are separate authorized actions, not an instruction to run both
automatically. Immutable dispatch/confirmation/removal markers retain uncertain
outcomes. Reconciliation reads native state and may confirm an already completed
effect; it never repeats create/start/stop/delete. Drift or partially completed
mutations can require separately reviewed administrator recovery/re-enrollment.
Removal retains the protected image, binding and lifecycle evidence until a
separate reviewed cleanup; repeated installation/removal of the same plan is
not a repair or automatic retry.
An endpoint revision requires a separately reviewed matching verifier lifecycle.
There is no qualified product updater or comprehensive uninstall/recovery flow.

### Explicit reviewed cleanup

This is a narrow **authorized-lab, already-elevated same-owner** action, not a
general uninstaller. Close/reconcile active work first. Inspection requires
native SCM service absence, a matching protected binding and confirmed owned
removal, or a valid retained retirement record after interrupted cleanup. A
stopped, pending-deletion, foreign or inaccessible service is not absence.

```powershell
& $shield --state $state verifier inspect-cleanup $plan --authorized-lab --expected-profile-digest $profileDigest --expected-plan-digest $planDigest
```

Review the returned inventory, identities, remaining/absent objects and
`cleanup_digest`. Only then set `$cleanupDigest` to that exact reviewed value
and explicitly dispatch:

```powershell
& $shield --state $state verifier cleanup $plan --authorized-lab --expected-profile-digest $profileDigest --expected-plan-digest $planDigest --expected-cleanup-digest $cleanupDigest
```

Use a **separate copy of the exact frozen executable**, not the protected
service image being removed. Only the six fixed binding/image/lifecycle files
and their exact empty plan directory can be removed. Unknown entries, reparse
points, hardlinks, changed ACLs, changed content or replaced object identities
refuse cleanup. Deletion validates protected ownership/permissions before
reading, compares the complete reviewed fingerprint on an exclusively opened
handle, and uses native by-handle disposition. The directory operation cannot
recursively delete children.

Before any deletion, cleanup publishes a protected retirement manifest and an
immutable dispatch record keyed by the exact reviewed digest. Publication uses
synced protected staging files and a same-directory, no-replace
`MoveFileExW` operation with `MOVEFILE_WRITE_THROUGH`; there is no overwrite,
cross-volume copy or reboot-deferred deletion. The digest-keyed destination
also rejects duplicate dispatch from a different copy of user state.
Retirement, dispatch and confirmation evidence remains under the protected
profile directory; interrupted staging files are retained rather than
indiscriminately swept.

Retirement blocks installation, service startup and daily verification of that
same plan, even if its old files reappear or retirement evidence is damaged.
After interruption, **inspect again and approve the fresh remaining-state
digest**. Only originally bound unchanged objects may remain; absent objects
are observed, not replay-deleted. Every published retirement/attempt or
observed deletion changes the review digest. Confirmation requires fresh
native service and payload/directory absence. Already confirmed cleanup
cannot be dispatched again.

Engineering bounds are 16 deletion-dispatch attempts per plan, 4096 inspected
profile-root entries and 16 KiB per JSON record. If the final deletion completed
but confirmation was interrupted, a fresh explicit review can confirm absence
without another deletion dispatch, including at the attempt limit. Exhausted
attempts with remaining objects require separately reviewed administrator
recovery; no quota reset or automatic retry is provided.

`cleaned` means only those owned verifier payloads and plan directory are absent.
The profile root and retirement evidence remain. App Control/WFP policies,
credentials, user state and other plans are untouched. This is not a
crash-atomic multi-file transaction, secure erasure, qualified power-loss
recovery, product update or complete uninstall. Privileged deployment,
interrupted/rebooted cleanup and installed-object behavior still require the
authorized disposable lab; unprivileged NTFS tests do not supply that evidence.

The shared controller/worker image must not eagerly import role-only Shell/COM
DLLs: doing so caused the real LPAC stdio test to fail at initialization with
`0xc0000142`. Those fixed system APIs are now resolved only in the verifier path,
using `LOAD_LIBRARY_SEARCH_SYSTEM32`; no worker capability or security-policy
exception was added. Both final-source debug/release LPAC workflows and scoped
native probes pass again.

No service was installed/started, and no WFP/App Control policy was changed
during this work. Successful SCM deployment, daily-user process/token reads,
native effects, adversarial replacement, startup/reboot, fault handling and
removal/recovery remain acceptance work. This feature passes no milestone gate.

## Experimental live lab setup

Do not run privileged setup on the development workstation merely to make a
demonstration work. Complete the R0/L0 authorization, isolated Windows restore,
provider-resource ownership, credential custody, independent caller and recovery
requirements first.

1. Select the actual Windows/NTFS configuration, custom client/model settings,
   named local note and real Graph resource, allowed/forbidden operations,
   setup/daily/recovery identities, native baselines and finite acceptance
   budgets. The defaults are engineering bounds, not accepted product budgets.
2. Use test-only Microsoft Graph application credentials and provider-native
   selected-resource read permissions. Verify allowed and valid forbidden
   resources/verbs with an independent caller. Do not add broad application
   scopes to repair a failed example. App-only Microsoft 365/SharePoint
   provisioning is not proof of personal Microsoft-account or consumer support.
3. Give the inference identity only the required native authority, approve
   disclosure to OpenAI, and record provider-side limits/costs and recovery.
   Local call/output-token allowances are not account-wide or hard financial
   limits and do not coordinate unrelated profiles or applications.
4. Generate a template with the exact binary that will run:

   ```powershell
   & $shield template --output .\pilot-profile.json
   ```

   Include `--protected-verifier` now if that mode is selected; do not edit an
   enrolled profile to enable it later. Provision the verifier separately after
   the owned App Control policy is active and before daily-user verification.

   As the provisioning operator, fill its `graph` object with actual
   `tenant_id`, `client_id`, `drive_id`, `item_id`, optional
   `forbidden_item_id`, and 1..8 exact lowercase `download_hosts`.
   Save UTF-8 without a BOM. Do not hand-edit generated owner/binary fields,
   ACLs or the journal. Only UTF-8 text/plain, text/markdown or application/json
   reference files are supported; they remain untrusted data.
5. As the unelevated owner, initialize a new private state directory, separate
   from the manual demonstration. Keep its returned profile digest.
   Existing state is never overwritten. Set credentials interactively:

   ```powershell
   $liveLab = Join-Path $env:TEMP ("Shield-live-lab-" + [guid]::NewGuid())
   New-Item -ItemType Directory -Path $liveLab | Out-Null
   $state = Join-Path $liveLab 'state'
   & $shield --state $state init --profile .\pilot-profile.json
   & $shield --state $state credential openai set
   & $shield --state $state credential graph set
   ```

   Secrets are not accepted as CLI arguments or saved in profiles/audit exports.
6. Only in the explicitly authorized disposable lab, use a separate elevated
   shell for `boundary install --authorized-lab --expected-profile-digest
   <digest>` with the same explicit `--state` path. The prototype is bound to
   the enrolled owner's SID; alternate-admin-account setup and a protected
   production broker deployment are not implemented. The optional LocalSystem
   read-only verifier is separate, not an elevated broker. WFP setup adds only the owned per-profile provider/sublayer/six
   exact-image deny filters, in a WFP transaction. Owned keys, image and
   intent are journaled before mutation. Explicit per-object ACLs keep control
   with SYSTEM/Administrators and grant only read/security-descriptor read to
   the enrolled SID. It never automatically elevates or changes engine-wide ACLs.
7. Return to the standard-user shell. Run `boundary verify`. Access denied,
   absent/changed objects, permissions or a changed image blocks the runtime; do not broaden
   privileges to mask it. Configuration is not an effect-test or pilot pass.
   The owned endpoint policy from the preceding section must also pass
   `endpoint verify` as the daily user before a live task can start.
   Existing or drifted WFP objects are not overwritten or permission-repaired
   automatically; preserve their owned-key evidence for authorized lab recovery.
8. Use `prepare --note <lab-note> --instruction <task>` without a fixture flag.
   The broker obtains and bounds the Graph reference before starting a worker,
   checks identity/version around capture, and seals the actual bytes/digest.
   Signed download URLs are not task grants or evidence.
9. Inspect the captured disclosure, then use `run <task> --authorized-lab`.
   It requires a trusted interactive disclosure challenge or an exact
   `--approved-disclosure-digest`. The worker gets no provider credentials.
   Refusal/incomplete output, unsupported tools/content, stale epochs,
   missing enforcement or unknown dispatch cannot become a publishable result.
10. Review and approve the closed artifact separately, then publish it. Real
    clean/contaminated utility, malicious-worker cases and all mandatory
    provider/composition/recovery/user gates remain acceptance work.

The fixed worker image is separate from the network-capable controller.
Persistent filters are intentional so closing the controller does not itself
remove that policy. This is a design property, not a measured controller-crash
or reboot guarantee. Reinstallation is not a repair for unknown native state.

## Publication, interruption and evidence

- Publication pins parent handles, locks the original, compares opened-object
  identity/version/content, consumes the exact approval durably, writes in
  place, syncs and reads back. **It is not crash-atomic replacement.**
  Existing writable mappings and hostile same-user/admin writers are not a
  qualified support claim. A changed original is refused before writing.
- The protected task directory retains the original note. State/snapshots are
  private plaintext, not general encrypted storage or DLP. They are retained
  until the owner deliberately archives/removes them; at most 128 task records
  are accepted per state directory. No production retention/GC policy is
  qualified. Do not commit/share state, real reference bytes or credentials.
- `cancel <task>` rotates local authority and requests named-job termination.
  It does not recall a dispatched HTTP request, disclosed content, provider
  token/session or completed effect. Removing a local stored credential also
  does not revoke the issuer's existing authority.
- After controller interruption, `recover <task>` requires exclusive controller
  ownership, verifies/removes the known task worker identity when applicable,
  and reconciles the journal. Reserved operations are not replayed; dispatched
  uncertain effects remain unknown; old unused approvals are invalidated.
  Remaining reservations are conservatively retained.
- An uncertain local publication requires `restore <task>` with a new trusted
  challenge or exact reviewed current-file digest. Restoration requires the
  same original file object and the protected backup digest, then writes and
  reads back the original bytes. It neither erases uncertain operation history
  nor recalls remote effects. It is not complete O1 eradication/recovery.
- `audit --export <new-file>` emits metadata/digests, not note/reference/model
  text or secrets. Its local ACL-protected hash chain detects tested corruption;
  it is not an independent, administrator-proof observer or remote effect log.
- For removal in the authorized lab, first close/reconcile affected work, keep
  the enrolled worker image/state, and use the separate elevated
  `boundary remove --authorized-lab --expected-profile-digest <digest>`.
  Removal verifies the owned exact policy before deleting it. A changed/missing
  worker or unknown native objects refuses automatic removal. Drift migration,
  reinstall/uninstall after damage and full incident recovery still need a
  tested authenticated deployment/recovery design.

## Required work before calling Shield complete

The milestone graph and full contract in [start.txt](start.txt) are unchanged.
R0/L0 and E0/A0/C0 feasibility must establish a usable, authorized profile before
hardening and acceptance. Required remaining work includes native endpoint
deployment/effect qualification and native-value comparison, validated privileged/standard-user
deployment, actual provider ceilings and existing-capability revocation,
network/IPC/process and fault testing on the same recorded configuration,
independent effect observations, integrated and assumed-compromise cases,
qualified recovery/re-enrollment, representative benign-user validation, and
owned signing/distribution/maintenance. Safe refusal and software tests cannot
replace those outcomes or silently turn the project into an agent-only product.

Implementation references:
[AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[Chromium effective LPAC token checks](https://github.com/chromium/chromium/blob/main/sandbox/win/src/app_container_test.cc),
[Winsock startup result handling](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsastartup),
[Winsock error meanings](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2),
[WFP ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers),
[native WFP AppID construction](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0),
[App Control management](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands),
[service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[native security updates](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo),
[pipe server identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid),
[asynchronous cancellation lifetime](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex),
[restricted system-DLL loading](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw),
[native baseline policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/example-appcontrol-base-policies),
[Graph content/download capabilities](https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0),
[OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create),
and [HTTP retry semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2).
