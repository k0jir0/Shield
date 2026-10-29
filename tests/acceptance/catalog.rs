use super::evidence::{Assertion, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Gate {
    R0,
    L0,
    E0,
    A0,
    C0,
    M0,
    E1,
    M1,
    C1,
    I1,
    O1,
    P0,
    Release,
    Extension,
}

impl Gate {
    pub fn prerequisites(self) -> &'static [Self] {
        use Gate::*;
        match self {
            R0 => &[],
            L0 => &[R0],
            E0 | A0 | C0 => &[L0],
            M0 => &[E0, A0, C0],
            E1 | M1 | C1 => &[M0],
            I1 => &[E1, M1, C1],
            O1 => &[I1],
            P0 => &[O1],
            Release | Extension => &[P0],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Governance,
    Endpoint,
    Worker,
    Provider,
    Integrated,
    Operations,
    User,
    Distribution,
}

impl Layer {
    pub fn sources(self) -> &'static [Source] {
        use Source::*;
        match self {
            Self::Governance => &[AuthorizedReview],
            Self::Endpoint => &[Native],
            Self::Worker | Self::Integrated | Self::Operations => &[Native, Provider],
            Self::Provider => &[Provider],
            Self::User => &[Native, UserStudy],
            Self::Distribution => &[Native, AuthorizedReview],
        }
    }

    pub fn enforcer(self) -> &'static str {
        match self {
            Self::Governance => "authorized operator; frozen scope, lab and acceptance decisions",
            Self::Endpoint => "native execution/admission policy, independent of Shield launching",
            Self::Worker => {
                "OS identity/files/process/job/network boundary and typed broker journal"
            }
            Self::Provider => "provider-native identity/resource/action/session authorization",
            Self::Integrated => "composed endpoint, worker/broker and provider gates",
            Self::Operations => "authenticated narrow responder, owned-state journal and recovery",
            Self::User => "trusted approval/status interface and real ordinary-user workflows",
            Self::Distribution => {
                "package signer, metadata verifier, installer and protected version floor"
            }
        }
    }

    pub fn observer(self) -> &'static str {
        match self {
            Self::Governance => {
                "authorized reviewer of the named decisions and safety prerequisites"
            }
            Self::Endpoint => {
                "native state plus independent execution/effect and policy-attribution observer"
            }
            Self::Worker => {
                "host-side resource/effect observer plus real model/reference service observations"
            }
            Self::Provider => {
                "independent direct caller and actual provider response/state observer"
            }
            Self::Integrated => {
                "independent local and remote effect observers under one frozen case plan"
            }
            Self::Operations => {
                "independent remaining-authority, health, incident and restored-effect observers"
            }
            Self::User => {
                "consented representative-user study and native task/prompt/cost measurements"
            }
            Self::Distribution => {
                "independent native consumer and protected installation/update/recovery observer"
            }
        }
    }

    pub fn recovery(self) -> &'static str {
        match self {
            Self::Governance => "stop/change/continue decision; no unauthorized mutation",
            Self::Endpoint => "reviewed owned-policy removal and verified login/boot recovery",
            Self::Worker => "lease withdrawal, verified job/handle closure, new review and restore",
            Self::Provider => {
                "independently verified credential/session/capability cutoff and resource cleanup"
            }
            Self::Integrated | Self::Operations => {
                "O1 partial-failure reconciliation and authenticated re-enrollment"
            }
            Self::User => {
                "usable authorized removal/recovery without disabling unrelated protection"
            }
            Self::Distribution => {
                "authenticated owned rollback/recovery without lowering the trusted version floor"
            }
        }
    }
}

pub struct Case {
    pub id: &'static str,
    pub gate: Gate,
    pub layer: Layer,
    pub assertion: Assertion,
    pub variants: &'static [&'static str],
    pub intent: &'static str,
    pub extension: Option<&'static str>,
}

macro_rules! cases {
    ($($id:ident: $gate:ident, $layer:ident, $assertion:ident, [$($variant:literal),+], $extension:expr, $intent:literal;)+) => {
        pub const CASES: &[Case] = &[$(Case {
            id: stringify!($id), gate: Gate::$gate, layer: Layer::$layer,
            assertion: Assertion::$assertion, variants: &[$($variant),+],
            extension: $extension, intent: $intent,
        }),+];

        #[cfg(feature = "acceptance")]
        mod live_contracts {
            $(#[test]
            fn $id() {
                super::super::evidence::verify_from_environment(stringify!($id))
                    .unwrap_or_else(|error| panic!("{}", shield::util::literal(&error)));
            })+
        }
    };
}

cases! {
    pilot_r0_scope_and_operators: R0, Governance, Review, ["selected"], None, "Select Windows/NTFS, client/model/provider, legitimate task, daily/setup/recovery identities and authority owners; no silent consumer/enterprise substitution.";
    pilot_r0_resource_authority_matrix: R0, Governance, Review, ["selected"], None, "Freeze covered assets, caller/resource/verb routes, grant ceilings, shared/task ownership, exclusions and independent observers.";
    pilot_r0_budgets_and_stop_rules: R0, Governance, Review, ["selected"], None, "Declare finite safety, effort, cost, trial, utility, false-block, response and recovery budgets before probes, with owner/review date/stop criteria.";
    pilot_r0_admission_and_disclosure: R0, Governance, Review, ["selected"], None, "Declare trust/bootstrap, unknown/changed code, rule breadth, offline behavior, provider disclosure and policy/recovery provenance.";
    pilot_l0_isolation_and_restore: L0, Governance, Review, ["selected"], None, "Authorize disposable lab, exclude production secrets/data, restrict host sharing/egress and demonstrate local snapshot plus boot recovery.";
    pilot_l0_provider_cleanup: L0, Provider, Recovery, ["selected"], None, "Provision owned test-only identities/resources and independently verify cleanup and actual remote state after local restore.";
    pilot_l0_secret_custody: L0, Governance, Review, ["selected"], None, "Keep replay tokens/sessions/URLs in a separate protected expiring store, using non-secret evidence identifiers.";
    pilot_l0_independent_callers: L0, Provider, Utility, ["selected"], None, "An independent direct client can legitimately retrieve the allowed test resource before restriction probes.";
    pilot_e0_native_eligibility: E0, Endpoint, Utility, ["selected"], None, "Verify actual edition/build/native authoring and UMCI eligibility; preserve native protections and declare unsupported observations.";
    pilot_e0_ordinary_positive_controls: E0, Endpoint, Utility, ["allow", "deny"], None, "Both inert ordinary-launch controls must demonstrate valid exact effects before Shield policy; already-native-blocked paths earn no Shield credit.";
    pilot_e0_trust_and_rule_breadth: E0, Endpoint, Safety, ["artifact", "changed_version", "same_signer"], None, "Test actual hash/publisher/product/version matching, deny precedence and trust bootstrap; approved or signed does not mean benign.";
    pilot_e0_install_update_remove: E0, Endpoint, Recovery, ["install", "update", "reboot", "remove"], None, "Exercise minimal reviewed policy, legitimate application lifecycle, active state and safe owned-policy removal/boot recovery.";
    pilot_e0_native_value_comparison: E0, Endpoint, Comparison, ["native", "equivalent_native", "shield"], None, "Compare identical workloads against actual Defender/SmartScreen/Smart App Control and equivalent native hardening; demonstrate incremental protection or safer operability.";
    pilot_a0_real_client_model: A0, Worker, Utility, ["selected"], None, "Complete a real client/model/reference spike; mocks, offline converters and uncontained success do not establish hardened compatibility.";
    pilot_a0_documented_interfaces: A0, Worker, Utility, ["authentication", "routing", "helpers", "termination"], None, "Verify documented client hooks, broker-only credentials, required rights/routes, termination and maintenance cost without broader access.";
    pilot_c0_provider_gate: C0, Provider, Utility, ["selected"], None, "Verify actual account/tenant eligibility, consent/licensing/setup burden, Selected resource assignments and absence of broader overlapping rights.";
    pilot_c0_identity_and_capabilities: C0, Provider, Review, ["selected"], None, "Freeze every claimed human/app credential class, token/session/download capability, alternate content path and provider-enforced ceiling.";
    pilot_c0_response_authority: C0, Provider, Recovery, ["selected"], None, "A separately authenticated actual responder can revoke the owned authority and recover test resources within the declared budget.";
    pilot_m0_default_deny_grants: M0, Worker, Safety, ["unknown_operation", "explicit_deny", "ceiling_widening"], None, "Versioned immutable task authority cannot widen profile/provider ceilings; deny wins and untrusted input/configuration cannot grant rights.";
    pilot_m0_caller_and_task_binding: M0, Worker, Safety, ["forged_id", "cross_task", "stale_epoch", "restarted_worker"], None, "Authenticate the actual OS execution instance and current task lease; caller PIDs/IDs and old allows cannot authorize dispatch or cached output.";
    pilot_m0_worker_effective_isolation: M0, Worker, Safety, ["files", "process_memory", "token_handles", "ipc"], None, "Verify effective LPAC/principal ACLs, host-secret and process/handle access; low integrity or separate processes alone are insufficient.";
    pilot_m0_child_and_delegated_execution: M0, Worker, Safety, ["child", "breakaway", "service_delegation", "interpreter"], None, "Hostile worker cannot exceed declared helper/process authority through child, breakaway, approved interpreter or IPC/service routes.";
    pilot_m0_inherited_handle_boundary: M0, Worker, Safety, ["worker_allowlist", "concurrent_helper"], None, "Worker receives only declared handles; temporary inheritable worker pipes cannot leak into concurrently launched host helpers.";
    pilot_m0_credential_isolation: M0, Worker, Safety, ["files", "environment", "process", "responses", "logs"], None, "Actual extraction probes cannot obtain broker credentials, binding keys, capability URLs or protected configuration from the covered surfaces.";
    pilot_m0_typed_broker: M0, Worker, Safety, ["http", "shell", "filesystem", "signing", "provider_tools"], None, "Reject generic capabilities and unauthorized provider tools/connectors/uploads; only fixed bounded routes and approved parameters are callable.";
    pilot_m0_approval_authentication: M0, Worker, Safety, ["forged_text", "synthetic_input", "replay", "changed_parameters"], None, "Trusted approvals bind exact caller/task/operation/resource/artifact/epoch/expiry; worker text and forged UI input cannot approve.";
    pilot_m0_atomic_reservations: M0, Worker, Safety, ["concurrent_tasks", "duplicate_operation", "controller_restart"], None, "Reserve one-use authority and task/shared capacity atomically before effects; retries and restarts cannot reset counts or union grants.";
    pilot_m0_bounded_untrusted_inputs: M0, Worker, Fault, ["stdio", "json", "http_stream", "decompression", "queue"], None, "Reject malformed/oversize input while consuming it and enforce finite allocation, parser, queue, rate and in-flight limits.";
    pilot_m0_resource_envelopes: M0, Worker, Performance, ["worker", "broker"], None, "Measure/enforce declared process, CPU, memory, staging, byte, runtime, egress and token bounds; distinguish hard limits from monitoring.";
    pilot_m0_hard_limit_breaches: M0, Worker, Fault, ["cpu", "memory", "processes", "time", "bytes", "tokens", "egress", "queue"], None, "A hostile workload exceeding each declared hard limit is stopped or revoked with an explicit reason, no published partial output, wider permission or unrelated deletion.";
    pilot_m0_enforcer_preflight: M0, Worker, Fault, ["missing", "inaccessible", "audit_only", "pending", "drift"], None, "Refuse before launch when required actual native/provider boundaries cannot be freshly verified; never elevate or retry unprotected.";
    pilot_m0_protected_state: M0, Worker, Safety, ["acl", "journal", "audit", "snapshot", "configuration"], None, "Workers cannot modify authoritative state, approvals, audit, configuration or protected input/output snapshots.";
    pilot_m0_profile_drift: M0, Worker, Fault, ["os", "binary", "model", "policy", "provider"], None, "Security-relevant drift withdraws affected health/results; fresh task nonce/lease variation within a frozen profile is not drift.";
    pilot_m0_native_network_boundary: M0, Endpoint, Safety, ["ipv4", "ipv6", "connect", "accept", "listen", "owned_acl"], None, "Installed exact-image persistent WFP objects enforce declared effects and enrolled-user read-only rights; in-memory ACL tests and configuration are not installed evidence.";
    pilot_m0_native_policy_reconciliation: M0, Endpoint, Fault, ["active", "staged", "unknown", "foreign", "partial_change"], None, "Reconcile exact native IDs/options/revisions/installed bytes and mutation ownership; disk-only, staged, pending or inaccessible state cannot authorize live work.";
    pilot_e1_ordinary_launch_paths: E1, Endpoint, Safety, ["standalone", "composed"], None, "Ordinary and alternate native launch routes prevent declared effects with exact owned-policy attribution; no Shield launcher or AI installation dependency.";
    pilot_e1_interpreter_and_script_effects: E1, Endpoint, Safety, ["standalone", "composed"], None, "Observe actual approved interpreter/delegation/script effects, including constrained PowerShell and unenlightened hosts, not only block events.";
    pilot_e1_policy_composition: E1, Endpoint, Safety, ["standalone", "composed"], None, "Test UMCI, base-policy intersection, supplemental breadth, explicit denies and integrated helper exceptions while preserving unrelated policies.";
    pilot_e1_application_lifecycle: E1, Endpoint, Utility, ["standalone", "composed"], None, "Legitimate installs, changed applications, DLLs, updates, documents and ordinary launches remain useful under final rules.";
    pilot_e1_reboot_and_owned_recovery: E1, Endpoint, Recovery, ["standalone", "composed"], None, "Reboot/activation/removal and final composed helpers retain usable login and owned-policy recovery without overwriting native controls.";
    pilot_e1_held_out_challenges: E1, Endpoint, Safety, ["standalone", "composed"], None, "Held-out signed/changed/delivered code and tampering cases test declared breadth; pre-existing processes are not claimed eradicated by admission.";
    pilot_m1_real_clean_task: M1, Worker, Utility, ["clean"], None, "Real Graph reference and model inference edit a staged note and publish exact reviewed bytes through a separate host grant.";
    pilot_m1_contaminated_utility: M1, Worker, Utility, ["reference", "instruction", "tool_response", "stateful_adaptive"], None, "Meet separately declared feasible contaminated-task utility budgets; refusing everything or model resistance cannot substitute.";
    pilot_m1_hostile_worker: M1, Worker, Safety, ["file_read", "file_write", "execution", "credentials", "configuration"], None, "Deterministically hostile worker attempts forbidden effects independently of model refusal; observed absence must cover transient effects.";
    pilot_m1_network_routes: M1, Worker, Safety, ["loopback", "lan", "internet", "ipv6", "metadata", "brokered"], None, "Test actual valid raw/indirect/brokered egress paths; Winsock startup failure is not complete network-denial proof.";
    pilot_m1_read_upload_composition: M1, Worker, Safety, ["ungranted_source", "approved_destination"], None, "Allowed destination/read rights cannot compose into disclosure of ungranted data; approved task content remains disclosable by contract.";
    pilot_m1_snapshot_and_disclosure: M1, Worker, Safety, ["replacement", "version", "alias", "format"], None, "Capture exact bounded reference identity/version/bytes before launch; changed snapshots and unsupported formats require new approval or refusal.";
    pilot_m1_redirect_and_capability_custody: M1, Worker, Safety, ["redirect", "alternate_host", "capability_url"], None, "Redirects are exact bounded HTTPS destinations; Graph bearer headers never cross origins and derived fetch URLs remain broker-private.";
    pilot_m1_persistence_and_reimport: M1, Worker, Safety, ["restart", "memory", "tool_registration", "artifact_import"], None, "Caches/configuration/memory remain task-scoped; re-imported artifacts are untrusted inputs, never persistent authority or automatic fetch/execute.";
    pilot_m1_passive_exact_review: M1, Worker, Safety, ["terminal", "markup", "bidi", "forged_approval"], None, "Render bounded literal content beside trusted operation labels; exact reviewed bytes remain unchanged through publication.";
    pilot_m1_publication_identity: M1, Worker, Safety, ["changed_original", "target_swap", "hardlink", "reparse", "alternate_stream"], None, "Publication rejects changed opened-object identity/version and unsupported paths; worker output cannot select a new host destination.";
    pilot_m1_quiescent_output: M1, Worker, Safety, ["worker_alive", "retained_handle", "pending_broker_work"], None, "Close/drain authority and verify no writer/helper can mutate the host-owned immutable artifact before review.";
    pilot_m1_uncertain_effects: M1, Worker, Fault, ["lost_response", "dispatch_crash", "publish_crash", "duplicate"], None, "Journal not-dispatched/dispatched/confirmed/unknown distinctly; uncertainty never becomes denial, free quota, safe rollback or automatic replay.";
    pilot_m1_restore_and_new_approval: M1, Worker, Recovery, ["interruption", "restore_conflict", "new_review"], None, "Restore exact protected original only with new host authority and identity checks; in-place writes are not advertised crash-atomic.";
    pilot_m1_supported_file_and_text_boundary: M1, Worker, Safety, ["unc_device", "alias", "encoding", "oversize", "synchronized_placeholder"], None, "Reject unsupported remote/device/alias/reparse/synchronized or invalid text inputs without executing content, silently normalizing approved bytes or changing destinations.";
    pilot_m1_expiry_cancel_and_host_loss: M1, Worker, Recovery, ["deadline", "cancel", "controller_loss", "monitor_loss"], None, "Withdraw leases/queued/cached authority, terminate and verify owned jobs/handles, then close; local closure cannot recall remote effects.";
    pilot_c1_allowed_direct_reads: C1, Provider, Utility, ["each_claimed_identity"], None, "Valid direct callers outside Shield can read the allowed real reference with only the declared service permissions.";
    pilot_c1_forbidden_resource: C1, Provider, Safety, ["each_claimed_identity"], None, "Real provider denies the valid second-resource request independently of broker routing; bad authentication is not a valid forbidden probe.";
    pilot_c1_forbidden_actions: C1, Provider, Safety, ["write", "delete", "permission_change", "consent_role_change"], None, "Provider-native authorization denies all declared out-of-scope actions for every included identity/credential class.";
    pilot_c1_alternate_content_routes: C1, Provider, Safety, ["descendant", "version", "alternate_endpoint", "download_share"], None, "Service ceilings hold across actual content aliases, descendants/versions and credential-like derived capabilities.";
    pilot_c1_existing_capability_cutoffs: C1, Provider, Recovery, ["access_token", "refresh_token", "session", "download_url"], None, "Independently test retained valid capabilities before/after response and record surviving authority and measured cutoff, not just new-token failure.";
    pilot_c1_revocation_causality: C1, Provider, Detection, ["unrevoked_control", "expiry", "outage", "throttle", "cached_reply"], None, "Distinguish revocation from expiry/outage/throttling/cache/invalid probes; unknown cause cannot be credited as successful containment.";
    pilot_i1_legitimate_composed_workflow: I1, Integrated, Utility, ["selected"], None, "Complete the real approved cloud-reference/model/note/review/publication workflow under the exact final composed configuration.";
    pilot_i1_connected_attack_chains: I1, Integrated, Safety, ["delivery", "cloud_injection", "credential_egress", "persistence"], None, "Exercise linked local/AI/provider attacks with independent effects and original protection claims retained.";
    pilot_i1_assumed_compromise: I1, Integrated, Safety, ["hostile_worker", "leaked_credential", "poisoned_memory"], None, "Start at later covered compromise stages so an early block cannot conceal missing downstream boundaries.";
    pilot_i1_drift_and_manifest_binding: I1, Integrated, Fault, ["policy", "helper", "os", "provider", "model"], None, "Results cannot be pooled across incompatible manifests or survive changed final-policy exceptions.";
    pilot_o1_detection_and_notification: O1, Operations, Detection, ["local", "provider", "integrated"], None, "Detect named inert incidents with protected evidence/trusted notification within budget; detection after effect is not prevention.";
    pilot_o1_evidence_loss_and_health: O1, Operations, Fault, ["observer_loss", "stale_health", "clock_order", "partial_activation"], None, "Expose unknown/degraded/pending/unsupported states and stop affected new work; no global green badge from one healthy plane.";
    pilot_o1_scoped_response: O1, Operations, Safety, ["unauthorized", "false_positive", "high_impact"], None, "Authenticate and bound response authority; no generic elevated remediation, broad quarantine, unrelated-control changes or implicit approval.";
    pilot_o1_shared_exposure_blast_radius: O1, Operations, Recovery, ["provider_identity", "binding_key", "signing_key"], None, "Withdraw dependent claims/tasks and rotate exposed shared authority at its full declared scope, not just the reporting task.";
    pilot_o1_normal_teardown_ownership: O1, Operations, Safety, ["task", "shared", "foreign"], None, "Normal closure removes only owned task grants/identities and preserves shared enforcers, credentials, unrelated files/policies and evidence.";
    pilot_o1_local_and_remote_containment: O1, Operations, Recovery, ["local_process", "broker_lease", "remote_capabilities"], None, "Verify remaining authority independently; slow/partial/unknown remote cutoff is incomplete containment despite local worker exit.";
    pilot_o1_authenticated_restore: O1, Operations, Recovery, ["backup", "conflict", "interrupted_response", "reenrollment"], None, "Authenticate known-good recovery, preserve bounded evidence, reject poisoned state and never replay old grants/destructive effects.";
    pilot_o1_root_compromise_and_irreversibility: O1, Operations, Fault, ["host_root", "completed_disclosure"], None, "Withdraw unsupported trust and require owner-approved rebuild; never claim app cleanup proves cleanliness or recalls completed disclosures.";
    pilot_o1_owned_lifecycle_reconciliation: O1, Operations, Recovery, ["partial_install", "partial_remove", "cleanup", "retirement"], None, "Reconcile interrupted native/service/WFP operations without replay; exact reviewed cleanup retains retirement and uncertain-attempt evidence.";
    pilot_o1_audit_integrity_and_attribution: O1, Operations, Detection, ["corrupt", "missing", "replayed", "unavailable_observer"], None, "Check protected sequence/time/profile/grant/operation/dispatch/effect attribution; local hash-chain integrity is not administrator-proof or an independent remote effect log.";
    pilot_o1_partial_external_revocation: O1, Operations, Recovery, ["deleted_local_credential", "fresh_token_only", "surviving_url", "local_snapshot_restore"], None, "Local deletion, new-token denial and snapshot rollback cannot conceal surviving issued authority; report partial state until independently verified cutoff.";
    pilot_p0_ordinary_workflows: P0, User, Usability, ["browser_download", "installation", "documents", "launch_update", "reboot_signin", "integrated_task"], None, "Consented representative benign users complete everyday non-agent and integrated tasks within declared utility/false-block/abandonment budgets.";
    pilot_p0_authority_comprehension: P0, User, Usability, ["admission", "disclosure", "publication", "status"], None, "Measure grant/coverage understanding with benign consented misleading-approval simulations; no safe-program claim from signature/click.";
    pilot_p0_silent_unchanged_launch: P0, User, Usability, ["unchanged_launch"], None, "Zero additional Shield prompts for unchanged already-approved application launches and zero manual hash/ACL/policy editing.";
    pilot_p0_recovery_and_removal: P0, User, Recovery, ["recovery", "uninstall"], None, "Actual intended operator can recover/remove without stranded login, missing keys or disabled native protection.";
    pilot_p0_performance_and_total_cost: P0, User, Performance, ["shield_only", "workload_baseline", "total_deployment"], None, "Meet predeclared footprint/RAM/CPU/startup/p95/alert/operator/licensing/inference/signing/support budgets, reported separately by scope.";
    release_first_download_native_compatibility: Release, Distribution, Utility, ["download", "install", "update", "uninstall"], None, "Real origin/metadata and new signed artifact versions work with native consumer protections intact; copied development binaries are not distribution evidence.";
    release_signing_trust_separation: Release, Distribution, Safety, ["package", "native_policy", "update_metadata"], None, "Exact whole-file and Authenticode pins do not authorize TUF metadata, App Control signers, benignness or update installation.";
    release_exact_pinned_publisher: Release, Distribution, Safety, ["whole_file", "certificate_der", "unsigned", "unknown_revocation", "hardlink", "sha2_digest"], None, "Verify complete bytes plus exact native primary signer/certificate DER pin and supported digest; fail unknown cache-only revocation and unsupported objects without trust enrollment, execution or unsigned fallback.";
    release_metadata_and_version_floor: Release, Distribution, Safety, ["signature", "expired", "rollback", "freeze", "mix_match"], None, "Verify authenticated/versioned/fresh metadata, bootstrap roots/time/offline rules and protected rollback resistance before any update effect.";
    release_key_rotation_and_outage: Release, Distribution, Recovery, ["rotate", "revoked", "unavailable_signer", "recovery_image"], None, "Rehearse signing/root/certificate rotation, renewal, unavailable signing service and admitted updated/recovery components without a bypass.";
    release_interrupted_owned_deployment: Release, Distribution, Recovery, ["install", "migrate", "update", "remove", "reboot"], None, "Protect program/configuration files and reconcile partial transitions while retaining ownership, authentication, version floor and unrelated controls.";
    release_evidence_privacy_and_retention: Release, Distribution, Safety, ["export", "logs", "telemetry", "retention"], None, "Bound storage/retention, redact secrets/capability URLs/raw user/provider content, render untrusted diagnostics passively and require export consent.";
    release_maintenance_and_support: Release, Governance, Review, ["selected"], None, "Name maintainer, supported versions, vulnerability intake/triage/patch expectations, signing recovery, finite support budget and end-of-support behavior.";
    conditional_protected_verifier: M0, Endpoint, Safety, ["ipc", "process_identity", "scm_acl", "protected_files", "replay"], Some("protected_verifier"), "Opt-in LocalSystem verifier authenticates exact clients/server/image/token/binding, accepts bounded fixed queries and never opens user SQLite or acts as a generic broker.";
    conditional_verifier_reviewed_cleanup: M0, Endpoint, Recovery, ["digest", "retirement", "interrupted", "quota", "foreign_entry"], Some("protected_verifier"), "After confirmed service absence, remove only exact reviewed protected owned files/directory by handle; retain no-replace retirement/attempt evidence, refuse replay and preserve unknown entries.";
    conditional_signed_base_policy_recovery: E0, Endpoint, Recovery, ["replacement", "interrupted", "reboot", "remove"], Some("signed_base_policy"), "Same PolicyID/equal-or-higher signed replacement, required option/update signers and restart precede base-policy removal; rehearse boot/key recovery.";
    conditional_sender_constrained_tokens: C1, Provider, Safety, ["binding", "replay", "unbound", "compromised_client"], Some("sender_constrained_tokens"), "Provider enforces real proof/token binding and replay checks; keys remain outside workers and no generic signing or intent guarantee is implied.";
    conditional_human_authentication: C1, Provider, Safety, ["phishing", "session", "device_client"], Some("human_identity"), "Verify applicable provider-enforced phishing-resistant human authentication/session controls, account eligibility and residual legitimate stolen-token authority.";
    future_local_only_information_flow: Extension, Worker, Safety, ["source_to_sink", "indirect_channel"], Some("local_only"), "A separately enforced local-only profile proves its declared disclosure flows; destination allowlists and process separation alone do not prove noninterference.";
    future_optional_local_ai_value: Extension, User, Comparison, ["native", "equivalent_native", "shield"], Some("local_ai"), "Compare enforcement-only/local-AI on held-out benign/adaptive inputs, precision/recall/false alerts, decisions and actual CPU/memory/power costs; retain only measured benefit.";
    future_optional_local_ai_quality: Extension, User, Classifier, ["held_out_corpus"], Some("local_ai"), "Derive precision, recall and false-positive rate from held-out positive/negative counts, with explicit quality/time/energy budgets; model timings elsewhere are not local CPU/power evidence.";
    future_additional_clients: Extension, Worker, Utility, ["selected_client"], Some("additional_client"), "A newly selected real AI client passes documented-interface and full containment/utility gates; custom-worker results do not imply arbitrary-agent support.";
    future_additional_platforms: Extension, Endpoint, Utility, ["selected_platform"], Some("additional_platform"), "Each additional OS needs its own native capability/entitlement/distribution/recovery profile and effects; Windows results cannot confer support.";
}
