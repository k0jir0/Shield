use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use shield::error::{Error, Result};
use shield::profile::Profile;
use shield::state::{Reference, Store, TaskKind};
use shield::{files, network, platform, providers, runtime, util};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Shield experimental Windows containment controller; not a certified endpoint-security product"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".shield-state")]
    state: PathBuf,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Read-only Windows inventory, not an enforcement test.
    Doctor,
    /// List native App Control policies without changing them.
    EndpointInventory,
    /// Verify exact artifact and pinned package publisher; does not authorize or install updates.
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    /// Author and explicitly provision an owned computer-wide App Control policy.
    Endpoint {
        #[command(subcommand)]
        action: EndpointAction,
    },
    /// Explicit opt-in lifecycle for the protected read-only App Control verifier.
    Verifier {
        #[command(subcommand)]
        action: VerifierAction,
    },
    /// Harmless owned LPAC/job probes, with no global policy changes.
    Selftest {
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Create an automatically fingerprinted, editable enrollment template.
    Template {
        #[arg(long, default_value = "Shield experimental pilot")]
        name: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        protected_verifier: bool,
        #[arg(long)]
        publisher_cert_sha256: Option<String>,
    },
    /// Create new private state; never overwrite existing state.
    Init {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Store/remove a profile-specific credential in Windows Credential Manager.
    Credential {
        #[arg(value_enum)]
        kind: CredentialKind,
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Capture a note and real Graph reference, or an explicitly marked local fixture.
    Prepare {
        #[arg(long)]
        note: PathBuf,
        #[arg(long)]
        instruction: String,
        #[arg(long)]
        fixture_reference: Option<PathBuf>,
    },
    /// Display the exact captured input/disclosure record.
    Inspect { task: Uuid },
    /// Experimental live model task; requires a separately authorized isolated lab.
    Run {
        task: Uuid,
        #[arg(long)]
        authorized_lab: bool,
        #[arg(long)]
        approved_disclosure_digest: Option<String>,
    },
    /// Import a human-created proposal for a MANUAL LAB task; never count it as AI completion.
    StageLab {
        task: Uuid,
        #[arg(long)]
        proposal: PathBuf,
    },
    /// Review the exact artifact; optionally create a separate short-lived publication approval.
    Review {
        task: Uuid,
        #[arg(long)]
        approve: bool,
        #[arg(long)]
        reviewed_digest: Option<String>,
    },
    /// Consume one exact publication approval against the unchanged original file.
    Publish {
        task: Uuid,
        #[arg(long)]
        approval: Uuid,
    },
    /// Revoke the local epoch and terminate its named job; cannot recall remote effects.
    Cancel { task: Uuid },
    /// Reconcile an interrupted controller after verifying task-job termination.
    Recover { task: Uuid },
    /// Restore the protected original snapshot after an uncertain local publication.
    Restore {
        task: Uuid,
        #[arg(long)]
        reviewed_current_digest: Option<String>,
    },
    /// Explicit, owned per-image WFP boundary management; never automatic elevation.
    Boundary {
        #[command(subcommand)]
        action: BoundaryAction,
    },
    /// Report local state honestly; this prototype cannot report an integrated-pilot pass.
    Status {
        #[arg(long)]
        require_ready: bool,
    },
    /// Verify and optionally export metadata-only local audit evidence.
    Audit {
        #[arg(long)]
        export: Option<PathBuf>,
    },
    #[command(name = "__worker", hide = true)]
    Worker,
    #[command(name = "__verifier-service", hide = true)]
    VerifierService {
        profile: Uuid,
        plan: Uuid,
        owner_sid: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CredentialKind {
    Openai,
    Graph,
}

#[derive(Subcommand)]
enum ReleaseAction {
    Verify {
        artifact: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        publisher_cert_sha256: String,
    },
}

impl CredentialKind {
    fn name(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Graph => "graph",
        }
    }
}

#[derive(Subcommand)]
enum CredentialAction {
    Set,
    Remove,
}

#[derive(Subcommand)]
enum BoundaryAction {
    Verify,
    Install {
        #[arg(long)]
        authorized_lab: bool,
        #[arg(long)]
        expected_profile_digest: String,
    },
    Remove {
        #[arg(long)]
        authorized_lab: bool,
        #[arg(long)]
        expected_profile_digest: String,
    },
}

#[derive(clap::Args)]
struct EndpointBinding {
    #[arg(long)]
    authorized_lab: bool,
    #[arg(long)]
    expected_profile_digest: String,
    #[arg(long)]
    expected_plan_digest: String,
}

impl EndpointBinding {
    fn approval(&self) -> shield::endpoint::ChangeApproval<'_> {
        shield::endpoint::ChangeApproval {
            authorized_lab: self.authorized_lab,
            profile_digest: &self.expected_profile_digest,
            plan_digest: &self.expected_plan_digest,
        }
    }
}

#[derive(Subcommand)]
enum VerifierAction {
    /// Fresh authenticated query; never an endpoint enforcement pass.
    Status { plan: Uuid },
    Install {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
    Remove {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
    /// Read native state and confirm a completed effect; never replay create/start/stop/delete.
    Reconcile {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
    /// Inspect fixed cleanup targets after confirmed service removal; does not delete anything.
    InspectCleanup {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
    /// Remove only the reviewed owned verifier files, retaining retirement/attempt evidence.
    Cleanup {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
        #[arg(long)]
        expected_cleanup_digest: String,
    },
}

#[derive(Subcommand)]
enum EndpointAction {
    /// Report native authoring prerequisites without changing policies or requiring state.
    AuthoringSupport,
    /// Build a reviewed native baseline plus exact EXE/DLL hash rules; does not install.
    Prepare {
        #[arg(long)]
        application: Vec<PathBuf>,
        #[arg(long)]
        previous: Option<Uuid>,
    },
    Inspect {
        plan: Uuid,
    },
    /// Verify the owned active policy and bytes, not an E0/E1 effect pass.
    Verify,
    Install {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
    Remove {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
    /// Reconcile an uncertain change without replaying native mutation.
    Reconcile {
        plan: Uuid,
        #[command(flatten)]
        binding: EndpointBinding,
    },
}

fn endpoint(store: &mut Store, action: EndpointAction) -> Result<()> {
    match action {
        EndpointAction::Prepare {
            application,
            previous,
        } => {
            let applications = application
                .iter()
                .map(|path| absolute(path))
                .collect::<Result<Vec<_>>>()?;
            display(&shield::endpoint::prepare(store, &applications, previous)?)
        }
        EndpointAction::Inspect { plan } => display(&shield::endpoint::inspect(store, plan)?),
        EndpointAction::Verify => {
            let plan = shield::endpoint::active_plan(store)?;
            display(
                &json!({"state": "configured_not_effect_certified", "policy": plan.policy_id, "plan": plan.id, "effect_gate_pass": false}),
            )
        }
        EndpointAction::Install { plan, binding } => display(&shield::endpoint::change(
            store,
            plan,
            true,
            binding.approval(),
        )?),
        EndpointAction::Remove { plan, binding } => display(&shield::endpoint::change(
            store,
            plan,
            false,
            binding.approval(),
        )?),
        EndpointAction::Reconcile { plan, binding } => display(&shield::endpoint::reconcile(
            store,
            plan,
            binding.approval(),
        )?),
        EndpointAction::AuthoringSupport => {
            unreachable!("authoring support does not need enrolled state")
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    files::validate_path(&path)?;
    Ok(path)
}

fn display(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", util::terminal_json(value)?);
    Ok(())
}

fn confirm(verb: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(Error::Denied("interactive approval needs a trusted terminal; automation must provide the exact displayed artifact/disclosure digest".into()));
    }
    let challenge = format!("{verb} {}", Uuid::new_v4());
    println!("Trusted host approval. Type exactly: {challenge}");
    let answer = Zeroizing::new(rpassword::prompt_password("Approval (not echoed): ")?);
    if answer.as_str() != challenge {
        return Err(Error::Denied("approval challenge did not match".into()));
    }
    Ok(())
}

fn idle(store: &Store) -> Result<()> {
    if store
        .tasks()?
        .iter()
        .any(|task| matches!(task.phase.as_str(), "running" | "revoking" | "publishing"))
    {
        return Err(Error::Denied(
            "profile has running or unreconciled authority; complete cancellation/recovery first"
                .into(),
        ));
    }
    Ok(())
}

fn boundary(store: &mut Store, action: BoundaryAction) -> Result<()> {
    let _control = store.control_lock()?;
    match action {
        BoundaryAction::Verify => display(&network::verify(
            store.profile.id,
            &store.worker_path(),
            &store.profile.binary_sha256,
        )?),
        action => {
            idle(store)?;
            let (install, authorized, expected) = match action {
                BoundaryAction::Install {
                    authorized_lab,
                    expected_profile_digest,
                } => (true, authorized_lab, expected_profile_digest),
                BoundaryAction::Remove {
                    authorized_lab,
                    expected_profile_digest,
                } => (false, authorized_lab, expected_profile_digest),
                BoundaryAction::Verify => unreachable!(),
            };
            if !authorized || expected != store.profile.digest()? {
                return Err(Error::Denied("boundary mutation requires an authorized isolated lab and the exact frozen profile digest".into()));
            }
            if install {
                store.profile.verify_host()?;
            } else {
                store.profile.verify_recovery_host()?;
            }
            store.event(None, "owned_network_change_requested", json!({
                "install": install, "profile": store.profile.id,
                "profile_digest": expected, "worker_sha256": store.profile.binary_sha256,
                "exact_image": store.worker_path(), "persistent": true,
                "owned_keys": network::owned_keys(store.profile.id),
                "scope": "owned per-profile WFP provider, sublayer and six exact-image ALE deny filters"
            }))?;
            if install {
                let result = network::install(
                    store.profile.id,
                    &store.worker_path(),
                    &store.profile.binary_sha256,
                )?;
                store.event(
                    None,
                    "owned_network_install_completed",
                    json!({"effect_tests": "not_implied"}),
                )?;
                display(&result)
            } else {
                network::remove(
                    store.profile.id,
                    &store.worker_path(),
                    &store.profile.binary_sha256,
                )?;
                store.event(
                    None,
                    "owned_network_removal_completed",
                    json!({"remaining_protection": "unverified_live_execution_blocked"}),
                )?;
                println!(
                    "Removed only the verified owned boundary. Live execution must now refuse."
                );
                Ok(())
            }
        }
    }
}

fn execute() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Action::Doctor => display(&json!({
            "environment": platform::environment()?,
            "elevated": platform::is_elevated()?,
            "integrated_pilot_ready": false,
            "scope": "development inventory only; no admission, model, provider or isolation pass"
        })),
        Action::EndpointInventory => display(&shield::endpoint::inventory()?),
        Action::Release {
            action:
                ReleaseAction::Verify {
                    artifact,
                    expected_sha256,
                    publisher_cert_sha256,
                },
        } => display(&shield::release::verify(
            &absolute(&artifact)?,
            &expected_sha256,
            &publisher_cert_sha256,
        )?),
        Action::Endpoint {
            action: EndpointAction::AuthoringSupport,
        } => display(&shield::endpoint::authoring_support()?),
        Action::Worker => shield::worker::run(),
        Action::VerifierService {
            profile,
            plan,
            owner_sid,
        } => shield::verifier::run_service(profile, plan, owner_sid),
        Action::Selftest { report } => {
            let report = report.as_deref().map(absolute).transpose()?;
            let result = shield::selftest::run(report.as_deref())?;
            display(&result)?;
            if !result.all_passed {
                return Err(Error::Denied(
                    "one or more native isolation probes failed".into(),
                ));
            }
            Ok(())
        }
        Action::Template {
            name,
            output,
            protected_verifier,
            publisher_cert_sha256,
        } => {
            let mut profile = Profile::draft(name)?;
            if protected_verifier {
                profile.endpoint_verifier = shield::profile::EndpointVerifier::ProtectedService;
            }
            profile.publisher_cert_sha256 = publisher_cert_sha256;
            profile.validate()?;
            if profile.publisher_cert_sha256.is_some() {
                profile.verify_host()?;
            }
            files::create_new(&absolute(&output)?, &serde_json::to_vec_pretty(&profile)?)?;
            println!(
                "Created draft enrollment template. Graph and all protection gates remain unverified."
            );
            Ok(())
        }
        Action::Init { profile } => {
            let profile = match profile {
                Some(path) => Profile::load(&absolute(&path)?)?,
                None => Profile::draft("Shield experimental pilot".into())?,
            };
            let store = Store::initialize(&absolute(&cli.state)?, profile)?;
            display(
                &json!({"state": store.root, "profile_digest": store.profile.digest()?, "ready": false}),
            )
        }
        command => {
            let mut store = Store::open(&absolute(&cli.state)?)?;
            match command {
                Action::Verifier { action } => match action {
                    VerifierAction::Status { plan } => {
                        display(&shield::verifier::status(&store, plan)?)
                    }
                    VerifierAction::Install { plan, binding } => display(
                        &shield::verifier::install(&store, plan, binding.approval())?,
                    ),
                    VerifierAction::Remove { plan, binding } => {
                        display(&shield::verifier::remove(&store, plan, binding.approval())?)
                    }
                    VerifierAction::Reconcile { plan, binding } => display(
                        &shield::verifier::reconcile(&store, plan, binding.approval())?,
                    ),
                    VerifierAction::InspectCleanup { plan, binding } => display(
                        &shield::verifier::inspect_cleanup(&store, plan, binding.approval())?,
                    ),
                    VerifierAction::Cleanup {
                        plan,
                        binding,
                        expected_cleanup_digest,
                    } => display(&shield::verifier::perform_cleanup(
                        &store,
                        plan,
                        binding.approval(),
                        &expected_cleanup_digest,
                    )?),
                },
                Action::Credential { kind, action } => {
                    store.profile.verify_host()?;
                    let target = store.profile.credential_target(kind.name())?;
                    match action {
                        CredentialAction::Set => {
                            let value = Zeroizing::new(rpassword::prompt_password(
                                "Test-only credential (not echoed): ",
                            )?);
                            platform::credential_write(&target, &value)?;
                            store.event(
                                None,
                                "credential_stored",
                                json!({"kind": kind.name(), "provider_ceiling": "not_verified"}),
                            )?;
                        }
                        CredentialAction::Remove => {
                            platform::credential_delete(&target)?;
                            store.event(
                                None,
                                "credential_locally_removed",
                                json!({"kind": kind.name(), "remote_revocation": "not_implied"}),
                            )?;
                        }
                    }
                    println!(
                        "Local credential action completed. Existing remote tokens, sessions and effects are not revoked by this action."
                    );
                    Ok(())
                }
                Action::Prepare {
                    note,
                    instruction,
                    fixture_reference,
                } => {
                    store.profile.verify_host()?;
                    let (kind, bytes, reference) = match fixture_reference {
                        Some(path) => {
                            let (bytes, _) = files::snapshot(
                                &absolute(&path)?,
                                store.profile.limits.input_bytes,
                            )?;
                            let reference = Reference {
                                provider: "manual_lab_fixture".into(),
                                resource: "local_fixture".into(),
                                version: None,
                                sha256: util::digest(&bytes),
                                bytes: bytes.len() as u64,
                            };
                            (TaskKind::ManualLab, bytes, reference)
                        }
                        None => {
                            let (bytes, reference) = providers::reference(&store.profile)?;
                            (TaskKind::Live, bytes, reference)
                        }
                    };
                    let id =
                        store.prepare(kind, &absolute(&note)?, instruction, &bytes, reference)?;
                    display(
                        &json!({"task": id, "kind": kind, "phase": "prepared", "disclosure_approved": false, "publication_approved": false}),
                    )
                }
                Action::Inspect { task } => {
                    let value = runtime::disclosure(&store, task)?;
                    display(
                        &json!({"disclosure": value, "disclosure_digest": util::json_digest(&value)?}),
                    )
                }
                Action::Run {
                    task,
                    authorized_lab,
                    approved_disclosure_digest,
                } => {
                    if !authorized_lab {
                        return Err(Error::Denied("live execution is experimental and requires an authorized isolated lab; this prototype is not a production protection path".into()));
                    }
                    let value = runtime::disclosure(&store, task)?;
                    let digest = util::json_digest(&value)?;
                    let approved = match approved_disclosure_digest {
                        Some(value) => value,
                        None => {
                            display(&value)?;
                            confirm("DISCLOSE")?;
                            digest
                        }
                    };
                    runtime::run(&mut store, task, &approved)?;
                    println!(
                        "Worker closed and proposal staged. No publication or integrated-gate pass is implied."
                    );
                    Ok(())
                }
                Action::StageLab { task, proposal } => {
                    let _control = store.control_lock()?;
                    store.profile.verify_host()?;
                    if store.task(task)?.spec.kind != TaskKind::ManualLab {
                        return Err(Error::Denied(
                            "manual proposals cannot replace live AI execution".into(),
                        ));
                    }
                    let (bytes, _) =
                        files::snapshot(&absolute(&proposal)?, store.profile.limits.output_bytes)?;
                    store.close(task, Some(&bytes), None)?;
                    println!(
                        "MANUAL LAB proposal staged. This is not a model/provider/isolation result."
                    );
                    Ok(())
                }
                Action::Review {
                    task,
                    approve,
                    reviewed_digest,
                } => {
                    let record = store.task(task)?;
                    let bytes = store.proposal(task)?;
                    let digest = util::digest(&bytes);
                    if let Some(reviewed) = reviewed_digest {
                        let approval = store.approve(task, &reviewed)?;
                        return display(&json!({
                            "approval": approval, "task": task, "artifact_sha256": digest,
                            "destination": record.spec.original_path, "expires_in_seconds": 300, "used": false
                        }));
                    }
                    display(
                        &json!({"task": task, "kind": record.spec.kind, "destination": record.spec.original_path, "original_sha256": record.spec.original.sha256, "artifact_sha256": digest, "publication": "in-place, not crash-atomic"}),
                    )?;
                    println!("----- UNTRUSTED PROPOSAL (literal controls escaped) -----");
                    println!("{}", util::literal(util::text(&bytes)?));
                    println!("----- END UNTRUSTED PROPOSAL -----");
                    if approve {
                        confirm("APPROVE PUBLICATION")?;
                        let approval = store.approve(task, &digest)?;
                        display(
                            &json!({"approval": approval, "task": task, "expires_in_seconds": 300, "used": false}),
                        )?;
                    }
                    Ok(())
                }
                Action::Publish { task, approval } => {
                    let _control = store.control_lock()?;
                    let operation = store.publish(task, approval)?;
                    display(
                        &json!({"operation": operation, "state": "succeeded", "readback_verified": true, "crash_atomic": false}),
                    )
                }
                Action::Cancel { task } => {
                    store.revoke(task)?;
                    let empty_job_observed = platform::terminate_task(task)?;
                    display(
                        &json!({"task": task, "local_epoch": "revoked", "named_job_found_and_observed_empty": empty_job_observed, "controller_reconciliation": "required_until_closed", "remote_effects": "not_recalled"}),
                    )
                }
                Action::Recover { task } => {
                    runtime::recover(&mut store, task)?;
                    display(
                        &json!({"task": task, "local_worker_authority": "closed", "operations": "no_replay_uncertain_dispatches_retained", "remote_revocation": "not_implied", "local_publication": store.task(task)?.phase}),
                    )
                }
                Action::Restore {
                    task,
                    reviewed_current_digest,
                } => {
                    let _control = store.control_lock()?;
                    let current = store.restoration_target(task)?;
                    let record = store.task(task)?;
                    display(
                        &json!({"task": task, "destination": record.spec.original_path, "current_sha256": current.sha256, "restore_sha256": record.spec.original.sha256, "external_effects": "not_recalled"}),
                    )?;
                    let digest = match reviewed_current_digest {
                        Some(value) => value,
                        None => {
                            confirm("RESTORE ORIGINAL")?;
                            current.sha256
                        }
                    };
                    store.restore(task, &digest)?;
                    println!(
                        "Original local bytes restored and read back. Remote effects/old uncertain operations were not erased or revoked."
                    );
                    Ok(())
                }
                Action::Boundary { action } => boundary(&mut store, action),
                Action::Endpoint { action } => endpoint(&mut store, action),
                Action::Status { require_ready } => {
                    let audit_events = store.verify_audit()?;
                    let host = match store.profile.verify_host() {
                        Ok(()) => json!({"state": "matches_frozen_profile"}),
                        Err(error) => {
                            json!({"state": "drift_or_unverified", "error": error.to_string()})
                        }
                    };
                    let boundary = match network::verify(
                        store.profile.id,
                        &store.worker_path(),
                        &store.profile.binary_sha256,
                    ) {
                        Ok(value) => {
                            json!({"state": "configured_not_effect_certified", "inventory": value})
                        }
                        Err(error) => {
                            json!({"state": "missing_or_unverifiable", "error": error.to_string()})
                        }
                    };
                    let tasks: Vec<_> = store.tasks()?.iter().map(|task| json!({
                        "task": task.spec.id, "kind": task.spec.kind, "phase": task.phase,
                        "model_calls_reserved": task.model_calls, "output_digest": task.output_digest, "error_code": task.error
                    })).collect();
                    let admission = match shield::endpoint::status(&store) {
                        Ok(value) => value,
                        Err(error) => {
                            json!({"state": "missing_or_unverifiable", "error": error.to_string(), "effect_gate_pass": false})
                        }
                    };
                    display(&json!({
                        "profile_digest": store.profile.digest()?, "host": host, "network": boundary,
                        "audit_chain_events": audit_events, "audit_limit": "local ACL-protected chain, not independent/admin-proof evidence",
                        "tasks": tasks, "integrated_pilot_ready": false,
                        "endpoint_admission": admission,
                        "gates": {"R0":"unverified","L0":"unverified","E0":"unverified","A0":"unverified","C0":"unverified","M0":"unverified","E1":"unverified","M1":"unverified","C1":"unverified","I1":"unverified","O1":"unverified","P0":"unverified"},
                        "warning": "Fixture completion, native inventory, configured filters and software tests cannot certify the integrated pilot."
                    }))?;
                    if require_ready {
                        return Err(Error::Denied(
                            "integrated protection has not been demonstrated".into(),
                        ));
                    }
                    Ok(())
                }
                Action::Audit { export } => {
                    let value = json!({"profile_digest": store.profile.digest()?, "events": store.evidence()?, "integrated_gate_pass": false});
                    if let Some(path) = export {
                        files::create_new(&absolute(&path)?, &serde_json::to_vec_pretty(&value)?)?;
                        println!("Exported verified metadata-only local evidence to a new file.");
                        Ok(())
                    } else {
                        display(&value)
                    }
                }
                _ => unreachable!("commands not requiring state are handled above"),
            }
        }
    }
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("Shield error: {}", util::literal(&error.to_string()));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_has_no_conflicting_arguments_or_subcommands() {
        Cli::command().debug_assert();
    }

    #[test]
    fn boundary_mutation_cannot_omit_the_exact_profile_binding() {
        assert!(
            Cli::try_parse_from(["shield", "boundary", "install", "--authorized-lab"]).is_err()
        );
        assert!(Cli::try_parse_from(["shield", "boundary", "remove", "--authorized-lab"]).is_err());
        assert!(Cli::try_parse_from(["shield", "credential", "openai", "set"]).is_ok());
        assert!(Cli::try_parse_from(["shield", "status", "--require-ready"]).is_ok());
        for action in ["install", "remove", "reconcile"] {
            assert!(
                Cli::try_parse_from([
                    "shield",
                    "endpoint",
                    action,
                    "d0d79666-e985-4f97-8be8-b1e26a2fa3ce",
                    "--authorized-lab",
                ])
                .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "shield",
                    "verifier",
                    action,
                    "d0d79666-e985-4f97-8be8-b1e26a2fa3ce",
                    "--authorized-lab",
                ])
                .is_err()
            );
        }
        assert!(Cli::try_parse_from(["shield", "endpoint", "authoring-support"]).is_ok());
    }

    #[test]
    fn verifier_cleanup_requires_exact_profile_plan_and_current_cleanup_review() {
        let plan = "d0d79666-e985-4f97-8be8-b1e26a2fa3ce";
        let digest = "a".repeat(64);
        let inspection = [
            "shield",
            "verifier",
            "inspect-cleanup",
            plan,
            "--authorized-lab",
            "--expected-profile-digest",
            &digest,
            "--expected-plan-digest",
            &digest,
        ];
        assert!(Cli::try_parse_from(inspection).is_ok());
        assert!(Cli::try_parse_from(&inspection[..7]).is_err());
        let cleanup = [
            "shield",
            "verifier",
            "cleanup",
            plan,
            "--authorized-lab",
            "--expected-profile-digest",
            &digest,
            "--expected-plan-digest",
            &digest,
        ];
        assert!(Cli::try_parse_from(cleanup).is_err());
        let mut approved = cleanup.to_vec();
        approved.extend(["--expected-cleanup-digest", &digest]);
        assert!(Cli::try_parse_from(&approved).is_ok());
        approved.extend(["--path", "C:\\arbitrary"]);
        assert!(Cli::try_parse_from(&approved).is_err());
    }

    #[test]
    fn release_verification_requires_both_independent_pins_and_cannot_install_or_enroll_trust() {
        let digest = "a".repeat(64);
        assert!(Cli::try_parse_from(["shield", "release", "verify", "candidate.exe"]).is_err());
        let verification = [
            "shield",
            "release",
            "verify",
            "candidate.exe",
            "--expected-sha256",
            &digest,
            "--publisher-cert-sha256",
            &digest,
        ];
        assert!(Cli::try_parse_from(verification).is_ok());
        let mut invalid = verification.to_vec();
        invalid.push("--install");
        assert!(Cli::try_parse_from(invalid).is_err());
        assert!(Cli::try_parse_from(["shield", "release", "trust", "candidate.exe"]).is_err());
    }
}
