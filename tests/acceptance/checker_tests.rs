use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::catalog::{CASES, Case, Gate};
use super::evidence::*;
use shield::util;
use uuid::Uuid;

const NOW: u64 = 1000;

struct Fixture {
    directory: tempfile::TempDir,
    plan: Plan,
}

// These in-memory/tempdir fixtures test the checker, never supply lab qualification.
fn artifact(root: &Path, bytes: &[u8]) -> Artifact {
    let sha256 = util::digest(bytes);
    let path = root.join("artifacts").join(format!("{sha256}.blob"));
    if path.exists() {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    } else {
        std::fs::write(path, bytes).unwrap();
    }
    Artifact { sha256 }
}

fn case(id: &str) -> &'static Case {
    CASES.iter().find(|case| case.id == id).unwrap()
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir(root.join("artifacts")).unwrap();
    std::fs::create_dir(root.join("runs")).unwrap();
    let profile = artifact(
        root,
        br#"{"fixture":"synthetic checker-only profile, not a deployment"}"#,
    );
    let workload = artifact(root, b"synthetic checker-only workload");
    let declaration = artifact(
        root,
        b"synthetic checker-only declaration, not authorization",
    );
    let mut cases = BTreeMap::new();
    for case in CASES
        .iter()
        .filter(|case| case.extension.is_none() && case.gate != Gate::Release)
    {
        let minimums = BTreeMap::from([
            (Metric::Completions, 1),
            (Metric::ImprovementBasisPoints, 1000),
        ]);
        let maximums = [
            Metric::ElapsedMs,
            Metric::ResponseMs,
            Metric::DetectionMs,
            Metric::RecoveryMs,
            Metric::FootprintBytes,
            Metric::PeakMemoryBytes,
            Metric::CpuMs,
            Metric::StartupMs,
            Metric::P95BrokerMs,
            Metric::TotalCostMilliunits,
            Metric::FalseBlocks,
            Metric::Prompts,
        ]
        .into_iter()
        .map(|metric| (metric, 100))
        .collect();
        cases.insert(
            case.id.to_owned(),
            CasePlan {
                trials_per_variant: 1,
                variants: case
                    .variants
                    .iter()
                    .map(|name| {
                        (
                            name.to_string(),
                            Variant {
                                profile: profile.clone(),
                                workload: workload.clone(),
                            },
                        )
                    })
                    .collect(),
                minimums,
                maximums,
                comparison: (case.assertion == Assertion::Comparison)
                    .then_some(Comparison::SaferOperability),
            },
        );
    }
    Fixture {
        directory,
        plan: Plan {
            schema_version: 1,
            frozen_at: 100,
            expires_at: 2000,
            owner: "checker-fixture-owner".into(),
            specification_sha256: specification_digest(),
            paper_sha256: paper_digest(),
            harness_sha256: harness_digest(),
            declarations: DECLARATIONS
                .iter()
                .map(|name| (name.to_string(), declaration.clone()))
                .collect(),
            enabled_extensions: BTreeSet::new(),
            cases,
        },
    }
}

impl Fixture {
    fn root(&self) -> &Path {
        self.directory.path()
    }

    fn plan_hash(&self) -> String {
        util::digest(&serde_json::to_vec_pretty(&self.plan).unwrap())
    }

    fn save_plan(&self) {
        std::fs::write(
            self.root().join("plan.json"),
            serde_json::to_vec_pretty(&self.plan).unwrap(),
        )
        .unwrap();
    }

    fn record(&self, id: &str) -> Record {
        let case = case(id);
        let settings = &self.plan.cases[id];
        let mut trials = Vec::new();
        for (variant, profile) in &settings.variants {
            for _ in 0..settings.trials_per_variant {
                let run_id = Uuid::new_v4();
                let metrics = [
                    (Metric::ForbiddenEffects, 0),
                    (Metric::PositiveControls, 1),
                    (Metric::Completions, 1),
                    (Metric::UnresolvedDecisions, 0),
                    (Metric::ReviewedRequirements, 1),
                    (Metric::ExpectedFaults, 1),
                    (Metric::Detections, 1),
                    (Metric::RemainingAuthority, 0),
                    (Metric::RecoveredScopes, 1),
                    (Metric::ManualSecurityEdits, 0),
                    (Metric::ExtraUnchangedLaunchPrompts, 0),
                    (Metric::FalseBlocks, 0),
                    (Metric::Prompts, 1),
                    (Metric::ElapsedMs, 50),
                    (Metric::ResponseMs, 50),
                    (Metric::DetectionMs, 50),
                    (Metric::RecoveryMs, 50),
                    (Metric::FootprintBytes, 50),
                    (Metric::PeakMemoryBytes, 50),
                    (Metric::CpuMs, 50),
                    (Metric::StartupMs, 50),
                    (Metric::P95BrokerMs, 50),
                    (Metric::TotalCostMilliunits, 50),
                    (Metric::TruePositive, 90),
                    (Metric::FalsePositive, 5),
                    (Metric::TrueNegative, 95),
                    (Metric::FalseNegative, 10),
                    (Metric::EnergyMillijoules, 50),
                    (
                        Metric::OperatorEffortMs,
                        if variant == "shield" { 40 } else { 80 },
                    ),
                ]
                .into_iter()
                .collect();
                let observation = Observation {
                    schema_version: 1,
                    run_id,
                    case_id: id.into(),
                    variant: variant.clone(),
                    plan_sha256: self.plan_hash(),
                    profile_sha256: profile.profile.sha256.clone(),
                    subject_principal: "fixture-subject".into(),
                    subject_trust_domain: "fixture-worker".into(),
                    observer_principal: "fixture-observer".into(),
                    observer_trust_domain: "fixture-host".into(),
                    observed_from: 199,
                    observed_until: 301,
                    status: ProbeStatus::Valid,
                    coverage: Coverage::Complete,
                    sources: case.layer.sources().iter().copied().collect(),
                    metrics,
                    raw_evidence: vec![artifact(self.root(), b"synthetic checker-only raw trace")],
                };
                trials.push(Trial {
                    run_id,
                    variant: variant.clone(),
                    profile_sha256: profile.profile.sha256.clone(),
                    workload_sha256: profile.workload.sha256.clone(),
                    started_at: 200,
                    completed_at: 300,
                    observation: artifact(self.root(), &serde_json::to_vec(&observation).unwrap()),
                });
            }
        }
        Record {
            schema_version: 1,
            case_id: id.into(),
            plan_sha256: self.plan_hash(),
            trials,
        }
    }

    fn edit_observation(
        &self,
        record: &mut Record,
        index: usize,
        edit: impl FnOnce(&mut Observation),
    ) {
        let path = self
            .root()
            .join("artifacts")
            .join(format!("{}.blob", record.trials[index].observation.sha256));
        let mut observation: Observation =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        edit(&mut observation);
        record.trials[index].observation =
            artifact(self.root(), &serde_json::to_vec(&observation).unwrap());
    }

    fn evaluate(&self, id: &str, record: &Record) -> Result<()> {
        validate_plan(self.root(), &self.plan, NOW)?;
        evaluate_record(
            &Replay {
                root: self.root(),
                plan: &self.plan,
                plan_hash: &self.plan_hash(),
                now: NOW,
            },
            case(id),
            &self.plan.cases[id],
            record,
            &mut BTreeSet::new(),
        )
    }
}

#[test]
fn catalog_covers_every_gate_and_maps_each_route_to_enforcer_observer_and_recovery() {
    let mut ids = BTreeSet::new();
    for case in CASES {
        assert!(ids.insert(case.id));
        assert!(!case.intent.is_empty() && !case.variants.is_empty());
        assert_eq!(
            case.variants.iter().copied().collect::<BTreeSet<_>>().len(),
            case.variants.len()
        );
        assert!(!case.layer.enforcer().is_empty());
        assert!(!case.layer.observer().is_empty());
        assert!(!case.layer.recovery().is_empty());
        if case.gate == Gate::Extension {
            assert!(case.extension.is_some());
        }
    }
    for gate in [
        Gate::R0,
        Gate::L0,
        Gate::E0,
        Gate::A0,
        Gate::C0,
        Gate::M0,
        Gate::E1,
        Gate::M1,
        Gate::C1,
        Gate::I1,
        Gate::O1,
        Gate::P0,
        Gate::Release,
        Gate::Extension,
    ] {
        assert!(
            CASES.iter().any(|case| case.gate == gate),
            "uncovered gate: {gate:?}"
        );
        fn visit(gate: Gate, chain: &mut BTreeSet<Gate>) {
            assert!(chain.insert(gate), "cyclic acceptance prerequisites");
            for parent in gate.prerequisites() {
                visit(*parent, chain);
            }
            chain.remove(&gate);
        }
        visit(gate, &mut BTreeSet::new());
    }
    assert_eq!(Gate::M0.prerequisites(), &[Gate::E0, Gate::A0, Gate::C0]);
    assert_eq!(Gate::I1.prerequisites(), &[Gate::E1, Gate::M1, Gate::C1]);
}

#[test]
fn checker_accepts_well_formed_measurements_for_every_assertion_kind_without_certifying_the_product()
 {
    let fixture = fixture();
    for id in [
        "pilot_r0_scope_and_operators",
        "pilot_e1_ordinary_launch_paths",
        "pilot_m1_real_clean_task",
        "pilot_m1_uncertain_effects",
        "pilot_o1_detection_and_notification",
        "pilot_o1_authenticated_restore",
        "pilot_p0_performance_and_total_cost",
        "pilot_p0_silent_unchanged_launch",
        "pilot_e0_native_value_comparison",
    ] {
        fixture.evaluate(id, &fixture.record(id)).unwrap();
    }
}

#[test]
fn complete_synthetic_predecessor_graph_replays_but_a_missing_required_record_withdraws_it() {
    let fixture = fixture();
    fixture.save_plan();
    for id in fixture.plan.cases.keys() {
        std::fs::write(
            fixture.root().join("runs").join(format!("{id}.json")),
            serde_json::to_vec(&fixture.record(id)).unwrap(),
        )
        .unwrap();
    }
    verify_case(fixture.root(), "pilot_p0_silent_unchanged_launch", NOW).unwrap();
    let first = fixture.record("pilot_r0_scope_and_operators");
    let mut reused = fixture.record("pilot_r0_resource_authority_matrix");
    reused.trials[0].run_id = first.trials[0].run_id;
    fixture.edit_observation(&mut reused, 0, |observation| {
        observation.run_id = first.trials[0].run_id
    });
    let first_path = fixture
        .root()
        .join("runs")
        .join("pilot_r0_scope_and_operators.json");
    let second_path = fixture
        .root()
        .join("runs")
        .join("pilot_r0_resource_authority_matrix.json");
    std::fs::write(&first_path, serde_json::to_vec(&first).unwrap()).unwrap();
    std::fs::write(&second_path, serde_json::to_vec(&reused).unwrap()).unwrap();
    assert!(
        verify_case(fixture.root(), "pilot_p0_silent_unchanged_launch", NOW)
            .unwrap_err()
            .contains("replayed")
    );
    std::fs::write(
        &second_path,
        serde_json::to_vec(&fixture.record("pilot_r0_resource_authority_matrix")).unwrap(),
    )
    .unwrap();
    std::fs::remove_file(
        fixture
            .root()
            .join("runs")
            .join("pilot_c1_forbidden_resource.json"),
    )
    .unwrap();
    assert!(verify_case(fixture.root(), "pilot_p0_silent_unchanged_launch", NOW).is_err());
}

#[test]
fn selected_conditional_controls_cannot_be_omitted_from_the_plan() {
    let mut fixture = fixture();
    fixture
        .plan
        .enabled_extensions
        .insert("protected_verifier".into());
    assert!(
        validate_plan(fixture.root(), &fixture.plan, NOW)
            .unwrap_err()
            .contains("conditional_protected_verifier")
    );
    assert_eq!(case("conditional_protected_verifier").gate, Gate::M0);
    assert_eq!(
        case("conditional_signed_base_policy_recovery").gate,
        Gate::E0
    );
    assert_eq!(case("conditional_sender_constrained_tokens").gate, Gate::C1);
    for selected in CASES
        .iter()
        .filter(|case| case.extension == Some("protected_verifier"))
    {
        let mut settings = fixture.plan.cases["pilot_o1_authenticated_restore"].clone();
        let variant = settings.variants.values().next().unwrap().clone();
        settings.variants = selected
            .variants
            .iter()
            .map(|name| (name.to_string(), variant.clone()))
            .collect();
        fixture.plan.cases.insert(selected.id.into(), settings);
    }
    fixture.save_plan();
    for id in fixture
        .plan
        .cases
        .keys()
        .filter(|id| id.starts_with("pilot_"))
    {
        std::fs::write(
            fixture.root().join("runs").join(format!("{id}.json")),
            serde_json::to_vec(&fixture.record(id)).unwrap(),
        )
        .unwrap();
    }
    let error = verify_case(fixture.root(), "pilot_e1_ordinary_launch_paths", NOW).unwrap_err();
    assert!(
        error.contains("conditional_protected_verifier.json"),
        "{error}"
    );
}

#[test]
fn aggregate_counts_fail_closed_instead_of_wrapping_or_saturating() {
    let mut fixture = fixture();
    let id = "pilot_o1_authenticated_restore";
    fixture.plan.cases.get_mut(id).unwrap().trials_per_variant = 2;
    let mut record = fixture.record(id);
    for index in 0..record.trials.len() {
        fixture.edit_observation(&mut record, index, |observation| {
            observation
                .metrics
                .insert(Metric::RecoveredScopes, u64::MAX);
        });
    }
    assert!(
        fixture
            .evaluate(id, &record)
            .unwrap_err()
            .contains("overflow")
    );
}

#[test]
fn classifier_quality_uses_actual_counts_and_rejects_undefined_or_below_budget_rates() {
    let mut fixture = fixture();
    fixture.plan.enabled_extensions.insert("local_ai".into());
    let comparison = fixture.plan.cases["pilot_e0_native_value_comparison"].clone();
    fixture
        .plan
        .cases
        .insert("future_optional_local_ai_value".into(), comparison);
    let id = "future_optional_local_ai_quality";
    let mut quality = fixture.plan.cases["pilot_m1_real_clean_task"].clone();
    let profile = quality.variants.values().next().unwrap().clone();
    quality.variants = BTreeMap::from([("held_out_corpus".into(), profile)]);
    quality.minimums.insert(Metric::PrecisionBasisPoints, 9000);
    quality.minimums.insert(Metric::RecallBasisPoints, 9000);
    quality
        .maximums
        .insert(Metric::FalsePositiveBasisPoints, 500);
    quality.maximums.insert(Metric::EnergyMillijoules, 100);
    fixture.plan.cases.insert(id.into(), quality);
    let record = fixture.record(id);
    fixture.evaluate(id, &record).unwrap();
    let mut record = fixture.record(id);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::TruePositive, 89);
        observation.metrics.insert(Metric::FalseNegative, 11);
    });
    assert!(fixture.evaluate(id, &record).is_err());
    let mut record = fixture.record(id);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::TruePositive, 0);
        observation.metrics.insert(Metric::FalsePositive, 0);
    });
    assert!(
        fixture
            .evaluate(id, &record)
            .unwrap_err()
            .contains("undefined")
    );
}

#[test]
fn missing_bundle_and_missing_predecessor_evidence_remain_red() {
    let empty = tempfile::tempdir().unwrap();
    assert!(verify_case(empty.path(), "pilot_r0_scope_and_operators", NOW).is_err());
    let fixture = fixture();
    fixture.save_plan();
    let id = "pilot_m1_real_clean_task";
    std::fs::write(
        fixture.root().join("runs").join(format!("{id}.json")),
        serde_json::to_vec(&fixture.record(id)).unwrap(),
    )
    .unwrap();
    let error = verify_case(fixture.root(), id, NOW).unwrap_err();
    assert!(
        error.contains("pilot_r0_scope_and_operators.json"),
        "{error}"
    );
}

#[test]
fn review_contract_can_be_replayed_but_cannot_grant_runtime_authority() {
    let fixture = fixture();
    fixture.save_plan();
    let id = "pilot_r0_scope_and_operators";
    std::fs::write(
        fixture.root().join("runs").join(format!("{id}.json")),
        serde_json::to_vec(&fixture.record(id)).unwrap(),
    )
    .unwrap();
    verify_case(fixture.root(), id, NOW).unwrap();
    assert!(!fixture.root().join(".shield-state").exists());
}

#[test]
fn missing_plans_decisions_budgets_and_zero_utility_are_not_defaults() {
    for change in 0..5 {
        let mut fixture = fixture();
        match change {
            0 => {
                fixture
                    .plan
                    .declarations
                    .remove("lab_authorization_and_recovery");
            }
            1 => {
                fixture.plan.cases.remove("pilot_c0_provider_gate");
            }
            2 => {
                fixture
                    .plan
                    .cases
                    .get_mut("pilot_m1_real_clean_task")
                    .unwrap()
                    .minimums
                    .clear();
            }
            3 => {
                fixture
                    .plan
                    .cases
                    .get_mut("pilot_m1_real_clean_task")
                    .unwrap()
                    .minimums
                    .insert(Metric::Completions, 0);
            }
            _ => {
                fixture
                    .plan
                    .cases
                    .get_mut("pilot_m1_uncertain_effects")
                    .unwrap()
                    .maximums
                    .clear();
            }
        }
        assert!(validate_plan(fixture.root(), &fixture.plan, NOW).is_err());
    }
}

#[test]
fn expired_future_or_changed_plans_cannot_reuse_old_results() {
    for change in 0..5 {
        let mut fixture = fixture();
        match change {
            0 => fixture.plan.expires_at = NOW - 1,
            1 => fixture.plan.frozen_at = NOW + 1,
            2 => fixture.plan.specification_sha256 = util::digest(b"old scope"),
            3 => fixture.plan.paper_sha256 = util::digest(b"old paper"),
            _ => fixture.plan.harness_sha256 = util::digest(b"old tests"),
        }
        assert!(validate_plan(fixture.root(), &fixture.plan, NOW).is_err());
    }
}

#[test]
fn unknown_skipped_invalid_and_already_native_blocked_probes_never_pass() {
    let fixture = fixture();
    let id = "pilot_e1_ordinary_launch_paths";
    for status in [
        ProbeStatus::Unknown,
        ProbeStatus::Skipped,
        ProbeStatus::Invalid,
        ProbeStatus::AlreadyNativeBlocked,
    ] {
        let mut record = fixture.record(id);
        fixture.edit_observation(&mut record, 0, |observation| observation.status = status);
        assert!(fixture.evaluate(id, &record).is_err());
    }
}

#[test]
fn gaps_self_observation_synthetic_sources_and_missing_raw_evidence_fail() {
    let fixture = fixture();
    let id = "pilot_m1_hostile_worker";
    for change in 0..7 {
        let mut record = fixture.record(id);
        fixture.edit_observation(&mut record, 0, |observation| match change {
            0 => observation.coverage = Coverage::Gap,
            1 => observation.observed_from = 201,
            2 => observation.observed_until = 299,
            3 => observation.observer_principal = observation.subject_principal.clone(),
            4 => observation.observer_trust_domain = observation.subject_trust_domain.clone(),
            5 => {
                observation.sources.insert(Source::Synthetic);
            }
            _ => observation.raw_evidence.clear(),
        });
        assert!(fixture.evaluate(id, &record).is_err());
    }
}

#[test]
fn local_proxy_or_model_observations_cannot_replace_real_required_provider_sources() {
    let fixture = fixture();
    let id = "pilot_m1_real_clean_task";
    let mut record = fixture.record(id);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.sources.remove(&Source::Provider);
    });
    assert!(fixture.evaluate(id, &record).is_err());
}

#[test]
fn any_forbidden_effect_or_missing_positive_control_fails_safety() {
    let fixture = fixture();
    let id = "pilot_e1_ordinary_launch_paths";
    for (metric, value) in [
        (Metric::ForbiddenEffects, 1),
        (Metric::PositiveControls, 0),
        (Metric::ResponseMs, 101),
    ] {
        let mut record = fixture.record(id);
        fixture.edit_observation(&mut record, 0, |observation| {
            observation.metrics.insert(metric, value);
        });
        assert!(fixture.evaluate(id, &record).is_err());
    }
    let mut record = fixture.record(id);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.remove(&Metric::ForbiddenEffects);
    });
    assert!(fixture.evaluate(id, &record).is_err());
}

#[test]
fn budgets_are_inclusive_and_one_unit_over_is_a_failure() {
    let fixture = fixture();
    let id = "pilot_m1_real_clean_task";
    let mut record = fixture.record(id);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::ElapsedMs, 100);
    });
    fixture.evaluate(id, &record).unwrap();
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::ElapsedMs, 101);
    });
    assert!(fixture.evaluate(id, &record).is_err());
}

#[test]
fn utility_cannot_be_substituted_by_refusal_or_one_trial_claiming_multiple_completions() {
    let fixture = fixture();
    let id = "pilot_m1_real_clean_task";
    for completions in [0, 2] {
        let mut record = fixture.record(id);
        fixture.edit_observation(&mut record, 0, |observation| {
            observation.metrics.insert(Metric::Completions, completions);
        });
        assert!(fixture.evaluate(id, &record).is_err());
    }
}

#[test]
fn wrong_identity_manifest_replay_and_timestamp_bindings_fail() {
    let fixture = fixture();
    let id = "pilot_e1_ordinary_launch_paths";
    for change in 0..7 {
        let mut record = fixture.record(id);
        match change {
            0 => record.plan_sha256 = util::digest(b"old plan"),
            1 => record.trials[0].profile_sha256 = util::digest(b"changed profile"),
            2 => record.trials[0].workload_sha256 = util::digest(b"changed workload"),
            3 => record.trials[0].started_at = fixture.plan.frozen_at,
            4 => record.trials[0].completed_at = NOW + 1,
            5 => record.trials[1].run_id = record.trials[0].run_id,
            _ => fixture.edit_observation(&mut record, 0, |observation| {
                observation.run_id = Uuid::new_v4()
            }),
        }
        assert!(fixture.evaluate(id, &record).is_err());
    }
}

#[test]
fn paired_variants_cannot_pool_counts_or_use_different_workloads() {
    let mut fixture = fixture();
    let id = "pilot_e1_ordinary_launch_paths";
    let mut record = fixture.record(id);
    record.trials.pop();
    assert!(fixture.evaluate(id, &record).is_err());
    let changed = artifact(fixture.root(), b"different fixture workload");
    fixture
        .plan
        .cases
        .get_mut(id)
        .unwrap()
        .variants
        .get_mut("composed")
        .unwrap()
        .workload = changed;
    assert!(validate_plan(fixture.root(), &fixture.plan, NOW).is_err());
}

#[test]
fn usability_zero_edit_and_unchanged_prompt_requirements_are_not_relaxable_budgets() {
    let fixture = fixture();
    let id = "pilot_p0_silent_unchanged_launch";
    for metric in [
        Metric::ManualSecurityEdits,
        Metric::ExtraUnchangedLaunchPrompts,
    ] {
        let mut record = fixture.record(id);
        fixture.edit_observation(&mut record, 0, |observation| {
            observation.metrics.insert(metric, 1);
        });
        assert!(fixture.evaluate(id, &record).is_err());
    }
}

#[test]
fn detection_fault_handling_and_recovery_are_distinct_from_prevention_and_utility() {
    let fixture = fixture();
    let detection = "pilot_o1_detection_and_notification";
    let mut record = fixture.record(detection);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::ForbiddenEffects, 1);
    });
    fixture.evaluate(detection, &record).unwrap();
    let recovery = "pilot_o1_authenticated_restore";
    let mut record = fixture.record(recovery);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::RemainingAuthority, 1);
    });
    assert!(fixture.evaluate(recovery, &record).is_err());
    let fault = "pilot_m1_uncertain_effects";
    let mut record = fixture.record(fault);
    fixture.edit_observation(&mut record, 0, |observation| {
        observation.metrics.insert(Metric::Completions, 0);
    });
    fixture.evaluate(fault, &record).unwrap();
}

#[test]
fn native_value_requires_comparable_observed_benefit_not_a_borrowed_native_block() {
    let mut fixture = fixture();
    let id = "pilot_e0_native_value_comparison";
    fixture.plan.cases.get_mut(id).unwrap().comparison = Some(Comparison::AddedProtection);
    let record = fixture.record(id);
    assert!(fixture.evaluate(id, &record).is_err());
    fixture.plan.cases.get_mut(id).unwrap().comparison = Some(Comparison::SaferOperability);
    let mut record = fixture.record(id);
    let index = record
        .trials
        .iter()
        .position(|trial| trial.variant == "shield")
        .unwrap();
    fixture.edit_observation(&mut record, index, |observation| {
        observation.metrics.insert(Metric::OperatorEffortMs, 80);
    });
    assert!(fixture.evaluate(id, &record).is_err());
}

#[test]
fn tampered_empty_oversize_or_noncanonical_artifacts_are_not_evidence() {
    let fixture = fixture();
    let id = "pilot_m1_real_clean_task";
    let mut record = fixture.record(id);
    record.trials[0].observation.sha256 = "..\\outside".into();
    assert!(fixture.evaluate(id, &record).is_err());
    let record = fixture.record(id);
    let path = fixture
        .root()
        .join("artifacts")
        .join(format!("{}.blob", record.trials[0].observation.sha256));
    std::fs::write(&path, b"changed").unwrap();
    assert!(fixture.evaluate(id, &record).is_err());
    std::fs::write(&path, b"").unwrap();
    assert!(fixture.evaluate(id, &record).is_err());
    std::fs::write(&path, vec![b'x'; 2 * 1024 * 1024 + 1]).unwrap();
    assert!(fixture.evaluate(id, &record).is_err());
}

#[test]
fn schemas_reject_unknown_fields_and_duplicate_map_keys() {
    let fixture = fixture();
    let mut value = serde_json::to_value(&fixture.plan).unwrap();
    value["pretend_gate_pass"] = true.into();
    assert!(serde_json::from_value::<Plan>(value).is_err());
    let text = serde_json::to_string(&fixture.plan).unwrap();
    let text = text.replacen(
        "\"enabled_extensions\":[]",
        "\"enabled_extensions\":[],\"enabled_extensions\":[]",
        1,
    );
    assert!(serde_json::from_str::<Plan>(&text).is_err());
    let text = serde_json::to_string(&fixture.plan).unwrap();
    let text = text.replacen(
        "\"completions\":1",
        "\"completions\":1,\"completions\":0",
        1,
    );
    assert!(serde_json::from_str::<Plan>(&text).is_err());
}

#[test]
fn optional_or_future_features_are_never_silent_successful_skips() {
    let fixture = fixture();
    fixture.save_plan();
    assert!(
        verify_case(fixture.root(), "future_local_only_information_flow", NOW)
            .unwrap_err()
            .contains("not selected")
    );
    assert!(
        verify_case(fixture.root(), "conditional_protected_verifier", NOW)
            .unwrap_err()
            .contains("not selected")
    );
}
