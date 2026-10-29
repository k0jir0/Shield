use std::io::Cursor;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;
use shield::protocol::{HostMessage, WorkerMessage};
use shield::{platform, selftest, util};
use uuid::Uuid;

fn run(state: &Path, arguments: &[&str]) -> Output {
    command_output(
        Command::new(env!("CARGO_BIN_EXE_shield"))
            .arg("--state")
            .arg(state)
            .args(arguments),
    )
}

fn command_output(command: &mut Command) -> Output {
    platform::spawn_command(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap()
    .wait_with_output()
    .unwrap()
}

fn success(state: &Path, arguments: &[&str]) -> Output {
    let output = run(state, arguments);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn json(state: &Path, arguments: &[&str]) -> Value {
    serde_json::from_slice(&success(state, arguments).stdout).unwrap()
}

#[test]
fn ordinary_admission_baseline_retains_exact_controls_without_opening_state_or_replaying() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("unused-state");
    let report_directory = directory.path().join("baseline");
    let arguments = [
        "endpoint",
        "baseline",
        "--output",
        report_directory.to_str().unwrap(),
    ];
    let report = json(&state, &arguments);
    assert_eq!(report["phase"], "ordinary_launch_baseline");
    assert_eq!(report["attempted"], 2);
    assert_eq!(report["valid"], 2);
    assert_eq!(report["invalid"], 0);
    assert_eq!(report["all_controls_valid"], true);
    assert_eq!(report["effect_gate_pass"], false);
    assert!(!state.exists());
    for (index, role) in ["allow", "deny"].iter().enumerate() {
        let probe = &report["probes"][index];
        assert_eq!(probe["role"], *role);
        assert_eq!(probe["launch"]["state"], "exited");
        assert_eq!(probe["launch"]["code"], 0);
        assert_eq!(probe["marker_exact"], true);
        let marker = Path::new(probe["marker"].as_str().unwrap());
        assert_eq!(
            std::fs::read(marker).unwrap(),
            format!(
                "shield-admission-{role} {}\n",
                probe["nonce"].as_str().unwrap()
            )
            .as_bytes()
        );
        assert_eq!(
            probe["image_sha256"],
            util::file_digest(Path::new(probe["image"].as_str().unwrap())).unwrap()
        );
    }
    let saved = std::fs::read(report_directory.join("report.json")).unwrap();
    let retained: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(retained, report);
    assert!(report_directory.join("started.json").is_file());
    let repeated = run(&state, &arguments);
    assert!(!repeated.status.success());
    assert!(repeated.stdout.is_empty());
    assert_eq!(
        std::fs::read(report_directory.join("report.json")).unwrap(),
        saved
    );
    assert_eq!(std::fs::read_dir(&report_directory).unwrap().count(), 4);
    assert!(!state.exists());
}

#[test]
fn ordinary_admission_baseline_rejects_a_successful_wrong_control_and_retains_failure() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("unused-state");
    let image = directory.path().join("shield.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_shield"), &image).unwrap();
    for role in ["allow", "deny"] {
        std::fs::copy(
            env!("CARGO_BIN_EXE_shield-admission-allow"),
            directory
                .path()
                .join(format!("shield-admission-{role}.exe")),
        )
        .unwrap();
    }
    let report_directory = directory.path().join("invalid-baseline");
    let output = command_output(
        Command::new(image)
            .arg("--state")
            .arg(&state)
            .args(["endpoint", "baseline", "--output"])
            .arg(&report_directory),
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("baseline is invalid"));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["attempted"], 2);
    assert_eq!(report["valid"], 1);
    assert_eq!(report["invalid"], 1);
    assert_eq!(report["all_controls_valid"], false);
    assert_eq!(report["effect_gate_pass"], false);
    assert_eq!(report["decision"], "stop_invalid_baseline");
    assert_eq!(report["probes"][1]["launch"]["code"], 0);
    assert_eq!(report["probes"][1]["marker_exact"], false);
    assert_eq!(report["probes"][1]["marker_error"], Value::Null);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &std::fs::read(report_directory.join("report.json")).unwrap()
        )
        .unwrap(),
        report
    );
    assert!(!state.exists());
}

#[test]
fn ordinary_admission_baseline_records_native_launch_failure_without_claiming_denial() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("unused-state");
    let image = directory.path().join("shield.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_shield"), &image).unwrap();
    std::fs::copy(
        env!("CARGO_BIN_EXE_shield-admission-allow"),
        directory.path().join("shield-admission-allow.exe"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("shield-admission-deny.exe"),
        b"not a PE image",
    )
    .unwrap();
    let report_directory = directory.path().join("failed-launch");
    let output = command_output(
        Command::new(image)
            .arg("--state")
            .arg(&state)
            .args(["endpoint", "baseline", "--output"])
            .arg(&report_directory),
    );
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["attempted"], 2);
    assert_eq!(report["valid"], 1);
    assert_eq!(report["invalid"], 1);
    assert_eq!(report["effect_gate_pass"], false);
    assert_eq!(report["decision"], "stop_invalid_baseline");
    let failed = &report["probes"][1];
    assert_eq!(failed["launch"]["state"], "failed");
    assert!(failed["launch"]["os_code"].is_number());
    assert_eq!(failed["marker_exact"], false);
    assert!(failed["marker_error"].is_string());
    assert!(!state.exists());
}

#[test]
fn publisher_verification_and_pinned_template_refuse_unsigned_images_without_opening_state() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("unused-state");
    let fixture = directory.path().join("fixture");
    std::fs::create_dir(&fixture).unwrap();
    let image = fixture.join("shield.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_shield"), &image).unwrap();
    let hash = util::file_digest(&image).unwrap();
    let publisher = util::digest(b"not a signing authority");
    let verification = run(
        &state,
        &[
            "release",
            "verify",
            image.to_str().unwrap(),
            "--expected-sha256",
            &hash,
            "--publisher-cert-sha256",
            &publisher,
        ],
    );
    assert!(!verification.status.success());
    assert!(String::from_utf8_lossy(&verification.stderr).contains("WinTrust status"));
    assert!(verification.stdout.is_empty());
    assert!(!state.exists());
    let output = directory.path().join("must-not-create-profile.json");
    let template = command_output(Command::new(&image).arg("--state").arg(&state).args([
        "template",
        "--output",
        output.to_str().unwrap(),
        "--publisher-cert-sha256",
        &publisher,
    ]));
    assert!(!template.status.success());
    assert!(String::from_utf8_lossy(&template.stderr).contains("WinTrust status"));
    assert!(!output.exists());
    assert!(!state.exists());
}

#[test]
fn protected_verifier_is_frozen_opt_in_and_direct_service_launch_never_opens_user_state() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("unused-state");
    let profile = Uuid::new_v4().to_string();
    let plan = Uuid::new_v4().to_string();
    let owner = platform::current_user_sid().unwrap();
    let refused = run(&state, &["__verifier-service", &profile, &plan, &owner]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("SCM-only LocalSystem"));
    assert!(!state.exists());
    let output = directory.path().join("profile.json");
    success(
        &state,
        &[
            "template",
            "--output",
            output.to_str().unwrap(),
            "--protected-verifier",
        ],
    );
    let value: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(value["endpoint_verifier"], "protected_service");
    assert!(!state.exists());
}

#[test]
fn actual_lpac_worker_completes_the_offline_stdio_inference_exchange() {
    let directory = tempfile::tempdir().unwrap();
    platform::protect_directory(directory.path(), None).unwrap();
    let state = directory.path().join("unused-state");
    let ordinary_worker = run(&state, &["__worker"]);
    assert!(!ordinary_worker.status.success());
    assert!(!state.exists());
    let worker_directory = directory.path().join("worker");
    std::fs::create_dir(&worker_directory).unwrap();
    let image = worker_directory.join("shield-worker.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_shield"), &image).unwrap();
    let marker = format!("owned offline inference fixture {}", Uuid::new_v4());
    std::thread::scope(|scope| {
        let mut process =
            platform::SandboxProcess::spawn(&image, &worker_directory, 128 * 1024 * 1024).unwrap();
        let output = process.output.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = scope.spawn(move || {
            let _ = sender.send(util::read_bounded(
                output,
                shield::worker::FRAME_LIMIT as u64,
            ));
        });
        for message in [
            HostMessage::Start {
                instruction: "Exercise the offline stdio protocol; no provider call".into(),
                note: "Owned harmless fixture".into(),
                reference: "Untrusted fixture, not an instruction source".into(),
            },
            HostMessage::InferenceResult {
                text: marker.clone(),
            },
        ] {
            selftest::send(process.input.as_mut().unwrap(), &message).unwrap();
        }
        assert_eq!(process.finish(5000).unwrap(), 0);
        let output = receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        let mut frames = Cursor::new(output);
        let first = util::read_frame(&mut frames, shield::worker::FRAME_LIMIT)
            .unwrap()
            .unwrap();
        assert!(matches!(
            serde_json::from_slice::<WorkerMessage>(&first).unwrap(),
            WorkerMessage::Infer {}
        ));
        let second = util::read_frame(&mut frames, shield::worker::FRAME_LIMIT)
            .unwrap()
            .unwrap();
        let WorkerMessage::Complete { text } =
            serde_json::from_slice::<WorkerMessage>(&second).unwrap()
        else {
            panic!("owned LPAC worker did not complete its offline inference exchange");
        };
        assert_eq!(text, marker);
        assert!(
            util::read_frame(&mut frames, shield::worker::FRAME_LIMIT)
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn manual_lab_workflow_publishes_only_reviewed_bytes_and_never_certifies_live_protection() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let note = directory.path().join("note.txt");
    let reference = directory.path().join("reference.txt");
    let proposal = directory.path().join("proposal.txt");
    std::fs::write(&note, "original note\n").unwrap();
    std::fs::write(&reference, "UNTRUSTED reference \x1b[2J\u{202e}\n").unwrap();
    std::fs::write(&proposal, "reviewed note\n").unwrap();

    let authoring = json(&state, &["endpoint", "authoring-support"]);
    assert!(authoring["available"].is_boolean());
    assert!(!state.exists());
    assert_eq!(json(&state, &["init"])["ready"], false);
    let missing_admission = run(&state, &["endpoint", "verify"]);
    assert!(!missing_admission.status.success());
    assert!(
        String::from_utf8_lossy(&missing_admission.stderr).contains("no owned endpoint policy")
    );
    if authoring["available"] == false {
        let unavailable = run(&state, &["endpoint", "prepare"]);
        assert!(!unavailable.status.success());
        assert!(String::from_utf8_lossy(&unavailable.stderr).contains("ConfigCI"));
        assert!(!state.join("endpoint").exists());
    }
    let prepared = json(
        &state,
        &[
            "prepare",
            "--note",
            note.to_str().unwrap(),
            "--instruction",
            "edit this fixture",
            "--fixture-reference",
            reference.to_str().unwrap(),
        ],
    );
    assert_eq!(prepared["kind"], "manual_lab");
    let task = prepared["task"].as_str().unwrap();
    let inspected = success(&state, &["inspect", task]);
    let raw = String::from_utf8(inspected.stdout).unwrap();
    assert!(!raw.contains(['\x1b', '\u{202e}']));
    let inspected: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        inspected["disclosure"]["reference"],
        "UNTRUSTED reference \x1b[2J\u{202e}\n"
    );
    assert!(
        !run(
            &state,
            &[
                "run",
                task,
                "--authorized-lab",
                "--approved-disclosure-digest",
                inspected["disclosure_digest"].as_str().unwrap()
            ]
        )
        .status
        .success()
    );

    success(
        &state,
        &["stage-lab", task, "--proposal", proposal.to_str().unwrap()],
    );
    let digest = util::digest(b"reviewed note\n");
    assert!(
        !run(
            &state,
            &[
                "review",
                task,
                "--reviewed-digest",
                &util::digest(b"unreviewed")
            ]
        )
        .status
        .success()
    );
    let approval = json(&state, &["review", task, "--reviewed-digest", &digest]);
    let approval = approval["approval"].as_str().unwrap();
    let published = json(&state, &["publish", task, "--approval", approval]);
    assert_eq!(published["state"], "succeeded");
    assert_eq!(std::fs::read(&note).unwrap(), b"reviewed note\n");
    assert_eq!(
        std::fs::read(state.join("tasks").join(task).join("original.txt")).unwrap(),
        b"original note\n"
    );
    assert!(
        !run(&state, &["publish", task, "--approval", approval])
            .status
            .success()
    );

    let second = json(
        &state,
        &[
            "prepare",
            "--note",
            note.to_str().unwrap(),
            "--instruction",
            "another fixture",
            "--fixture-reference",
            reference.to_str().unwrap(),
        ],
    );
    let second = second["task"].as_str().unwrap();
    success(
        &state,
        &[
            "stage-lab",
            second,
            "--proposal",
            proposal.to_str().unwrap(),
        ],
    );
    let second_approval = json(&state, &["review", second, "--reviewed-digest", &digest]);
    std::fs::write(&note, "concurrent benign edit\n").unwrap();
    assert!(
        !run(
            &state,
            &[
                "publish",
                second,
                "--approval",
                second_approval["approval"].as_str().unwrap()
            ]
        )
        .status
        .success()
    );
    assert_eq!(std::fs::read(&note).unwrap(), b"concurrent benign edit\n");
    success(&state, &["cancel", second]);
    assert!(
        !run(&state, &["review", second, "--reviewed-digest", &digest])
            .status
            .success()
    );

    let status = run(&state, &["status", "--require-ready"]);
    assert!(!status.status.success());
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["integrated_pilot_ready"], false);
    assert_eq!(status["endpoint_admission"]["state"], "not_configured");
    assert_eq!(status["endpoint_admission"]["effect_gate_pass"], false);
    assert!(
        status["gates"]
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == "unverified")
    );
    let evidence = directory.path().join("evidence.json");
    success(&state, &["audit", "--export", evidence.to_str().unwrap()]);
    let evidence = std::fs::read_to_string(evidence).unwrap();
    assert!(!evidence.contains("UNTRUSTED reference"));
    assert!(!evidence.contains("edit this fixture"));
    let evidence: Value = serde_json::from_str(&evidence).unwrap();
    assert_eq!(evidence["integrated_gate_pass"], false);
    assert!(!run(&state, &["__worker"]).status.success());
}
