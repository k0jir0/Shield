use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

use crate::error::{Error, Result, invalid};
use crate::{endpoint, files, platform, util};

const IMAGE_LIMIT: u64 = 128 * 1024 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NativeObservation {
    Observed { value: Value },
    Unavailable { error: String },
}

impl NativeObservation {
    fn capture(result: Result<Value>) -> Self {
        match result {
            Ok(value) => Self::Observed { value },
            Err(error) => Self::Unavailable {
                error: error.to_string(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Launch {
    Exited { code: Option<i32> },
    Failed { error: String, os_code: Option<i32> },
    TimedOut,
}

#[derive(Debug, Serialize)]
pub struct Probe {
    pub role: &'static str,
    pub image: PathBuf,
    pub image_sha256: String,
    pub nonce: String,
    pub marker: PathBuf,
    pub launch: Launch,
    pub elapsed_ms: u128,
    pub marker_exact: bool,
    pub marker_error: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub run_id: Uuid,
    pub started_at: u64,
    pub completed_at: u64,
    pub controller_sha256: String,
    pub environment: platform::Environment,
    pub phase: &'static str,
    pub authoring: NativeObservation,
    pub native_inventory: NativeObservation,
    pub probes: Vec<Probe>,
    pub attempted: usize,
    pub valid: usize,
    pub invalid: usize,
    pub all_controls_valid: bool,
    pub decision: &'static str,
    pub effect_gate_pass: bool,
    pub limitation: &'static str,
}

struct OrdinaryChild(Child);

impl Drop for OrdinaryChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                if let Err(error) = self.0.kill() {
                    eprintln!("Shield owned baseline process termination failed: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("Shield owned baseline process reaping failed: {error}");
                }
            }
        }
    }
}

fn wait(child: Child) -> Result<Launch> {
    let mut child = OrdinaryChild(child);
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(Launch::Exited {
                code: status.code(),
            });
        }
        if Instant::now() >= deadline {
            child.0.kill().map_err(|error| {
                Error::Unknown(format!("owned admission probe termination failed: {error}"))
            })?;
            child.0.wait()?;
            return Ok(Launch::TimedOut);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn control_valid(launch: &Launch, marker_exact: bool, marker_error: &Option<String>) -> bool {
    matches!(launch, Launch::Exited { code: Some(0) }) && marker_exact && marker_error.is_none()
}

fn probe(image: &Path, role: &'static str, output: &Path) -> Result<Probe> {
    files::check_no_reparse(image)?;
    let _image_directories = files::pin_directories(
        image
            .parent()
            .ok_or_else(|| invalid("admission probe has no parent directory"))?,
    )?;
    // Cargo may hardlink these inert build artifacts; hold all links against writes.
    let mut pinned = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(image)?;
    if !pinned.metadata()?.is_file() {
        return Err(invalid("admission probe must be a regular executable file"));
    }
    let image_sha256 = util::digest(&util::read_bounded(&mut pinned, IMAGE_LIMIT)?);
    let nonce = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let directory = output.join(format!("Shield-admission-{nonce}"));
    std::fs::create_dir(&directory)?;
    let _marker_directories = files::pin_directories(&directory)?;
    let marker = directory.join("marker.txt");
    let started = Instant::now();
    let launch = match platform::spawn_command(
        Command::new(image)
            .arg(&marker)
            .arg(&nonce)
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    ) {
        Ok(child) => wait(child)?,
        Err(error) => Launch::Failed {
            os_code: error.raw_os_error(),
            error: error.to_string(),
        },
    };
    let elapsed_ms = started.elapsed().as_millis();
    pinned.seek(SeekFrom::Start(0))?;
    if util::digest(&util::read_bounded(&mut pinned, IMAGE_LIMIT)?) != image_sha256 {
        return Err(Error::Unknown(
            "admission probe image changed during observation".into(),
        ));
    }
    let expected = format!("shield-admission-{role} {nonce}\n");
    let (marker_exact, marker_error) = match files::snapshot_bytes(&marker, 256) {
        Ok((bytes, _)) => (bytes == expected.as_bytes(), None),
        Err(error) => (false, Some(error.to_string())),
    };
    let valid = control_valid(&launch, marker_exact, &marker_error);
    Ok(Probe {
        role,
        image: image.to_owned(),
        image_sha256,
        nonce,
        marker,
        launch,
        elapsed_ms,
        marker_exact,
        marker_error,
        valid,
    })
}

pub fn run(output: &Path) -> Result<Report> {
    let executable = std::env::current_exe()?;
    let images = executable
        .parent()
        .ok_or_else(|| invalid("controller executable has no directory"))?;
    run_with_images(output, images)
}

fn run_with_images(output: &Path, images: &Path) -> Result<Report> {
    if platform::is_elevated()? {
        return Err(Error::Denied(
            "ordinary admission baselines require an unelevated daily-user context".into(),
        ));
    }
    files::validate_path(output)?;
    let _output_parents = files::pin_directories(
        output
            .parent()
            .ok_or_else(|| invalid("baseline output has no parent directory"))?,
    )?;
    let run_id = Uuid::new_v4();
    let started_at = util::now()?;
    let environment = platform::environment()?;
    let controller_sha256 = util::file_digest(&std::env::current_exe()?)?;
    std::fs::create_dir(output)?;
    platform::protect_directory(output, None)?;
    let _output_directory = files::pin_directories(output)?;
    files::create_new(
        &output.join("started.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1, "run_id": run_id, "started_at": started_at,
            "phase": "ordinary_launch_baseline", "effect_gate_pass": false,
            "controller_sha256": controller_sha256,
            "environment": environment,
            "warning": "Only report.json records completion. Interrupted runs must not be replayed into this directory."
        }))?,
    )?;
    let authoring = NativeObservation::capture(endpoint::authoring_support());
    let native_inventory = NativeObservation::capture(endpoint::inventory());
    let mut probes = Vec::new();
    for role in ["allow", "deny"] {
        probes.push(probe(
            &images.join(format!("shield-admission-{role}.exe")),
            role,
            output,
        )?);
    }
    let valid = probes.iter().filter(|probe| probe.valid).count();
    let all_controls_valid = valid == 2;
    let prerequisites_observed = matches!(&authoring, NativeObservation::Observed { value } if value["available"] == true)
        && matches!(&native_inventory, NativeObservation::Observed { .. });
    let report = Report {
        schema_version: 1,
        run_id,
        started_at,
        completed_at: util::now()?,
        controller_sha256,
        environment,
        phase: "ordinary_launch_baseline",
        authoring,
        native_inventory,
        attempted: probes.len(),
        valid,
        invalid: probes.len() - valid,
        probes,
        all_controls_valid,
        decision: if !all_controls_valid {
            "stop_invalid_baseline"
        } else if !prerequisites_observed {
            "stop_native_prerequisites_unavailable_or_unverified"
        } else {
            "requires_authorized_lab_comparison"
        },
        effect_gate_pass: false,
        limitation: "Two trusted inert controls, one ordinary direct launch each, observed by the unelevated controller through exit status and exact markers. Not an independent/admin-proof observer, absence-of-effect proof, native-block attribution, alternate-route test, native-value comparison, or E0/E1 pass. No policies, services, provider resources or credentials are changed. Fixture stderr is not captured. The five-second process timeout is an engineering bound, not a whole-command latency guarantee. Report paths and the user SID are local diagnostic identity data; do not upload without review.",
    };
    files::create_new(
        &output.join("report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_baseline_has_no_completion_record_and_cannot_reuse_its_directory() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("incomplete");
        assert!(run_with_images(&output, directory.path()).is_err());
        let started = std::fs::read(output.join("started.json")).unwrap();
        assert!(!output.join("report.json").exists());
        assert!(run_with_images(&output, directory.path()).is_err());
        assert_eq!(std::fs::read(output.join("started.json")).unwrap(), started);
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 1);
    }

    #[test]
    fn exact_marker_alone_never_proves_a_valid_positive_control() {
        for launch in [
            Launch::TimedOut,
            Launch::Failed {
                error: "native denial, not attribution".into(),
                os_code: Some(4551),
            },
            Launch::Exited { code: Some(1) },
            Launch::Exited { code: None },
        ] {
            assert!(!control_valid(&launch, true, &None));
        }
        let success = Launch::Exited { code: Some(0) };
        assert!(control_valid(&success, true, &None));
        assert!(!control_valid(&success, false, &None));
        assert!(!control_valid(
            &success,
            true,
            &Some("observer failed".into())
        ));
    }

    #[test]
    fn ordinary_process_deadline_terminates_and_reaps_the_owned_child() {
        const FIXTURE: &str = "SHIELD_BASELINE_DEADLINE_FIXTURE";
        if std::env::var(FIXTURE).as_deref() == Ok("owned-test-child") {
            thread::sleep(Duration::from_secs(30));
            return;
        }
        let started = Instant::now();
        let child = platform::spawn_command(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "baseline::tests::ordinary_process_deadline_terminates_and_reaps_the_owned_child",
                ])
                .env(FIXTURE, "owned-test-child")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .unwrap();
        assert!(matches!(wait(child).unwrap(), Launch::TimedOut));
        assert!(started.elapsed() >= PROBE_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(15));
    }
}
