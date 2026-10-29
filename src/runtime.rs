use std::io::BufReader;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use uuid::Uuid;

use crate::error::{Error, Result, invalid};
use crate::protocol::{HostMessage, WorkerMessage};
use crate::state::{Grant, Store, TaskKind};
use crate::{endpoint, network, platform, providers, selftest, util, worker};

pub fn disclosure(store: &Store, id: Uuid) -> Result<serde_json::Value> {
    let task = store.task(id)?;
    let (note, reference) = store.inputs(&task)?;
    Ok(json!({
        "task": task.spec,
        "model": store.profile.model,
        "inference_destination": "https://api.openai.com/v1/responses",
        "provider_storage_request": false,
        "note": note,
        "reference": reference,
        "warning": "Approval discloses these exact bytes to the inference provider. It does not approve publication, prove provider retention policy, or establish integrated protection."
    }))
}

pub fn disclosure_digest(store: &Store, id: Uuid) -> Result<String> {
    util::json_digest(&disclosure(store, id)?)
}

fn receive(receiver: &Receiver<Vec<u8>>, deadline: Instant) -> Result<WorkerMessage> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Deadline)?;
    let frame = match receiver.recv_timeout(remaining) {
        Ok(frame) => frame,
        Err(RecvTimeoutError::Timeout) => return Err(Error::Deadline),
        Err(RecvTimeoutError::Disconnected) => {
            return Err(Error::Protocol(
                "worker exited or its bounded protocol reader failed",
            ));
        }
    };
    serde_json::from_slice(&frame).map_err(|_| {
        Error::Protocol("worker sent malformed JSON or an unknown protocol operation/field")
    })
}

fn error_code(error: &Error) -> &'static str {
    match error {
        Error::Deadline => "deadline",
        Error::Denied(_) => "authorization_or_completion_denied",
        Error::Unknown(_) => "external_effect_unknown",
        Error::Quota(_) => "quota",
        Error::Protocol(_) => "protocol",
        Error::Remote { .. } => "remote_response",
        Error::Windows { .. } => "native_failure",
        Error::Journal(_) => "journal",
        Error::Io(_) => "io",
        Error::Invalid(_) | Error::Json(_) => "invalid_input",
        Error::Unsupported(_) => "unsupported",
    }
}

fn inference(
    store: &mut Store,
    grant: &Grant,
    parameters: &serde_json::Value,
    deadline: Instant,
) -> Result<String> {
    let parameters_digest = util::json_digest(parameters)?;
    let operation = store.reserve_model(
        grant.task_id,
        grant.epoch,
        "single-inference",
        &parameters_digest,
    )?;
    if operation.replay {
        if operation.state != "succeeded" {
            return Err(Error::Unknown(format!(
                "operation {} is {}; automatic inference replay is forbidden",
                operation.id, operation.state
            )));
        }
        let text = store.cached_model_result(grant.task_id, grant.epoch, operation.id)?;
        store.event(
            Some(grant.task_id),
            "cached_model_result_authorized",
            json!({"operation": operation.id}),
        )?;
        return Ok(text);
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Deadline)?;
    store.dispatched(operation.id)?;
    match providers::infer(&store.profile, parameters, remaining) {
        Ok(completion) => {
            let text = completion.text;
            if let Err(error) =
                store.save_model_result(grant.task_id, operation.id, text.as_bytes())
            {
                return Err(Error::Unknown(format!(
                    "inference returned but operation {} could not be durably finalized: {error}",
                    operation.id
                )));
            }
            store.event(Some(grant.task_id), "model_completion_observed", json!({
                "operation": operation.id, "response_id": completion.response_id,
                "resolved_model": completion.model, "reported_output_tokens": completion.output_tokens,
                "requested_model": store.profile.model
            }))?;
            store.authorize(grant.task_id, grant.epoch)?;
            Ok(text)
        }
        Err(error) => {
            let outcome = match &error {
                Error::Remote {
                    status: 400 | 401 | 403 | 413 | 429,
                    ..
                } => "denied",
                Error::Windows {
                    operation: "CredReadW",
                    ..
                } => "denied",
                Error::Denied(_) => "failed",
                _ => "unknown",
            };
            if let Err(journal) = store.outcome(operation.id, outcome, None) {
                return Err(Error::Unknown(format!(
                    "inference failed ({}) and its outcome could not be recorded: {journal}",
                    error_code(&error)
                )));
            }
            Err(error)
        }
    }
}

fn conversation(
    store: &mut Store,
    grant: &Grant,
    process: &mut platform::SandboxProcess,
    receiver: &Receiver<Vec<u8>>,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let task = store.task(grant.task_id)?;
    let (note, reference) = store.inputs(&task)?;
    let parameters =
        providers::inference_parameters(&store.profile, &task.spec.instruction, &note, &reference)?;
    store.authorize(grant.task_id, grant.epoch)?;
    selftest::send(
        process
            .input
            .as_mut()
            .ok_or_else(|| invalid("worker input is closed"))?,
        &HostMessage::Start {
            instruction: task.spec.instruction,
            note,
            reference,
        },
    )?;
    let mut inference_digest = None;
    for _ in 0..8 {
        store.authorize(grant.task_id, grant.epoch)?;
        match receive(receiver, deadline)? {
            WorkerMessage::Infer {} => {
                let text = inference(store, grant, &parameters, deadline)?;
                store.authorize(grant.task_id, grant.epoch)?;
                inference_digest = Some(util::digest(text.as_bytes()));
                selftest::send(
                    process
                        .input
                        .as_mut()
                        .ok_or_else(|| invalid("worker input is closed"))?,
                    &HostMessage::InferenceResult { text },
                )?;
            }
            WorkerMessage::Complete { text } => {
                if text.is_empty()
                    || text.len() as u64 > store.profile.limits.output_bytes
                    || inference_digest.as_deref() != Some(&util::digest(text.as_bytes()))
                {
                    return Err(Error::Protocol(
                        "worker completion does not match the bounded completed model result",
                    ));
                }
                util::text(text.as_bytes())?;
                store.authorize(grant.task_id, grant.epoch)?;
                return Ok(text.into_bytes());
            }
            WorkerMessage::ProbeResult { .. } => {
                return Err(Error::Protocol(
                    "a live worker attempted to submit diagnostic evidence",
                ));
            }
        }
    }
    Err(Error::Protocol(
        "worker exceeded the finite protocol-operation limit",
    ))
}

fn native_health(store: &Store) -> Result<()> {
    store.profile.verify_host()?;
    network::verify(
        store.profile.id,
        &store.worker_path(),
        &store.profile.binary_sha256,
    )?;
    endpoint::active_plan(store)?;
    Ok(())
}

fn deadline_watch(
    job: std::os::windows::io::OwnedHandle,
    deadline: Instant,
    stop: Receiver<()>,
) -> Result<()> {
    match stop.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(()) => Ok(()),
        Err(reason) => {
            platform::terminate_job(&job)?;
            match reason {
                RecvTimeoutError::Timeout => Err(Error::Deadline),
                RecvTimeoutError::Disconnected => Err(Error::Denied(
                    "deadline watchdog owner disappeared before worker exit was verified".into(),
                )),
            }
        }
    }
}

fn completed_output(
    result: Result<Vec<u8>>,
    exit: u32,
    monitors: [Result<()>; 3],
    deadline: Instant,
    validate_native_and_authority: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    let bytes = result?;
    for monitor in monitors {
        monitor?;
    }
    if exit != 0 {
        return Err(Error::Denied(format!(
            "worker did not exit successfully; native exit=0x{exit:08x}"
        )));
    }
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    validate_native_and_authority()?;
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    Ok(bytes)
}

fn watch(
    root: std::path::PathBuf,
    grant: Grant,
    job: std::os::windows::io::OwnedHandle,
    deadline: Instant,
    stop: Receiver<()>,
) -> Result<()> {
    let store = match Store::open(&root) {
        Ok(store) => store,
        Err(error) => {
            platform::terminate_job(&job)?;
            return Err(error);
        }
    };
    let mut next_native_check = Instant::now();
    loop {
        let authorization = if Instant::now() >= deadline {
            Err(Error::Deadline)
        } else {
            store.authorize(grant.task_id, grant.epoch)
        };
        if let Err(error) = authorization {
            platform::terminate_job(&job)?;
            return Err(error);
        }
        if Instant::now() >= next_native_check {
            if let Err(error) = native_health(&store) {
                platform::terminate_job(&job)?;
                return Err(error);
            }
            next_native_check = Instant::now() + Duration::from_secs(1);
        }
        match stop.recv_timeout(Duration::from_millis(100)) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

pub fn run(store: &mut Store, id: Uuid, approved_disclosure_digest: &str) -> Result<()> {
    let _control = store.control_lock()?;
    store.profile.verify_host()?;
    if platform::is_elevated()? {
        return Err(Error::Denied("the runtime must not run elevated; use elevation only for the explicit owned-boundary setup helper".into()));
    }
    let task = store.task(id)?;
    if task.spec.kind != TaskKind::Live || task.phase != "prepared" {
        return Err(Error::Denied(
            "live execution requires a prepared real-provider task, not a manual fixture".into(),
        ));
    }
    if approved_disclosure_digest != disclosure_digest(store, id)? {
        return Err(Error::Denied("input-disclosure approval does not bind this exact task, profile, model, and snapshots".into()));
    }
    let worker_path = store.worker_path();
    let boundary = network::verify(store.profile.id, &worker_path, &store.profile.binary_sha256)?;
    let admission = endpoint::active_plan(store)?;
    let preflight = selftest::run_with_worker(None, Some(&worker_path))?;
    store.event(
        Some(id),
        "native_preflight",
        json!({
            "worker_sha256": boundary.worker_sha256,
            "persistent_filters": boundary.persistent_exact_image_filters,
            "endpoint_policy": admission.policy_id,
            "endpoint_revision": admission.revision,
            "all_scoped_probes_passed": preflight.all_passed,
            "observations": preflight.observations,
            "integrated_gate_pass": false
        }),
    )?;
    if !preflight.all_passed {
        return Err(Error::Denied(
            "a required native isolation probe failed; no task input was sent to a worker".into(),
        ));
    }
    let grant = store.begin(id)?;
    let deadline =
        Instant::now() + Duration::from_secs(u64::from(store.profile.limits.deadline_seconds));
    let directory = worker_path
        .parent()
        .ok_or_else(|| invalid("dedicated worker has no parent directory"))?;
    let mut process = match platform::SandboxProcess::spawn_named(
        &worker_path,
        directory,
        store.profile.limits.worker_memory_mib as usize * 1024 * 1024,
        id,
    ) {
        Ok(process) => process,
        Err(error) => {
            store.revoke(id)?;
            store.event(
                Some(id),
                "worker_launch_failed",
                json!({"error_code": error_code(&error), "reconciliation_required": true}),
            )?;
            return Err(error);
        }
    };
    let job = process.job_handle()?;
    let deadline_job = process.job_handle()?;
    let output = process
        .output
        .take()
        .ok_or_else(|| invalid("worker output is closed"))?;
    let (sender, receiver) = mpsc::sync_channel(2);
    let reader = thread::spawn(move || -> Result<()> {
        let mut reader = BufReader::new(output);
        for _ in 0..8 {
            let Some(frame) = util::read_frame(&mut reader, worker::FRAME_LIMIT)? else {
                return Ok(());
            };
            sender.try_send(frame).map_err(|_| {
                Error::Protocol("worker flooded or outlived its bounded protocol channel")
            })?;
        }
        Err(Error::Protocol("worker exceeded the bounded frame count"))
    });
    let (stop, stopped) = mpsc::channel();
    let (deadline_stop, deadline_stopped) = mpsc::channel();
    let deadline_watchdog =
        thread::spawn(move || deadline_watch(deadline_job, deadline, deadline_stopped));
    let root = store.root.clone();
    let watched_grant = grant.clone();
    let watchdog = thread::spawn(move || watch(root, watched_grant, job, deadline, stopped));
    let result = match conversation(store, &grant, &mut process, &receiver, deadline) {
        Err(error) => match process.terminate() {
            Ok(()) => Err(error),
            Err(termination) => Err(Error::Unknown(format!(
                "worker termination failed after {}: {termination}",
                error_code(&error)
            ))),
        },
        result => result,
    };
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(5000) as u32;
    let finished = process.finish(remaining);
    let deadline_stop_result = if finished.is_ok() {
        deadline_stop
            .send(())
            .map_err(|_| invalid("deadline watchdog stopped before worker completion"))
    } else {
        Ok(())
    };
    drop(deadline_stop);
    drop(stop);
    let watchdog_result = watchdog
        .join()
        .unwrap_or_else(|_| Err(invalid("lease watchdog thread panicked")));
    let deadline_result = deadline_watchdog
        .join()
        .unwrap_or_else(|_| Err(invalid("deadline watchdog thread panicked")))
        .and(deadline_stop_result);
    let reader_result = reader
        .join()
        .unwrap_or_else(|_| Err(invalid("worker protocol reader thread panicked")));
    for (name, status) in [
        ("lease watchdog", &watchdog_result),
        ("deadline watchdog", &deadline_result),
        ("worker protocol reader", &reader_result),
    ] {
        if let Err(error) = status {
            eprintln!("Shield {name}: {}", util::literal(&error.to_string()));
        }
    }
    let exit = match finished {
        Ok(exit) => exit,
        Err(error) => {
            store.revoke(id)?;
            store.event(
                Some(id),
                "worker_finish_unverified",
                json!({"error_code": error_code(&error), "reconciliation_required": true}),
            )?;
            return Err(error);
        }
    };
    let result = completed_output(
        result,
        exit,
        [watchdog_result, deadline_result, reader_result],
        deadline,
        || {
            native_health(store)?;
            store.authorize(grant.task_id, grant.epoch)
        },
    );
    match result {
        Ok(bytes) => store.close(id, Some(&bytes), None),
        Err(error) => {
            store.close(id, None, Some(error_code(&error)))?;
            Err(error)
        }
    }
}

pub fn recover(store: &mut Store, id: Uuid) -> Result<()> {
    let _control = store.control_lock()?;
    if store.task(id)?.spec.kind == TaskKind::Live {
        platform::terminate_task(id)?;
        platform::cleanup_task_identity(id)?;
    }
    store.reconcile(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

    fn suspended_owned_process() -> (Child, OwnedHandle) {
        let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert!(!raw_job.is_null(), "{}", std::io::Error::last_os_error());
        let job = unsafe { OwnedHandle::from_raw_handle(raw_job) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        // Never resume the test image: only its termination in the owned job is observed.
        let mut child = platform::spawn_command(
            Command::new(std::env::current_exe().unwrap())
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .unwrap();
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) } == 0 {
            let error = std::io::Error::last_os_error();
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("assign owned suspended test process: {error}");
        }
        (child, job)
    }

    fn observe_termination(child: &mut Child, deadline: Instant) {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(1));
                return;
            }
            assert!(
                Instant::now() < deadline,
                "owned process outlived its deadline"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn deadline_monitor_terminates_an_owned_process_without_native_queries() {
        let (mut child, job) = suspended_owned_process();
        assert!(child.try_wait().unwrap().is_none());
        let (stop, stopped) = mpsc::channel();
        let deadline = Instant::now() + Duration::from_millis(150);
        let monitor = thread::spawn(move || deadline_watch(job, deadline, stopped));
        observe_termination(&mut child, deadline + Duration::from_secs(2));
        assert!(matches!(monitor.join().unwrap(), Err(Error::Deadline)));
        drop(stop);
    }

    #[test]
    fn deadline_monitor_fails_closed_when_its_owner_disappears() {
        let (mut child, job) = suspended_owned_process();
        let (stop, stopped) = mpsc::channel();
        let observed_by = Instant::now() + Duration::from_secs(2);
        let monitor = thread::spawn(move || {
            deadline_watch(job, Instant::now() + Duration::from_secs(30), stopped)
        });
        drop(stop);
        observe_termination(&mut child, observed_by);
        assert!(matches!(monitor.join().unwrap(), Err(Error::Denied(_))));
    }

    #[test]
    fn successful_completion_rechecks_native_state_and_authority() {
        let checked = Cell::new(0);
        let output = completed_output(
            Ok(b"staged text".to_vec()),
            0,
            [Ok(()), Ok(()), Ok(())],
            Instant::now() + Duration::from_secs(5),
            || {
                checked.set(checked.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(output, b"staged text");
        assert_eq!(checked.get(), 1);
        let denied = completed_output(
            Ok(b"staged text".to_vec()),
            0,
            [Ok(()), Ok(()), Ok(())],
            Instant::now() + Duration::from_secs(5),
            || Err(Error::Denied("native policy changed".into())),
        );
        assert!(matches!(denied, Err(Error::Denied(_))));
    }

    #[test]
    fn failed_monitors_or_worker_cannot_close_a_successful_output() {
        for failed in 0..3 {
            let checked = Cell::new(false);
            let monitors = std::array::from_fn(|index| {
                if index == failed {
                    Err(Error::Denied("monitor failed".into()))
                } else {
                    Ok(())
                }
            });
            let result = completed_output(
                Ok(b"staged text".to_vec()),
                0,
                monitors,
                Instant::now() + Duration::from_secs(5),
                || {
                    checked.set(true);
                    Ok(())
                },
            );
            assert!(matches!(result, Err(Error::Denied(_))));
            assert!(!checked.get());
        }
        let checked = Cell::new(false);
        let result = completed_output(
            Ok(b"staged text".to_vec()),
            1,
            [Ok(()), Ok(()), Ok(())],
            Instant::now() + Duration::from_secs(5),
            || {
                checked.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::Denied(_))));
        assert!(!checked.get());
    }

    #[test]
    fn completion_does_not_release_output_after_a_slow_final_check() {
        let deadline = Instant::now() + Duration::from_millis(30);
        let result = completed_output(
            Ok(b"staged text".to_vec()),
            0,
            [Ok(()), Ok(()), Ok(())],
            deadline,
            || {
                thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
                );
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::Deadline)));
    }

    #[test]
    fn unknown_protocol_operations_and_fields_are_not_authority() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(br#"{"type":"publish","destination":"C:\\private.txt"}"#.to_vec())
            .unwrap();
        assert!(receive(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        sender
            .send(br#"{"type":"infer","url":"https://attacker.example"}"#.to_vec())
            .unwrap();
        assert!(receive(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
    }
}
