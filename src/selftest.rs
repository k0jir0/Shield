use std::fs::{File, OpenOptions};
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use crate::error::{Error, Result, invalid};
use crate::platform;
use crate::protocol::{HostMessage, LoopbackConnection, WorkerMessage};
use crate::util::{file_digest, literal, read_bounded, read_frame};
use crate::worker::FRAME_LIMIT;

#[derive(Debug, Serialize)]
pub struct Observation {
    pub name: &'static str,
    pub passed: bool,
    pub actual: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub run_id: Uuid,
    pub binary_sha256: String,
    pub environment: platform::Environment,
    pub controller_elevated: bool,
    pub worker_isolation: &'static str,
    pub observations: Vec<Observation>,
    pub all_passed: bool,
    pub limitation: &'static str,
}

struct Workspace {
    path: PathBuf,
    active: bool,
}

impl Workspace {
    fn close(&mut self) -> Result<()> {
        std::fs::remove_dir_all(&self.path)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.close()
        {
            eprintln!("Shield owned self-test workspace cleanup failed: {error}");
        }
    }
}

struct CanaryCredential {
    target: String,
    active: bool,
}

impl CanaryCredential {
    fn close(&mut self) -> Result<()> {
        platform::credential_delete(&self.target)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for CanaryCredential {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.close()
        {
            eprintln!("Shield self-test credential cleanup failed: {error}");
        }
    }
}

pub fn send(file: &mut File, message: &HostMessage) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() + 1 > FRAME_LIMIT {
        return Err(invalid("host protocol message exceeds its byte bound"));
    }
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn decode_probe(output: Result<Vec<u8>>, exit: u32) -> Result<WorkerMessage> {
    if exit != 0 {
        let diagnostic = match output {
            Ok(bytes) => literal(&String::from_utf8_lossy(&bytes[..bytes.len().min(2048)])),
            Err(error) => literal(&error.to_string()),
        };
        return Err(Error::Unsupported(format!(
            "restricted worker exited with native status 0x{exit:08x}; bounded diagnostic: {diagnostic}"
        )));
    }
    let bytes = output?;
    let mut reader = Cursor::new(&bytes);
    let frame = read_frame(&mut reader, FRAME_LIMIT)?
        .ok_or_else(|| invalid("worker exited without a probe result"))?;
    if reader.position() != bytes.len() as u64 {
        return Err(Error::Protocol(
            "self-test worker sent more than one bounded response",
        ));
    }
    Ok(serde_json::from_slice(&frame)?)
}

pub fn run(report_path: Option<&Path>) -> Result<Report> {
    run_with_worker(report_path, None)
}

pub fn run_with_worker(
    report_path: Option<&Path>,
    existing_worker: Option<&Path>,
) -> Result<Report> {
    let run_id = Uuid::new_v4();
    let root = std::env::temp_dir().join(format!("Shield-selftest-{run_id}"));
    std::fs::create_dir(&root)?;
    let mut workspace = Workspace {
        path: root.clone(),
        active: true,
    };
    platform::protect_directory(&root, None)?;
    let executable = std::env::current_exe()?;
    let worker_path = match existing_worker {
        Some(path) => path.to_owned(),
        None => {
            let binary_directory = root.join("worker");
            std::fs::create_dir(&binary_directory)?;
            let path = binary_directory.join("shield-worker.exe");
            std::fs::copy(&executable, &path)?;
            path
        }
    };
    let binary_directory = worker_path
        .parent()
        .ok_or_else(|| invalid("worker path has no parent"))?;
    if file_digest(&worker_path)? != file_digest(&executable)? {
        return Err(Error::Denied(
            "self-test worker differs from the controller executable".into(),
        ));
    }
    let canary = root.join("host-private.txt");
    let marker = format!("host-only-{run_id}");
    std::fs::write(&canary, &marker)?;
    if std::fs::read_to_string(&canary)? != marker {
        return Err(invalid("host file-read positive control failed"));
    }
    let target = format!("Shield/selftest/{run_id}");
    platform::credential_write(&target, &marker)?;
    let mut credential = CanaryCredential {
        target: target.clone(),
        active: true,
    };
    if *platform::credential_read(&target)? != marker {
        return Err(invalid("credential positive control failed"));
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let positive_connection = platform::probe_loopback(port)?;
    if !matches!(positive_connection, LoopbackConnection::Connected {}) {
        return Err(invalid(format!(
            "native host loopback positive control failed: {positive_connection:?}"
        )));
    }
    let _ = listener.accept()?;
    let mut process =
        platform::SandboxProcess::spawn(&worker_path, binary_directory, 128 * 1024 * 1024)?;
    let output = process
        .output
        .take()
        .ok_or_else(|| invalid("restricted worker stdout is missing"))?;
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let value = read_bounded(output, FRAME_LIMIT as u64);
        let _ = sender.send(value);
    });
    send(
        process
            .input
            .as_mut()
            .ok_or_else(|| invalid("restricted worker stdin is missing"))?,
        &HostMessage::Probe {
            forbidden_file: canary.to_string_lossy().into_owned(),
            parent_pid: std::process::id(),
            credential_target: target,
            loopback_port: port,
        },
    )?;
    let frame = match receiver.recv_timeout(Duration::from_secs(8)) {
        Ok(frame) => frame,
        Err(_) => {
            process.terminate()?;
            process.finish(5000)?;
            reader
                .join()
                .map_err(|_| invalid("self-test reader thread panicked"))?;
            return Err(Error::Deadline);
        }
    };
    let exit = process.finish(5000)?;
    reader
        .join()
        .map_err(|_| invalid("self-test reader thread panicked"))?;
    let result = decode_probe(frame, exit)?;
    let WorkerMessage::ProbeResult {
        file_read,
        process_memory_open,
        credential_read,
        loopback,
        child_spawned,
    } = result
    else {
        return Err(invalid("worker returned the wrong self-test response"));
    };
    let network_observed = match listener.accept() {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => return Err(error.into()),
    };
    let mut observations = vec![
        Observation {
            name: "worker_exited_normally",
            passed: exit == 0,
            actual: exit.to_string(),
        },
        Observation {
            name: "host_file_read_denied",
            passed: !file_read && std::fs::read_to_string(&canary)? == marker,
            actual: format!("worker_read_succeeded={file_read}"),
        },
        Observation {
            name: "controller_memory_access_denied",
            passed: !process_memory_open,
            actual: format!("worker_open_succeeded={process_memory_open}"),
        },
        Observation {
            name: "host_credential_read_denied",
            passed: !credential_read,
            actual: format!("worker_read_succeeded={credential_read}"),
        },
        Observation {
            name: "winsock_loopback_not_connected_and_no_connection_observed",
            passed: !matches!(loopback, LoopbackConnection::Connected {}) && !network_observed,
            actual: format!("worker={loopback:?}; listener_accepted={network_observed}"),
        },
        Observation {
            name: "child_process_not_created",
            passed: !child_spawned,
            actual: format!("child_spawned={child_spawned}"),
        },
    ];
    for (name, cleanup) in [
        ("owned_test_credential_removed", credential.close()),
        ("owned_test_workspace_removed", workspace.close()),
    ] {
        observations.push(Observation {
            name,
            passed: cleanup.is_ok(),
            actual: match cleanup {
                Ok(()) => "verified API completion".into(),
                Err(error) => error.to_string(),
            },
        });
    }
    let report = Report {
        run_id,
        binary_sha256: file_digest(&executable)?,
        environment: platform::environment()?,
        controller_elevated: platform::is_elevated()?,
        worker_isolation: "zero_capability_lpac_with_effective_package_access_verification",
        all_passed: observations.iter().all(|observation| observation.passed),
        observations,
        limitation: "Scoped deterministic LPAC/job probes only. Winsock startup failure is recorded separately from a denied connect and does not prove all network or brokered paths are blocked. This does not pass E1, M1, C1, I1, O1, or P0, test Internet/LAN completeness, prove every process right, or establish native application-control/provider/model coverage.",
    };
    if let Some(path) = report_path {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        serde_json::to_writer_pretty(&mut file, &report)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    drop(credential);
    drop(workspace);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_worker_preserves_native_status_and_terminal_safe_diagnostic() {
        let error = decode_probe(Ok(b"\nthread panicked: \x1b[2J denied\n".to_vec()), 101)
            .unwrap_err()
            .to_string();
        assert!(error.contains("0x00000065"));
        assert!(error.contains("thread panicked"));
        assert!(!error.contains('\x1b'));
        let long = decode_probe(Ok(vec![b'x'; 8000]), 101)
            .unwrap_err()
            .to_string();
        assert!(long.len() < 2400);
    }

    #[test]
    fn probe_accepts_exactly_one_strict_complete_response() {
        let frame = b"{\"type\":\"infer\"}\n";
        assert!(matches!(
            decode_probe(Ok(frame.to_vec()), 0).unwrap(),
            WorkerMessage::Infer {}
        ));
        let mut repeated = frame.to_vec();
        repeated.extend(frame);
        assert!(decode_probe(Ok(repeated), 0).is_err());
        assert!(decode_probe(Ok(frame[..frame.len() - 1].to_vec()), 0).is_err());
        assert!(decode_probe(Ok(b"{\"type\":\"infer\",\"extra\":true}\n".to_vec()), 0).is_err());
    }
}
