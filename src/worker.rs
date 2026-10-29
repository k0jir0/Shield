use std::io::{BufReader, Write};
use std::process::Command;

use crate::error::{Result, invalid};
use crate::protocol::{HostMessage, WorkerMessage};
use crate::util::read_frame;

pub const FRAME_LIMIT: usize = 2 * 1024 * 1024;

fn send(message: &WorkerMessage) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, message)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

pub fn run() -> Result<()> {
    crate::platform::require_worker_context()?;
    let mut input = BufReader::new(std::io::stdin().lock());
    let first = read_frame(&mut input, FRAME_LIMIT)?
        .ok_or_else(|| invalid("worker did not receive a host message"))?;
    match serde_json::from_slice::<HostMessage>(&first)? {
        HostMessage::Start { .. } => {
            send(&WorkerMessage::Infer {})?;
            let next = read_frame(&mut input, FRAME_LIMIT)?
                .ok_or_else(|| invalid("worker did not receive an inference result"))?;
            let HostMessage::InferenceResult { text } = serde_json::from_slice(&next)? else {
                return Err(invalid("unexpected host message after inference request"));
            };
            send(&WorkerMessage::Complete { text })
        }
        HostMessage::Probe {
            forbidden_file,
            parent_pid,
            credential_target,
            loopback_port,
        } => {
            let child = Command::new(std::env::current_exe()?)
                .arg("__worker")
                .spawn();
            let child_spawned = match child {
                Ok(mut child) => {
                    child.kill()?;
                    child.wait()?;
                    true
                }
                Err(_) => false,
            };
            send(&WorkerMessage::ProbeResult {
                file_read: std::fs::read(forbidden_file).is_ok(),
                process_memory_open: crate::platform::can_open_process_memory(parent_pid),
                credential_read: crate::platform::credential_read(&credential_target).is_ok(),
                loopback: crate::platform::probe_loopback(loopback_port)?,
                child_spawned,
            })
        }
        HostMessage::Stop {} => Ok(()),
        HostMessage::InferenceResult { .. } => {
            Err(invalid("worker received a result before a task"))
        }
    }
}
