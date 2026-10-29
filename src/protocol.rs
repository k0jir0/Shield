use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketOperation {
    Startup,
    Create,
    Nonblocking,
    Connect,
    Wait,
    ReadError,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum LoopbackConnection {
    Connected {},
    Failed {
        operation: SocketOperation,
        windows_error: i32,
    },
    TimedOut {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMessage {
    Start {
        instruction: String,
        note: String,
        reference: String,
    },
    InferenceResult {
        text: String,
    },
    Probe {
        forbidden_file: String,
        parent_pid: u32,
        credential_target: String,
        loopback_port: u16,
    },
    Stop {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerMessage {
    Infer {},
    Complete {
        text: String,
    },
    ProbeResult {
        file_read: bool,
        process_memory_open: bool,
        credential_read: bool,
        loopback: LoopbackConnection,
        child_spawned: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_operations_reject_unknown_fields_without_changing_the_wire_format() {
        assert!(
            serde_json::from_str::<WorkerMessage>(
                r#"{"type":"infer","url":"https://attacker.example"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<HostMessage>(r#"{"type":"stop","grant":"forged"}"#).is_err()
        );
        assert!(serde_json::from_str::<WorkerMessage>(r#"{"type":"infer"}"#).is_ok());
        assert!(serde_json::from_str::<HostMessage>(r#"{"type":"stop"}"#).is_ok());
        assert_eq!(
            serde_json::to_string(&WorkerMessage::Infer {}).unwrap(),
            r#"{"type":"infer"}"#
        );
        for value in [
            r#"{"outcome":"connected","extra":true}"#,
            r#"{"outcome":"timed_out","extra":true}"#,
            r#"{"outcome":"failed","operation":"arbitrary","windows_error":1}"#,
        ] {
            assert!(serde_json::from_str::<LoopbackConnection>(value).is_err());
        }
    }
}
