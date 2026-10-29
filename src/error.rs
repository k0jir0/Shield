use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration or input: {0}")]
    Invalid(String),
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("unsupported protection boundary: {0}")]
    Unsupported(String),
    #[error("operation outcome is unknown; do not retry automatically: {0}")]
    Unknown(String),
    #[error("quota exhausted: {0}")]
    Quota(String),
    #[error("operation deadline exceeded; consult task state for verified worker termination")]
    Deadline,
    #[error("Windows operation {operation} failed: {source}")]
    Windows {
        operation: &'static str,
        source: io::Error,
    },
    #[error("remote operation {operation} returned HTTP {status}; response content was not logged")]
    Remote {
        operation: &'static str,
        status: u16,
    },
    #[error("remote protocol violation: {0}")]
    Protocol(&'static str),
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error("state journal failure: {0}")]
    Journal(#[from] rusqlite::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}
