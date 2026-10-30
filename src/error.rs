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
    #[error("state journal failure: {}", journal_diagnostic(.0))]
    Journal(#[from] rusqlite::Error),
    #[error("invalid JSON: {}", json_diagnostic(.0))]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

fn journal_diagnostic(error: &rusqlite::Error) -> String {
    match error {
        rusqlite::Error::SqliteFailure(code, _) => format!(
            "SQLite {:?} (extended code {}); raw diagnostic withheld",
            code.code, code.extended_code
        ),
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::ToSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => {
            "journal data conversion failed; raw diagnostic withheld".into()
        }
        rusqlite::Error::QueryReturnedNoRows => "required journal record is missing".into(),
        _ => "journal operation failed; raw diagnostic withheld".into(),
    }
}

fn json_diagnostic(error: &serde_json::Error) -> String {
    format!(
        "{:?} at line {}, column {}; raw diagnostic withheld",
        error.classify(),
        error.line(),
        error.column()
    )
}

pub fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    const SENTINEL: &str =
        "owned-diagnostic-fixture-https://tenant.example/capability?token=fixture-only";

    #[test]
    fn diagnostic_redaction_preserves_sqlite_codes_but_not_trigger_messages() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TABLE fixture(value INTEGER);
             CREATE TRIGGER refuse BEFORE INSERT ON fixture BEGIN
             SELECT RAISE(FAIL,'{SENTINEL}'); END;"
            ))
            .unwrap();
        let raw = connection
            .execute("INSERT INTO fixture VALUES(1)", [])
            .unwrap_err();
        assert!(raw.to_string().contains(SENTINEL));
        let code = raw.sqlite_error().unwrap().extended_code;
        let error = Error::from(raw);
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains(SENTINEL));
        assert!(!diagnostic.contains("tenant.example"));
        assert!(diagnostic.contains("ConstraintViolation"));
        assert!(diagnostic.contains(&code.to_string()));
        assert!(error.source().unwrap().to_string().contains(SENTINEL));
    }

    #[test]
    fn diagnostic_redaction_keeps_json_category_and_location_not_rejected_values() {
        #[derive(Debug, serde::Deserialize)]
        enum Choice {
            Allowed,
        }
        let raw =
            serde_json::from_str::<Choice>(&serde_json::to_string(SENTINEL).unwrap()).unwrap_err();
        assert!(raw.to_string().contains(SENTINEL));
        let line = raw.line();
        let column = raw.column();
        let error = Error::from(raw);
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains(SENTINEL));
        assert!(diagnostic.contains("Data"));
        assert!(diagnostic.contains(&format!("line {line}")));
        assert!(diagnostic.contains(&format!("column {column}")));
        assert!(error.source().unwrap().to_string().contains(SENTINEL));
    }

    #[test]
    fn diagnostic_redaction_does_not_forward_nested_sql_conversion_sources() {
        let raw = rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            io::Error::other(SENTINEL).into(),
        );
        assert!(raw.to_string().contains(SENTINEL));
        let error = Error::from(raw);
        assert!(!error.to_string().contains(SENTINEL));
        assert!(error.to_string().contains("conversion"));
        assert!(error.source().unwrap().to_string().contains(SENTINEL));
    }
}
