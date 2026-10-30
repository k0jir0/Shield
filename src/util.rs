use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result, invalid};

pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| invalid("system clock is before the Unix epoch"))
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn json_digest(value: &impl Serialize) -> Result<String> {
    Ok(digest(&serde_json::to_vec(value)?))
}

pub fn file_digest(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let capacity = usize::try_from(limit.min(64 * 1024))
        .map_err(|_| invalid("input bound is not representable"))?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("input exceeds its declared byte bound"));
    }
    Ok(bytes)
}

pub fn read_frame(reader: &mut impl BufRead, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(invalid("unterminated worker protocol frame"))
            };
        }
        let consumed = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        if frame.len().saturating_add(consumed) > limit {
            return Err(invalid("worker protocol frame exceeds its byte bound"));
        }
        frame.extend_from_slice(&buffer[..consumed]);
        let complete = frame.last() == Some(&b'\n');
        reader.consume(consumed);
        if complete {
            frame.pop();
            return Ok(Some(frame));
        }
    }
}

pub fn literal(text: &str) -> String {
    let mut output = String::new();
    for character in text.chars() {
        match character {
            '\n' => output.push('\n'),
            '\t' => output.push_str("\\t"),
            '\r' => output.push_str("\\r"),
            value if unsafe_display_character(value) => {
                output.push_str(&format!("\\u{{{:x}}}", u32::from(value)));
            }
            value => output.push(value),
        }
    }
    output
}

fn unsafe_display_character(value: char) -> bool {
    value.is_control()
        || matches!(value, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

pub fn terminal_json(value: &impl Serialize) -> Result<String> {
    let json = serde_json::to_string_pretty(value)?;
    terminal_json_text(&json, usize::MAX)
}

fn terminal_json_text(json: &str, limit: usize) -> Result<String> {
    let mut output = String::new();
    for character in json.chars() {
        let escaped = !character.is_ascii() && unsafe_display_character(character);
        let size = if escaped {
            character.len_utf16() * 6
        } else {
            character.len_utf8()
        };
        if size > limit.saturating_sub(output.len()) {
            return Err(Error::Quota(
                "terminal JSON exceeds its fixed rendered-byte bound".into(),
            ));
        }
        if escaped {
            let mut units = [0_u16; 2];
            for unit in character.encode_utf16(&mut units) {
                output.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            output.push(character);
        }
    }
    Ok(output)
}

pub fn json_pretty_bounded(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    struct BoundedJson {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for BoundedJson {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "serialized JSON exceeds its byte bound",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = BoundedJson {
        bytes: Vec::with_capacity(limit.min(64 * 1024)),
        limit,
    };
    match serde_json::to_writer_pretty(&mut writer, value) {
        Ok(()) => Ok(writer.bytes),
        Err(error) if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) => Err(
            Error::Quota("serialized JSON exceeds its fixed byte bound".into()),
        ),
        Err(error) => Err(error.into()),
    }
}

pub fn terminal_json_bounded(value: &impl Serialize, limit: usize) -> Result<String> {
    let bytes = json_pretty_bounded(value, limit)?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("JSON serializer produced invalid UTF-8"))?;
    terminal_json_text(json, limit)
}

pub fn text(bytes: &[u8]) -> Result<&str> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid("only UTF-8 text is supported"))?;
    if value.contains('\0') {
        return Err(invalid("NUL bytes are not supported in text artifacts"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_audit_json_counts_pretty_encoding_and_accepts_only_the_exact_limit() {
        let value = serde_json::json!({"events": ["line\n\"\\", "data"]});
        let expected = serde_json::to_vec_pretty(&value).unwrap();
        assert_eq!(
            json_pretty_bounded(&value, expected.len()).unwrap(),
            expected
        );
        assert!(json_pretty_bounded(&value, expected.len() - 1).is_err());
        assert!(json_pretty_bounded(&serde_json::json!({}), 0).is_err());
        let limit = crate::state::AUDIT_EXPORT_BYTES;
        let overhead = serde_json::to_vec_pretty(&serde_json::json!({"padding": ""}))
            .unwrap()
            .len();
        let value = serde_json::json!({"padding": "x".repeat(limit - overhead)});
        assert_eq!(json_pretty_bounded(&value, limit).unwrap().len(), limit);
        assert!(json_pretty_bounded(&value, limit - 1).is_err());
    }

    #[test]
    fn bounded_audit_terminal_counts_passive_unicode_expansion() {
        let value = serde_json::json!({"text": "\u{202e}\u{e0001}"});
        let encoded = serde_json::to_vec_pretty(&value).unwrap();
        let expected = terminal_json(&value).unwrap();
        assert!(expected.len() > encoded.len());
        assert_eq!(
            terminal_json_bounded(&value, expected.len()).unwrap(),
            expected
        );
        assert!(terminal_json_bounded(&value, expected.len() - 1).is_err());
        assert!(terminal_json_bounded(&value, encoded.len()).is_err());
    }

    #[test]
    fn canonical_sha256_requires_exactly_64_lowercase_hex_digits() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(is_sha256(&"0".repeat(64)));
        for value in [
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            &"g".repeat(64),
        ] {
            assert!(!is_sha256(value));
        }
    }
    use std::io::Cursor;

    #[test]
    fn limits_are_checked_before_unbounded_allocation() {
        assert!(read_bounded(Cursor::new(b"12345"), 4).is_err());
        assert_eq!(read_bounded(Cursor::new(b"1234"), 4).unwrap(), b"1234");
        assert!(read_frame(&mut Cursor::new(b"12345\n"), 5).is_err());
        assert_eq!(
            read_frame(&mut Cursor::new(b"1234\n"), 5).unwrap(),
            Some(b"1234".to_vec())
        );
        assert!(read_frame(&mut Cursor::new(b"missing newline"), 100).is_err());
    }

    #[test]
    fn preview_cannot_emit_terminal_or_direction_controls() {
        assert_eq!(literal("a\x1b[2J\u{202e}b"), "a\\u{1b}[2J\\u{202e}b");
        assert_eq!(literal("a\nb\tc"), "a\nb\\tc");
        assert!(text(b"a\0b").is_err());
        assert!(text(&[0xff]).is_err());
    }

    #[test]
    fn terminal_json_is_safe_and_still_round_trips_exact_data() {
        let value = serde_json::json!({"note": "line\n\u{202e}\x1b[2J\u{200b}"});
        let output = terminal_json(&value).unwrap();
        assert!(!output.contains(['\u{202e}', '\u{200b}', '\x1b']));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap(),
            value
        );
    }
}
