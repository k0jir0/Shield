use std::io::{BufRead, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Result, invalid};

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
    let mut output = String::new();
    for character in json.chars() {
        if !character.is_ascii() && unsafe_display_character(character) {
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
