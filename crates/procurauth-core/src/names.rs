//! Names and ids: the text rules of the protocol.
//!
//! These functions check the names of types, actions and limits (5.2), the
//! ids of nodes (4.1) and the percent-encoding of an id (5.2).

use thiserror::Error;

/// The longest id of a node, in bytes (4.1).
pub const MAX_ID_BYTES: usize = 256;
/// The deepest type in the tree of types (4.1).
pub const MAX_TYPE_DEPTH: usize = 4;
/// The name of the root type.
pub const SERVICE: &str = "service";
/// The action that opens a service to a subject (8.3). A document never lists it.
pub const ACCESS_ACTION: &str = "access";

/// True when `name` is a name of a type or of a limit (5.2).
/// It has 1 to 32 characters: a to z first, then a to z, 0 to 9 or underscore.
pub fn is_type_or_limit_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= 32
        && first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// True when `name` is the name of an action (5.2).
/// It has 1 to 64 characters: parts of a to z, 0 to 9 and underscore, with `.` between the parts.
pub fn is_action_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Why an id is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum IdError {
    /// The id has no byte.
    #[error("the id is empty")]
    Empty,
    /// The id has more than 256 bytes.
    #[error("the id has {0} bytes, and the maximum is 256")]
    TooLong(usize),
    /// The id has a control character.
    #[error("the id has a control character")]
    ControlCharacter,
}

/// Check an id of a node: 1 to 256 bytes of UTF-8, with no control character (4.1).
///
/// # Errors
/// Returns the first rule that the id breaks.
pub fn validate_id(id: &str) -> Result<(), IdError> {
    if id.is_empty() {
        Err(IdError::Empty)
    } else if id.len() > MAX_ID_BYTES {
        Err(IdError::TooLong(id.len()))
    } else if id.chars().any(char::is_control) {
        Err(IdError::ControlCharacter)
    } else {
        Ok(())
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode an id as 5.2 says: each byte outside A-Z, a-z, 0-9, `-`,
/// `.`, `_` and `~` becomes `%XX` with upper-case hexadecimal digits.
pub fn encode_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for byte in id.bytes() {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Why a text is not a canonical percent-encoded id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// A `%` has no two hexadecimal digits after it.
    #[error("a `%` at byte {0} has no two hexadecimal digits after it")]
    BadEscape(usize),
    /// A `%XX` uses lower-case hexadecimal digits.
    #[error("the escape at byte {0} must use upper-case hexadecimal digits")]
    LowerCase(usize),
    /// A byte that 5.2 requires to be encoded appears as it is.
    #[error("the byte at position {0} must be percent-encoded")]
    NotEncoded(usize),
    /// The decoded bytes are not UTF-8.
    #[error("the decoded bytes are not UTF-8")]
    NotUtf8,
}

/// Decode an id that 5.2 encoded. The decoder is strict: it accepts only
/// the form that [`encode_id`] makes.
///
/// # Errors
/// Returns the first problem of the text.
pub fn decode_id(text: &str) -> Result<String, DecodeError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%' {
            let pair = bytes.get(i + 1..i + 3).ok_or(DecodeError::BadEscape(i))?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return Err(DecodeError::BadEscape(i));
            }
            if pair.iter().any(u8::is_ascii_lowercase) {
                return Err(DecodeError::LowerCase(i));
            }
            let hex = std::str::from_utf8(pair).map_err(|_| DecodeError::BadEscape(i))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| DecodeError::BadEscape(i))?);
            i += 3;
        } else if is_unreserved(byte) {
            out.push(byte);
            i += 1;
        } else {
            return Err(DecodeError::NotEncoded(i));
        }
    }
    String::from_utf8(out).map_err(|_| DecodeError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_5_2_type_names() {
        for good in ["host", "a", "a_1", &"a".repeat(32)] {
            assert!(is_type_or_limit_name(good), "{good}");
        }
        for bad in ["", "1a", "_a", "Host", "a-b", "a.b", &"a".repeat(33)] {
            assert!(!is_type_or_limit_name(bad), "{bad}");
        }
    }

    #[test]
    fn p_5_2_action_names() {
        for good in ["data.read", "a", "mcp.session", "a_b.c1", &"a".repeat(64)] {
            assert!(is_action_name(good), "{good}");
        }
        for bad in [
            "",
            ".a",
            "a.",
            "a..b",
            "Data.read",
            "a-b",
            "a b",
            &"a".repeat(65),
        ] {
            assert!(!is_action_name(bad), "{bad}");
        }
    }

    #[test]
    fn p_4_1_id_bounds() {
        assert_eq!(validate_id(""), Err(IdError::Empty));
        assert!(validate_id(&"a".repeat(256)).is_ok());
        assert_eq!(validate_id(&"a".repeat(257)), Err(IdError::TooLong(257)));
        assert_eq!(validate_id("a\nb"), Err(IdError::ControlCharacter));
        assert_eq!(validate_id("a\u{7f}"), Err(IdError::ControlCharacter));
        assert!(validate_id("caf\u{e9}/\u{1F600}").is_ok());
    }

    #[test]
    fn p_4_1_id_limit_counts_bytes_not_characters() {
        let id = "\u{e9}".repeat(129);
        assert_eq!(id.chars().count(), 129);
        assert_eq!(validate_id(&id), Err(IdError::TooLong(258)));
    }

    #[test]
    fn p_5_2_encode_id() {
        assert_eq!(encode_id("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(encode_id("a/b"), "a%2Fb");
        assert_eq!(encode_id("a:b c"), "a%3Ab%20c");
        assert_eq!(encode_id("\u{e9}"), "%C3%A9");
        assert_eq!(encode_id("a%b"), "a%25b");
    }

    #[test]
    fn p_5_2_decode_id_round_trip() {
        for id in ["prod", "a/b", "a:b c", "\u{e9}\u{1F600}", "100%", "a%2Fb"] {
            assert_eq!(decode_id(&encode_id(id)).unwrap(), id);
        }
    }

    #[test]
    fn p_5_2_decode_id_is_strict() {
        assert_eq!(decode_id("a%2fb"), Err(DecodeError::LowerCase(1)));
        assert_eq!(decode_id("a/b"), Err(DecodeError::NotEncoded(1)));
        assert_eq!(decode_id("a b"), Err(DecodeError::NotEncoded(1)));
        assert_eq!(decode_id("a%2"), Err(DecodeError::BadEscape(1)));
        assert_eq!(decode_id("a%zz"), Err(DecodeError::BadEscape(1)));
        assert_eq!(decode_id("%FF"), Err(DecodeError::NotUtf8));
    }
}
