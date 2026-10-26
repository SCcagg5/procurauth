//! The text of the key, from the standard input.

use std::fmt;
use std::io::Read;

/// The most bytes that the program reads from the standard input.
/// A key format gives at most 1024 characters, so a longer input is not a key.
pub const MAX_INPUT_BYTES: usize = 4096;

/// The text of a key. The type has no `Display`, and its `Debug` hides the text.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyText(String);

impl KeyText {
    /// Wrap a text.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The text. Pass it to the checker only. Never print it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyText(<hidden>)")
    }
}

/// Why the program cannot use the standard input. The error never holds the text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    /// The read failed. The value is the kind of the I/O error.
    Read(std::io::ErrorKind),
    /// The input has more than [`MAX_INPUT_BYTES`] bytes.
    TooLong,
    /// The input has no text, or only one line end.
    Empty,
    /// The bytes are not UTF-8.
    NotUtf8,
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(kind) => write!(f, "Cannot read the standard input: {kind}."),
            Self::TooLong => write!(
                f,
                "The standard input has more than {MAX_INPUT_BYTES} bytes. A key has at most 1024 characters."
            ),
            Self::Empty => f.write_str(
                "The standard input has no text. Send the text of the key on the standard input.",
            ),
            Self::NotUtf8 => f.write_str("The standard input is not UTF-8 text."),
        }
    }
}

impl std::error::Error for InputError {}

/// Remove exactly one line end from the end of the bytes: `\r\n` or `\n`.
/// A second line end stays in the text, and the checker reports it.
pub fn strip_line_end(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes)
}

/// Read the text of a key. The function reads at most [`MAX_INPUT_BYTES`] bytes
/// and one more, to find an input that is too long. It removes one line end.
///
/// # Errors
/// Returns the cause when the input is not usable. The error never holds the text.
pub fn read_key<R: Read>(reader: R) -> Result<KeyText, InputError> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_INPUT_BYTES + 1).unwrap_or(u64::MAX);
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| InputError::Read(e.kind()))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(InputError::TooLong);
    }
    let body = strip_line_end(&bytes);
    if body.is_empty() {
        return Err(InputError::Empty);
    }
    String::from_utf8(body.to_vec())
        .map(KeyText)
        .map_err(|_| InputError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_end_is_removed() {
        assert_eq!(strip_line_end(b"abc\n"), b"abc");
        assert_eq!(strip_line_end(b"abc\r\n"), b"abc");
        assert_eq!(strip_line_end(b"abc\n\n"), b"abc\n");
        assert_eq!(strip_line_end(b"abc\r"), b"abc\r");
        assert_eq!(strip_line_end(b"abc"), b"abc");
        assert_eq!(strip_line_end(b"\n"), b"");
    }

    #[test]
    fn the_debug_form_hides_the_text() {
        let text = KeyText::new("mcp_secret");
        assert!(!format!("{text:?}").contains("secret"));
    }

    #[test]
    fn the_read_is_bounded() {
        let long = vec![b'a'; MAX_INPUT_BYTES + 1];
        assert_eq!(read_key(&long[..]).unwrap_err(), InputError::TooLong);
        let exact = vec![b'a'; MAX_INPUT_BYTES];
        assert!(read_key(&exact[..]).is_ok());
        let endless = std::io::repeat(b'a');
        assert_eq!(read_key(endless).unwrap_err(), InputError::TooLong);
    }

    #[test]
    fn the_empty_and_the_bad_inputs() {
        assert_eq!(read_key(&b""[..]).unwrap_err(), InputError::Empty);
        assert_eq!(read_key(&b"\n"[..]).unwrap_err(), InputError::Empty);
        assert_eq!(
            read_key(&b"mcp_\xff\xfe\n"[..]).unwrap_err(),
            InputError::NotUtf8
        );
    }

    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken"))
        }
    }

    #[test]
    fn a_read_error_has_a_kind_and_no_text() {
        let error = read_key(Broken).unwrap_err();
        assert_eq!(error, InputError::Read(std::io::ErrorKind::Other));
    }
}
