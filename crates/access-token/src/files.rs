//! Input files and the standard input, with a size bound.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::Fault;

/// The largest input that the program reads, in bytes. A token has about 1 KB.
pub const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn read_bounded(reader: &mut dyn Read, name: &str) -> Result<String, Fault> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Fault::new(format!("Cannot read {name}: {error}.")))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Fault::new(format!(
            "The input {name} has more than {MAX_INPUT_BYTES} bytes."
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| Fault::new(format!("The input {name} is not valid UTF-8 text.")))
}

/// Read a text file. The path `-` means the standard input when `stdin` is given.
///
/// # Errors
/// Returns a fault when the file cannot be read, is too large or is not UTF-8.
pub fn read_text(path: &Path, stdin: Option<&mut dyn Read>) -> Result<String, Fault> {
    if path.as_os_str() == "-"
        && let Some(stdin) = stdin
    {
        return read_bounded(stdin, "the standard input");
    }
    let name = format!("the file `{}`", path.display());
    let mut file =
        File::open(path).map_err(|error| Fault::new(format!("Cannot open {name}: {error}.")))?;
    read_bounded(&mut file, &name)
}

/// Remove one line end from the end of a text: `\n` or `\r\n`.
pub fn strip_line_end(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_end_is_removed_one_time() {
        assert_eq!(strip_line_end("abc\n"), "abc");
        assert_eq!(strip_line_end("abc\r\n"), "abc");
        assert_eq!(strip_line_end("abc\n\n"), "abc\n");
        assert_eq!(strip_line_end("abc"), "abc");
    }

    #[test]
    fn the_standard_input_is_read_for_a_dash_only_when_it_is_given() {
        let mut input: &[u8] = b"text";
        assert_eq!(read_text(Path::new("-"), Some(&mut input)).unwrap(), "text");
        assert!(read_text(Path::new("-"), None).is_err());
    }

    #[test]
    fn an_input_that_is_not_utf8_or_too_large_is_refused() {
        let mut bad: &[u8] = &[0xff, 0xfe];
        assert!(read_text(Path::new("-"), Some(&mut bad)).is_err());
        let big = vec![b'a'; MAX_INPUT_BYTES as usize + 1];
        let mut reader: &[u8] = &big;
        let error = read_text(Path::new("-"), Some(&mut reader)).unwrap_err();
        assert!(error.lines()[0].contains("more than"));
    }
}
