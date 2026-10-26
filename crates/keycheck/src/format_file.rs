//! The format file: a `key-format` document, read with the strict reader of the core.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use procurauth_core::json::parse_slice;
use procurauth_core::key_format::KeyFormat;

/// The most bytes that the program reads from the format file.
pub const MAX_FORMAT_FILE_BYTES: usize = 65_536;

/// Read a format file. The result is the typed format, or one line of
/// diagnostic for each problem. A line names the member, the expected value and
/// the value found. The lines never show the path, because an argument can be a key.
pub(crate) fn load(path: &Path) -> Result<KeyFormat, Vec<String>> {
    let file = File::open(path)
        .map_err(|e| vec![format!("Cannot open the format file: {}.", e.kind())])?;
    let limit = u64::try_from(MAX_FORMAT_FILE_BYTES + 1).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| vec![format!("Cannot read the format file: {}.", e.kind())])?;
    parse(&bytes)
}

/// Read a format from the bytes of a format file.
pub(crate) fn parse(bytes: &[u8]) -> Result<KeyFormat, Vec<String>> {
    if bytes.len() > MAX_FORMAT_FILE_BYTES {
        return Err(vec![format!(
            "The format file has more than {MAX_FORMAT_FILE_BYTES} bytes."
        )]);
    }
    let value =
        parse_slice(bytes).map_err(|e| vec![hide_long_tokens(&format!("format file: {e}."))])?;
    KeyFormat::from_value(&value).map_err(|findings| {
        findings
            .iter()
            .map(|finding| hide_long_tokens(&format!("format file: {finding}")))
            .collect()
    })
}

/// The longest run of characters without a space that a diagnostic can show.
pub(crate) const MAX_TOKEN_CHARACTERS: usize = 24;

/// Replace each run of more than [`MAX_TOKEN_CHARACTERS`] characters without a
/// space by a count. A finding about the format file repeats the value that it
/// found. A user can give the text of a key as the format file by mistake.
/// The text of a key must never reach an output.
pub(crate) fn hide_long_tokens(line: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        let count = run.chars().count();
        if count > MAX_TOKEN_CHARACTERS {
            out.push_str(&format!("<{count} characters hidden>"));
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in line.chars() {
        if c.is_whitespace() {
            flush(&mut run, &mut out);
            out.push(c);
        } else {
            run.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_run_is_hidden_and_a_short_run_is_kept() {
        assert_eq!(hide_long_tokens("a $.length b"), "a $.length b");
        let long = "x".repeat(25);
        assert_eq!(
            hide_long_tokens(&format!("found \"{long}\".")),
            "found <28 characters hidden>"
        );
        let edge = "y".repeat(24);
        assert_eq!(hide_long_tokens(&edge), edge);
    }
}
