//! The read of the inputs: a file, or an HTTP URL for the document.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::http::{self, Limits};

/// The most bytes that the tool reads from a file. A larger file is an error.
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

/// Read a file as UTF-8 text, with a bound.
///
/// # Errors
/// Returns a message when the file cannot be read, is too large or is not UTF-8.
pub fn read_file(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let file = File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!(
            "cannot read {shown}: the file is larger than {MAX_FILE_BYTES} bytes"
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("cannot read {shown}: the file is not UTF-8"))
}

/// Read the document from a file or from an HTTP URL.
///
/// # Errors
/// Returns a message when the input cannot be read.
pub fn read_document(source: &str, limits: Limits) -> Result<String, String> {
    if http::is_url(source) {
        let bytes = http::get(source, limits)?;
        String::from_utf8(bytes).map_err(|_| format!("URL {source}: the body is not UTF-8"))
    } else {
        read_file(Path::new(source))
    }
}
