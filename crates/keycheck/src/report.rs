//! The text and the JSON of the verdict.
//!
//! Neither form holds the text of the key. The JSON shape is in
//! `schemas/keycheck-output.schema.json`. The code writes the JSON by hand,
//! so that the order of the members never changes.

use procurauth_core::key_format::KeyFormatError;
use serde_json::Value;

use crate::Verdict;

/// A string as a JSON string, with the escapes.
fn quote(text: &str) -> String {
    Value::from(text).to_string()
}

fn detail(error: &KeyFormatError) -> String {
    match error {
        KeyFormatError::Prefix { expected } => format!("{{\"expected\":{}}}", quote(expected)),
        KeyFormatError::Length { expected, found } => {
            format!("{{\"expected\":{expected},\"found\":{found}}}")
        }
        KeyFormatError::Alphabet { position, alphabet } => {
            format!(
                "{{\"position\":{position},\"alphabet\":{}}}",
                quote(alphabet)
            )
        }
        KeyFormatError::Checksum => "{}".to_owned(),
    }
}

/// The text form. A bad key gives one line: `bad: <cause> (<detail>)`.
/// A good key gives the line `good`, the digest and the hint.
pub fn render_text(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Good(info) => format!("good\nsha256: {}\nhint: {}\n", info.digest_hex, info.hint),
        Verdict::Bad(error) => format!("bad: {error}\n"),
    }
}

/// The JSON form: one object on one line, then a line end.
pub fn render_json(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Good(info) => format!(
            "{{\"verdict\":\"good\",\"sha256\":{},\"hint\":{}}}\n",
            quote(&info.digest_hex),
            quote(&info.hint)
        ),
        Verdict::Bad(error) => format!(
            "{{\"verdict\":\"bad\",\"cause\":\"{}\",\"message\":{},\"detail\":{}}}\n",
            error.cause(),
            quote(&error.to_string()),
            detail(error)
        ),
    }
}
