//! The settings of the server, the defaults and the table of keys.
//!
//! The program reads its settings one time, at start, into [`Settings`].
//! The data file and the command line are the only sources. The program
//! reads no environment variable. A value is never changed to make it fit:
//! a value that is out of range stops the program before the port opens.
//! The table [`KEYS`] is the source of the configuration reference in the README.

use std::io::Write;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::StartError;
use crate::faults::Fault;

/// The default address of the listener.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8181";
/// The default number of worker threads.
pub const DEFAULT_WORKERS: usize = 8;
/// The largest number of worker threads.
pub const MAX_WORKERS: usize = 256;
/// The time to read a whole request, after its first byte.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// The default value of `procurauth_usage_max_seconds` (6.9).
pub const DEFAULT_USAGE_MAX_SECONDS: u64 = 5;
/// The default value of `procurauth_idle_max_seconds` (10.7).
pub const DEFAULT_IDLE_MAX_SECONDS: u64 = 30;
/// The default value of `procurauth_evaluations_max_bytes` (10.7a).
pub const DEFAULT_EVALUATIONS_MAX_BYTES: u64 = 1_048_576;
/// The default value of `procurauth_evaluations_max_items` (10.7a).
pub const DEFAULT_EVALUATIONS_MAX_ITEMS: u64 = 100;
/// The path of the metadata document.
pub const METADATA_PATH: &str = "/.well-known/authzen-configuration";
/// The path of the Access Evaluation API.
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";
/// The path of the Access Evaluations API.
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";
/// The start of the paths of the admin endpoints.
pub const ADMIN_PREFIX: &str = "/__fake/";

/// One key of the configuration.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    /// The name of the flag, or the path of the member in the data file.
    pub name: &'static str,
    /// Where the key comes from: `flag` or `data file`.
    pub source: &'static str,
    /// The type or the range of the value.
    pub value: &'static str,
    /// The default, or `none`.
    pub default: &'static str,
    /// The meaning of the key.
    pub meaning: &'static str,
}

/// The table of keys. The README holds the same table, and a test compares them.
pub const KEYS: [Key; 14] = [
    Key {
        name: "data-file",
        source: "argument",
        value: "path",
        default: "none, mandatory",
        meaning: "The data file.",
    },
    Key {
        name: "--listen",
        source: "flag",
        value: "ADDRESS:PORT",
        default: DEFAULT_LISTEN,
        meaning: "The address of the listener. Port 0 chooses a free port.",
    },
    Key {
        name: "--clock-start",
        source: "flag",
        value: "whole seconds since the Unix epoch",
        default: "none, the system clock",
        meaning: "A fixed clock. It stops at this time. Do not give it with `clock.now`.",
    },
    Key {
        name: "--admin",
        source: "flag",
        value: "no value",
        default: "off",
        meaning: "Enable the admin endpoints under `/__fake/`.",
    },
    Key {
        name: "--credential-file",
        source: "flag",
        value: "path",
        default: "none, no credential",
        meaning: "The file with the credential of the PEP. The PDP then requires `Authorization: Bearer`.",
    },
    Key {
        name: "--failures",
        source: "flag",
        value: "path",
        default: "none",
        meaning: "A file with more failures. It can use the kinds `close`, `invalid_json` and `no_units`.",
    },
    Key {
        name: "--workers",
        source: "flag",
        value: "whole number from 1 to 256",
        default: "8",
        meaning: "The number of worker threads. One open connection uses one thread.",
    },
    Key {
        name: "--print-config",
        source: "flag",
        value: "no value",
        default: "off",
        meaning: "Check everything, print the values that apply, and exit with 0. The port stays closed.",
    },
    Key {
        name: "clock.now",
        source: "data file",
        value: "whole seconds since the Unix epoch",
        default: "none, the system clock",
        meaning: "A fixed clock. Do not give it with `--clock-start`.",
    },
    Key {
        name: "metadata.usage_max_seconds",
        source: "data file",
        value: "whole number from 1",
        default: "5",
        meaning: "The member `procurauth_usage_max_seconds` of the metadata (6.9).",
    },
    Key {
        name: "metadata.idle_max_seconds",
        source: "data file",
        value: "whole number from 1",
        default: "30",
        meaning: "The member `procurauth_idle_max_seconds`. The PDP closes an idle connection after this time (10.7).",
    },
    Key {
        name: "metadata.evaluations_max_bytes",
        source: "data file",
        value: "whole number from 1",
        default: "1048576",
        meaning: "The member `procurauth_evaluations_max_bytes`. A larger body gets HTTP 413 (10.7a).",
    },
    Key {
        name: "metadata.evaluations_max_items",
        source: "data file",
        value: "whole number from 1",
        default: "100",
        meaning: "The member `procurauth_evaluations_max_items`. More items get HTTP 400 (10.7a).",
    },
    Key {
        name: "counters, failures, services, subjects",
        source: "data file",
        value: "see the schema `fake-pdp-data`",
        default: "none",
        meaning: "The directory, the first counter values and the failures.",
    },
];

/// The table of keys as a Markdown table. The README holds this text.
pub fn reference_table() -> String {
    let mut out = String::from(
        "| Key | Source | Value | Default | Meaning |\n| --- | --- | --- | --- | --- |\n",
    );
    for key in KEYS {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            key.name, key.source, key.value, key.default, key.meaning
        ));
    }
    out
}

/// The credential of the PEP. The server keeps only the SHA-256 digest.
#[derive(Clone)]
pub struct Credential {
    digest: [u8; 32],
    source: String,
}

impl Credential {
    /// A credential from the text of a file. The function removes one line end at the end.
    /// `source` names the origin for messages, for example `file:/run/pep.token`.
    ///
    /// # Errors
    /// Returns an error when the value is empty.
    pub fn from_file_text(text: &str, source: &str) -> Result<Self, StartError> {
        let value = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        if value.is_empty() {
            return Err(StartError::Config(format!(
                "Key `--credential-file`: expected a file with a value that is not empty, found an empty value in {source}."
            )));
        }
        Ok(Self {
            digest: Sha256::digest(value.as_bytes()).into(),
            source: source.to_owned(),
        })
    }

    /// The SHA-256 digest of the value.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The origin of the value, for the effective configuration.
    pub fn source(&self) -> &str {
        &self.source
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// The options of the server, besides the data file.
pub struct Options {
    /// Enable the admin endpoints under `/__fake/`.
    pub admin: bool,
    /// A fixed clock that starts at this time. The data file must not give a clock then.
    pub clock_start: Option<u64>,
    /// The credential of the PEP. Without it, the PDP asks for no credential,
    /// unless a service of the data has `credential_sha256`.
    pub credential: Option<Credential>,
    /// More failures than the data file holds. They come after the failures of the data file.
    pub extra_faults: Vec<Fault>,
    /// The number of worker threads, from 1 to [`MAX_WORKERS`].
    pub workers: usize,
    /// The time to read a whole request after its first byte.
    pub read_timeout: Duration,
    /// Where the text log goes. Without it, the server writes no text log.
    pub log: Option<Box<dyn Write + Send>>,
    /// Where the diagnostics go, for example a rejected request. Without it, the server writes none.
    pub diagnostics: Option<Box<dyn Write + Send>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            admin: false,
            clock_start: None,
            credential: None,
            extra_faults: Vec::new(),
            workers: DEFAULT_WORKERS,
            read_timeout: DEFAULT_READ_TIMEOUT,
            log: None,
            diagnostics: None,
        }
    }
}

/// The values that apply, after the defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `procurauth_usage_max_seconds`.
    pub usage_max_seconds: u64,
    /// `procurauth_idle_max_seconds`.
    pub idle_max_seconds: u64,
    /// `procurauth_evaluations_max_bytes`. It also bounds each other request body.
    pub evaluations_max_bytes: u64,
    /// `procurauth_evaluations_max_items`.
    pub evaluations_max_items: u64,
    /// True when the admin endpoints are on.
    pub admin: bool,
    /// The number of worker threads.
    pub workers: usize,
    /// The start of a fixed clock, when the clock is fixed at start.
    pub clock_start: Option<u64>,
}

/// One line of the effective configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigLine {
    /// The key.
    pub key: String,
    /// The value that applies. A secret never shows here.
    pub value: String,
    /// `default`, `flag` or `data file`.
    pub source: String,
}

impl ConfigLine {
    pub(crate) fn new(key: &str, value: impl ToString, source: &str) -> Self {
        Self {
            key: key.to_owned(),
            value: value.to_string(),
            source: source.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_12_a_credential_from_a_file_loses_one_line_end() {
        let a = Credential::from_file_text("secret\n", "file:/x").unwrap();
        let b = Credential::from_file_text("secret", "file:/x").unwrap();
        let c = Credential::from_file_text("secret\r\n", "file:/x").unwrap();
        let d = Credential::from_file_text("secret\n\n", "file:/x").unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest(), c.digest());
        assert_ne!(a.digest(), d.digest());
    }

    #[test]
    fn p_12_an_empty_credential_is_an_error_that_names_the_key_and_the_file() {
        for text in ["", "\n", "\r\n"] {
            let error = Credential::from_file_text(text, "file:/run/pep.token").unwrap_err();
            let message = error.to_string();
            assert!(message.contains("--credential-file"), "{message}");
            assert!(message.contains("/run/pep.token"), "{message}");
        }
    }

    #[test]
    fn the_debug_text_of_a_credential_holds_no_digest() {
        let c = Credential::from_file_text("secret", "file:/x").unwrap();
        let text = format!("{c:?}");
        assert!(!text.contains("secret"));
        assert!(!text.contains("digest"));
    }

    #[test]
    fn the_defaults_of_the_table_are_the_defaults_of_the_code() {
        let default_of = |name: &str| KEYS.iter().find(|k| k.name == name).unwrap().default;
        assert_eq!(default_of("--listen"), DEFAULT_LISTEN);
        assert_eq!(default_of("--workers"), DEFAULT_WORKERS.to_string());
        assert_eq!(
            default_of("metadata.usage_max_seconds"),
            DEFAULT_USAGE_MAX_SECONDS.to_string()
        );
        assert_eq!(
            default_of("metadata.idle_max_seconds"),
            DEFAULT_IDLE_MAX_SECONDS.to_string()
        );
        assert_eq!(
            default_of("metadata.evaluations_max_bytes"),
            DEFAULT_EVALUATIONS_MAX_BYTES.to_string()
        );
        assert_eq!(
            default_of("metadata.evaluations_max_items"),
            DEFAULT_EVALUATIONS_MAX_ITEMS.to_string()
        );
    }
}
