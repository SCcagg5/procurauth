//! The configuration of the reference service: strict, closed and fail-fast.
//!
//! The configuration file is a JSON object. It is the only source of the
//! values. The program reads an environment variable only when the file names it
//! with a member that ends in `_env`. The program reads the content of a file
//! only when the file names its path with a member that ends in `_file`.
//!
//! These rules apply:
//!
//! - The schema is closed. An unknown member and a duplicate member stop the program.
//! - Each error names the key, the expected type or range, and the value found.
//! - The program does not change a value to make it fit. A value that is out of range stops the program.
//! - The program reads the file one time into [`Settings`]. The rest of the code reads only this structure.
//! - A key that accepts indirection takes exactly one of three forms: `<name>`, `<name>_env` and `<name>_file`.
//! - A secret takes only `_env` and `_file`. A secret in clear text in the file stops the program.
//! - A variable that does not exist, an empty value, and a file that the program cannot read stop the program.
//! - Two keys that contradict each other stop the program.
//!
//! The table [`KEYS`] is the source of the configuration reference in the README.
//! [`reference_table`] writes it, and a test compares it with the README.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use procurauth_core::finding::{JsonPath, Report};
use procurauth_core::json::parse_str;
use procurauth_core::jws::KeySet;
use procurauth_core::read::{Obj, Unknown};
use procurauth_pep::config::{PdpConfig, PepConfig, Secret};
use serde_json::Value;

use crate::http::Limits;

/// One key of the configuration.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    /// The section of the key: `pdp`, or the empty text for the top level.
    pub section: &'static str,
    /// The name of the member in its section.
    pub leaf: &'static str,
    /// The name of the member that names an environment variable, when the key accepts it.
    pub env: Option<&'static str>,
    /// The name of the member that names a file, when the key accepts it.
    pub file: Option<&'static str>,
    /// The type or the range of the value.
    pub value: &'static str,
    /// The default, or `none, mandatory`, or `none`.
    pub default: &'static str,
    /// True for a secret: it takes only the forms `_env` and `_file`.
    pub secret: bool,
    /// The meaning of the key.
    pub meaning: &'static str,
}

impl Key {
    /// The name of the key, for example `pdp.url`.
    pub fn name(&self) -> String {
        if self.section.is_empty() {
            self.leaf.to_owned()
        } else {
            format!("{}.{}", self.section, self.leaf)
        }
    }

    fn member(&self, leaf: &str) -> String {
        if self.section.is_empty() {
            leaf.to_owned()
        } else {
            format!("{}.{leaf}", self.section)
        }
    }
}

macro_rules! key {
    ($section:literal, $leaf:literal, indirect, $value:literal, $default:literal, $meaning:literal) => {
        Key {
            section: $section,
            leaf: $leaf,
            env: Some(concat!($leaf, "_env")),
            file: Some(concat!($leaf, "_file")),
            value: $value,
            default: $default,
            secret: false,
            meaning: $meaning,
        }
    };
    ($section:literal, $leaf:literal, secret, $value:literal, $default:literal, $meaning:literal) => {
        Key {
            section: $section,
            leaf: $leaf,
            env: Some(concat!($leaf, "_env")),
            file: Some(concat!($leaf, "_file")),
            value: $value,
            default: $default,
            secret: true,
            meaning: $meaning,
        }
    };
    ($section:literal, $leaf:literal, plain, $value:literal, $default:literal, $meaning:literal) => {
        Key {
            section: $section,
            leaf: $leaf,
            env: None,
            file: None,
            value: $value,
            default: $default,
            secret: false,
            meaning: $meaning,
        }
    };
}

/// The default address of the listener.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// The table of keys, in the order of the effective configuration.
pub const KEYS: [Key; 23] = [
    key!(
        "",
        "listen",
        indirect,
        "ADDRESS:PORT with an IP address",
        "127.0.0.1:8080",
        "The address of the listener. Port 0 chooses a free port."
    ),
    key!(
        "",
        "workers",
        plain,
        "whole number from 1 to 256",
        "8",
        "The number of worker threads. One open connection uses one thread."
    ),
    key!(
        "",
        "max_body_bytes",
        plain,
        "whole number from 1 to 67108864",
        "1048576",
        "The largest body of a request. A larger body gets HTTP 413."
    ),
    key!(
        "",
        "read_timeout_seconds",
        plain,
        "whole number from 1 to 3600",
        "10",
        "The time to read a whole request after its first byte."
    ),
    key!(
        "",
        "idle_timeout_seconds",
        plain,
        "whole number from 1 to 3600",
        "30",
        "The time that an idle connection of a client stays open."
    ),
    key!(
        "",
        "service_id",
        plain,
        "id of 1 to 256 bytes (4.1)",
        "datastore",
        "The id of the service: the `aud` of the tokens and the `server` of the action document."
    ),
    key!(
        "",
        "token_header",
        plain,
        "HTTP header name",
        "X-Identity-Token",
        "The header with the identity token (9.4). It is never `Authorization`, `Proxy-Authorization` or `Cookie`."
    ),
    key!(
        "",
        "issuer",
        indirect,
        "text that is not empty",
        "none, mandatory",
        "The value of the claim `iss` (9.4)."
    ),
    key!(
        "",
        "max_token_age_seconds",
        plain,
        "whole number from 1 to 86400",
        "300",
        "The longest life of a token, `exp` minus `iat` (9.4)."
    ),
    key!(
        "",
        "clock_skew_seconds",
        plain,
        "whole number from 0 to 3600",
        "30",
        "The clock skew for `iat` and `exp` (9.4)."
    ),
    key!(
        "",
        "jwks",
        indirect,
        "JWK Set (RFC 7517) with public keys; the forms `_env` and `_file` give its JSON text",
        "none, mandatory",
        "The public keys of the edge (9.4). A set with more than one key needs a `kid` in each token."
    ),
    key!(
        "",
        "cache_ttl_seconds",
        plain,
        "whole number from 0 to 3600",
        "0",
        "The longest life of a kept answer (10.1). 0 keeps no answer."
    ),
    key!(
        "",
        "cache_max_entries",
        plain,
        "whole number from 0 to 10000000",
        "10000",
        "The most kept answers (10.1b). The value 0 contradicts a `cache_ttl_seconds` above 0."
    ),
    key!(
        "",
        "display_max_questions",
        plain,
        "whole number from 1 to 1000",
        "50",
        "The most questions that one request to the options route asks (5.6)."
    ),
    key!(
        "",
        "mcp_path",
        plain,
        "path that starts with a slash",
        "none",
        "The path of the MCP endpoint. Without it, the service has no MCP endpoint."
    ),
    key!(
        "pdp",
        "url",
        indirect,
        "URL with the scheme `http` (this program has no TLS client)",
        "none, mandatory",
        "The URL of the PDP."
    ),
    key!(
        "pdp",
        "credential",
        secret,
        "text that is not empty, with visible ASCII characters",
        "none, mandatory",
        "The credential of the service for the PDP. The service sends it in `Authorization: Bearer` (10.0)."
    ),
    key!(
        "pdp",
        "allow_insecure_pdp_link",
        plain,
        "boolean",
        "false",
        "Accept an `http` URL. Set it for a test on the loopback address. Without it, an `http` URL stops the program."
    ),
    key!(
        "pdp",
        "request_timeout_ms",
        plain,
        "whole number from 1 to 600000",
        "5000",
        "The longest wait for an answer to a question without `context.usage`."
    ),
    key!(
        "pdp",
        "usage_wait_margin_ms",
        plain,
        "whole number from 1 to 600000",
        "1000",
        "The time that the service adds to the time that the PDP publishes for a question with `context.usage` (10.6)."
    ),
    key!(
        "pdp",
        "idle_close_after_ms",
        plain,
        "whole number from 1 to 600000",
        "5000",
        "The longest idle time of a connection to the PDP. The service also closes it after half of the time that the PDP publishes (10.7)."
    ),
    key!(
        "pdp",
        "max_connections",
        plain,
        "whole number from 1 to 256",
        "4",
        "The most connections to the PDP at one time (10.7)."
    ),
    key!(
        "pdp",
        "plain_retries",
        plain,
        "whole number from 0 to 5",
        "1",
        "How many times the service asks again a question without `context.usage` after a lost connection (10.6)."
    ),
];

fn key_of(name: &str) -> &'static Key {
    // A name that is not in the table is a mistake of the code, so a test checks each name.
    KEYS.iter().find(|k| k.name() == name).unwrap_or(&KEYS[0])
}

/// The table of keys as a Markdown table. The README holds this text.
pub fn reference_table() -> String {
    let mut out = String::from(
        "| Key | Value | Default | Indirection | Meaning |\n| --- | --- | --- | --- | --- |\n",
    );
    for key in KEYS {
        let indirection = match (key.secret, key.env.is_some()) {
            (true, _) => "`_env` and `_file` only",
            (false, true) => "`_env` and `_file`",
            (false, false) => "none",
        };
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            key.name(),
            key.value,
            key.default,
            indirection,
            key.meaning
        );
    }
    out
}

/// Where a value came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// The value is the default of the table.
    Default,
    /// The value is in the configuration file.
    File,
    /// The value is in this environment variable.
    Env(String),
    /// The value is the content of this file.
    FileOf(String),
}

impl Source {
    /// The word for the effective configuration: `default`, `file`, `env:VAR` or `file:/path`.
    pub fn text(&self) -> String {
        match self {
            Self::Default => "default".to_owned(),
            Self::File => "file".to_owned(),
            Self::Env(name) => format!("env:{name}"),
            Self::FileOf(path) => format!("file:{path}"),
        }
    }
}

/// One line of the effective configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigLine {
    /// The key.
    pub key: String,
    /// The value that applies. A secret shows as `<hidden>`.
    pub value: String,
    /// The source of the value.
    pub source: Source,
}

/// The places that the reader may use besides the file: the environment and other files.
pub struct Sources<'a> {
    /// The value of an environment variable, or `None` when it is not set.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// The content of a file, or the reason that the program cannot read it.
    pub file: &'a dyn Fn(&Path) -> Result<String, String>,
}

/// The sources of the real program: the environment of the process and the file system.
pub fn real_sources<R>(run: impl FnOnce(&Sources<'_>) -> R) -> R {
    let env = |name: &str| std::env::var(name).ok();
    let file = |path: &Path| std::fs::read_to_string(path).map_err(|e| e.to_string());
    run(&Sources {
        env: &env,
        file: &file,
    })
}

/// The values that apply. The program reads the file one time into this structure.
#[derive(Debug)]
pub struct Settings {
    /// The address of the listener.
    pub listen: SocketAddr,
    /// The number of worker threads.
    pub workers: usize,
    /// The bounds of a client connection.
    pub limits: Limits,
    /// The configuration of the PEP.
    pub pep: PepConfig,
    /// The path of the MCP endpoint.
    pub mcp_path: Option<String>,
}

/// The settings and the effective configuration.
#[derive(Debug)]
pub struct Loaded {
    /// The values that apply.
    pub settings: Settings,
    /// Each key, the value that applies and its source. A secret never shows.
    pub lines: Vec<ConfigLine>,
}

impl Loaded {
    /// The effective configuration as text: one line for each key.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            let _ = writeln!(
                out,
                "{} = {}  ({})",
                line.key,
                line.value,
                line.source.text()
            );
        }
        out
    }
}

struct Reader<'a> {
    sources: &'a Sources<'a>,
    errors: Vec<String>,
    lines: Vec<ConfigLine>,
}

fn quote(text: &str) -> String {
    format!("{text:?}")
}

fn valid_variable(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Reader<'_> {
    fn error(&mut self, key: &str, expected: &str, found: &str) {
        self.errors
            .push(format!("Key `{key}`: expected {expected}, found {found}."));
    }

    fn line(&mut self, key: &Key, value: String, source: Source) {
        self.lines.push(ConfigLine {
            key: key.name(),
            value,
            source,
        });
    }

    /// Read a text from the file, from the environment or from a file. The result is the text and its source.
    fn text(&mut self, obj: &mut Obj<'_>, key: &'static Key) -> Option<(String, Source)> {
        let direct = obj.optional(key.leaf);
        let env = key.env.and_then(|n| obj.optional(n));
        let file = key.file.and_then(|n| obj.optional(n));
        self.pick(key, direct, env, file, |reader, key, value| match value {
            Value::String(text) => Some(text.clone()),
            other => {
                reader.error(&key.name(), "a string", &other.to_string());
                None
            }
        })
    }

    /// Choose the form, and read the value of the form.
    fn pick(
        &mut self,
        key: &'static Key,
        direct: Option<&Value>,
        env: Option<&Value>,
        file: Option<&Value>,
        read_direct: impl FnOnce(&mut Self, &Key, &Value) -> Option<String>,
    ) -> Option<(String, Source)> {
        let name = key.name();
        if key.secret
            && let Some(_) = direct
        {
            self.error(
                &name,
                &format!(
                    "`{}` or `{}`, because a secret never is in clear text in the file",
                    key.member(key.env.unwrap_or("")),
                    key.member(key.file.unwrap_or(""))
                ),
                "a value in clear text (the value stays hidden)",
            );
            return None;
        }
        let present: Vec<String> = [
            (direct.is_some(), key.member(key.leaf)),
            (env.is_some(), key.member(key.env.unwrap_or(""))),
            (file.is_some(), key.member(key.file.unwrap_or(""))),
        ]
        .into_iter()
        .filter_map(|(there, member)| there.then_some(format!("`{member}`")))
        .collect();
        if present.len() > 1 {
            let allowed = if key.secret {
                format!(
                    "one of `{}` and `{}`",
                    key.member(key.env.unwrap_or("")),
                    key.member(key.file.unwrap_or(""))
                )
            } else {
                format!("exactly one of the forms of `{name}`")
            };
            self.error(
                &name,
                &allowed,
                &format!("{} members: {}", present.len(), present.join(", ")),
            );
            return None;
        }
        if let Some(value) = direct {
            return read_direct(self, key, value).map(|v| (v, Source::File));
        }
        if let Some(value) = env {
            let member = key.member(key.env.unwrap_or(""));
            let Value::String(var) = value else {
                self.error(
                    &member,
                    "the name of an environment variable",
                    &value.to_string(),
                );
                return None;
            };
            if !valid_variable(var) {
                self.error(
                    &member,
                    "the name of an environment variable (letters, digits and underscore)",
                    &quote(var),
                );
                return None;
            }
            return match (self.sources.env)(var) {
                None => {
                    self.error(
                        &member,
                        "the name of an environment variable that is set",
                        &format!("{} (the variable does not exist)", quote(var)),
                    );
                    None
                }
                Some(text) if text.is_empty() => {
                    self.error(
                        &member,
                        "an environment variable with a value that is not empty",
                        &format!("{} (the value is empty)", quote(var)),
                    );
                    None
                }
                Some(text) => Some((text, Source::Env(var.clone()))),
            };
        }
        if let Some(value) = file {
            let member = key.member(key.file.unwrap_or(""));
            let Value::String(path) = value else {
                self.error(&member, "the path of a file", &value.to_string());
                return None;
            };
            return match (self.sources.file)(Path::new(path)) {
                Err(reason) => {
                    self.error(
                        &member,
                        "the path of a file that the program can read",
                        &format!("{} ({reason})", quote(path)),
                    );
                    None
                }
                Ok(text) => {
                    let text = text
                        .strip_suffix("\r\n")
                        .or_else(|| text.strip_suffix('\n'))
                        .unwrap_or(&text)
                        .to_owned();
                    if text.is_empty() {
                        self.error(
                            &member,
                            "a file with a content that is not empty",
                            &format!("{} (the content is empty)", quote(path)),
                        );
                        None
                    } else {
                        Some((text, Source::FileOf(path.clone())))
                    }
                }
            };
        }
        None
    }

    /// A key with a default. The result is the default when the key is absent.
    fn text_or(&mut self, obj: &mut Obj<'_>, key: &'static Key) -> (String, Source) {
        match self.text(obj, key) {
            Some(found) => found,
            None => (key.default.to_owned(), Source::Default),
        }
    }

    /// A mandatory text. An absent key is an error.
    fn mandatory(&mut self, obj: &mut Obj<'_>, key: &'static Key) -> Option<(String, Source)> {
        let before = self.errors.len();
        let found = self.text(obj, key);
        if found.is_none() && self.errors.len() == before {
            let forms = match (key.env, key.file) {
                (Some(_), Some(_)) => format!(
                    "one of `{}`, `{}` and `{}`",
                    key.member(key.leaf),
                    key.member(key.env.unwrap_or("")),
                    key.member(key.file.unwrap_or(""))
                ),
                _ => format!("the member `{}`", key.member(key.leaf)),
            };
            let forms = if key.secret {
                format!(
                    "one of `{}` and `{}`",
                    key.member(key.env.unwrap_or("")),
                    key.member(key.file.unwrap_or(""))
                )
            } else {
                forms
            };
            self.error(&key.name(), &forms, "no member");
        }
        found
    }

    fn whole(&mut self, obj: &mut Obj<'_>, name: &'static str, min: u64, max: u64) -> u64 {
        let key = key_of(name);
        let range = format!("a whole number from {min} to {max}");
        match obj.optional(key.leaf) {
            None => {
                let default = key.default.parse::<u64>().unwrap_or(min);
                self.line(key, default.to_string(), Source::Default);
                default
            }
            Some(value) => match value.as_u64() {
                Some(number) if (min..=max).contains(&number) => {
                    self.line(key, number.to_string(), Source::File);
                    number
                }
                Some(number) => {
                    self.error(name, &range, &number.to_string());
                    min
                }
                None => {
                    self.error(name, &range, &value.to_string());
                    min
                }
            },
        }
    }

    /// A text with a default, and no indirection.
    fn plain_text(&mut self, obj: &mut Obj<'_>, name: &'static str) -> (String, Source) {
        let key = key_of(name);
        match obj.optional(key.leaf) {
            None => (key.default.to_owned(), Source::Default),
            Some(Value::String(text)) => (text.clone(), Source::File),
            Some(other) => {
                self.error(name, "a string", &other.to_string());
                (key.default.to_owned(), Source::Default)
            }
        }
    }
}

/// Read the configuration from the text of the file.
///
/// # Errors
/// Returns every error. Each error names the key, the expected value and the value found.
pub fn load(text: &str, sources: &Sources<'_>) -> Result<Loaded, Vec<String>> {
    let value =
        parse_str(text).map_err(|e| vec![format!("The configuration is not valid JSON: {e}.")])?;
    let mut report = Report::new();
    let root = JsonPath::root();
    let Some(mut obj) = Obj::new(&value, &root, "config", Unknown::Error, &mut report) else {
        return Err(report.findings().iter().map(ToString::to_string).collect());
    };
    let mut reader = Reader {
        sources,
        errors: Vec::new(),
        lines: Vec::new(),
    };
    let loaded = read_all(&mut reader, &mut obj, &mut report);
    obj.finish(&mut report);
    let mut errors: Vec<String> = report.findings().iter().map(ToString::to_string).collect();
    errors.extend(reader.errors);
    match loaded {
        Some(settings) if errors.is_empty() => Ok(Loaded {
            settings,
            lines: reader.lines,
        }),
        _ => Err(errors),
    }
}

/// Read the configuration from a file.
///
/// # Errors
/// Returns every error. A file that the program cannot read is one error.
pub fn load_file(path: &Path, sources: &Sources<'_>) -> Result<Loaded, Vec<String>> {
    let text = (sources.file)(path).map_err(|reason| {
        vec![format!(
            "Cannot read the configuration file {}: {reason}.",
            path.display()
        )]
    })?;
    load(&text, sources)
}

fn duration_ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

fn read_all(reader: &mut Reader<'_>, obj: &mut Obj<'_>, report: &mut Report) -> Option<Settings> {
    // The top level, in the order of the table.
    let listen_key = key_of("listen");
    let (listen_text, listen_source) = reader.text_or(obj, listen_key);
    let listen = match listen_text.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            reader.error(
                "listen",
                "ADDRESS:PORT with an IP address, for example 127.0.0.1:8080",
                &quote(&listen_text),
            );
            None
        }
    };
    reader.line(listen_key, listen_text, listen_source);
    let workers = reader.whole(obj, "workers", 1, 256);
    let max_body = reader.whole(obj, "max_body_bytes", 1, 67_108_864);
    let read_timeout = reader.whole(obj, "read_timeout_seconds", 1, 3600);
    let idle_timeout = reader.whole(obj, "idle_timeout_seconds", 1, 3600);
    let (service_id, source) = reader.plain_text(obj, "service_id");
    reader.line(key_of("service_id"), service_id.clone(), source);
    let (token_header, source) = reader.plain_text(obj, "token_header");
    reader.line(key_of("token_header"), token_header.clone(), source);
    let issuer = reader.mandatory(obj, key_of("issuer"));
    if let Some((text, source)) = &issuer {
        reader.line(key_of("issuer"), text.clone(), source.clone());
    }
    let max_age = reader.whole(obj, "max_token_age_seconds", 1, 86_400);
    let skew = reader.whole(obj, "clock_skew_seconds", 0, 3600);
    let keys = read_jwks(reader, obj);
    let cache_ttl = reader.whole(obj, "cache_ttl_seconds", 0, 3600);
    let cache_entries = reader.whole(obj, "cache_max_entries", 0, 10_000_000);
    let display = reader.whole(obj, "display_max_questions", 1, 1000);
    let mcp_path = read_mcp_path(reader, obj);

    // The section `pdp`.
    let pdp = obj.object_opt("pdp", "config", Unknown::Error, report);
    let pdp_settings = match pdp {
        Some(mut section) => read_pdp(reader, &mut section, report),
        None => {
            reader.error("pdp", "an object with the keys `pdp.url` and `pdp.credential_env` or `pdp.credential_file`", "no member");
            None
        }
    };

    let (listen, issuer, keys, pdp_settings) = (listen?, issuer?, keys?, pdp_settings?);
    let mut pep = PepConfig::new(
        service_id,
        token_header,
        issuer.0,
        keys,
        max_age,
        skew,
        pdp_settings,
    );
    pep.cache_ttl = Duration::from_secs(cache_ttl);
    pep.cache_max_entries = usize::try_from(cache_entries).unwrap_or(usize::MAX);
    pep.display_max_questions = usize::try_from(display).unwrap_or(usize::MAX);
    // The contradictions and the rules of the library.
    if let Err(errors) = pep.check() {
        reader.errors.extend(errors.iter().map(ToString::to_string));
        return None;
    }
    Some(Settings {
        listen,
        workers: usize::try_from(workers).unwrap_or(1),
        limits: Limits {
            max_body: usize::try_from(max_body).unwrap_or(usize::MAX),
            read_timeout: Duration::from_secs(read_timeout),
            idle_timeout: Duration::from_secs(idle_timeout),
        },
        pep,
        mcp_path,
    })
}

fn read_jwks(reader: &mut Reader<'_>, obj: &mut Obj<'_>) -> Option<KeySet> {
    let key = key_of("jwks");
    let direct = obj.optional(key.leaf);
    let env = key.env.and_then(|n| obj.optional(n));
    let file = key.file.and_then(|n| obj.optional(n));
    let before = reader.errors.len();
    // The direct form is a JSON object. The other forms give its JSON text.
    let picked = reader.pick(key, direct, env, file, |_, _, _| Some(String::new()));
    let Some((text, source)) = picked else {
        if reader.errors.len() == before {
            reader.error(
                "jwks",
                "one of `jwks`, `jwks_env` and `jwks_file`",
                "no member",
            );
        }
        return None;
    };
    let result = match (&source, direct) {
        (Source::File, Some(value)) => KeySet::from_jwks_value(value),
        _ => KeySet::from_jwks_str(&text),
    };
    match result {
        Ok(set) => {
            let summary = format!(
                "{} key{} ({})",
                set.len(),
                if set.len() == 1 { "" } else { "s" },
                set.keys()
                    .iter()
                    .map(|k| format!(
                        "{}{}",
                        k.algorithm().as_str(),
                        k.kid().map_or(String::new(), |kid| format!(" kid={kid}"))
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            reader.line(key, summary, source);
            Some(set)
        }
        Err(findings) => {
            for finding in findings {
                reader.errors.push(format!("Key `jwks`: {finding}"));
            }
            None
        }
    }
}

fn read_mcp_path(reader: &mut Reader<'_>, obj: &mut Obj<'_>) -> Option<String> {
    let key = key_of("mcp_path");
    let found = match obj.optional(key.leaf) {
        None => None,
        Some(Value::String(path)) => Some(path.as_str()),
        Some(other) => {
            reader.error(
                "mcp_path",
                "a path that starts with a slash",
                &other.to_string(),
            );
            return None;
        }
    };
    let Some(path) = found else {
        reader.line(key, "none".to_owned(), Source::Default);
        return None;
    };
    reader.line(key, path.to_owned(), Source::File);
    let reserved = [
        crate::app::ACTIONS_PATH,
        crate::app::OPTIONS_PATH,
        "/copy",
        "/hosts",
    ];
    let bad_form = !path.starts_with('/')
        || path
            .bytes()
            .any(|b| b <= 0x20 || b >= 0x7f || b == b'?' || b == b'#');
    if bad_form {
        reader.error(
            "mcp_path",
            "a path that starts with a slash, with visible ASCII characters and no `?` or `#`",
            &quote(path),
        );
    } else if reserved.contains(&path) || path.starts_with("/hosts/") {
        reader.error(
            "mcp_path",
            "a path that no other route uses (contradiction with a route of the service)",
            &quote(path),
        );
    } else if !cfg!(feature = "mcp") {
        reader.error(
            "mcp_path",
            "no value, because this program has no MCP endpoint (built without the feature `mcp`)",
            &quote(path),
        );
    } else {
        return Some(path.to_owned());
    }
    None
}

fn read_pdp(reader: &mut Reader<'_>, obj: &mut Obj<'_>, report: &mut Report) -> Option<PdpConfig> {
    let url = reader.mandatory(obj, key_of("pdp.url"));
    if let Some((text, source)) = &url {
        reader.line(key_of("pdp.url"), text.clone(), source.clone());
    }
    let credential = reader.mandatory(obj, key_of("pdp.credential"));
    if let Some((_, source)) = &credential {
        reader.line(
            key_of("pdp.credential"),
            "<hidden>".to_owned(),
            source.clone(),
        );
    }
    let allow = obj.boolean_opt("allow_insecure_pdp_link", report);
    reader.line(
        key_of("pdp.allow_insecure_pdp_link"),
        allow.unwrap_or(false).to_string(),
        if allow.is_some() {
            Source::File
        } else {
            Source::Default
        },
    );
    let request_timeout = reader.whole(obj, "pdp.request_timeout_ms", 1, 600_000);
    let margin = reader.whole(obj, "pdp.usage_wait_margin_ms", 1, 600_000);
    let idle = reader.whole(obj, "pdp.idle_close_after_ms", 1, 600_000);
    let connections = reader.whole(obj, "pdp.max_connections", 1, 256);
    let retries = reader.whole(obj, "pdp.plain_retries", 0, 5);
    obj.finish(report);
    let ((url, _), (credential, _)) = (url?, credential?);
    let mut pdp = PdpConfig::new(url, Secret::new(credential));
    pdp.allow_insecure_pdp_link = allow.unwrap_or(false);
    pdp.request_timeout = duration_ms(request_timeout);
    pdp.usage_wait_margin = duration_ms(margin);
    pdp.idle_close_after = duration_ms(idle);
    pdp.max_connections = usize::try_from(connections).unwrap_or(1);
    pdp.plain_retries = u32::try_from(retries).unwrap_or(1);
    Some(pdp)
}
