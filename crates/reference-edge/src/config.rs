//! The configuration of the reference edge: strict, closed and fail-fast.
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
use procurauth_core::jws::SigningKey;
use procurauth_core::key_format::KeyFormat;
use procurauth_core::names::validate_id;
use procurauth_core::read::{Obj, Unknown};
use procurauth_pep::config::{PdpConfig, Secret};
use procurauth_pep::url::{Scheme, Url};
use serde_json::Value;

use crate::http::Limits;
use crate::keys::KeyStore;
use crate::proxy::Upstream;

/// One key of the configuration.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    /// The section of the key: `upstream`, `signing` or `pdp`, or the empty text for the top level.
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
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8090";

/// The table of keys, in the order of the effective configuration.
pub const KEYS: [Key; 27] = [
    key!(
        "",
        "listen",
        indirect,
        "ADDRESS:PORT with an IP address",
        "127.0.0.1:8090",
        "The address of the listener. Port 0 chooses a free port."
    ),
    key!(
        "",
        "workers",
        plain,
        "whole number from 1 to 256",
        "16",
        "The number of worker threads. One open connection uses one thread."
    ),
    key!(
        "",
        "max_body_bytes",
        plain,
        "whole number from 1 to 67108864",
        "1048576",
        "The largest body of a request that the edge accepts. A larger body gets HTTP 413, after the key is good."
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
        "none, mandatory",
        "The id of the service behind the edge: the `aud` of the tokens and the resource of the question for `access`."
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
        "The value of the claim `iss` (9.4). The service must have the same value."
    ),
    key!(
        "",
        "token_life_seconds",
        plain,
        "whole number from 1 to 86400",
        "60",
        "The life of a token, `exp` minus `iat` (9.2). The value must not be above `max_token_age_seconds`."
    ),
    key!(
        "",
        "max_token_age_seconds",
        plain,
        "whole number from 1 to 86400",
        "300",
        "The longest life that the service accepts for a token (9.2). A `token_life_seconds` above it stops the program."
    ),
    key!(
        "",
        "token_cache_max_entries",
        plain,
        "whole number from 0 to 10000000",
        "0",
        "The most tokens that the edge keeps (9.9). 0 keeps no token. When the table is full, the edge signs a new token."
    ),
    key!(
        "",
        "key_format",
        indirect,
        "key format document (`schemas/key-format.schema.json`); the forms `_env` and `_file` give its JSON text",
        "none, mandatory",
        "The format of the text of a key (3.8). A text that does not follow it is refused with no look at the keys file."
    ),
    key!(
        "",
        "keys",
        indirect,
        "keys file document (see the section The keys file); the forms `_env` and `_file` give its JSON text",
        "none, mandatory",
        "The keys that the edge knows, each with the SHA-256 digest of its text, its subject id and its owner."
    ),
    key!(
        "upstream",
        "url",
        indirect,
        "URL with the scheme `http`, a host and no path (this program has no TLS client)",
        "none, mandatory",
        "The service behind the edge. The edge sends each accepted request there."
    ),
    key!(
        "upstream",
        "connect_timeout_ms",
        plain,
        "whole number from 1 to 600000",
        "2000",
        "The longest time to open a connection to the service. A longer time gives HTTP 504."
    ),
    key!(
        "upstream",
        "response_timeout_seconds",
        plain,
        "whole number from 1 to 3600",
        "30",
        "The longest wait for a byte of the answer of the service. Before the head, a longer wait gives HTTP 504."
    ),
    key!(
        "signing",
        "key",
        secret,
        "private key of Ed25519 or P-256 in PKCS#8 PEM form",
        "none, mandatory",
        "The signing key of the edge. The edge uses it for the identity token only (9.2). Its algorithm is `Ed25519` or `ES256`."
    ),
    key!(
        "signing",
        "kid",
        plain,
        "text of 1 to 128 visible ASCII characters",
        "none",
        "The `kid` in the header of each token (9.4). Set it when the service trusts more than one key."
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
        "The credential of the edge for the PDP. The edge sends it in `Authorization: Bearer` (10.0)."
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
        "The longest wait for an answer to the question for `access`. A longer wait gives HTTP 503."
    ),
    key!(
        "pdp",
        "idle_close_after_ms",
        plain,
        "whole number from 1 to 600000",
        "5000",
        "The longest idle time of a connection to the PDP. The edge also closes it after half of the time that the PDP publishes (10.7)."
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
        "How many times the edge asks again after a lost connection. The question for `access` has no `context.usage` (10.6)."
    ),
    key!(
        "pdp",
        "metadata_max_age_seconds",
        plain,
        "whole number from 1 to 86400",
        "3600",
        "The longest age of the metadata of the PDP. After this age the edge reads it again."
    ),
    key!(
        "pdp",
        "max_response_bytes",
        plain,
        "whole number from 1 to 67108864",
        "1048576",
        "The largest answer of the PDP that the edge reads."
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
    /// The id of the service behind the edge.
    pub service_id: String,
    /// The header of the identity token.
    pub token_header: String,
    /// The value of the claim `iss`.
    pub issuer: String,
    /// The life of a token, in seconds.
    pub token_life_seconds: u64,
    /// The most kept tokens.
    pub token_cache_max_entries: usize,
    /// The format of the text of a key.
    pub key_format: KeyFormat,
    /// The keys that the edge knows.
    pub keys: KeyStore,
    /// The signing key of the edge.
    pub signing_key: SigningKey,
    /// The `kid` of the tokens.
    pub signing_kid: Option<String>,
    /// The service behind the edge.
    pub upstream: Upstream,
    /// The link to the PDP.
    pub pdp: PdpConfig,
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

    /// A mandatory text. An absent key is an error.
    fn mandatory(&mut self, obj: &mut Obj<'_>, key: &'static Key) -> Option<(String, Source)> {
        let before = self.errors.len();
        let found = self.text(obj, key);
        if found.is_none() && self.errors.len() == before {
            self.absent(key);
        }
        found
    }

    fn absent(&mut self, key: &'static Key) {
        let forms = if key.secret {
            format!(
                "one of `{}` and `{}`",
                key.member(key.env.unwrap_or("")),
                key.member(key.file.unwrap_or(""))
            )
        } else if key.env.is_some() && key.file.is_some() {
            format!(
                "one of `{}`, `{}` and `{}`",
                key.member(key.leaf),
                key.member(key.env.unwrap_or("")),
                key.member(key.file.unwrap_or(""))
            )
        } else {
            format!("the member `{}`", key.member(key.leaf))
        };
        self.error(&key.name(), &forms, "no member");
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
                    self.line(key, number.to_string(), Source::File);
                    min
                }
                None => {
                    self.error(name, &range, &value.to_string());
                    min
                }
            },
        }
    }

    /// A text with a default, and no indirection. The result is `None` when the key is absent and the default is none.
    fn plain_text(&mut self, obj: &mut Obj<'_>, name: &'static str) -> Option<String> {
        let key = key_of(name);
        match obj.optional(key.leaf) {
            None => None,
            Some(Value::String(text)) => Some(text.clone()),
            Some(other) => {
                self.error(name, "a string", &other.to_string());
                None
            }
        }
    }

    /// A JSON document that the file gives as an object, or that `_env` or `_file` gives as text.
    fn document(&mut self, obj: &mut Obj<'_>, key: &'static Key) -> Option<(Value, Source)> {
        let direct = obj.optional(key.leaf);
        let env = key.env.and_then(|n| obj.optional(n));
        let file = key.file.and_then(|n| obj.optional(n));
        let before = self.errors.len();
        let picked = self.pick(key, direct, env, file, |reader, key, value| {
            if value.is_object() {
                Some(String::new())
            } else {
                reader.error(&key.name(), "a JSON object", &value.to_string());
                None
            }
        });
        let Some((text, source)) = picked else {
            if self.errors.len() == before {
                self.absent(key);
            }
            return None;
        };
        match (&source, direct) {
            (Source::File, Some(value)) => Some((value.clone(), source)),
            _ => match parse_str(&text) {
                Ok(value) => Some((value, source)),
                Err(error) => {
                    self.error(
                        &key.name(),
                        "a text that is a JSON document (strict: no duplicate member)",
                        &format!("a text that is not valid ({error})"),
                    );
                    None
                }
            },
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

const FORBIDDEN_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

fn read_all(reader: &mut Reader<'_>, obj: &mut Obj<'_>, report: &mut Report) -> Option<Settings> {
    // The top level, in the order of the table.
    let listen_key = key_of("listen");
    let (listen_text, listen_source) = match reader.text(obj, listen_key) {
        Some(found) => found,
        None => (listen_key.default.to_owned(), Source::Default),
    };
    let listen = match listen_text.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            reader.error(
                "listen",
                "ADDRESS:PORT with an IP address, for example 127.0.0.1:8090",
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
    let service_id = read_service_id(reader, obj);
    let token_header = read_token_header(reader, obj);
    let issuer = reader.mandatory(obj, key_of("issuer"));
    if let Some((text, source)) = &issuer {
        reader.line(key_of("issuer"), text.clone(), source.clone());
        if text.is_empty() {
            reader.error("issuer", "a text that is not empty", "\"\"");
        }
    }
    let life = reader.whole(obj, "token_life_seconds", 1, 86_400);
    let max_age = reader.whole(obj, "max_token_age_seconds", 1, 86_400);
    if life > max_age {
        reader.error(
            "token_life_seconds",
            &format!(
                "a whole number that is not above `max_token_age_seconds`, {max_age} (contradiction, protocol 9.2)"
            ),
            &life.to_string(),
        );
    }
    let cache_entries = reader.whole(obj, "token_cache_max_entries", 0, 10_000_000);
    let key_format = read_key_format(reader, obj);
    let keys = read_keys(reader, obj);

    let upstream = match obj.object_opt("upstream", "config", Unknown::Error, report) {
        Some(mut section) => read_upstream(reader, &mut section, report),
        None => {
            reader.error(
                "upstream",
                "an object with the key `upstream.url`",
                "no member",
            );
            None
        }
    };
    let signing = match obj.object_opt("signing", "config", Unknown::Error, report) {
        Some(mut section) => read_signing(reader, &mut section, report),
        None => {
            reader.error(
                "signing",
                "an object with the key `signing.key_env` or `signing.key_file`",
                "no member",
            );
            None
        }
    };
    let pdp = match obj.object_opt("pdp", "config", Unknown::Error, report) {
        Some(mut section) => read_pdp(reader, &mut section, report),
        None => {
            reader.error(
                "pdp",
                "an object with the keys `pdp.url` and `pdp.credential_env` or `pdp.credential_file`",
                "no member",
            );
            None
        }
    };

    let (listen, issuer, key_format, keys, upstream, (signing_key, signing_kid), pdp) = (
        listen?,
        issuer?,
        key_format?,
        keys?,
        upstream?,
        signing?,
        pdp?,
    );
    let service_id = service_id?;
    let token_header = token_header?;
    // The contradictions between keys.
    if let Ok(addresses) =
        std::net::ToSocketAddrs::to_socket_addrs(&(upstream.host.as_str(), upstream.port))
        && addresses.into_iter().any(|a| a == listen)
    {
        reader.error(
            "upstream.url",
            &format!(
                "an address other than `listen`, {listen} (contradiction: the edge would send its requests to itself)"
            ),
            &quote(&format!("http://{}:{}", upstream.host, upstream.port)),
        );
    }
    if let Err(errors) = pdp.check() {
        reader.errors.extend(errors.iter().map(ToString::to_string));
    }
    if !reader.errors.is_empty() {
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
        service_id,
        token_header,
        issuer: issuer.0,
        token_life_seconds: life,
        token_cache_max_entries: usize::try_from(cache_entries).unwrap_or(usize::MAX),
        key_format,
        keys,
        signing_key,
        signing_kid,
        upstream,
        pdp,
    })
}

fn read_service_id(reader: &mut Reader<'_>, obj: &mut Obj<'_>) -> Option<String> {
    let key = key_of("service_id");
    let Some(id) = reader.plain_text(obj, "service_id") else {
        if !reader
            .errors
            .iter()
            .any(|e| e.starts_with("Key `service_id`"))
        {
            reader.absent(key);
        }
        return None;
    };
    reader.line(key, id.clone(), Source::File);
    if let Err(error) = validate_id(&id) {
        reader.error(
            "service_id",
            &format!("an id of 1 to 256 bytes with no control character ({error})"),
            &quote(&id),
        );
        return None;
    }
    Some(id)
}

fn read_token_header(reader: &mut Reader<'_>, obj: &mut Obj<'_>) -> Option<String> {
    let key = key_of("token_header");
    let (name, source) = match reader.plain_text(obj, "token_header") {
        Some(name) => (name, Source::File),
        None => (key.default.to_owned(), Source::Default),
    };
    reader.line(key, name.clone(), source);
    if !crate::http::is_token(&name) {
        reader.error(
            "token_header",
            "an HTTP header name with 1 or more token characters",
            &quote(&name),
        );
        return None;
    }
    if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        reader.error(
            "token_header",
            "a header other than `Authorization`, `Proxy-Authorization` and `Cookie` (9.4)",
            &quote(&name),
        );
        return None;
    }
    Some(name)
}

fn read_key_format(reader: &mut Reader<'_>, obj: &mut Obj<'_>) -> Option<KeyFormat> {
    let key = key_of("key_format");
    let (value, source) = reader.document(obj, key)?;
    match KeyFormat::from_value(&value) {
        Ok(format) => {
            let checksum = if format.checksum.is_some() {
                " with a checksum"
            } else {
                ""
            };
            reader.line(
                key,
                format!(
                    "prefix {}, {} characters{checksum}",
                    quote(&format.prefix),
                    format.length
                ),
                source,
            );
            Some(format)
        }
        Err(findings) => {
            for finding in findings {
                reader.errors.push(format!("Key `key_format`: {finding}"));
            }
            None
        }
    }
}

fn read_keys(reader: &mut Reader<'_>, obj: &mut Obj<'_>) -> Option<KeyStore> {
    let key = key_of("keys");
    let (value, source) = reader.document(obj, key)?;
    match KeyStore::from_value(&value) {
        Ok(store) => {
            reader.line(key, format!("{} entries", store.len()), source);
            Some(store)
        }
        Err(errors) => {
            for error in errors {
                reader.errors.push(format!("Key `keys`: {error}"));
            }
            None
        }
    }
}

fn read_upstream(
    reader: &mut Reader<'_>,
    obj: &mut Obj<'_>,
    report: &mut Report,
) -> Option<Upstream> {
    let key = key_of("upstream.url");
    let url = reader.mandatory(obj, key);
    if let Some((text, source)) = &url {
        reader.line(key, text.clone(), source.clone());
    }
    let connect = reader.whole(obj, "upstream.connect_timeout_ms", 1, 600_000);
    let response = reader.whole(obj, "upstream.response_timeout_seconds", 1, 3600);
    obj.finish(report);
    let (text, _) = url?;
    let parsed = match Url::parse(&text) {
        Ok(url) => url,
        Err(error) => {
            // A URL with user information can hold a secret. The message does not show it.
            let found = if text.contains('@') {
                format!("a URL with user information ({error}; the value stays hidden)")
            } else {
                format!("{} ({error})", quote(&text))
            };
            reader.error("upstream.url", "an absolute `http` URL with a host", &found);
            return None;
        }
    };
    if parsed.scheme != Scheme::Http {
        reader.error(
            "upstream.url",
            "an `http` URL, because this program has no TLS client",
            &quote(&text),
        );
        return None;
    }
    if !parsed.path.is_empty() && parsed.path != "/" {
        reader.error(
            "upstream.url",
            "a URL with no path, because the edge keeps the path of each request",
            &quote(&text),
        );
        return None;
    }
    Some(Upstream {
        host: parsed.host,
        port: parsed.port,
        connect_timeout: Duration::from_millis(connect),
        response_timeout: Duration::from_secs(response),
    })
}

fn read_signing(
    reader: &mut Reader<'_>,
    obj: &mut Obj<'_>,
    report: &mut Report,
) -> Option<(SigningKey, Option<String>)> {
    let key = key_of("signing.key");
    let pem = reader.mandatory(obj, key);
    let kid_key = key_of("signing.kid");
    let kid = reader.plain_text(obj, "signing.kid");
    obj.finish(report);
    let (pem, source) = pem?;
    let signing = match SigningKey::from_pkcs8_pem(&pem) {
        Ok(signing) => {
            reader.line(
                key,
                format!("<hidden> ({})", signing.algorithm().as_str()),
                source,
            );
            Some(signing)
        }
        Err(error) => {
            reader.line(key, "<hidden>".to_owned(), source);
            reader.error(
                "signing.key",
                "a private key of Ed25519 or P-256 in PKCS#8 PEM form",
                &format!("a text that is not such a key ({error}; the value stays hidden)"),
            );
            None
        }
    };
    match &kid {
        None => reader.line(kid_key, "none".to_owned(), Source::Default),
        Some(kid) => {
            reader.line(kid_key, kid.clone(), Source::File);
            if kid.is_empty() || kid.len() > 128 || kid.bytes().any(|b| !(0x21..0x7f).contains(&b))
            {
                reader.error(
                    "signing.kid",
                    "a text of 1 to 128 visible ASCII characters",
                    &quote(kid),
                );
                return None;
            }
        }
    }
    Some((signing?, kid))
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
    let idle = reader.whole(obj, "pdp.idle_close_after_ms", 1, 600_000);
    let connections = reader.whole(obj, "pdp.max_connections", 1, 256);
    let retries = reader.whole(obj, "pdp.plain_retries", 0, 5);
    let metadata_age = reader.whole(obj, "pdp.metadata_max_age_seconds", 1, 86_400);
    let max_response = reader.whole(obj, "pdp.max_response_bytes", 1, 67_108_864);
    obj.finish(report);
    let ((url, _), (credential, _)) = (url?, credential?);
    let mut pdp = PdpConfig::new(url, Secret::new(credential));
    pdp.allow_insecure_pdp_link = allow.unwrap_or(false);
    pdp.request_timeout = Duration::from_millis(request_timeout);
    pdp.idle_close_after = Duration::from_millis(idle);
    pdp.max_connections = usize::try_from(connections).unwrap_or(1);
    pdp.plain_retries = u32::try_from(retries).unwrap_or(1);
    pdp.metadata_max_age = Duration::from_secs(metadata_age);
    pdp.max_response_bytes = max_response;
    Some(pdp)
}
