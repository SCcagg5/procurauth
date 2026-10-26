//! The configuration of a service for `access-token check` (protocol 9.4).
//!
//! The file is one JSON object. The schema is closed: an unknown member or a
//! duplicate member is an error. The reader gives every error, with the path
//! of the member, the expected value and the value found. The reader parses
//! the file one time into a [`Config`]. The rest of the program reads only
//! this structure. The schema is `schemas/access-token-config.schema.json`.
//!
//! | Member | Type | Meaning |
//! | --- | --- | --- |
//! | `token_header` | string | The name of the header with the token. |
//! | `iss` | string | The value of the claim `iss`. |
//! | `service_id` | string | The id of the service: the value of `aud`. |
//! | `max_age_seconds` | whole number, 1 or more | The longest life of a token. |
//! | `skew_seconds` | whole number, 0 or more | The clock skew. |
//! | `jwks` | object | A JWK Set with the public keys of the edge. |
//! | `pem_keys` | array | Public keys in PEM form, each with an optional `kid`. |
//!
//! The file needs at least one key in `jwks` or in `pem_keys`. The file has
//! no default value and no secret.

use procurauth_core::finding::{JsonPath, Report, show};
use procurauth_core::identity::TokenPolicy;
use procurauth_core::json::parse_str;
use procurauth_core::jws::{Algorithm, KeySet, PublicKey};
use procurauth_core::names::validate_id;
use procurauth_core::read::{Obj, Unknown};
use serde_json::{Value, json};

/// The header names that the protocol forbids for the token (9.4).
const FORBIDDEN_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

/// One error of the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// The place of the member, for example `$.max_age_seconds`.
    pub path: String,
    /// The paragraph of the protocol.
    pub rule: &'static str,
    /// The message, with the expected value and the value found.
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: rule {}: {}", self.path, self.rule, self.message)
    }
}

/// What the program knows about one public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// The `kid` of the key.
    pub kid: Option<String>,
    /// The algorithm that the key checks.
    pub algorithm: Algorithm,
    /// The place in the file, for example `jwks.keys[0]`.
    pub source: String,
}

/// The configuration of a service, parsed one time.
#[derive(Debug)]
pub struct Config {
    /// The name of the header with the token.
    pub token_header: String,
    /// The values that the checks of 9.4 use.
    pub policy: TokenPolicy,
    /// The public keys of the edge.
    pub keys: KeySet,
    /// A summary of each key, in the order of the set.
    pub key_info: Vec<KeyInfo>,
}

impl Config {
    /// Read the configuration from JSON text.
    ///
    /// # Errors
    /// Returns every error of the file. The program stops before it checks a token.
    pub fn parse(text: &str) -> Result<Self, Vec<ConfigError>> {
        let value = parse_str(text).map_err(|error| {
            vec![ConfigError {
                path: error.path.to_string(),
                rule: "9.4",
                message: format!("The text is not valid JSON: {error}."),
            }]
        })?;
        Self::from_value(&value)
    }

    /// Read the configuration from a JSON value.
    ///
    /// # Errors
    /// Returns every error of the value.
    pub fn from_value(value: &Value) -> Result<Self, Vec<ConfigError>> {
        let mut report = Report::new();
        let mut errors = Vec::new();
        let root = JsonPath::root();
        let Some(mut obj) = Obj::new(value, &root, "9.4", Unknown::Error, &mut report) else {
            return Err(convert(report, ""));
        };
        let token_header = obj.string("token_header", &mut report);
        let iss = obj.string("iss", &mut report);
        let service_id = obj.string("service_id", &mut report);
        let max_age = obj.whole("max_age_seconds", &mut report);
        let skew = obj.whole("skew_seconds", &mut report);
        let jwks = obj.optional("jwks");
        let pem_keys = obj.array_opt("pem_keys", &mut report);
        obj.finish(&mut report);
        errors.extend(convert(report, ""));

        let mut add = |path: &str, rule: &'static str, message: String| {
            errors.push(ConfigError {
                path: path.to_owned(),
                rule,
                message,
            });
        };
        if let Some(name) = token_header
            && let Err(message) = check_header_name(name)
        {
            add("$.token_header", "9.4", message);
        }
        if iss == Some("") {
            add(
                "$.iss",
                "9.4",
                "Member `iss`: expected a text that is not empty, found an empty text.".to_owned(),
            );
        }
        if let Some(id) = service_id
            && let Err(error) = validate_id(id)
        {
            add(
                "$.service_id",
                "4.1",
                format!(
                    "Member `service_id`: expected an id of 1 to 256 bytes with no control character ({error}), found {}.",
                    show(&json!(id))
                ),
            );
        }
        if max_age == Some(0) {
            add(
                "$.max_age_seconds",
                "9.4",
                "Member `max_age_seconds`: expected a whole number of 1 or more, found 0."
                    .to_owned(),
            );
        }

        let mut keys: Vec<PublicKey> = Vec::new();
        let mut info: Vec<KeyInfo> = Vec::new();
        if let Some(jwks) = jwks {
            match KeySet::from_jwks_value(jwks) {
                Ok(set) => {
                    for (index, key) in set.into_keys().into_iter().enumerate() {
                        info.push(KeyInfo {
                            kid: key.kid().map(str::to_owned),
                            algorithm: key.algorithm(),
                            source: format!("jwks.keys[{index}]"),
                        });
                        keys.push(key);
                    }
                }
                Err(findings) => {
                    for finding in findings {
                        add(
                            &format!("$.jwks{}", finding.path.as_str().trim_start_matches('$')),
                            finding.rule,
                            finding.message,
                        );
                    }
                }
            }
        }
        if let Some(items) = pem_keys {
            read_pem_keys(items, &mut keys, &mut info, &mut add);
        }
        if jwks.is_none() && pem_keys.is_none() {
            add(
                "$",
                "9.4",
                "The configuration needs at least one public key: expected the member `jwks` or `pem_keys`."
                    .to_owned(),
            );
        }
        if pem_keys.is_some_and(<[Value]>::is_empty) && jwks.is_none() {
            add(
                "$.pem_keys",
                "9.4",
                "Member `pem_keys`: expected at least one key, found an empty array.".to_owned(),
            );
        }
        check_kids(&info, &mut add);

        match (token_header, iss, service_id, max_age, skew) {
            (Some(token_header), Some(iss), Some(service_id), Some(max_age), Some(skew))
                if errors.is_empty() =>
            {
                Ok(Self {
                    token_header: token_header.to_owned(),
                    policy: TokenPolicy {
                        issuer: iss.to_owned(),
                        service_id: service_id.to_owned(),
                        max_age_seconds: max_age,
                        skew_seconds: skew,
                    },
                    keys: KeySet::from_keys(keys),
                    key_info: info,
                })
            }
            _ => Err(errors),
        }
    }

    /// The values that apply, as JSON. A key shows its `kid`, its algorithm and its place.
    pub fn effective(&self) -> Value {
        let keys: Vec<Value> = self
            .key_info
            .iter()
            .map(|key| {
                json!({
                    "kid": key.kid,
                    "alg": key.algorithm.as_str(),
                    "source": format!("file:{}", key.source),
                })
            })
            .collect();
        json!({
            "token_header": self.token_header,
            "iss": self.policy.issuer,
            "service_id": self.policy.service_id,
            "max_age_seconds": self.policy.max_age_seconds,
            "skew_seconds": self.policy.skew_seconds,
            "keys": keys,
        })
    }
}

/// The text that a message shows for a PEM value. It shows the label only, never the body:
/// the text can be a private key by mistake.
fn pem_label(pem: &str) -> String {
    let first = pem.lines().next().unwrap_or("").trim();
    if first.starts_with("-----BEGIN ") && first.ends_with("-----") && first.len() <= 40 {
        format!("a PEM text with the line `{first}`")
    } else {
        "a text that is not a PEM text".to_owned()
    }
}

fn convert(report: Report, prefix: &str) -> Vec<ConfigError> {
    report
        .into_findings()
        .into_iter()
        .map(|finding| ConfigError {
            path: format!("{prefix}{}", finding.path),
            rule: finding.rule,
            message: finding.message,
        })
        .collect()
}

/// The rules for the name of the header: an HTTP field name, and not a forbidden one (9.4).
fn check_header_name(name: &str) -> Result<(), String> {
    let token_char = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.is_empty() || !name.chars().all(token_char) {
        return Err(format!(
            "Member `token_header`: expected an HTTP field name (letters, digits and `!#$%&'*+-.^_`|~`), found {}.",
            show(&json!(name))
        ));
    }
    if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "Member `token_header`: expected a header other than `Authorization`, `Proxy-Authorization` and `Cookie`, found {}.",
            show(&json!(name))
        ));
    }
    Ok(())
}

fn read_pem_keys(
    items: &[Value],
    keys: &mut Vec<PublicKey>,
    info: &mut Vec<KeyInfo>,
    add: &mut impl FnMut(&str, &'static str, String),
) {
    for (index, item) in items.iter().enumerate() {
        let path = format!("$.pem_keys[{index}]");
        let mut report = Report::new();
        let item_path = JsonPath::root().key("pem_keys").index(index);
        let Some(mut obj) = Obj::new(item, &item_path, "9.4", Unknown::Error, &mut report) else {
            for error in convert(report, "") {
                add(&error.path, error.rule, error.message);
            }
            continue;
        };
        let kid = obj.string_opt("kid", &mut report);
        let pem = obj.string("pem", &mut report);
        obj.finish(&mut report);
        for error in convert(report, "") {
            add(&error.path, error.rule, error.message);
        }
        if kid == Some("") {
            add(
                &format!("{path}.kid"),
                "9.4",
                "Member `kid`: expected a text that is not empty, found an empty text.".to_owned(),
            );
        }
        if let Some(pem) = pem {
            match PublicKey::from_spki_pem(pem, kid) {
                Ok(key) => {
                    info.push(KeyInfo {
                        kid: key.kid().map(str::to_owned),
                        algorithm: key.algorithm(),
                        source: format!("pem_keys[{index}]"),
                    });
                    keys.push(key);
                }
                Err(_) => add(
                    &format!("{path}.pem"),
                    "9.2",
                    format!(
                        "Member `pem`: expected a PEM public key (label PUBLIC KEY) for Ed25519 or P-256, found {}.",
                        pem_label(pem)
                    ),
                ),
            }
        }
    }
}

/// The rules for the `kid` of the whole set (9.4).
fn check_kids(info: &[KeyInfo], add: &mut impl FnMut(&str, &'static str, String)) {
    let mut seen: Vec<&str> = Vec::new();
    for key in info {
        if let Some(kid) = key.kid.as_deref() {
            if seen.contains(&kid) {
                add(
                    "$",
                    "9.4",
                    format!(
                        "The `kid` {} occurs more than one time in `{}`: expected a different `kid` for each key.",
                        show(&json!(kid)),
                        key.source
                    ),
                );
            }
            seen.push(kid);
        }
    }
    if info.len() > 1 {
        for key in info.iter().filter(|key| key.kid.is_none()) {
            add(
                "$",
                "9.4",
                format!(
                    "The set holds {} keys, and the key in `{}` has no `kid`: expected a `kid` for each key.",
                    info.len(),
                    key.source
                ),
            );
        }
    }
}
