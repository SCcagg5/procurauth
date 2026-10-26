//! The typed configuration of the PEP.
//!
//! The application reads its own configuration file, one time at start, and
//! builds a [`PepConfig`]. The library reads no file and no environment
//! variable. [`PepConfig::check`] finds every error, and it never changes a
//! value to make it fit. Each error names the key, the expected value and the
//! value found. No error holds the credential of the PDP.
//!
//! # Defaults
//!
//! | Key | Default |
//! | --- | --- |
//! | `pdp.allow_insecure_pdp_link` | `false` |
//! | `pdp.request_timeout` | 5 seconds |
//! | `pdp.usage_wait_margin` | 1 second |
//! | `pdp.idle_close_after` | 5 seconds |
//! | `pdp.max_connections` | 4 |
//! | `pdp.evaluations_max_bytes` | 32768 |
//! | `pdp.evaluations_max_items` | 50 |
//! | `pdp.max_response_bytes` | 1048576 |
//! | `pdp.plain_retries` | 1 |
//! | `pdp.metadata_max_age` | 3600 seconds |
//! | `cache_ttl` | 0 (no kept answer) |
//! | `cache_max_entries` | 10000 |
//! | `display_max_questions` | 50 |

use std::fmt;
use std::time::Duration;

use procurauth_core::jws::KeySet;
use procurauth_core::names::validate_id;

use crate::url::{Scheme, Url};

/// A secret text, for example the credential of the PDP. It never shows in a
/// debug text or in an error.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// A secret from its text.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The text of the secret. Use it only to build a header for the PDP.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<hidden>)")
    }
}

/// One error of the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// The key, for example `pdp.url`.
    pub key: String,
    /// The expected type or range.
    pub expected: String,
    /// The value found. It is never a secret.
    pub found: String,
}

impl ConfigError {
    fn new(key: &str, expected: &str, found: impl Into<String>) -> Self {
        Self {
            key: key.to_owned(),
            expected: expected.to_owned(),
            found: found.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Key `{}`: expected {}, found {}.",
            self.key, self.expected, self.found
        )
    }
}

impl std::error::Error for ConfigError {}

/// The link to the PDP (10.0, step 4; 10.7; 10.7a).
#[derive(Clone, Debug)]
pub struct PdpConfig {
    /// The URL of the PDP. The PEP reads the metadata at
    /// `/.well-known/authzen-configuration` below this origin.
    pub url: String,
    /// The credential of the service for the PDP. The PEP sends it in
    /// `Authorization: Bearer` (10.0, step 4).
    pub credential: Secret,
    /// True to accept an `http` URL. The default is `false`: the link must be
    /// secured, and a secured link has an `https` URL. Set it for a test on
    /// the loopback address, or for a link that another layer secures.
    pub allow_insecure_pdp_link: bool,
    /// The longest wait for an answer to a question without `context.usage`.
    pub request_timeout: Duration,
    /// The time that the PEP adds to `procurauth_usage_max_seconds` for a
    /// question with `context.usage` (10.6). The PEP waits at least as long as
    /// `request_timeout`.
    pub usage_wait_margin: Duration,
    /// The longest idle time of a connection. The PEP also closes an idle
    /// connection after half of `procurauth_idle_max_seconds` (10.7). The lower value
    /// applies.
    pub idle_close_after: Duration,
    /// The most connections to the PDP at one time (10.7).
    pub max_connections: usize,
    /// The largest body of one Access Evaluations request, until the metadata
    /// gives `procurauth_evaluations_max_bytes` (10.7a). The lower value applies.
    pub evaluations_max_bytes: u64,
    /// The most items of one Access Evaluations request, until the metadata
    /// gives `procurauth_evaluations_max_items` (10.7a). The lower value applies.
    pub evaluations_max_items: u64,
    /// The largest answer that the PEP reads, in bytes.
    pub max_response_bytes: u64,
    /// How many times the PEP asks again a question without `context.usage`
    /// after a lost connection. A question with `context.usage` is never asked
    /// again after an error, except when the request was not sent (10.6).
    pub plain_retries: u32,
    /// The longest age of the metadata. After this age the PEP reads it again.
    pub metadata_max_age: Duration,
}

impl PdpConfig {
    /// A link with the documented defaults.
    pub fn new(url: impl Into<String>, credential: Secret) -> Self {
        Self {
            url: url.into(),
            credential,
            allow_insecure_pdp_link: false,
            request_timeout: Duration::from_secs(5),
            usage_wait_margin: Duration::from_secs(1),
            idle_close_after: Duration::from_secs(5),
            max_connections: 4,
            evaluations_max_bytes: 32 * 1024,
            evaluations_max_items: 50,
            max_response_bytes: 1024 * 1024,
            plain_retries: 1,
            metadata_max_age: Duration::from_secs(3600),
        }
    }
}

/// The configuration of a PEP (9.4, 10.0, 10.1).
#[derive(Debug)]
pub struct PepConfig {
    /// The id of the service. It is the `aud` of the tokens and the member
    /// `server` of the action document (5.2).
    pub service_id: String,
    /// The name of the header with the identity token (9.4). It is never
    /// `Authorization`, `Proxy-Authorization` or `Cookie`.
    pub token_header: String,
    /// The value of the claim `iss` (9.4).
    pub issuer: String,
    /// The public keys of the edge (9.4).
    pub trusted_keys: KeySet,
    /// The longest life of a token, `exp` minus `iat`, in seconds (9.4).
    pub max_token_age_seconds: u64,
    /// The clock skew, in seconds. It applies to `iat` and to `exp` (9.4).
    pub clock_skew_seconds: u64,
    /// The link to the PDP.
    pub pdp: PdpConfig,
    /// The longest life of a kept answer (10.1). Zero keeps no answer.
    pub cache_ttl: Duration,
    /// The most kept answers (10.1b). The bound does not depend on the clients.
    pub cache_max_entries: usize,
    /// The most questions that one request to the options route asks (5.6).
    pub display_max_questions: usize,
}

const FORBIDDEN_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

impl PepConfig {
    /// A configuration with the documented defaults for the keys that the
    /// arguments do not name.
    pub fn new(
        service_id: impl Into<String>,
        token_header: impl Into<String>,
        issuer: impl Into<String>,
        trusted_keys: KeySet,
        max_token_age_seconds: u64,
        clock_skew_seconds: u64,
        pdp: PdpConfig,
    ) -> Self {
        Self {
            service_id: service_id.into(),
            token_header: token_header.into(),
            issuer: issuer.into(),
            trusted_keys,
            max_token_age_seconds,
            clock_skew_seconds,
            pdp,
            cache_ttl: Duration::ZERO,
            cache_max_entries: 10_000,
            display_max_questions: 50,
        }
    }

    /// Check every key. The function returns all the errors, and it changes
    /// nothing.
    ///
    /// # Errors
    /// Returns one error for each key with a bad value, and one error for each
    /// pair of keys that contradict each other.
    pub fn check(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();
        if let Err(error) = validate_id(&self.service_id) {
            errors.push(ConfigError::new(
                "service_id",
                &format!("an id of 1 to 256 bytes with no control character ({error})"),
                format!("{:?}", self.service_id),
            ));
        }
        let header = self.token_header.as_str();
        if header.is_empty() || !header.bytes().all(is_token_char) {
            errors.push(ConfigError::new(
                "token_header",
                "an HTTP header name with 1 or more token characters",
                format!("{header:?}"),
            ));
        } else if FORBIDDEN_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
            errors.push(ConfigError::new(
                "token_header",
                "a header other than `Authorization`, `Proxy-Authorization` and `Cookie` (9.4)",
                format!("{header:?}"),
            ));
        }
        if self.issuer.is_empty() {
            errors.push(ConfigError::new(
                "issuer",
                "a text that is not empty",
                "\"\"",
            ));
        }
        if self.trusted_keys.is_empty() {
            errors.push(ConfigError::new(
                "trusted_keys",
                "at least one public key (9.4)",
                "no key",
            ));
        }
        if self.max_token_age_seconds == 0 {
            errors.push(ConfigError::new(
                "max_token_age_seconds",
                "a whole number of 1 or more",
                "0",
            ));
        }
        self.check_pdp(&mut errors);
        if !self.cache_ttl.is_zero() && self.cache_max_entries == 0 {
            errors.push(ConfigError::new(
                "cache_max_entries",
                "a whole number of 1 or more, because `cache_ttl` is not zero (contradiction)",
                "0",
            ));
        }
        if self.display_max_questions == 0 {
            errors.push(ConfigError::new(
                "display_max_questions",
                "a whole number of 1 or more",
                "0",
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn check_pdp(&self, errors: &mut Vec<ConfigError>) {
        let pdp = &self.pdp;
        match Url::parse(&pdp.url) {
            Err(error) => errors.push(ConfigError::new(
                "pdp.url",
                "an absolute `https` URL, or an `http` URL with `pdp.allow_insecure_pdp_link`",
                if pdp.url.contains('@') {
                    format!("a URL with user information (the value stays hidden): {error}")
                } else {
                    format!("{:?} ({error})", pdp.url)
                },
            )),
            Ok(url) => {
                if url.scheme == Scheme::Http && !pdp.allow_insecure_pdp_link {
                    errors.push(ConfigError::new(
                        "pdp.url",
                        "an `https` URL, because the link to the PDP must be secured (10.0, step 4) and `pdp.allow_insecure_pdp_link` is false",
                        format!("{:?}", pdp.url),
                    ));
                }
            }
        }
        let credential = pdp.credential.expose();
        if credential.is_empty() {
            errors.push(ConfigError::new(
                "pdp.credential",
                "a text that is not empty",
                "an empty text",
            ));
        } else if credential.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
            errors.push(ConfigError::new(
                "pdp.credential",
                "visible ASCII characters only, with no space",
                "a value with another character (the value stays hidden)",
            ));
        }
        for (key, value) in [
            ("pdp.request_timeout", pdp.request_timeout),
            ("pdp.idle_close_after", pdp.idle_close_after),
            ("pdp.metadata_max_age", pdp.metadata_max_age),
        ] {
            if value.is_zero() {
                errors.push(ConfigError::new(key, "a duration of more than 0", "0"));
            }
        }
        if pdp.max_connections == 0 {
            errors.push(ConfigError::new(
                "pdp.max_connections",
                "a whole number of 1 or more",
                "0",
            ));
        }
        for (key, value) in [
            ("pdp.evaluations_max_bytes", pdp.evaluations_max_bytes),
            ("pdp.evaluations_max_items", pdp.evaluations_max_items),
            ("pdp.max_response_bytes", pdp.max_response_bytes),
        ] {
            if value == 0 {
                errors.push(ConfigError::new(key, "a whole number of 1 or more", "0"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_core::jws::SigningKey;

    fn keys() -> KeySet {
        KeySet::from_keys(vec![
            SigningKey::from_ed25519_seed(&[7; 32]).public_key(None),
        ])
    }

    fn good() -> PepConfig {
        let mut pdp = PdpConfig::new("https://pdp.example", Secret::new("s3cret-credential"));
        pdp.max_connections = 2;
        PepConfig::new(
            "datastore",
            "X-Identity-Token",
            "https://edge.example",
            keys(),
            300,
            30,
            pdp,
        )
    }

    fn keys_of(errors: &[ConfigError]) -> Vec<&str> {
        errors.iter().map(|e| e.key.as_str()).collect()
    }

    #[test]
    fn a_good_configuration_has_no_error() {
        assert!(good().check().is_ok());
    }

    #[test]
    fn p_10_0_an_http_url_needs_the_explicit_flag() {
        let mut config = good();
        config.pdp.url = "http://127.0.0.1:8181".into();
        let errors = config.check().unwrap_err();
        assert_eq!(keys_of(&errors), ["pdp.url"]);
        assert!(errors[0].to_string().contains("secured"), "{}", errors[0]);
        config.pdp.allow_insecure_pdp_link = true;
        assert!(config.check().is_ok());
    }

    #[test]
    fn p_9_4_the_token_header_is_not_authorization_or_cookie() {
        for name in ["Authorization", "cookie", "Proxy-Authorization"] {
            let mut config = good();
            config.token_header = name.into();
            assert_eq!(
                keys_of(&config.check().unwrap_err()),
                ["token_header"],
                "{name}"
            );
        }
        let mut config = good();
        config.token_header = "X Bad".into();
        assert_eq!(keys_of(&config.check().unwrap_err()), ["token_header"]);
    }

    #[test]
    fn each_error_names_the_key_the_expected_value_and_the_value() {
        let mut config = good();
        config.max_token_age_seconds = 0;
        let error = &config.check().unwrap_err()[0];
        assert_eq!(error.key, "max_token_age_seconds");
        assert_eq!(
            error.to_string(),
            "Key `max_token_age_seconds`: expected a whole number of 1 or more, found 0."
        );
    }

    #[test]
    fn the_check_returns_every_error() {
        let mut config = good();
        config.service_id = String::new();
        config.issuer = String::new();
        config.trusted_keys = KeySet::default();
        config.pdp.max_connections = 0;
        let errors = config.check().unwrap_err();
        assert_eq!(
            keys_of(&errors),
            [
                "service_id",
                "issuer",
                "trusted_keys",
                "pdp.max_connections"
            ]
        );
    }

    #[test]
    fn a_cache_with_no_room_contradicts_its_ttl() {
        let mut config = good();
        config.cache_ttl = Duration::from_secs(5);
        config.cache_max_entries = 0;
        assert_eq!(keys_of(&config.check().unwrap_err()), ["cache_max_entries"]);
    }

    #[test]
    fn no_error_and_no_debug_text_holds_the_credential() {
        let mut config = good();
        config.pdp.credential = Secret::new("bad credential with space");
        let errors = config.check().unwrap_err();
        let text = format!("{errors:?} {config:?}");
        assert!(!text.contains("bad credential"), "{text}");
        assert!(!text.contains("s3cret"), "{text}");
        assert_eq!(format!("{:?}", Secret::new("abc")), "Secret(<hidden>)");
    }

    #[test]
    fn a_zero_duration_is_an_error() {
        let mut config = good();
        config.pdp.request_timeout = Duration::ZERO;
        assert_eq!(
            keys_of(&config.check().unwrap_err()),
            ["pdp.request_timeout"]
        );
    }
}
