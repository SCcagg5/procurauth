//! The edge: it decides each request, and it makes the request for the service.
//!
//! For each request the edge does these jobs, in this order.
//!
//! 1. It reads the text of the key from `Authorization: Bearer` (1.4).
//! 2. It checks the form of the text with the key format (3.8). It finds the key by
//!    the SHA-256 digest of the text in the keys file.
//! 3. It asks the PDP for the action `access` on the service for the subject of the key (8.3).
//! 4. It makes an identity token for the subject, or it takes a kept one (9.9).
//! 5. It removes the text of the key and each copy of the token header that the client sent.
//!    It sets its own token, and it sends the request to the service (9.1).
//!
//! Each refusal is HTTP 401 with `WWW-Authenticate: Bearer` and an empty body (9.8, MCP 6.1).
//! The header has `error="invalid_token"` when the request has the text of a key. The edge
//! never redirects, and it never answers 400, 404 or 405 by itself for a request that it can
//! read (MCP 6.2). The edge decides on the head of the request alone. It reads the body only
//! for a request that it accepts.
//!
//! The reason of a refusal goes to the log only. Three keys get the same answer. These are a key
//! that is not good, a key that the edge does not know, and a key without `access`.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use procurauth_core::key_format::KeyFormat;
use procurauth_pep::access::{Access, AccessGate};
use procurauth_pep::clock::Clock;
use procurauth_pep::config::ConfigError;
use procurauth_pep::refusal::UnavailableCause;
use procurauth_pep::reply::HttpReply;
use procurauth_pep::transport::PdpTransport;

use crate::config::Settings;
use crate::keys::KeyStore;
use crate::proxy::{Forward, Upstream, request_headers};
use crate::token::{Signer, TokenCache};

/// Why the edge refuses a request. It is for the log. The client never gets it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The request has no header `Authorization`.
    NoAuthorization,
    /// The header `Authorization` has another scheme than `Bearer`, or no text.
    NotBearer,
    /// The request has more than one header `Authorization`.
    ManyAuthorization,
    /// The text does not follow the key format (3.8).
    BadFormat(&'static str),
    /// The edge does not know the text.
    UnknownKey,
    /// The PDP gave `false` for `access` (8.3).
    NoAccess,
    /// The PDP gave no valid answer (the edge cannot decide).
    PdpUnavailable(String),
}

impl Cause {
    /// A short fixed text for the log.
    pub fn label(&self) -> String {
        match self {
            Self::NoAuthorization => "no_authorization".to_owned(),
            Self::NotBearer => "not_bearer".to_owned(),
            Self::ManyAuthorization => "many_authorization".to_owned(),
            Self::BadFormat(cause) => format!("bad_format:{cause}"),
            Self::UnknownKey => "unknown_key".to_owned(),
            Self::NoAccess => "no_access".to_owned(),
            Self::PdpUnavailable(text) => format!("pdp_unavailable:{text}"),
        }
    }
}

/// The decision of the edge for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Send the request to the service, with this identity token.
    Forward {
        /// The identity token.
        token: String,
        /// The subject id, for the log.
        subject: String,
    },
    /// Refuse the request with this reply.
    Refuse {
        /// The reply.
        reply: HttpReply,
        /// The cause, for the log.
        cause: Cause,
    },
}

/// The edge: its rules and its state.
pub struct Edge {
    service_id: String,
    token_header: String,
    format: KeyFormat,
    keys: KeyStore,
    gate: AccessGate,
    signer: Signer,
    cache: Mutex<TokenCache>,
    clock: Arc<dyn Clock>,
    upstream: Upstream,
    log: Mutex<Box<dyn Write + Send>>,
}

impl std::fmt::Debug for Edge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Edge")
            .field("service_id", &self.service_id)
            .field("token_header", &self.token_header)
            .finish_non_exhaustive()
    }
}

/// The reply for a request that has no key text: `WWW-Authenticate: Bearer` (9.8).
pub fn no_key_reply() -> HttpReply {
    HttpReply::empty(401).with_header("WWW-Authenticate", "Bearer")
}

/// The reply for a request that has the text of a key that the edge refuses (9.8).
/// The header has no `resource_metadata` (MCP 6.3).
pub fn invalid_key_reply() -> HttpReply {
    HttpReply::empty(401).with_header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
}

impl Edge {
    /// Build the edge from the settings. The transport is the link to the PDP.
    ///
    /// # Errors
    /// Returns every error of the link to the PDP.
    pub fn new(
        settings: Settings,
        transport: Arc<dyn PdpTransport>,
        clock: Arc<dyn Clock>,
        log: Box<dyn Write + Send>,
    ) -> Result<Self, Vec<ConfigError>> {
        let gate = AccessGate::new(
            &settings.service_id,
            &settings.pdp,
            transport,
            Arc::clone(&clock),
        )?;
        let life = settings.token_life_seconds;
        // The edge gives a kept token again until a quarter of its life remains.
        let margin = life / 4;
        Ok(Self {
            service_id: settings.service_id,
            token_header: settings.token_header,
            format: settings.key_format,
            keys: settings.keys,
            gate,
            signer: Signer::new(
                settings.signing_key,
                settings.signing_kid,
                settings.issuer,
                life,
            ),
            cache: Mutex::new(TokenCache::new(settings.token_cache_max_entries, margin)),
            clock,
            upstream: settings.upstream,
            log: Mutex::new(log),
        })
    }

    /// The service behind the edge.
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// The id of the service.
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// The number of kept tokens now (9.9).
    pub fn kept_tokens(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Write one line to the log: the method, the path and the status, and the cause of a
    /// refusal. The line never has a header, a query or a body.
    pub fn log_line(&self, method: &str, path: &str, status: u16, note: &str) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let line = if note.is_empty() {
            format!("{method} {path} {status}\n")
        } else {
            format!("{method} {path} {status} ({note})\n")
        };
        let _ = log.write_all(line.as_bytes());
        let _ = log.flush();
    }

    fn refuse(cause: Cause) -> Verdict {
        let reply = match &cause {
            Cause::NoAuthorization | Cause::NotBearer => no_key_reply(),
            Cause::PdpUnavailable(_) => HttpReply::empty(503),
            Cause::ManyAuthorization
            | Cause::BadFormat(_)
            | Cause::UnknownKey
            | Cause::NoAccess => invalid_key_reply(),
        };
        Verdict::Refuse { reply, cause }
    }

    /// Decide a request from its headers (8.3, 9.8).
    pub fn decide(&self, headers: &[(String, String)]) -> Verdict {
        let mut values = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str());
        let Some(first) = values.next() else {
            return Self::refuse(Cause::NoAuthorization);
        };
        if values.next().is_some() {
            return Self::refuse(Cause::ManyAuthorization);
        }
        let Some(text) = bearer_text(first) else {
            return Self::refuse(Cause::NotBearer);
        };
        if let Err(error) = self.format.check(text) {
            return Self::refuse(Cause::BadFormat(error.cause()));
        }
        let Some(entry) = self.keys.find(text) else {
            return Self::refuse(Cause::UnknownKey);
        };
        match self.gate.check(&entry.subject) {
            Ok(Access::Granted) => {}
            Ok(Access::Denied(_)) => return Self::refuse(Cause::NoAccess),
            Err(cause) => return Self::refuse(Cause::PdpUnavailable(unavailable_label(&cause))),
        }
        let now = self.clock.now_seconds();
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(kept) = cache.get(&entry.subject, &self.service_id, now) {
            return Verdict::Forward {
                token: kept.token.clone(),
                subject: entry.subject.clone(),
            };
        }
        let made = self.signer.make(
            &entry.subject,
            entry.owner.as_deref(),
            &self.service_id,
            now,
        );
        cache.put(&entry.subject, &self.service_id, &made, now);
        Verdict::Forward {
            token: made.token,
            subject: entry.subject.clone(),
        }
    }

    /// The request for the service (9.1). The edge removes the text of the key and each copy of
    /// the token header that the client sent, and it sets its own token.
    pub fn forward_request(
        &self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        token: &str,
    ) -> Forward {
        Forward {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: request_headers(headers, &self.token_header, token),
            body,
        }
    }
}

/// The text of a key in a header `Authorization` with the scheme `Bearer`. The scheme has no case
/// (RFC 9110, 11.1). The function returns `None` for another scheme and for a header with no text.
fn bearer_text(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let text = rest.trim_matches(' ');
    (!text.is_empty()).then_some(text)
}

fn unavailable_label(cause: &UnavailableCause) -> String {
    match cause {
        UnavailableCause::Transport(text) => format!("transport, {text}"),
        UnavailableCause::Status(code) => format!("status {code}"),
        UnavailableCause::Answer(text) => format!("answer, {text}"),
        UnavailableCause::Metadata(text) => format!("metadata, {text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_9_8_the_scheme_has_no_case_and_a_header_without_a_text_has_no_key() {
        assert_eq!(bearer_text("Bearer abc"), Some("abc"));
        assert_eq!(bearer_text("bearer abc"), Some("abc"));
        assert_eq!(bearer_text("BEARER  abc "), Some("abc"));
        assert_eq!(bearer_text("Bearer"), None);
        assert_eq!(bearer_text("Bearer  "), None);
        assert_eq!(bearer_text("Basic abc"), None);
        assert_eq!(bearer_text("abc"), None);
    }

    #[test]
    fn p_9_8_the_two_refusals_have_the_headers_of_the_text() {
        let none = no_key_reply();
        assert_eq!(none.status, 401);
        assert_eq!(none.header("www-authenticate"), Some("Bearer"));
        assert!(none.body.is_empty());
        let invalid = invalid_key_reply();
        assert_eq!(invalid.status, 401);
        assert_eq!(
            invalid.header("www-authenticate"),
            Some("Bearer error=\"invalid_token\"")
        );
        assert!(invalid.body.is_empty());
        assert!(
            !invalid
                .header("www-authenticate")
                .unwrap()
                .contains("resource_metadata")
        );
    }
}
