//! The refusals of a PEP and their HTTP form (10.3).
//!
//! A [`Refusal`] says why the PEP does not let an operation run. The type
//! holds the cause for the logs of the service. The client never sees the
//! cause. The client sees only the status, the header `Retry-After` and a
//! fixed short body. The PEP never sends `context.reason` to the client.

use std::fmt;

use procurauth_core::authzen::Reason;
use serde_json::json;

use crate::reply::HttpReply;

/// Why the PEP refuses an identity token (9.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthFailure {
    /// The request has no header with the token.
    NoToken,
    /// The request has the header of the token more than one time.
    DuplicateHeader,
    /// The token fails a check of 9.4.
    Token {
        /// The name of the check, for example `signature` or `exp`.
        check: String,
        /// The paragraph of the protocol.
        rule: &'static str,
        /// The reason, for the log.
        detail: String,
    },
}

/// Why the PEP treats an answer of the PDP as a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenialCause {
    /// The PDP answered `false`.
    Decision,
    /// The PDP answered `true` to a question with `context.usage`, without
    /// `context.usage.units` (6.12).
    NoUsageUnits,
    /// The answer has a ceiling that the PEP cannot apply (7.5).
    UnknownCeiling(String),
}

/// Why the PEP cannot get a valid answer from the PDP (10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnavailableCause {
    /// The exchange with the PDP failed: no connection, a timeout or a lost answer.
    Transport(String),
    /// The PDP answered with an HTTP status other than 200.
    Status(u16),
    /// The answer is not a valid answer of the protocol.
    Answer(String),
    /// The metadata of the PDP is not valid.
    Metadata(String),
}

/// The reason that the PEP does not let an operation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No valid identity token: HTTP 401 (9.4).
    Unauthenticated(AuthFailure),
    /// A `false` answer without `budget_exceeded`, or an answer that the PEP
    /// treats as `false`: HTTP 403.
    Forbidden {
        /// The reason of the PDP. It is for the log. The client never gets it.
        reason: Option<Reason>,
        /// Why the PEP refuses.
        cause: DenialCause,
    },
    /// A `false` answer with `budget_exceeded`: HTTP 429 (10.3).
    RateLimited {
        /// The seconds to wait, a whole number from 1.
        retry_after: u64,
    },
    /// The PDP gave no valid answer: HTTP 503 (10.3).
    Unavailable(UnavailableCause),
    /// The service made a mistake, for example an operation with an action that the
    /// document does not declare: HTTP 500. The PEP sends no question.
    Internal(String),
}

impl Refusal {
    /// The HTTP status of the refusal (10.3).
    pub fn status(&self) -> u16 {
        match self {
            Self::Unauthenticated(_) => 401,
            Self::Forbidden { .. } => 403,
            Self::RateLimited { .. } => 429,
            Self::Unavailable(_) => 503,
            Self::Internal(_) => 500,
        }
    }

    /// The value of the header `Retry-After`, in seconds, for a 429.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
        }
    }

    /// A fixed word for the body of the refusal. It holds no value of the request.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::Unauthenticated(_) => "unauthorized",
            Self::Forbidden { .. } => "forbidden",
            Self::RateLimited { .. } => "rate_limited",
            Self::Unavailable(_) => "unavailable",
            Self::Internal(_) => "internal_error",
        }
    }

    /// The reply for a plain HTTP route (10.3). The body is a JSON object with
    /// one member, `error`, that holds a fixed word. A 429 has `Retry-After`.
    pub fn to_http(&self) -> HttpReply {
        let reply = HttpReply::json(self.status(), &json!({"error": self.public_message()}));
        match self.retry_after() {
            Some(seconds) => reply.with_header("Retry-After", seconds.to_string()),
            None => reply,
        }
    }
}

impl fmt::Display for Refusal {
    /// The text for the log of the service. Do not send it to a client.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated(AuthFailure::NoToken) => {
                write!(f, "401: the request has no identity token")
            }
            Self::Unauthenticated(AuthFailure::DuplicateHeader) => {
                write!(
                    f,
                    "401: the header of the identity token occurs more than one time"
                )
            }
            Self::Unauthenticated(AuthFailure::Token {
                check,
                rule,
                detail,
            }) => write!(
                f,
                "401: the token fails the check `{check}` (rule {rule}): {detail}"
            ),
            Self::Forbidden { reason, cause } => {
                let reason = reason.as_ref().map_or("none", Reason::as_str);
                match cause {
                    DenialCause::Decision => {
                        write!(f, "403: the PDP answered false (reason: {reason})")
                    }
                    DenialCause::NoUsageUnits => write!(
                        f,
                        "403: the PDP answered true without `context.usage.units` (6.12)"
                    ),
                    DenialCause::UnknownCeiling(name) => write!(
                        f,
                        "403: the answer has the ceiling `{name}`, which the PEP cannot apply (7.5)"
                    ),
                }
            }
            Self::RateLimited { retry_after } => {
                write!(f, "429: the budget is spent, retry after {retry_after} s")
            }
            Self::Unavailable(cause) => match cause {
                UnavailableCause::Transport(text) => {
                    write!(f, "503: the exchange with the PDP failed: {text}")
                }
                UnavailableCause::Status(code) => {
                    write!(f, "503: the PDP answered with the HTTP status {code}")
                }
                UnavailableCause::Answer(text) => {
                    write!(f, "503: the answer of the PDP is not valid: {text}")
                }
                UnavailableCause::Metadata(text) => {
                    write!(f, "503: the metadata of the PDP is not valid: {text}")
                }
            },
            Self::Internal(text) => write!(f, "500: {text}"),
        }
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;

    fn forbidden(reason: Option<Reason>) -> Refusal {
        Refusal::Forbidden {
            reason,
            cause: DenialCause::Decision,
        }
    }

    #[test]
    fn p_10_3_the_status_of_each_refusal() {
        assert_eq!(Refusal::Unauthenticated(AuthFailure::NoToken).status(), 401);
        assert_eq!(forbidden(None).status(), 403);
        assert_eq!(Refusal::RateLimited { retry_after: 12 }.status(), 429);
        assert_eq!(
            Refusal::Unavailable(UnavailableCause::Status(500)).status(),
            503
        );
        assert_eq!(Refusal::Internal("x".into()).status(), 500);
    }

    #[test]
    fn p_10_3_a_429_has_the_header_retry_after() {
        let reply = Refusal::RateLimited { retry_after: 12 }.to_http();
        assert_eq!(reply.status, 429);
        assert_eq!(reply.header("Retry-After"), Some("12"));
        let other = forbidden(None).to_http();
        assert_eq!(other.header("Retry-After"), None);
    }

    #[test]
    fn p_10_3_the_body_never_holds_the_reason() {
        for reason in [
            Reason::UnknownSubject,
            Reason::InvalidResource,
            Reason::InvalidRequest,
            Reason::Other("other_reason".into()),
        ] {
            let text = reason.as_str().to_owned();
            let reply = forbidden(Some(reason)).to_http();
            let body = String::from_utf8(reply.body).unwrap();
            assert!(!body.contains(&text), "{body}");
            assert_eq!(body, r#"{"error":"forbidden"}"#);
        }
        let reply = Refusal::RateLimited { retry_after: 3 }.to_http();
        assert!(
            !String::from_utf8(reply.body)
                .unwrap()
                .contains("budget_exceeded")
        );
    }

    #[test]
    fn the_log_text_names_the_cause() {
        let text = forbidden(Some(Reason::UnknownSubject)).to_string();
        assert!(text.contains("unknown_subject"), "{text}");
    }
}
