//! The link to the PDP: the trait that an application can implement.
//!
//! The PEP talks to the PDP through a [`PdpTransport`]. The library gives
//! [`crate::http_client::HttpTransport`], a synchronous HTTP/1.1 client for `http`
//! URLs. A deployment needs TLS (10.0, step 4). This library has no TLS code.
//! An application that needs TLS implements this trait with its own TLS client.
//!
//! The transport tells the PEP how an exchange failed. The kind of failure
//! decides if the PEP may send a question with `context.usage` again (10.6).

use std::fmt;
use std::time::Duration;

/// An answer of the PDP at the level of HTTP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The headers, as name and value pairs.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// Why an exchange with the PDP failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The request did not leave the PEP: no connection, or no free connection.
    /// The PDP cannot have seen the request, so the PEP can send it again (10.6).
    NotSent(String),
    /// The PEP wrote the request and the time ran out before the answer was complete.
    Timeout,
    /// The PEP wrote the request, or a part of it, and the connection failed.
    /// The PDP can have counted the units (10.6).
    Lost(String),
    /// The answer is not a valid HTTP/1.1 answer.
    Malformed(String),
    /// The answer is larger than the bound.
    TooLarge,
    /// The transport does not support the scheme of the URL, for example `https`.
    Unsupported(String),
}

impl TransportError {
    /// True when the PEP can send a question with `context.usage` again (10.6).
    /// This is true only when the request did not leave the PEP.
    pub fn request_was_not_sent(&self) -> bool {
        matches!(self, Self::NotSent(_))
    }

    /// True when a question without `context.usage` can go again after this
    /// failure on a connection that the PEP reused.
    pub fn can_repeat_plain_question(&self) -> bool {
        matches!(self, Self::NotSent(_) | Self::Lost(_))
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSent(text) => write!(f, "the request was not sent: {text}"),
            Self::Timeout => f.write_str("the time ran out before the answer was complete"),
            Self::Lost(text) => write!(f, "the connection failed after the request: {text}"),
            Self::Malformed(text) => write!(f, "the answer is not valid HTTP: {text}"),
            Self::TooLarge => f.write_str("the answer is larger than the bound"),
            Self::Unsupported(text) => write!(f, "the transport cannot use this URL: {text}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The exchange of one HTTP request and one answer with the PDP.
///
/// An implementation keeps its connections open between requests (10.7). It
/// follows no redirect. It gives the body as bytes, and the PEP reads the JSON.
/// The URL is absolute and its origin is the origin of the PDP.
pub trait PdpTransport: Send + Sync {
    /// True when the transport can use URLs with this scheme, `http` or `https`.
    /// The PEP asks at start, and it stops when a secured link needs `https`.
    fn supports_scheme(&self, scheme: &str) -> bool;

    /// Send a POST request with a JSON body, and read the whole answer.
    /// The `timeout` bounds the whole exchange, from the first byte written.
    ///
    /// # Errors
    /// Returns the kind of failure. See [`TransportError`].
    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError>;

    /// Send a GET request and read the whole answer.
    ///
    /// # Errors
    /// Returns the kind of failure. See [`TransportError`].
    fn get_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError>;

    /// Tell the transport the longest idle time of a connection (10.7). The PEP
    /// calls this when it knows the idle time that the PDP publishes. The
    /// default does nothing.
    fn set_idle_close(&self, _idle_close_after: Duration) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_10_6_only_an_unsent_request_can_go_again_with_usage() {
        assert!(TransportError::NotSent("x".into()).request_was_not_sent());
        assert!(!TransportError::Timeout.request_was_not_sent());
        assert!(!TransportError::Lost("x".into()).request_was_not_sent());
        assert!(!TransportError::Malformed("x".into()).request_was_not_sent());
        assert!(!TransportError::TooLarge.request_was_not_sent());
    }

    #[test]
    fn a_plain_question_can_go_again_after_a_lost_connection_but_not_a_timeout() {
        assert!(TransportError::Lost("x".into()).can_repeat_plain_question());
        assert!(TransportError::NotSent("x".into()).can_repeat_plain_question());
        assert!(!TransportError::Timeout.can_repeat_plain_question());
    }
}
