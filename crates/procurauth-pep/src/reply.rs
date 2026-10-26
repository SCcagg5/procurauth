//! A transport-independent HTTP reply.
//!
//! The library never writes to a socket for a client. It gives the status,
//! the headers and the body, and the application sends them.

/// The status, the headers and the body of a reply to a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// The HTTP status code.
    pub status: u16,
    /// The headers, as name and value pairs. The names have no fixed case.
    pub headers: Vec<(String, String)>,
    /// The body. It can be empty.
    pub body: Vec<u8>,
}

impl HttpReply {
    /// A reply with no header and no body.
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A reply with a JSON body and the `Content-Type` of JSON.
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.to_string().into_bytes(),
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// The value of the first header with this name. The match ignores case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_is_found_without_case() {
        let reply = HttpReply::empty(429).with_header("Retry-After", "12");
        assert_eq!(reply.header("retry-after"), Some("12"));
        assert_eq!(reply.header("x"), None);
        assert!(reply.body.is_empty());
    }

    #[test]
    fn a_json_reply_has_a_content_type() {
        let reply = HttpReply::json(200, &serde_json::json!({"a": 1}));
        assert_eq!(reply.header("content-type"), Some("application/json"));
        assert_eq!(reply.body, br#"{"a":1}"#);
    }
}
