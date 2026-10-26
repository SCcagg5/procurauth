//! A small parser for the URL of the PDP.
//!
//! The PEP needs only the scheme, the host, the port and the path of an
//! `http` or `https` URL. The parser refuses user information, a query and a
//! fragment. It never follows a redirect.

use std::fmt;

/// The scheme of a URL that the PEP uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http`: no TLS.
    Http,
    /// `https`: with TLS.
    Https,
}

impl Scheme {
    /// The word of the scheme.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// The default port of the scheme.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A parsed `http` or `https` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// The scheme.
    pub scheme: Scheme,
    /// The host in lower case, with no brackets.
    pub host: String,
    /// The port. It is the default port of the scheme when the text has none.
    pub port: u16,
    /// The path. It is empty or it starts with `/`.
    pub path: String,
}

/// Why a text is not a URL that the PEP accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlError(String);

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UrlError {}

fn bad(text: &str) -> UrlError {
    UrlError(text.to_owned())
}

impl Url {
    /// Read a URL.
    ///
    /// # Errors
    /// Returns an error when the text is not an absolute `http` or `https` URL
    /// with a host. Returns an error when it has user information, a query or a
    /// fragment.
    pub fn parse(text: &str) -> Result<Self, UrlError> {
        let (scheme, rest) = if let Some(rest) = text.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err(bad("the scheme is not `http` or `https`"));
        };
        if text.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
            return Err(bad(
                "the text has a space, a control character or a byte above 126",
            ));
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(bad("the URL has user information"));
        }
        if path.contains('?') || path.contains('#') || authority.contains(['?', '#']) {
            return Err(bad("the URL has a query or a fragment"));
        }
        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (host, after) = inner
                .split_once(']')
                .ok_or_else(|| bad("the IPv6 host has no closing bracket"))?;
            let port = match after {
                "" => None,
                other => Some(
                    other
                        .strip_prefix(':')
                        .ok_or_else(|| bad("the text after the IPv6 host is not a port"))?,
                ),
            };
            (host, port)
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err(bad("the URL has no host"));
        }
        if host.contains(['[', ']', ':']) && !authority.starts_with('[') {
            return Err(bad("the host has a character that it must not have"));
        }
        let port = match port {
            None => scheme.default_port(),
            Some(text) => {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad("the port is not a whole number"));
                }
                match text.parse::<u16>() {
                    Ok(0) | Err(_) => return Err(bad("the port is not a number from 1 to 65535")),
                    Ok(port) => port,
                }
            }
        };
        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            path: path.to_owned(),
        })
    }

    /// The host and the port, for a socket address and for the header `Host`.
    /// The port shows only when it is not the default port of the scheme.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The host and the port for a connection, for example `127.0.0.1:8181`.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The text of the URL without a slash at its end, for example `http://127.0.0.1:8181`.
    pub fn base_text(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.host_header(),
            self.path.trim_end_matches('/')
        )
    }

    /// True when the other URL has the same scheme, host and port.
    pub fn same_origin(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }

    /// A URL with the same origin and this path.
    #[must_use]
    pub fn with_path(&self, path: &str) -> Self {
        Self {
            path: path.to_owned(),
            ..self.clone()
        }
    }

    /// The URL as text, with the path.
    pub fn to_text(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.host_header(),
            self.path
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_has_a_scheme_a_host_a_port_and_a_path() {
        let url = Url::parse("http://127.0.0.1:8181/pdp").unwrap();
        assert_eq!(url.scheme, Scheme::Http);
        assert_eq!(url.host, "127.0.0.1");
        assert_eq!(url.port, 8181);
        assert_eq!(url.path, "/pdp");
        assert_eq!(url.authority(), "127.0.0.1:8181");
        assert_eq!(url.host_header(), "127.0.0.1:8181");
        assert_eq!(url.base_text(), "http://127.0.0.1:8181/pdp");
    }

    #[test]
    fn the_default_port_does_not_show_in_the_host_header() {
        let url = Url::parse("https://Pdp.Example/").unwrap();
        assert_eq!(url.host, "pdp.example");
        assert_eq!(url.port, 443);
        assert_eq!(url.host_header(), "pdp.example");
        assert_eq!(url.base_text(), "https://pdp.example");
    }

    #[test]
    fn an_ipv6_host_has_brackets_in_the_header() {
        let url = Url::parse("http://[::1]:9000").unwrap();
        assert_eq!(url.host, "::1");
        assert_eq!(url.host_header(), "[::1]:9000");
        assert_eq!(url.authority(), "[::1]:9000");
    }

    #[test]
    fn a_bad_url_is_refused() {
        for text in [
            "",
            "ftp://x",
            "http://",
            "http://:80",
            "http://a@b",
            "http://a?x=1",
            "http://a/b#c",
            "http://a:0",
            "http://a:99999",
            "http://a:x",
            "http://a b",
            "http://a:1:2",
            "http://[::1",
        ] {
            assert!(Url::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn the_origin_ignores_the_path() {
        let a = Url::parse("http://h:1/a").unwrap();
        let b = Url::parse("http://h:1/b").unwrap();
        let c = Url::parse("http://h:2/a").unwrap();
        assert!(a.same_origin(&b));
        assert!(!a.same_origin(&c));
        assert_eq!(a.with_path("/x").to_text(), "http://h:1/x");
    }
}
