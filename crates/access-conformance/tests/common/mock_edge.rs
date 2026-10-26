//! A scripted mock of an edge. It knows three key texts, asks the PDP for the
//! action `access`, and forwards the accepted requests with an identity token.
//! The flags of [`EdgeDefects`] make it wrong in one way each.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use procurauth_core::jws::{SigningKey, sign_compact};
use serde_json::{Value, json};

use super::http::{Req, Resp, Server, call};
use super::{examples, system_now};

/// The text of the key that the edge accepts.
pub const VALID_KEY: &str = "pk_live_0000000000000000000000000000000000000000001";
/// The text of a key that the edge knows and whose subject has no `access`.
pub const NO_ACCESS_KEY: &str = "pk_live_0000000000000000000000000000000000000000002";
/// The text of a key that the edge does not know.
pub const UNKNOWN_KEY: &str = "pk_live_0000000000000000000000000000000000000000003";
/// The credential of the mock for the PDP.
pub const CREDENTIAL: &str = "mock-edge-credential";
/// The header of the identity token.
pub const TOKEN_HEADER: &str = "X-Identity-Token";

#[derive(Clone, Default)]
pub struct EdgeDefects {
    /// The edge forwards the header `Authorization`.
    pub keep_authorization: bool,
    /// The edge keeps the header of the identity token that the client sent.
    pub keep_forged_header: bool,
    /// The edge answers a refusal with a redirect.
    pub redirect_on_refusal: bool,
    /// A refusal has a body.
    pub body_on_refusal: bool,
    /// The identity token has no `kid`.
    pub no_kid: bool,
    /// The claim `sub` of the token holds the text of the key.
    pub leak_key: bool,
    /// The edge does not ask the PDP for `access`.
    pub skip_access_check: bool,
    /// The edge refuses a request with no key, and it adds an error parameter.
    pub error_on_missing: bool,
    /// The edge keeps identity tokens.
    pub token_cache: bool,
    /// The edge gives a kept token to a client that it did not authenticate.
    pub cache_leak: bool,
}

pub struct MockEdge {
    pub addr: SocketAddr,
    server: Server,
}

struct State {
    cache: std::sync::Mutex<std::collections::HashMap<String, String>>,
    pdp: SocketAddr,
    upstream: SocketAddr,
    defects: EdgeDefects,
    key: SigningKey,
}

fn refusal(defects: &EdgeDefects, with_error: bool) -> Resp {
    let challenge = if with_error {
        "Bearer error=\"invalid_token\""
    } else {
        "Bearer"
    };
    let mut response = if defects.redirect_on_refusal {
        Resp::new(302).header("Location", "/login")
    } else {
        Resp::new(401)
    }
    .header("WWW-Authenticate", challenge);
    if defects.body_on_refusal {
        response.body = b"{\"error\":\"invalid_token\"}".to_vec();
    }
    response
}

impl State {
    fn access(&self, subject: &str) -> bool {
        let question = json!({
            "subject": {"type": "user", "id": subject},
            "action": {"name": "access"},
            "resource": {"type": "service", "id": "datastore"}
        });
        let body = question.to_string();
        let auth = format!("Bearer {CREDENTIAL}");
        let Some(reply) = call(
            self.pdp,
            "POST",
            "/access/v1/evaluation",
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &auth),
            ],
            Some(body.as_bytes()),
            Duration::from_secs(2),
        ) else {
            return false;
        };
        reply.status == 200 && reply.json()["decision"] == json!(true)
    }

    fn token(&self, subject: &str, owner: &str, text: &str) -> String {
        let now = system_now();
        let mut header = json!({"alg": "Ed25519", "typ": "JWT"});
        if !self.defects.no_kid {
            header["kid"] = json!("edge-ed25519");
        }
        let sub = if self.defects.leak_key { text } else { subject };
        let claims = json!({
            "iss": "https://edge.example", "sub": sub, "aud": "datastore",
            "iat": now, "exp": now + 60, "owner": owner
        });
        sign_compact(&header, &claims, &self.key)
    }

    fn handle(&self, req: Req) -> Resp {
        let defects = &self.defects;
        let Some(auth) = req.header("authorization") else {
            if defects.cache_leak {
                let token = self.cache.lock().unwrap().values().next().cloned();
                if let Some(token) = token {
                    return self.forward(&req, token);
                }
            }
            return refusal(defects, defects.error_on_missing);
        };
        let Some(text) = auth.strip_prefix("Bearer ") else {
            return refusal(defects, false);
        };
        let (subject, owner) = match text {
            VALID_KEY => ("key:ann-k1", "ann"),
            NO_ACCESS_KEY => ("key:ann-k2", "ann"),
            _ => return refusal(defects, true),
        };
        if !defects.skip_access_check && !self.access(subject) {
            return refusal(defects, true);
        }
        let token = if defects.token_cache {
            let mut cache = self.cache.lock().unwrap();
            cache
                .entry(subject.to_owned())
                .or_insert_with(|| self.token(subject, owner, text))
                .clone()
        } else {
            self.token(subject, owner, text)
        };
        self.forward(&req, token)
    }

    fn forward(&self, req: &Req, token: String) -> Resp {
        let defects = &self.defects;
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in &req.headers {
            let lower = name.to_ascii_lowercase();
            let skip = matches!(lower.as_str(), "host" | "content-length" | "connection")
                || (lower == "authorization" && !defects.keep_authorization)
                || (lower == TOKEN_HEADER.to_ascii_lowercase());
            if !skip {
                headers.push((name.clone(), value.clone()));
            }
        }
        match req.header(TOKEN_HEADER) {
            Some(forged) if defects.keep_forged_header => {
                headers.push((TOKEN_HEADER.to_owned(), forged.to_owned()));
            }
            _ => headers.push((TOKEN_HEADER.to_owned(), token)),
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let body = (!req.body.is_empty()).then_some(req.body.as_slice());
        match call(
            self.upstream,
            &req.method,
            &req.target,
            &refs,
            body,
            Duration::from_secs(3),
        ) {
            Some(reply) => Resp {
                status: reply.status,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: reply.body,
            },
            None => Resp::new(503),
        }
    }
}

impl MockEdge {
    pub fn start(pdp: SocketAddr, upstream: SocketAddr, defects: EdgeDefects) -> Self {
        let key = SigningKey::from_pkcs8_pem(
            &std::fs::read_to_string(examples().join("test-edge-ed25519.pem")).unwrap(),
        )
        .unwrap();
        let state = Arc::new(State {
            cache: std::sync::Mutex::default(),
            pdp,
            upstream,
            defects,
            key,
        });
        let server = Server::start("127.0.0.1:0", move |req| state.handle(req));
        Self {
            addr: server.addr,
            server,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// The profile for the mock edge. The PDP and the upstream listen on the given ports.
pub fn profile(
    pdp_port: u16,
    upstream_port: u16,
    dir: &std::path::Path,
    jwks: &str,
    mcp: bool,
    token_cache: bool,
) -> Value {
    let write = |name: &str, text: &str| super::write(dir, name, &format!("{text}\n"));
    let valid = write("valid-key.txt", VALID_KEY);
    let no_access = write("no-access-key.txt", NO_ACCESS_KEY);
    let unknown = write("unknown-key.txt", UNKNOWN_KEY);
    let credential = write("edge-credential.txt", CREDENTIAL);
    let mut edge = json!({
        "service": "datastore",
        "token_header": TOKEN_HEADER,
        "trust": {
            "iss": "https://edge.example", "max_age_seconds": 300, "skew_seconds": 30,
            "jwks_file": examples().join(jwks).display().to_string()
        },
        "keys": {
            "valid": {"text_file": valid, "subject": "key:ann-k1", "owner": "ann"},
            "no_access": {"text_file": no_access},
            "unknown": {"text_file": unknown}
        },
        "upstream": {"listen": format!("127.0.0.1:{upstream_port}")},
        "pdp": {"listen": format!("127.0.0.1:{pdp_port}"), "directory": "access.json", "credential_file": credential}
    });
    if mcp {
        edge["mcp_path"] = json!("/mcp");
    }
    if token_cache {
        edge["token_cache"] = json!(true);
    }
    json!({"edge": edge, "timeouts": {"request_seconds": 5, "case_seconds": 60, "settle_ms": 50}})
}
