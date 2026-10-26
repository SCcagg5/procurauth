//! Helpers for the integration tests. An edge signs tokens. A transport records
//! the questions and answers from a script. The document is the one of section 13.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_token::make::{Shape, make_token};
use procurauth_core::action_document::ActionDocument;
use procurauth_core::jws::{KeySet, SigningKey};
use procurauth_pep::Pep;
use procurauth_pep::clock::ManualClock;
use procurauth_pep::config::{PdpConfig, PepConfig, Secret};
use procurauth_pep::transport::{HttpResponse, PdpTransport, TransportError};
use serde_json::{Value, json};

/// The time of the tests, in seconds since the Unix epoch. It is the clock of the data of section 13.
pub const NOW: u64 = 1_792_569_648;
pub const ISSUER: &str = "https://edge.example";
pub const SERVICE: &str = "datastore";
pub const HEADER: &str = "X-Identity-Token";
pub const KEY_ALICE: &str = "key:9b1c04e2aa71f0c3";
pub const KEY_BOB: &str = "key:4d2e8f6a10b37c95";

/// The data of protocol section 13, with Bob and his key.
pub fn datastore_data() -> Value {
    serde_json::from_str(include_str!(
        "../../../../conformance/directories/datastore.json"
    ))
    .unwrap()
}

/// The data file of the series of budgets of the conformance cases.
pub fn budgets_data() -> Value {
    serde_json::from_str(include_str!(
        "../../../../conformance/directories/budgets.json"
    ))
    .unwrap()
}

/// The action document of the service `datastore` in a data file.
pub fn document_of(data: &Value) -> ActionDocument {
    ActionDocument::from_value(&data["services"][0]["document"]).unwrap()
}

pub fn datastore_document() -> ActionDocument {
    document_of(&datastore_data())
}

/// The edge: it signs identity tokens.
pub struct Edge {
    key: SigningKey,
}

impl Edge {
    pub fn new() -> Self {
        Self {
            key: SigningKey::from_ed25519_seed(&[7; 32]),
        }
    }

    /// An edge with an ES256 key.
    pub fn es256() -> Self {
        Self {
            key: SigningKey::from_es256_scalar(&[9; 32]).unwrap(),
        }
    }

    pub fn keys(&self) -> KeySet {
        KeySet::from_keys(vec![self.key.public_key(None)])
    }

    pub fn claims(&self, sub: &str, owner: Option<&str>) -> Value {
        let mut claims = json!({
            "iss": ISSUER, "sub": sub, "aud": SERVICE,
            "iat": NOW - 10, "exp": NOW + 290,
        });
        if let Some(owner) = owner {
            claims["owner"] = json!(owner);
        }
        claims
    }

    pub fn token(&self, sub: &str) -> String {
        self.sign(&self.claims(sub, None))
    }

    pub fn token_for_key(&self, sub: &str, owner: &str) -> String {
        self.sign(&self.claims(sub, Some(owner)))
    }

    pub fn sign(&self, claims: &Value) -> String {
        make_token(&shape(), claims, &self.key).token
    }

    pub fn sign_with(&self, shape: &Shape, claims: &Value) -> String {
        make_token(shape, claims, &self.key).token
    }
}

pub fn shape() -> Shape {
    Shape {
        alg: None,
        typ: None,
        kid: None,
        crit: None,
        bad_signature: false,
    }
}

/// A configuration for a PDP at this URL. The link is `http`, so the flag is set.
pub fn config(pdp_url: &str, edge: &Edge) -> PepConfig {
    let mut pdp = PdpConfig::new(pdp_url, Secret::new("test-credential-of-the-service"));
    pdp.allow_insecure_pdp_link = true;
    pdp.request_timeout = Duration::from_secs(3);
    PepConfig::new(SERVICE, HEADER, ISSUER, edge.keys(), 300, 30, pdp)
}

/// A PEP with a manual clock that shows [`NOW`].
pub fn pep(
    transport: Arc<dyn PdpTransport>,
    edge: &Edge,
    pdp_url: &str,
    tweak: impl FnOnce(&mut PepConfig),
) -> (Pep, ManualClock) {
    let clock = ManualClock::at_seconds(NOW);
    let mut cfg = config(pdp_url, edge);
    tweak(&mut cfg);
    let pep = Pep::with_clock(
        cfg,
        datastore_document(),
        transport,
        Arc::new(clock.clone()),
    )
    .unwrap();
    (pep, clock)
}

/// What the PEP sent.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Value>,
    pub timeout: Duration,
}

impl Seen {
    pub fn path(&self) -> &str {
        let rest = self
            .url
            .split_once("://")
            .map_or(self.url.as_str(), |(_, r)| r);
        rest.find('/').map_or("/", |i| &rest[i..])
    }

    pub fn has_usage(&self) -> bool {
        self.body
            .as_ref()
            .is_some_and(|b| b.to_string().contains("\"usage\""))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub type Handler = Box<dyn FnMut(&Seen) -> Result<HttpResponse, TransportError> + Send>;

/// A transport that records each request and answers from a function.
pub struct Scripted {
    seen: Mutex<Vec<Seen>>,
    handler: Mutex<Handler>,
}

pub fn json_response(status: u16, body: &Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.to_string().into_bytes(),
    }
}

impl Scripted {
    pub fn new(
        handler: impl FnMut(&Seen) -> Result<HttpResponse, TransportError> + Send + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            handler: Mutex::new(Box::new(handler)),
        })
    }

    /// A PDP that answers each question with a function of the question. The
    /// metadata path gets 404, so the PEP uses the default paths.
    pub fn answering(mut f: impl FnMut(&Value) -> Value + Send + 'static) -> Arc<Self> {
        Self::new(move |seen| match (&seen.body, seen.method) {
            (Some(body), "POST") => {
                if body.get("evaluations").is_some() {
                    let top = body.clone();
                    let items: Vec<Value> = body["evaluations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let mut question = item.clone();
                            question["subject"] = top["subject"].clone();
                            if let Some(context) = top.get("context") {
                                question["context"] = context.clone();
                            }
                            f(&question)
                        })
                        .collect();
                    Ok(json_response(200, &json!({"evaluations": items})))
                } else {
                    Ok(json_response(200, &f(body)))
                }
            }
            _ => Ok(json_response(404, &json!({}))),
        })
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// The POST requests only.
    pub fn posts(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| s.method == "POST")
            .collect()
    }

    pub fn clear(&self) {
        self.seen.lock().unwrap().clear();
    }

    pub fn usage_posts(&self) -> usize {
        self.posts().iter().filter(|s| s.has_usage()).count()
    }

    pub fn plain_posts(&self) -> usize {
        self.posts().iter().filter(|s| !s.has_usage()).count()
    }

    fn record(&self, seen: Seen) -> Result<HttpResponse, TransportError> {
        self.seen.lock().unwrap().push(seen.clone());
        (self.handler.lock().unwrap())(&seen)
    }
}

impl PdpTransport for Scripted {
    fn supports_scheme(&self, _scheme: &str) -> bool {
        true
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.record(Seen {
            method: "POST",
            url: url.to_owned(),
            headers: headers.to_vec(),
            body: Some(serde_json::from_slice(body).unwrap()),
            timeout,
        })
    }

    fn get_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.record(Seen {
            method: "GET",
            url: url.to_owned(),
            headers: headers.to_vec(),
            body: None,
            timeout,
        })
    }
}

/// An answer `true` with these ceilings and this usage.
pub fn yes(limits: Value, units: Option<u64>) -> Value {
    let mut context = json!({});
    if !limits.is_null() && limits != json!({}) {
        context["limits"] = limits;
    }
    if let Some(units) = units {
        context["usage"] = json!({"units": units});
    }
    if context == json!({}) {
        json!({"decision": true})
    } else {
        json!({"decision": true, "context": context})
    }
}

pub fn no() -> Value {
    json!({"decision": false})
}

pub fn budget_exceeded(seconds: u64) -> Value {
    json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": seconds}})
}

/// A PDP that answers `true` to everything. A question with usage gets `units` 1.
pub fn yes_to_all() -> Arc<Scripted> {
    Scripted::answering(|q| {
        let usage = q.pointer("/context/usage").is_some();
        yes(json!({}), usage.then_some(1))
    })
}
