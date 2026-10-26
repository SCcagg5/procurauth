//! The identity token of the edge (protocol 9.2, 9.3) and the kept tokens (9.9).
//!
//! The edge signs the token with the library of `access-token`. The claims are
//! `iss`, `sub`, `aud`, `iat` and `exp`. A token for a key also has `owner`.
//! The token never holds the text of the key. The edge uses its signing key for
//! the identity token only (9.2).
//!
//! The edge can keep the tokens that it made. It gives a kept token again only
//! to the same subject for the same service, and only before `exp` minus a
//! margin. The table has a fixed size. When it is full, the edge signs a new
//! token and keeps nothing (9.9).

use std::collections::HashMap;

use access_token::make::{Shape, make_token};
use procurauth_core::jws::SigningKey;
use serde_json::{Map, Value};

/// The signing key of the edge and the rules for the tokens that it makes.
pub struct Signer {
    key: SigningKey,
    kid: Option<String>,
    issuer: String,
    life_seconds: u64,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("algorithm", &self.key.algorithm().as_str())
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("life_seconds", &self.life_seconds)
            .finish_non_exhaustive()
    }
}

/// A token and the time of its end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Made {
    /// The token in compact form.
    pub token: String,
    /// The claim `exp`, in seconds since the Unix epoch.
    pub expires_at: u64,
}

impl Signer {
    /// A signer. `life_seconds` is `exp` minus `iat` (9.2).
    pub fn new(key: SigningKey, kid: Option<String>, issuer: String, life_seconds: u64) -> Self {
        Self {
            key,
            kid,
            issuer,
            life_seconds,
        }
    }

    /// The life of a token, in seconds.
    pub fn life_seconds(&self) -> u64 {
        self.life_seconds
    }

    /// The name of the algorithm of the key: `Ed25519` or `ES256`.
    pub fn algorithm(&self) -> &'static str {
        self.key.algorithm().as_str()
    }

    /// Make a token for a subject and a service. `owner` is the owner of a key (9.3).
    pub fn make(&self, subject: &str, owner: Option<&str>, service: &str, now: u64) -> Made {
        let expires_at = now.saturating_add(self.life_seconds);
        let mut claims = Map::new();
        claims.insert("iss".into(), Value::from(self.issuer.as_str()));
        claims.insert("sub".into(), Value::from(subject));
        claims.insert("aud".into(), Value::from(service));
        claims.insert("iat".into(), Value::from(now));
        claims.insert("exp".into(), Value::from(expires_at));
        if let Some(owner) = owner {
            claims.insert("owner".into(), Value::from(owner));
        }
        let shape = Shape {
            alg: None,
            typ: None,
            kid: self.kid.clone(),
            crit: None,
            bad_signature: false,
        };
        let made = make_token(&shape, &Value::Object(claims), &self.key);
        Made {
            token: made.token,
            expires_at,
        }
    }
}

/// The kept tokens, by subject and service.
#[derive(Debug, Default)]
pub struct TokenCache {
    entries: HashMap<(String, String), Made>,
    max_entries: usize,
    margin_seconds: u64,
}

impl TokenCache {
    /// A table for at most `max_entries` tokens. A token is given again only while
    /// more than `margin_seconds` remain before its `exp`. With 0 entries the edge keeps nothing.
    pub fn new(max_entries: usize, margin_seconds: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            margin_seconds,
        }
    }

    /// The number of kept tokens.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the table holds no token.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The kept token of a subject for a service, when it is still good at `now`.
    pub fn get(&self, subject: &str, service: &str, now: u64) -> Option<&Made> {
        self.entries
            .get(&(subject.to_owned(), service.to_owned()))
            .filter(|made| now.saturating_add(self.margin_seconds) < made.expires_at)
    }

    /// Keep a token. When the table is full, the edge removes the tokens that ended. When it
    /// is still full, the edge keeps nothing.
    pub fn put(&mut self, subject: &str, service: &str, made: &Made, now: u64) {
        if self.max_entries == 0 {
            return;
        }
        let key = (subject.to_owned(), service.to_owned());
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.entries.retain(|_, kept| now < kept.expires_at);
            if self.entries.len() >= self.max_entries {
                return;
            }
        }
        self.entries.insert(key, made.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_core::identity::Claims;
    use procurauth_core::jws::KeySet;

    fn signer(kid: Option<&str>, life: u64) -> Signer {
        Signer::new(
            SigningKey::from_ed25519_seed(&[7; 32]),
            kid.map(str::to_owned),
            "https://edge.example".to_owned(),
            life,
        )
    }

    fn claims_of(token: &str) -> Value {
        use base64::Engine as _;
        let payload = token.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn header_of(token: &str) -> Value {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn p_9_3_the_token_of_a_key_has_the_claims_and_the_owner() {
        let made =
            signer(Some("edge-ed25519"), 60).make("key:ann-k1", Some("ann"), "datastore", 1000);
        assert_eq!(made.expires_at, 1060);
        let claims = claims_of(&made.token);
        assert_eq!(claims["iss"], "https://edge.example");
        assert_eq!(claims["sub"], "key:ann-k1");
        assert_eq!(claims["aud"], "datastore");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 1060);
        assert_eq!(claims["owner"], "ann");
        assert!(claims.get("act").is_none());
        assert!(Claims::from_value(&claims).is_ok());
    }

    #[test]
    fn p_9_3_the_token_of_a_person_has_no_owner() {
        let made = signer(None, 60).make("ann", None, "datastore", 1000);
        assert!(claims_of(&made.token).get("owner").is_none());
    }

    #[test]
    fn p_9_2_the_header_has_the_algorithm_the_type_and_the_kid() {
        let with = header_of(&signer(Some("k1"), 60).make("ann", None, "s", 1).token);
        assert_eq!(with["alg"], "Ed25519");
        assert_eq!(with["typ"], "JWT");
        assert_eq!(with["kid"], "k1");
        let without = header_of(&signer(None, 60).make("ann", None, "s", 1).token);
        assert!(without.get("kid").is_none());
    }

    #[test]
    fn p_9_2_an_es256_key_signs_a_token_that_the_public_key_checks() {
        use procurauth_core::identity::{TokenPolicy, verify};
        let key = SigningKey::from_es256_scalar(&[9; 32]).unwrap();
        let keys = KeySet::from_keys(vec![key.public_key(None)]);
        let signer = Signer::new(key, None, "https://edge.example".into(), 60);
        assert_eq!(signer.algorithm(), "ES256");
        let made = signer.make("key:a", Some("o"), "datastore", 1000);
        let policy = TokenPolicy {
            issuer: "https://edge.example".into(),
            service_id: "datastore".into(),
            max_age_seconds: 300,
            skew_seconds: 30,
        };
        assert!(verify(&made.token, &keys, &policy, 1010).is_ok());
    }

    #[test]
    fn p_9_9_a_kept_token_is_given_before_exp_minus_the_margin_only() {
        let mut cache = TokenCache::new(10, 15);
        let made = signer(None, 60).make("a", None, "s", 1000);
        cache.put("a", "s", &made, 1000);
        assert_eq!(cache.get("a", "s", 1000), Some(&made));
        assert_eq!(cache.get("a", "s", 1044), Some(&made));
        assert_eq!(cache.get("a", "s", 1045), None);
        assert_eq!(cache.get("a", "s", 2000), None);
    }

    #[test]
    fn p_9_9_a_kept_token_is_for_the_same_subject_and_the_same_service_only() {
        let mut cache = TokenCache::new(10, 0);
        let made = signer(None, 60).make("a", None, "s", 1000);
        cache.put("a", "s", &made, 1000);
        assert!(cache.get("b", "s", 1001).is_none());
        assert!(cache.get("a", "other", 1001).is_none());
    }

    #[test]
    fn p_9_9_the_table_has_a_bound_and_a_full_table_keeps_nothing_new() {
        let mut cache = TokenCache::new(2, 0);
        let signer = signer(None, 60);
        for name in ["a", "b", "c"] {
            let made = signer.make(name, None, "s", 1000);
            cache.put(name, "s", &made, 1000);
        }
        assert_eq!(cache.len(), 2);
        assert!(cache.get("c", "s", 1001).is_none());
        // Tokens that ended leave the table when a new one needs the room.
        let late = signer.make("c", None, "s", 5000);
        cache.put("c", "s", &late, 5000);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("c", "s", 5001).is_some());
    }

    #[test]
    fn a_table_with_no_entry_keeps_nothing() {
        let mut cache = TokenCache::new(0, 0);
        let made = signer(None, 60).make("a", None, "s", 1000);
        cache.put("a", "s", &made, 1000);
        assert!(cache.is_empty());
    }
}
