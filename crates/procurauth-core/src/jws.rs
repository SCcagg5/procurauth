//! Keys and signatures for the identity token (protocol 9.2 and 9.4).
//!
//! The protocol names two algorithms: `Ed25519` and `ES256`. This module
//! reads the public keys of an edge from a JWK Set and checks a JWS signature.
//! It also signs a token for the tests and for the tools that make tokens.
//! It has no code for the `none` algorithm, and no code for a symmetric key.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, Verifier};
use serde_json::{Value, json};
use thiserror::Error;

use crate::finding::{Finding, JsonPath, Report, show};
use crate::json::parse_str;
use crate::read::{Obj, Unknown};

/// The algorithms of 9.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519. The JOSE name is `Ed25519` [RFC 9864]. The name `EdDSA` is deprecated.
    Ed25519,
    /// ECDSA with P-256 and SHA-256.
    Es256,
}

impl Algorithm {
    /// The name in the header `alg`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Es256 => "ES256",
        }
    }

    /// Read the name of an algorithm. Any other name, also `none`, `EdDSA` and `HS256`, gives `None`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "Ed25519" => Some(Self::Ed25519),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }
}

enum Inner {
    Ed25519(ed25519_dalek::VerifyingKey),
    Es256(p256::ecdsa::VerifyingKey),
}

/// A public key of an edge.
pub struct PublicKey {
    kid: Option<String>,
    inner: Inner,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl PublicKey {
    /// The id of the key in its set, when it has one.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The algorithm that the key checks.
    pub fn algorithm(&self) -> Algorithm {
        match self.inner {
            Inner::Ed25519(_) => Algorithm::Ed25519,
            Inner::Es256(_) => Algorithm::Es256,
        }
    }

    /// Check a signature over `input`. The signature has the form of a JWS:
    /// 64 bytes for both algorithms.
    pub fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        match &self.inner {
            Inner::Ed25519(key) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|sig| key.verify_strict(input, &sig).is_ok()),
            Inner::Es256(key) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|sig| key.verify(input, &sig).is_ok()),
        }
    }

    /// Read a public key from a PEM text: a SubjectPublicKeyInfo of Ed25519
    /// or of P-256 (the PEM label `PUBLIC KEY`). The key can have a `kid`.
    ///
    /// # Errors
    /// Returns an error when the text is not such a key. The error never holds the text.
    pub fn from_spki_pem(pem: &str, kid: Option<&str>) -> Result<Self, PublicKeyError> {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        let inner = if let Ok(key) = ed25519_dalek::VerifyingKey::from_public_key_pem(pem) {
            Inner::Ed25519(key)
        } else if let Ok(key) =
            <p256::ecdsa::VerifyingKey as DecodePublicKey>::from_public_key_pem(pem)
        {
            Inner::Es256(key)
        } else {
            return Err(PublicKeyError::NotSupported);
        };
        Ok(Self {
            kid: kid.map(str::to_owned),
            inner,
        })
    }

    /// The key as a JWK [RFC 7517].
    pub fn to_jwk(&self) -> Value {
        let mut jwk = match &self.inner {
            Inner::Ed25519(key) => json!({
                "kty": "OKP", "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(key.as_bytes()),
            }),
            Inner::Es256(key) => {
                let point = key.to_encoded_point(false);
                json!({
                    "kty": "EC", "crv": "P-256",
                    "x": point.x().map(|x| URL_SAFE_NO_PAD.encode(x)).unwrap_or_default(),
                    "y": point.y().map(|y| URL_SAFE_NO_PAD.encode(y)).unwrap_or_default(),
                })
            }
        };
        if let Some(kid) = &self.kid {
            jwk["kid"] = json!(kid);
        }
        jwk
    }
}

/// Why a public key cannot be read from a PEM text.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PublicKeyError {
    /// The text is not a SPKI PEM public key of Ed25519 or P-256.
    #[error("the text is not a SPKI PEM public key for Ed25519 or P-256")]
    NotSupported,
}

/// Why a key cannot be selected for a token (9.4).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SelectError {
    /// The token has a `kid` that the set does not hold.
    #[error("the set has no key with this `kid`")]
    UnknownKid,
    /// The set holds more than one key, and the token has no `kid`.
    #[error("the set holds more than one key, and the token has no `kid`")]
    KidRequired,
}

/// The public keys of an edge: a JWK Set [RFC 7517, 5].
#[derive(Debug, Default)]
pub struct KeySet {
    keys: Vec<PublicKey>,
}

impl KeySet {
    /// A set from keys.
    pub fn from_keys(keys: Vec<PublicKey>) -> Self {
        Self { keys }
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when the set has no key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keys.
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// Give the keys to the caller, for example to merge two sets.
    pub fn into_keys(self) -> Vec<PublicKey> {
        self.keys
    }

    /// Choose the key for a token (9.4). When the set holds more than one key,
    /// the token must have a `kid`, and the set must hold it. When the set
    /// holds one key and the token has no `kid`, the service uses that key.
    ///
    /// # Errors
    /// Returns an error when no key fits the rule.
    pub fn select(&self, kid: Option<&str>) -> Result<&PublicKey, SelectError> {
        match kid {
            Some(kid) => self
                .keys
                .iter()
                .find(|key| key.kid() == Some(kid))
                .ok_or(SelectError::UnknownKid),
            None if self.keys.len() == 1 => Ok(&self.keys[0]),
            None => Err(SelectError::KidRequired),
        }
    }

    /// Read a JWK Set from JSON text. The reader is strict.
    ///
    /// # Errors
    /// Returns a finding for each problem.
    pub fn from_jwks_str(text: &str) -> Result<Self, Vec<Finding>> {
        match parse_str(text) {
            Ok(value) => Self::from_jwks_value(&value),
            Err(error) => {
                let mut report = Report::new();
                report.error(
                    &error.path,
                    "9.4",
                    "bad_json",
                    format!("The text is not valid JSON: {error}."),
                );
                Err(report.into_findings())
            }
        }
    }

    /// Read a JWK Set from a JSON value. The set holds only public keys of
    /// the types `OKP` with `Ed25519` and `EC` with `P-256`.
    ///
    /// # Errors
    /// Returns a finding for each problem.
    pub fn from_jwks_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let mut report = Report::new();
        let root = JsonPath::root();
        let mut keys = Vec::new();
        if let Some(mut obj) = Obj::new(value, &root, "9.4", Unknown::Error, &mut report) {
            let items = obj.array("keys", &mut report);
            obj.finish(&mut report);
            let items = items.unwrap_or_default();
            if items.is_empty() && !report.has_errors() {
                report.error(&root.key("keys"), "9.4", "no_keys", "The set has no key.");
            }
            for (index, item) in items.iter().enumerate() {
                keys.extend(read_jwk(item, &root.key("keys").index(index), &mut report));
            }
            let mut seen = std::collections::HashSet::new();
            for (index, key) in keys.iter().enumerate() {
                if let Some(kid) = key.kid()
                    && !seen.insert(kid.to_owned())
                {
                    report.error(
                        &root.key("keys").index(index).key("kid"),
                        "9.4",
                        "duplicate_kid",
                        format!("The `kid` {} occurs more than one time.", show(&json!(kid))),
                    );
                }
            }
        }
        if report.has_errors() {
            Err(report.into_findings())
        } else {
            Ok(Self { keys })
        }
    }
}

fn read_jwk(value: &Value, path: &JsonPath, report: &mut Report) -> Option<PublicKey> {
    let start = report.error_count();
    let mut obj = Obj::new(value, path, "9.2", Unknown::Error, report)?;
    let kty = obj.string("kty", report);
    let crv = obj.string("crv", report);
    let x = obj.string("x", report);
    let y = obj.string_opt("y", report);
    let kid = obj.string_opt("kid", report);
    let alg = obj.string_opt("alg", report);
    let usage = obj.string_opt("use", report);
    let key_ops = obj.strings_opt("key_ops", report);
    if obj.optional("d").is_some() {
        report.error(
            &path.key("d"),
            "9.4",
            "private_key",
            "The set must hold public keys only. This key has the member `d`.",
        );
    }
    obj.finish(report);

    if let Some(usage) = usage
        && usage != "sig"
    {
        report.error(
            &path.key("use"),
            "9.2",
            "bad_use",
            format!(
                "Member `use`: expected `sig`, found {}.",
                show(&json!(usage))
            ),
        );
    }
    if let Some(ops) = key_ops
        && ops != ["verify"]
    {
        report.error(
            &path.key("key_ops"),
            "9.2",
            "bad_key_ops",
            "Member `key_ops`: expected [\"verify\"].",
        );
    }
    if kid.is_some_and(str::is_empty) {
        report.error(
            &path.key("kid"),
            "9.4",
            "bad_kid",
            "Member `kid` must not be empty.",
        );
    }
    let decode = |text: &str, key: &str, report: &mut Report| -> Option<[u8; 32]> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        if bytes.is_none() {
            report.error(
                &path.key(key),
                "9.2",
                "bad_coordinate",
                format!("Member `{key}`: expected 32 bytes in base64url with no padding."),
            );
        }
        bytes
    };
    let (algorithm, inner) = match (kty?, crv?) {
        ("OKP", "Ed25519") => {
            if y.is_some() {
                report.error(
                    &path.key("y"),
                    "9.2",
                    "unknown_member",
                    "An `Ed25519` key has no member `y`.",
                );
            }
            let bytes = decode(x?, "x", report)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes);
            match key {
                Ok(key) => (Algorithm::Ed25519, Inner::Ed25519(key)),
                Err(_) => {
                    report.error(
                        &path.key("x"),
                        "9.2",
                        "bad_coordinate",
                        "Member `x` is not a point of the curve.",
                    );
                    return None;
                }
            }
        }
        ("EC", "P-256") => {
            let x_bytes = decode(x?, "x", report);
            let y_bytes = match y {
                Some(y) => decode(y, "y", report),
                None => {
                    report.error(path, "9.2", "missing_member", "Member `y` is absent.");
                    None
                }
            };
            let (x_bytes, y_bytes) = (x_bytes?, y_bytes?);
            let point = p256::EncodedPoint::from_affine_coordinates(
                &x_bytes.into(),
                &y_bytes.into(),
                false,
            );
            match p256::ecdsa::VerifyingKey::from_encoded_point(&point) {
                Ok(key) => (Algorithm::Es256, Inner::Es256(key)),
                Err(_) => {
                    report.error(
                        path,
                        "9.2",
                        "bad_coordinate",
                        "The members `x` and `y` are not a point of the curve P-256.",
                    );
                    return None;
                }
            }
        }
        (kty, crv) => {
            report.error(
                path,
                "9.2",
                "bad_key_type",
                format!(
                    "Expected `kty` `OKP` with `crv` `Ed25519`, or `kty` `EC` with `crv` `P-256`, found {} with {}.",
                    show(&json!(kty)),
                    show(&json!(crv))
                ),
            );
            return None;
        }
    };
    if let Some(alg) = alg
        && Algorithm::parse(alg) != Some(algorithm)
    {
        report.error(
            &path.key("alg"),
            "9.2",
            "bad_alg",
            format!(
                "Member `alg`: expected `{}` for this key, found {}.",
                algorithm.as_str(),
                show(&json!(alg))
            ),
        );
    }
    (report.error_count() == start).then(|| PublicKey {
        kid: kid.map(str::to_owned),
        inner,
    })
}

/// Why a private key cannot be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SigningKeyError {
    /// The text is not a PKCS#8 PEM private key of Ed25519 or P-256.
    #[error("the text is not a PKCS#8 PEM private key for Ed25519 or P-256")]
    NotSupported,
    /// The bytes are not a valid private key.
    #[error("the bytes are not a valid private key")]
    Invalid,
}

/// A private key, to sign tokens for tests. A service never holds one.
pub enum SigningKey {
    /// An Ed25519 key.
    Ed25519(ed25519_dalek::SigningKey),
    /// A P-256 key.
    Es256(p256::ecdsa::SigningKey),
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.algorithm().as_str())
    }
}

impl SigningKey {
    /// An Ed25519 key from its 32-byte seed.
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// A P-256 key from its 32-byte secret scalar.
    ///
    /// # Errors
    /// Returns an error when the scalar is zero or not below the order of the curve.
    pub fn from_es256_scalar(scalar: &[u8; 32]) -> Result<Self, SigningKeyError> {
        p256::ecdsa::SigningKey::from_slice(scalar)
            .map(Self::Es256)
            .map_err(|_| SigningKeyError::Invalid)
    }

    /// Read a PKCS#8 PEM private key, for Ed25519 or for P-256.
    ///
    /// # Errors
    /// Returns an error when the text is not such a key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, SigningKeyError> {
        if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::Ed25519(key));
        }
        if let Ok(key) = <p256::ecdsa::SigningKey as DecodePrivateKey>::from_pkcs8_pem(pem) {
            return Ok(Self::Es256(key));
        }
        Err(SigningKeyError::NotSupported)
    }

    /// The algorithm of the key.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Es256(_) => Algorithm::Es256,
        }
    }

    /// The public key, with an optional `kid`.
    pub fn public_key(&self, kid: Option<&str>) -> PublicKey {
        let inner = match self {
            Self::Ed25519(key) => Inner::Ed25519(key.verifying_key()),
            Self::Es256(key) => Inner::Es256(*key.verifying_key()),
        };
        PublicKey {
            kid: kid.map(str::to_owned),
            inner,
        }
    }

    /// The JWK Set that holds the public key.
    pub fn public_jwks(&self, kid: Option<&str>) -> Value {
        json!({"keys": [self.public_key(kid).to_jwk()]})
    }

    fn sign(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.sign(input).to_bytes().to_vec(),
            Self::Es256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input);
                signature.to_bytes().to_vec()
            }
        }
    }
}

/// The public key of Ed25519 as a PKCS#8 SPKI document in PEM form, for tools that write it.
///
/// # Errors
/// Returns an error when the encoding fails.
pub fn ed25519_public_pem(key: &PublicKey) -> Option<String> {
    match &key.inner {
        Inner::Ed25519(key) => key
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .ok(),
        Inner::Es256(_) => None,
    }
}

/// Make a JWS in compact form. The function signs with the real algorithm of
/// `key`, and it writes `header` as it is. Thus a test can make a token
/// whose header names another algorithm.
pub fn sign_compact(header: &Value, payload: &Value, key: &SigningKey) -> String {
    sign_compact_text(&header.to_string(), &payload.to_string(), key)
}

/// Make a JWS in compact form from the exact text of the header and of the
/// payload. A test uses it to make a token that no JSON value can describe,
/// for example a payload with a duplicate member.
pub fn sign_compact_text(header: &str, payload: &str, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Decode base64url with no padding, as JWS requires.
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn ed_key() -> SigningKey {
        SigningKey::from_ed25519_seed(&[7; 32])
    }

    pub(crate) fn es_key() -> SigningKey {
        SigningKey::from_es256_scalar(&[9; 32]).unwrap()
    }

    #[test]
    fn p_9_2_algorithm_names() {
        assert_eq!(Algorithm::parse("Ed25519"), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::parse("ES256"), Some(Algorithm::Es256));
        for bad in ["none", "None", "EdDSA", "HS256", "RS256", "es256", ""] {
            assert_eq!(Algorithm::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn p_9_2_both_algorithms_sign_and_verify() {
        for key in [ed_key(), es_key()] {
            let public = key.public_key(None);
            let signature = key.sign(b"input");
            assert_eq!(signature.len(), 64);
            assert!(public.verify(b"input", &signature));
            assert!(!public.verify(b"other", &signature));
            let mut bad = signature.clone();
            bad[0] ^= 1;
            assert!(!public.verify(b"input", &bad));
            assert!(!public.verify(b"input", &signature[..63]));
        }
    }

    #[test]
    fn p_9_4_a_key_does_not_verify_the_signature_of_another_key() {
        let signature = ed_key().sign(b"input");
        let other = SigningKey::from_ed25519_seed(&[8; 32]).public_key(None);
        assert!(!other.verify(b"input", &signature));
    }

    #[test]
    fn p_9_4_the_jwk_set_round_trip() {
        for key in [ed_key(), es_key()] {
            let jwks = key.public_jwks(Some("k1"));
            let set = KeySet::from_jwks_value(&jwks).unwrap();
            assert_eq!(set.len(), 1);
            assert_eq!(set.keys()[0].kid(), Some("k1"));
            assert_eq!(set.keys()[0].algorithm(), key.algorithm());
            assert_eq!(set.keys()[0].to_jwk(), jwks["keys"][0]);
            assert!(set.keys()[0].verify(b"x", &key.sign(b"x")));
        }
    }

    #[test]
    fn p_9_4_the_set_refuses_a_private_key_an_unknown_member_and_bad_data() {
        let good = ed_key().public_jwks(None)["keys"][0].clone();
        let with = |name: &str, value: Value| {
            let mut jwk = good.clone();
            jwk[name] = value;
            KeySet::from_jwks_value(&json!({"keys": [jwk]}))
        };
        assert_eq!(with("d", json!("AA")).unwrap_err()[0].code, "private_key");
        assert_eq!(
            with("extra", json!(1)).unwrap_err()[0].code,
            "unknown_member"
        );
        assert_eq!(with("alg", json!("EdDSA")).unwrap_err()[0].code, "bad_alg");
        assert_eq!(with("alg", json!("ES256")).unwrap_err()[0].code, "bad_alg");
        assert!(with("alg", json!("Ed25519")).is_ok());
        assert_eq!(with("use", json!("enc")).unwrap_err()[0].code, "bad_use");
        assert_eq!(
            with("x", json!("AAAA")).unwrap_err()[0].code,
            "bad_coordinate"
        );
        assert_eq!(
            with("x", json!("AA==")).unwrap_err()[0].code,
            "bad_coordinate"
        );
        assert_eq!(
            with("crv", json!("Ed448")).unwrap_err()[0].code,
            "bad_key_type"
        );
        assert_eq!(with("kid", json!("")).unwrap_err()[0].code, "bad_kid");
        assert!(KeySet::from_jwks_value(&json!({"keys": []})).is_err());
        assert!(KeySet::from_jwks_value(&json!({"keys": [good], "x": 1})).is_err());
        assert!(KeySet::from_jwks_value(&json!([])).is_err());
    }

    #[test]
    fn p_9_4_the_set_refuses_two_keys_with_the_same_kid() {
        let a = ed_key().public_key(Some("k")).to_jwk();
        let b = es_key().public_key(Some("k")).to_jwk();
        let error = KeySet::from_jwks_value(&json!({"keys": [a, b]})).unwrap_err();
        assert_eq!(error[0].code, "duplicate_kid");
        assert_eq!(error[0].path.as_str(), "$.keys[1].kid");
    }

    #[test]
    fn p_9_4_the_set_refuses_a_point_that_is_not_on_the_curve() {
        let mut jwk = es_key().public_key(None).to_jwk();
        jwk["y"] = jwk["x"].clone();
        assert_eq!(
            KeySet::from_jwks_value(&json!({"keys": [jwk]})).unwrap_err()[0].code,
            "bad_coordinate"
        );
    }

    #[test]
    fn p_9_4_the_set_refuses_duplicate_members_in_the_text() {
        let text = r#"{"keys": [], "keys": []}"#;
        assert_eq!(KeySet::from_jwks_str(text).unwrap_err()[0].code, "bad_json");
    }

    #[test]
    fn p_9_4_a_set_gives_its_keys_back() {
        let set = KeySet::from_keys(vec![
            ed_key().public_key(Some("a")),
            es_key().public_key(None),
        ]);
        let keys = set.into_keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid(), Some("a"));
        assert_eq!(KeySet::from_keys(keys).len(), 2);
    }

    #[test]
    fn p_9_4_key_selection() {
        let a = ed_key().public_key(Some("a"));
        let b = es_key().public_key(Some("b"));
        let set = KeySet::from_keys(vec![a, b]);
        assert_eq!(set.select(Some("b")).unwrap().algorithm(), Algorithm::Es256);
        assert_eq!(set.select(Some("c")).unwrap_err(), SelectError::UnknownKid);
        assert_eq!(set.select(None).unwrap_err(), SelectError::KidRequired);
        let single = KeySet::from_keys(vec![ed_key().public_key(None)]);
        assert!(single.select(None).is_ok());
        assert_eq!(
            single.select(Some("a")).unwrap_err(),
            SelectError::UnknownKid
        );
    }

    #[test]
    fn p_9_2_pkcs8_pem_round_trip_for_ed25519() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let pem = key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        let read = SigningKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(read.algorithm(), Algorithm::Ed25519);
        assert_eq!(
            read.public_key(None).to_jwk(),
            SigningKey::Ed25519(key).public_key(None).to_jwk()
        );
        assert!(ed25519_public_pem(&read.public_key(None)).is_some());
    }

    #[test]
    fn p_9_2_pkcs8_pem_round_trip_for_p256() {
        use p256::pkcs8::EncodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_slice(&[5; 32]).unwrap();
        let pem = key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
        let read = SigningKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(read.algorithm(), Algorithm::Es256);
        assert!(SigningKey::from_pkcs8_pem("not a key").is_err());
    }

    #[test]
    fn p_9_4_a_public_key_reads_from_a_spki_pem() {
        use p256::pkcs8::EncodePublicKey as _;
        let ed = ed_key();
        let pem = ed25519_public_pem(&ed.public_key(None)).unwrap();
        let read = PublicKey::from_spki_pem(&pem, Some("k1")).unwrap();
        assert_eq!(read.kid(), Some("k1"));
        assert_eq!(read.algorithm(), Algorithm::Ed25519);
        assert!(read.verify(b"x", &ed.sign(b"x")));

        let es = es_key();
        let SigningKey::Es256(secret) = &es else {
            panic!("the key must be ES256");
        };
        let pem = secret
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let read = PublicKey::from_spki_pem(&pem, None).unwrap();
        assert_eq!(read.algorithm(), Algorithm::Es256);
        assert!(read.verify(b"x", &es.sign(b"x")));
    }

    #[test]
    fn p_9_4_a_bad_pem_is_not_a_public_key() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        for text in [
            "",
            "not a key",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        ] {
            assert_eq!(
                PublicKey::from_spki_pem(text, None).unwrap_err(),
                PublicKeyError::NotSupported
            );
        }
        let private = ed25519_dalek::SigningKey::from_bytes(&[3; 32])
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        assert!(PublicKey::from_spki_pem(&private, None).is_err());
    }

    #[test]
    fn p_9_2_a_zero_scalar_is_not_a_key() {
        assert_eq!(
            SigningKey::from_es256_scalar(&[0; 32]).unwrap_err(),
            SigningKeyError::Invalid
        );
    }
}
