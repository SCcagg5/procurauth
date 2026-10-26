//! Identity tokens: the runner makes them as the test edge (series U), and it
//! checks them as the service behind an edge (series E).

use std::fs;
use std::path::Path;

use base64::Engine as _;
use procurauth_core::identity::{TokenPolicy, verify};
use procurauth_core::json::parse_slice;
use procurauth_core::jws::{KeySet, PublicKey, SigningKey, b64url_decode, sign_compact};
use serde_json::{Map, Value, json};

use crate::model::{Defect, TokenAlg, TokenSpec};
use crate::profile::{TokenProfile, TrustProfile};

/// The largest file that the runner reads.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Read a small text file. The error names the member and the path, never the content.
///
/// # Errors
/// Returns a message when the file cannot be read as UTF-8 text.
pub(crate) fn read_file(key: &str, path: &Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| {
        format!(
            "Key `{key}`: cannot read the file `{}`: {e}.",
            path.display()
        )
    })?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "Key `{key}`: expected a file of {MAX_FILE_BYTES} bytes at most, found {} bytes in `{}`.",
            meta.len(),
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(|e| {
        format!(
            "Key `{key}`: cannot read the file `{}` as UTF-8 text: {e}.",
            path.display()
        )
    })
}

/// Read a secret from a file: the content without the last line end.
///
/// # Errors
/// Returns a message when the file cannot be read or is empty.
pub(crate) fn read_secret(key: &str, path: &Path) -> Result<String, String> {
    let text = read_file(key, path)?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text)
        .to_owned();
    if text.is_empty() {
        return Err(format!(
            "Key `{key}`: expected a file that is not empty, found an empty file `{}`.",
            path.display()
        ));
    }
    Ok(text)
}

/// Why a token cannot be made.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MintError {
    /// The profile has no key for this algorithm.
    NoKey(TokenAlg),
}

struct SigningEntry {
    alg: TokenAlg,
    kid: Option<String>,
    key: SigningKey,
}

/// The test edge: it signs the tokens that a service accepts.
pub(crate) struct Signer {
    entries: Vec<SigningEntry>,
    iss: String,
    service: String,
    max_age: u64,
    skew: u64,
}

impl Signer {
    /// Read the keys of the profile.
    ///
    /// # Errors
    /// Returns every problem with a key file.
    pub(crate) fn load(
        profile: &TokenProfile,
        service: &str,
        key_prefix: &str,
    ) -> Result<Self, Vec<String>> {
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        for (index, file) in profile.keys.iter().enumerate() {
            let name = format!("{key_prefix}.keys[{index}].file");
            let text = match read_file(&name, &file.file) {
                Ok(text) => text,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            match SigningKey::from_pkcs8_pem(&text) {
                Ok(key) => {
                    let found = key.algorithm().as_str();
                    if found == file.alg.name() {
                        entries.push(SigningEntry {
                            alg: file.alg,
                            kid: file.kid.clone(),
                            key,
                        });
                    } else {
                        errors.push(format!(
                            "Key `{key_prefix}.keys[{index}].alg`: expected the algorithm of the key in `{}`, which is {found}, found \"{}\".",
                            file.file.display(),
                            file.alg.name()
                        ));
                    }
                }
                Err(_) => errors.push(format!(
                    "Key `{name}`: expected a PKCS#8 PEM private key for Ed25519 or P-256 in `{}`.",
                    file.file.display()
                )),
            }
        }
        if errors.is_empty() {
            Ok(Self {
                entries,
                iss: profile.iss.clone(),
                service: service.to_owned(),
                max_age: profile.max_age_seconds,
                skew: profile.skew_seconds,
            })
        } else {
            Err(errors)
        }
    }

    /// Make a token at the time `now`.
    ///
    /// # Errors
    /// Returns [`MintError::NoKey`] when the profile has no key for the algorithm of the token.
    pub(crate) fn mint(&self, spec: &TokenSpec, now: u64) -> Result<String, MintError> {
        let alg = spec.alg.unwrap_or(TokenAlg::Ed25519);
        let entry = self
            .entries
            .iter()
            .find(|e| e.alg == alg)
            .ok_or(MintError::NoKey(alg))?;
        let life = (self.max_age / 2).max(1);
        let (mut iat, mut exp) = (now, now + life);
        let mut header = Map::new();
        header.insert("alg".into(), json!(alg.name()));
        header.insert("typ".into(), json!("JWT"));
        if let Some(kid) = &entry.kid {
            header.insert("kid".into(), json!(kid));
        }
        let mut iss = self.iss.clone();
        let mut aud = self.service.clone();
        let mut flip = false;
        let mut strip = false;
        match spec.defect {
            None => {}
            Some(Defect::BadSignature) => flip = true,
            Some(Defect::Expired) => {
                exp = now.saturating_sub(self.skew + 10);
                iat = exp.saturating_sub(life.min(10));
            }
            Some(Defect::FutureIat) => {
                iat = now + self.skew + 10;
                exp = iat + life;
            }
            Some(Defect::LongLife) => exp = now + self.max_age + self.skew + 10,
            Some(Defect::AtJwt) => {
                header.insert("typ".into(), json!("at+jwt"));
            }
            Some(Defect::AlgNone) => {
                header.insert("alg".into(), json!("none"));
                strip = true;
            }
            Some(Defect::AlgHs256) => {
                header.insert("alg".into(), json!("HS256"));
            }
            Some(Defect::AlgEddsa) => {
                header.insert("alg".into(), json!("EdDSA"));
            }
            Some(Defect::WrongIssuer) => iss = "https://other-issuer.invalid".to_owned(),
            Some(Defect::WrongAudience) => aud = "other-service-conformance".to_owned(),
            Some(Defect::UnknownKid) => {
                header.insert("kid".into(), json!("unknown-kid-conformance"));
            }
        }
        let mut claims = Map::new();
        claims.insert("iss".into(), json!(iss));
        claims.insert("sub".into(), json!(spec.subject));
        claims.insert("aud".into(), json!(aud));
        claims.insert("iat".into(), json!(iat));
        claims.insert("exp".into(), json!(exp));
        if let Some(owner) = &spec.owner {
            claims.insert("owner".into(), json!(owner));
        }
        overlay(&mut claims, &spec.claims);
        overlay(&mut header, &spec.header);
        let token = sign_compact(&Value::Object(header), &Value::Object(claims), &entry.key);
        let (input, signature) = token.rsplit_once('.').unwrap_or((token.as_str(), ""));
        if strip {
            return Ok(format!("{input}."));
        }
        if flip {
            let mut bytes = b64url_decode(signature).unwrap_or_default();
            if let Some(first) = bytes.first_mut() {
                *first ^= 0x01;
            }
            return Ok(format!(
                "{input}.{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
            ));
        }
        Ok(token)
    }
}

/// Set members of a map. A `null` removes the member.
fn overlay(target: &mut Map<String, Value>, changes: &Map<String, Value>) {
    for (name, value) in changes {
        if value.is_null() {
            target.remove(name);
        } else {
            target.insert(name.clone(), value.clone());
        }
    }
}

/// The checks of the service behind an edge: the public keys and the policy.
pub(crate) struct Verifier {
    keys: KeySet,
    policy: TokenPolicy,
    key_count: usize,
}

/// A token that passed the checks, with its parts as JSON.
#[derive(Debug)]
pub(crate) struct Decoded {
    /// The JOSE header.
    pub(crate) header: Value,
    /// The claims.
    pub(crate) claims: Value,
}

impl Verifier {
    /// Read the public keys of the profile.
    ///
    /// # Errors
    /// Returns every problem with a key file.
    pub(crate) fn load(trust: &TrustProfile, service: &str) -> Result<Self, Vec<String>> {
        let mut keys: Vec<PublicKey> = Vec::new();
        let mut errors = Vec::new();
        if let Some(file) = &trust.jwks_file {
            match read_file("edge.trust.jwks_file", file) {
                Ok(text) => match KeySet::from_jwks_str(&text) {
                    Ok(set) => keys.extend(set.into_keys()),
                    Err(findings) => {
                        for finding in findings {
                            errors.push(format!(
                                "Key `edge.trust.jwks_file`: expected a JWK Set of public keys in `{}`: {}",
                                file.display(),
                                finding.message
                            ));
                        }
                    }
                },
                Err(e) => errors.push(e),
            }
        }
        for (index, (file, kid)) in trust.pem_keys.iter().enumerate() {
            let name = format!("edge.trust.pem_keys[{index}].file");
            match read_file(&name, file) {
                Ok(text) => match PublicKey::from_spki_pem(&text, kid.as_deref()) {
                    Ok(key) => keys.push(key),
                    Err(_) => errors.push(format!(
                        "Key `{name}`: expected a public key in PEM form in `{}`.",
                        file.display()
                    )),
                },
                Err(e) => errors.push(e),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let key_count = keys.len();
        Ok(Self {
            keys: KeySet::from_keys(keys),
            policy: TokenPolicy {
                issuer: trust.iss.clone(),
                service_id: service.to_owned(),
                max_age_seconds: trust.max_age_seconds,
                skew_seconds: trust.skew_seconds,
            },
            key_count,
        })
    }

    /// The number of keys in the key set of the edge.
    pub(crate) fn key_count(&self) -> usize {
        self.key_count
    }

    /// Check a token, and read its header and its claims.
    ///
    /// # Errors
    /// Returns a message with the first check that fails.
    pub(crate) fn check(&self, token: &str, now: u64) -> Result<Decoded, String> {
        verify(token, &self.keys, &self.policy, now).map_err(|e| e.to_string())?;
        let mut parts = token.split('.');
        let (Some(h), Some(p)) = (parts.next(), parts.next()) else {
            return Err("the token has no header and no payload".to_owned());
        };
        let decode = |part: &str, what: &str| -> Result<Value, String> {
            let bytes =
                b64url_decode(part).ok_or_else(|| format!("the {what} is not base64url"))?;
            parse_slice(&bytes).map_err(|e| format!("the {what} is not JSON: {e}"))
        };
        Ok(Decoded {
            header: decode(h, "header")?,
            claims: decode(p, "payload")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::KeyFile;
    use procurauth_core::identity::inspect;

    const ED_SEED: [u8; 32] = [7; 32];

    fn signer(max_age: u64, skew: u64) -> Signer {
        Signer {
            entries: vec![
                SigningEntry {
                    alg: TokenAlg::Ed25519,
                    kid: Some("k1".into()),
                    key: SigningKey::from_ed25519_seed(&ED_SEED),
                },
                SigningEntry {
                    alg: TokenAlg::Es256,
                    kid: Some("k2".into()),
                    key: SigningKey::from_es256_scalar(&[9; 32]).unwrap(),
                },
            ],
            iss: "https://edge.example".into(),
            service: "datastore".into(),
            max_age,
            skew,
        }
    }

    fn keys_for_ed() -> KeySet {
        KeySet::from_keys(vec![
            SigningKey::from_ed25519_seed(&ED_SEED).public_key(Some("k1")),
            SigningKey::from_es256_scalar(&[9; 32])
                .unwrap()
                .public_key(Some("k2")),
        ])
    }

    fn policy() -> TokenPolicy {
        TokenPolicy {
            issuer: "https://edge.example".into(),
            service_id: "datastore".into(),
            max_age_seconds: 300,
            skew_seconds: 30,
        }
    }

    fn spec(defect: Option<Defect>) -> TokenSpec {
        TokenSpec {
            subject: "alice".into(),
            owner: None,
            alg: None,
            claims: Map::new(),
            header: Map::new(),
            defect,
        }
    }

    const NOW: u64 = 1_792_569_648;

    fn failed_check(token: &str) -> Option<String> {
        let inspection = inspect(token, &keys_for_ed(), &policy(), NOW);
        inspection
            .first_failure()
            .map(|c| c.name.as_str().to_owned())
    }

    #[test]
    fn a_good_token_passes_every_check() {
        let token = signer(300, 30).mint(&spec(None), NOW).unwrap();
        assert_eq!(failed_check(&token), None);
    }

    #[test]
    fn a_token_for_a_key_has_the_owner() {
        let mut s = spec(None);
        s.subject = "key:abc".into();
        s.owner = Some("alice".into());
        let token = signer(300, 30).mint(&s, NOW).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let claims: Value = serde_json::from_slice(&b64url_decode(payload).unwrap()).unwrap();
        assert_eq!(claims["owner"], "alice");
        assert_eq!(claims["sub"], "key:abc");
        assert_eq!(claims["aud"], "datastore");
    }

    #[test]
    fn each_defect_makes_the_check_that_it_names_fail() {
        let expected = [
            (Defect::BadSignature, "signature"),
            (Defect::Expired, "exp"),
            (Defect::FutureIat, "iat"),
            (Defect::LongLife, "life"),
            (Defect::AtJwt, "typ"),
            // The core reads the empty third part of the token as a failure of the structure.
            (Defect::AlgNone, "structure"),
            (Defect::AlgHs256, "alg"),
            (Defect::AlgEddsa, "alg"),
            (Defect::WrongIssuer, "iss"),
            (Defect::WrongAudience, "aud"),
            (Defect::UnknownKid, "kid"),
        ];
        for (defect, check) in expected {
            let token = signer(300, 30).mint(&spec(Some(defect)), NOW).unwrap();
            assert_eq!(failed_check(&token).as_deref(), Some(check), "{defect:?}");
        }
    }

    #[test]
    fn a_token_with_the_algorithm_none_has_an_empty_signature() {
        let token = signer(300, 30)
            .mint(&spec(Some(Defect::AlgNone)), NOW)
            .unwrap();
        assert!(token.ends_with('.'));
    }

    #[test]
    fn a_null_in_claims_or_header_removes_the_member() {
        let mut s = spec(None);
        s.claims.insert("iss".into(), Value::Null);
        s.claims.insert("x_extra".into(), json!({"a": 1}));
        s.header.insert("typ".into(), Value::Null);
        let token = signer(300, 30).mint(&s, NOW).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let header: Value = serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        let claims: Value = serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert!(header.get("typ").is_none());
        assert!(claims.get("iss").is_none());
        assert_eq!(claims["x_extra"], json!({"a": 1}));
        assert_eq!(failed_check(&token).as_deref(), Some("typ"));
    }

    #[test]
    fn a_token_with_es256_needs_an_es256_key() {
        let mut s = spec(None);
        s.alg = Some(TokenAlg::Es256);
        let token = signer(300, 30).mint(&s, NOW).unwrap();
        assert_eq!(failed_check(&token), None);
        let one = Signer {
            entries: vec![SigningEntry {
                alg: TokenAlg::Ed25519,
                kid: None,
                key: SigningKey::from_ed25519_seed(&ED_SEED),
            }],
            ..signer(300, 30)
        };
        assert_eq!(one.mint(&s, NOW), Err(MintError::NoKey(TokenAlg::Es256)));
    }

    #[test]
    fn a_short_max_age_still_gives_a_good_token() {
        let token = signer(1, 0).mint(&spec(None), NOW).unwrap();
        let mut p = policy();
        p.max_age_seconds = 1;
        p.skew_seconds = 0;
        let inspection = inspect(&token, &keys_for_ed(), &p, NOW);
        assert!(inspection.passed(), "{inspection:?}");
    }

    #[test]
    fn the_signer_reads_the_key_file_and_never_prints_it() {
        let dir = std::env::temp_dir().join("access-conformance-tokens-unit");
        fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.pem");
        fs::write(
            &bad,
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let profile = TokenProfile {
            header: "X-Identity-Token".into(),
            iss: "i".into(),
            max_age_seconds: 300,
            skew_seconds: 30,
            keys: vec![KeyFile {
                alg: TokenAlg::Ed25519,
                kid: None,
                file: bad.clone(),
            }],
        };
        let Err(errors) = Signer::load(&profile, "s", "pep.token") else {
            panic!("the key is not valid");
        };
        assert!(errors[0].contains("pep.token.keys[0].file"));
        assert!(!errors[0].contains("AAAA"));
        let missing = TokenProfile {
            keys: vec![KeyFile {
                alg: TokenAlg::Ed25519,
                kid: None,
                file: dir.join("missing.pem"),
            }],
            ..profile
        };
        let Err(errors) = Signer::load(&missing, "s", "pep.token") else {
            panic!("the file is missing");
        };
        assert!(errors[0].contains("cannot read the file"));
    }

    #[test]
    fn a_secret_file_loses_its_last_line_end_only() {
        let dir = std::env::temp_dir().join("access-conformance-tokens-unit");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret.txt");
        fs::write(&file, "abc\n\n").unwrap();
        assert_eq!(read_secret("k", &file).unwrap(), "abc\n");
        fs::write(&file, "\n").unwrap();
        assert!(read_secret("k", &file).is_err());
    }
}
