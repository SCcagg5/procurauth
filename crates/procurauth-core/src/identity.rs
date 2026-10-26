//! The identity token (protocol section 9).
//!
//! [`inspect`] runs each check of 9.4 on a token and reports the result of
//! every check. [`verify`] stops at the first failure and gives the claims
//! of a good token. The functions never read a clock: the caller gives the
//! time. A service sends no detail of a failure to its client (9.4 gives
//! HTTP 401), so these results are for logs and for tests.

use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::finding::{Finding, JsonPath, Report, show, type_word};
use crate::json::parse_slice;
use crate::jws::{Algorithm, KeySet, PublicKey, SelectError, b64url_decode};
use crate::read::{Obj, Unknown};
use crate::subject::{SubjectKind, classify};

/// The header type of an identity token (9.2).
pub const TOKEN_TYPE: &str = "JWT";
/// The longest token that the functions read, in bytes. A token is about 1 KB.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// What a service knows about its edge (9.4). The configuration of the
/// service gives each value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPolicy {
    /// The value of `iss`.
    pub issuer: String,
    /// The id of the service: the value of `aud`.
    pub service_id: String,
    /// The longest life of a token (`exp` minus `iat`), in seconds.
    pub max_age_seconds: u64,
    /// The clock skew, in seconds. It applies to `iat` and to `exp`.
    pub skew_seconds: u64,
}

/// The claims of an identity token (9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// The edge that made the token.
    pub iss: String,
    /// The id of the subject (section 3). A PEP treats it as opaque text (3.3).
    pub sub: String,
    /// The services for which the token is good. The JSON value is a string or an array.
    pub aud: Vec<String>,
    /// The time of issue, in seconds since the Unix epoch.
    pub iat: u64,
    /// The end of the life of the token, in seconds since the Unix epoch.
    pub exp: u64,
    /// The owner of a key (9.3). It is for logs and for approvals (9.5).
    pub owner: Option<String>,
}

impl Claims {
    /// Read the claims. A claim that is not known is ignored (9.4).
    ///
    /// # Errors
    /// Returns a finding for each claim that is absent or has a wrong type.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        Self::read(value, false)
    }

    /// Read the claims as a PEP does. The claim `owner` is for logs and for
    /// approvals only, and a PEP never uses it in a decision (9.5). Thus an
    /// `owner` that is not a string, or that is empty, is read as no owner and
    /// is not an error. Every other claim follows [`Claims::from_value`].
    ///
    /// # Errors
    /// Returns a finding for each claim that is absent or has a wrong type.
    pub fn from_value_for_pep(value: &Value) -> Result<Self, Vec<Finding>> {
        Self::read(value, true)
    }

    fn read(value: &Value, ignore_bad_owner: bool) -> Result<Self, Vec<Finding>> {
        let mut report = Report::new();
        let claims = read_claims(value, ignore_bad_owner, &mut report);
        match claims {
            Some(claims) if !report.has_errors() => Ok(claims),
            _ => Err(report.into_findings()),
        }
    }

    /// The claims as JSON. A single audience is a string.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("iss".into(), json!(self.iss));
        m.insert("sub".into(), json!(self.sub));
        m.insert(
            "aud".into(),
            if self.aud.len() == 1 {
                json!(self.aud[0])
            } else {
                json!(self.aud)
            },
        );
        m.insert("iat".into(), json!(self.iat));
        m.insert("exp".into(), json!(self.exp));
        if let Some(owner) = &self.owner {
            m.insert("owner".into(), json!(owner));
        }
        Value::Object(m)
    }

    /// The life of the token, `exp` minus `iat`. It is `None` when `exp` is before `iat`.
    pub fn life(&self) -> Option<u64> {
        self.exp.checked_sub(self.iat)
    }
}

fn read_claims(value: &Value, ignore_bad_owner: bool, report: &mut Report) -> Option<Claims> {
    let mut obj = Obj::new(value, &JsonPath::root(), "9.3", Unknown::Ignore, report)?;
    let iss = obj.string("iss", report);
    let sub = obj.string("sub", report);
    let aud = read_aud(&mut obj, report);
    let iat = obj.whole("iat", report);
    let exp = obj.whole("exp", report);
    let owner = if ignore_bad_owner {
        obj.optional("owner")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    } else {
        obj.string_opt("owner", report)
    };
    for (key, text) in [("iss", iss), ("sub", sub), ("owner", owner)] {
        if text == Some("") {
            report.error(
                &obj.member_path(key),
                "9.3",
                "empty_claim",
                format!("Claim `{key}` must not be empty."),
            );
        }
    }
    Some(Claims {
        iss: iss?.to_owned(),
        sub: sub?.to_owned(),
        aud: aud?,
        iat: iat?,
        exp: exp?,
        owner: owner.map(str::to_owned),
    })
}

fn read_aud(obj: &mut Obj<'_>, report: &mut Report) -> Option<Vec<String>> {
    let path = obj.member_path("aud");
    let value = obj.required("aud", report)?;
    match value {
        Value::String(text) => Some(vec![text.clone()]),
        Value::Array(items) => {
            let mut out = Vec::new();
            for (index, item) in items.iter().enumerate() {
                if let Some(text) = item.as_str() {
                    out.push(text.to_owned());
                } else {
                    report.error(
                        &path.index(index),
                        "9.4",
                        "wrong_type",
                        format!(
                            "Expected a string, found {}: {}.",
                            type_word(item),
                            show(item)
                        ),
                    );
                    return None;
                }
            }
            Some(out)
        }
        other => {
            report.error(
                &path,
                "9.4",
                "wrong_type",
                format!(
                    "Claim `aud`: expected a string or an array of strings, found {}: {}.",
                    type_word(other),
                    show(other)
                ),
            );
            None
        }
    }
}

/// The checks that the profile of 9.3 makes on the claims, for a tool that
/// makes or lints tokens. A PEP never calls it: the PEP does not read a
/// meaning from the subject id (3.3), and it does not use `owner` (9.5).
pub fn profile_findings(claims: &Value) -> Vec<Finding> {
    let mut report = Report::new();
    let root = JsonPath::root();
    let parsed = match Claims::from_value(claims) {
        Ok(parsed) => parsed,
        Err(findings) => return findings,
    };
    match (classify(&parsed.sub), &parsed.owner) {
        (SubjectKind::Key { .. }, None) => report.error(
            &root,
            "9.3",
            "missing_owner",
            "A token for a key has the claim `owner`.",
        ),
        (SubjectKind::Key { .. }, Some(owner)) if classify(owner) != SubjectKind::Person => report
            .error(
                &root.key("owner"),
                "3.1",
                "bad_owner",
                format!(
                    "Claim `owner`: expected the id of a person, which has no colon, found {}.",
                    show(&json!(owner))
                ),
            ),
        (SubjectKind::Person, Some(_)) => report.warning(
            &root.key("owner"),
            "9.3",
            "owner_on_person_token",
            "A token for a person has no claim `owner`.",
        ),
        (SubjectKind::Unknown, _) => report.error(
            &root.key("sub"),
            "3.7",
            "unknown_subject",
            format!(
                "Claim `sub`: {} is not the id of a person or of a key.",
                show(&json!(parsed.sub))
            ),
        ),
        _ => {}
    }
    if claims.get("act").is_some() {
        report.error(
            &root.key("act"),
            "9.3",
            "act_claim",
            "The token has no claim `act`. The claim `sub` is the key, not the person.",
        );
    }
    report.into_findings()
}

/// The name of one check of 9.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckName {
    /// The token has three parts in base64url, and the header and the payload are JSON objects.
    Structure,
    /// The header has no `crit` member.
    Header,
    /// `alg` is `Ed25519` or `ES256`.
    Alg,
    /// `typ` is `JWT`.
    Typ,
    /// The key set has a key for the token.
    Kid,
    /// The signature is good.
    Signature,
    /// The payload has the claims of 9.3.
    Claims,
    /// `iss` is the issuer of the service.
    Iss,
    /// `sub` is a string.
    Sub,
    /// `aud` holds the id of the service.
    Aud,
    /// `iat` is not later than the clock plus the skew.
    Iat,
    /// The clock is not later than `exp` plus the skew.
    Exp,
    /// `exp` minus `iat` is not more than the maximum age.
    Life,
}

impl CheckName {
    /// The name as a word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Structure => "structure",
            Self::Header => "header",
            Self::Alg => "alg",
            Self::Typ => "typ",
            Self::Kid => "kid",
            Self::Signature => "signature",
            Self::Claims => "claims",
            Self::Iss => "iss",
            Self::Sub => "sub",
            Self::Aud => "aud",
            Self::Iat => "iat",
            Self::Exp => "exp",
            Self::Life => "life",
        }
    }

    /// The paragraph of the protocol that gives the check.
    pub fn rule(self) -> &'static str {
        match self {
            Self::Alg | Self::Typ => "9.2",
            Self::Claims | Self::Sub => "9.3",
            _ => "9.4",
        }
    }
}

impl fmt::Display for CheckName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The token passes the check.
    Pass,
    /// The token fails the check.
    Fail,
    /// The check did not run, because an earlier check failed.
    NotRun,
}

/// One check, with its result and a short detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    /// The check.
    pub name: CheckName,
    /// The result.
    pub outcome: Outcome,
    /// For a pass, the value that the check read. For a failure, the reason.
    pub detail: String,
}

/// The result of all checks on one token.
#[derive(Clone, Debug)]
pub struct Inspection {
    /// Every check, always in the same order.
    pub checks: Vec<Check>,
    /// The claims, when the payload has them. The signature may be bad: check [`Inspection::passed`].
    pub claims: Option<Claims>,
    /// The algorithm of the header, when it is one of 9.2.
    pub algorithm: Option<Algorithm>,
    /// The `kid` of the header.
    pub kid: Option<String>,
}

impl Inspection {
    /// True when every check passes.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.outcome == Outcome::Pass)
    }

    /// The first check that fails.
    pub fn first_failure(&self) -> Option<&Check> {
        self.checks.iter().find(|c| c.outcome == Outcome::Fail)
    }
}

/// A token that passes every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The algorithm of the header.
    pub algorithm: Algorithm,
    /// The `kid` of the header.
    pub kid: Option<String>,
    /// The claims.
    pub claims: Claims,
}

/// A token that fails a check.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("The identity token fails the check `{check}` (rule {rule}): {detail}")]
pub struct TokenError {
    /// The first check that fails.
    pub check: CheckName,
    /// The paragraph of the protocol.
    pub rule: &'static str,
    /// The reason.
    pub detail: String,
}

/// Check a token and stop at the first failure.
///
/// # Errors
/// Returns the first check that fails.
pub fn verify(
    token: &str,
    keys: &KeySet,
    policy: &TokenPolicy,
    now: u64,
) -> Result<VerifiedToken, TokenError> {
    first_failure_or_token(inspect(token, keys, policy, now))
}

/// Check a token as a PEP does, and stop at the first failure. It is the same
/// as [`verify`], except for the claim `owner`: a PEP ignores an `owner` that
/// is not a text (9.5, [`Claims::from_value_for_pep`]).
///
/// # Errors
/// Returns the first check that fails.
pub fn verify_for_pep(
    token: &str,
    keys: &KeySet,
    policy: &TokenPolicy,
    now: u64,
) -> Result<VerifiedToken, TokenError> {
    first_failure_or_token(inspect_with(token, keys, policy, now, true))
}

fn first_failure_or_token(inspection: Inspection) -> Result<VerifiedToken, TokenError> {
    if let Some(check) = inspection.first_failure() {
        return Err(TokenError {
            check: check.name,
            rule: check.name.rule(),
            detail: check.detail.clone(),
        });
    }
    match (inspection.algorithm, inspection.claims) {
        (Some(algorithm), Some(claims))
            if inspection.checks.iter().all(|c| c.outcome == Outcome::Pass) =>
        {
            Ok(VerifiedToken {
                algorithm,
                kid: inspection.kid,
                claims,
            })
        }
        _ => Err(TokenError {
            check: CheckName::Structure,
            rule: "9.4",
            detail: "The token does not pass every check.".to_owned(),
        }),
    }
}

struct Builder {
    checks: Vec<Check>,
}

impl Builder {
    fn new() -> Self {
        let order = [
            CheckName::Structure,
            CheckName::Header,
            CheckName::Alg,
            CheckName::Typ,
            CheckName::Kid,
            CheckName::Signature,
            CheckName::Claims,
            CheckName::Iss,
            CheckName::Sub,
            CheckName::Aud,
            CheckName::Iat,
            CheckName::Exp,
            CheckName::Life,
        ];
        Self {
            checks: order
                .into_iter()
                .map(|name| Check {
                    name,
                    outcome: Outcome::NotRun,
                    detail: String::new(),
                })
                .collect(),
        }
    }

    fn set(&mut self, name: CheckName, pass: bool, detail: impl Into<String>) {
        if let Some(check) = self.checks.iter_mut().find(|c| c.name == name) {
            check.outcome = if pass { Outcome::Pass } else { Outcome::Fail };
            check.detail = detail.into();
        }
    }
}

/// Run every check of 9.4 on a token.
pub fn inspect(token: &str, keys: &KeySet, policy: &TokenPolicy, now: u64) -> Inspection {
    inspect_with(token, keys, policy, now, false)
}

fn inspect_with(
    token: &str,
    keys: &KeySet,
    policy: &TokenPolicy,
    now: u64,
    ignore_bad_owner: bool,
) -> Inspection {
    let mut b = Builder::new();
    let mut result = Inspection {
        checks: Vec::new(),
        claims: None,
        algorithm: None,
        kid: None,
    };
    let parts = split_token(token);
    let (header, payload, signature, signing_input) = match parts {
        Ok(parts) => parts,
        Err(detail) => {
            b.set(CheckName::Structure, false, detail);
            result.checks = b.checks;
            return result;
        }
    };
    let header_value = parse_slice(&header);
    let payload_value = parse_slice(&payload);
    let header_object = header_value.as_ref().ok().and_then(Value::as_object);
    let structure_error = match (&header_value, &payload_value) {
        (Err(e), _) => Some(format!("The header is not valid JSON: {e}.")),
        (_, Err(e)) => Some(format!("The payload is not valid JSON: {e}.")),
        (Ok(h), _) if !h.is_object() => Some("The header is not a JSON object.".to_owned()),
        _ => None,
    };
    if let Some(detail) = structure_error {
        b.set(CheckName::Structure, false, detail);
        result.checks = b.checks;
        return result;
    }
    b.set(CheckName::Structure, true, "3 parts");
    let Some(header) = header_object else {
        result.checks = b.checks;
        return result;
    };

    if header.contains_key("crit") {
        b.set(
            CheckName::Header,
            false,
            "The header has the member `crit`, and no extension is supported.",
        );
    } else {
        b.set(CheckName::Header, true, "no `crit`");
    }

    // alg
    let alg_text = header.get("alg").and_then(Value::as_str);
    let algorithm = alg_text.and_then(Algorithm::parse);
    match (alg_text, algorithm) {
        (_, Some(algorithm)) => b.set(CheckName::Alg, true, algorithm.as_str()),
        (Some(text), None) => b.set(
            CheckName::Alg,
            false,
            format!(
                "Header `alg`: expected `Ed25519` or `ES256`, found {}.",
                show(&json!(text))
            ),
        ),
        (None, None) => b.set(
            CheckName::Alg,
            false,
            "Header `alg` is absent, or it is not a string.",
        ),
    }
    result.algorithm = algorithm;

    // typ
    match header.get("typ").and_then(Value::as_str) {
        Some(TOKEN_TYPE) => b.set(CheckName::Typ, true, TOKEN_TYPE),
        Some(other) => b.set(
            CheckName::Typ,
            false,
            format!(
                "Header `typ`: expected `JWT`, found {}.",
                show(&json!(other))
            ),
        ),
        None => b.set(
            CheckName::Typ,
            false,
            "Header `typ` is absent, or it is not a string.",
        ),
    }

    // kid and signature
    let kid = match header.get("kid") {
        None => Ok(None),
        Some(Value::String(kid)) => Ok(Some(kid.as_str())),
        Some(other) => Err(format!(
            "Header `kid`: expected a string, found {}.",
            show(other)
        )),
    };
    let key: Option<&PublicKey> = match &kid {
        Err(detail) => {
            b.set(CheckName::Kid, false, detail.clone());
            None
        }
        Ok(kid) => match keys.select(*kid) {
            Ok(key) => {
                b.set(
                    CheckName::Kid,
                    true,
                    kid.map_or_else(|| "one key in the set".to_owned(), str::to_owned),
                );
                Some(key)
            }
            Err(error @ (SelectError::UnknownKid | SelectError::KidRequired)) => {
                b.set(
                    CheckName::Kid,
                    false,
                    format!("The set has no key for the token: {error}."),
                );
                None
            }
        },
    };
    if let Ok(Some(kid)) = &kid {
        result.kid = Some((*kid).to_owned());
    }
    if let (Some(key), Some(algorithm)) = (key, algorithm) {
        if key.algorithm() != algorithm {
            b.set(
                CheckName::Signature,
                false,
                format!(
                    "The header says `{}`, and the key is for `{}`.",
                    algorithm.as_str(),
                    key.algorithm().as_str()
                ),
            );
        } else if key.verify(signing_input.as_bytes(), &signature) {
            b.set(CheckName::Signature, true, "good");
        } else {
            b.set(CheckName::Signature, false, "The signature is not good.");
        }
    }

    // claims
    let payload_value = payload_value.unwrap_or(Value::Null);
    match Claims::read(&payload_value, ignore_bad_owner) {
        Ok(claims) => {
            b.set(CheckName::Claims, true, "iss, sub, aud, iat, exp");
            result.claims = Some(claims);
        }
        Err(findings) => {
            let detail = findings
                .first()
                .map_or_else(String::new, |f| f.message.clone());
            b.set(CheckName::Claims, false, detail);
        }
    }
    if let Value::Object(map) = &payload_value {
        check_claims(&mut b, map, policy, now);
    }
    result.checks = b.checks;
    result
}

fn claim_problem(map: &Map<String, Value>, name: &str, expected: &str) -> Option<String> {
    match map.get(name) {
        None => Some(format!("Claim `{name}` is absent.")),
        Some(value) => Some(format!(
            "Claim `{name}`: expected {expected}, found {}: {}.",
            type_word(value),
            show(value)
        )),
    }
}

fn check_claims(b: &mut Builder, map: &Map<String, Value>, policy: &TokenPolicy, now: u64) {
    // iss
    match map
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(iss) if iss == policy.issuer => b.set(CheckName::Iss, true, iss),
        Some(iss) => b.set(
            CheckName::Iss,
            false,
            format!(
                "Claim `iss`: expected {}, found {}.",
                show(&json!(policy.issuer)),
                show(&json!(iss))
            ),
        ),
        None => b.set(
            CheckName::Iss,
            false,
            claim_problem(map, "iss", "a string that is not empty").unwrap_or_default(),
        ),
    }
    // sub
    match map
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(_) => b.set(CheckName::Sub, true, "present"),
        None => b.set(
            CheckName::Sub,
            false,
            claim_problem(map, "sub", "a string that is not empty").unwrap_or_default(),
        ),
    }
    // aud
    let audience: Option<Vec<&str>> = match map.get("aud") {
        Some(Value::String(text)) => Some(vec![text.as_str()]),
        Some(Value::Array(items)) => items.iter().map(Value::as_str).collect(),
        _ => None,
    };
    match audience {
        Some(list) if list.contains(&policy.service_id.as_str()) => {
            b.set(CheckName::Aud, true, policy.service_id.clone())
        }
        Some(list) => b.set(
            CheckName::Aud,
            false,
            format!(
                "Claim `aud`: expected a value with {}, found {}.",
                show(&json!(policy.service_id)),
                show(&json!(list))
            ),
        ),
        None => b.set(
            CheckName::Aud,
            false,
            claim_problem(map, "aud", "a string or an array of strings").unwrap_or_default(),
        ),
    }
    let iat = map.get("iat").and_then(Value::as_u64);
    let exp = map.get("exp").and_then(Value::as_u64);
    // iat
    match iat {
        Some(iat) if iat <= now.saturating_add(policy.skew_seconds) => {
            b.set(CheckName::Iat, true, format!("{iat}"))
        }
        Some(iat) => b.set(
            CheckName::Iat,
            false,
            format!(
                "Claim `iat` is {iat}, which is later than the clock {now} plus the skew {} s.",
                policy.skew_seconds
            ),
        ),
        None => b.set(
            CheckName::Iat,
            false,
            claim_problem(map, "iat", "a whole number of 0 or more").unwrap_or_default(),
        ),
    }
    // exp
    match exp {
        Some(exp) if now <= exp.saturating_add(policy.skew_seconds) => {
            b.set(CheckName::Exp, true, format!("{exp}"))
        }
        Some(exp) => b.set(
            CheckName::Exp,
            false,
            format!(
                "The clock {now} is later than `exp` {exp} plus the skew {} s.",
                policy.skew_seconds
            ),
        ),
        None => b.set(
            CheckName::Exp,
            false,
            claim_problem(map, "exp", "a whole number of 0 or more").unwrap_or_default(),
        ),
    }
    // life
    if let (Some(iat), Some(exp)) = (iat, exp) {
        match exp.checked_sub(iat) {
            None => b.set(
                CheckName::Life,
                false,
                format!("Claim `exp` {exp} is before claim `iat` {iat}."),
            ),
            Some(life) if life <= policy.max_age_seconds => {
                b.set(
                    CheckName::Life,
                    true,
                    format!("life {life} s, max {} s", policy.max_age_seconds),
                );
            }
            Some(life) => b.set(
                CheckName::Life,
                false,
                format!(
                    "The life of the token is {life} s, and the maximum age is {} s.",
                    policy.max_age_seconds
                ),
            ),
        }
    }
}

type Parts = (Vec<u8>, Vec<u8>, Vec<u8>, String);

fn split_token(token: &str) -> Result<Parts, String> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(format!(
            "The token has {} bytes, and the maximum is {MAX_TOKEN_BYTES}.",
            token.len()
        ));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(format!(
            "The token has {} parts, and a JWS has 3.",
            parts.len()
        ));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err("A part of the token is empty.".to_owned());
    }
    let decode = |part: &str, what: &str| {
        b64url_decode(part).ok_or_else(|| format!("The {what} is not base64url with no padding."))
    };
    Ok((
        decode(header, "header")?,
        decode(payload, "payload")?,
        decode(signature, "signature")?,
        format!("{header}.{payload}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::{SigningKey, sign_compact, sign_compact_text};

    const NOW: u64 = 1_792_569_700;

    fn ed() -> SigningKey {
        SigningKey::from_ed25519_seed(&[7; 32])
    }

    fn es() -> SigningKey {
        SigningKey::from_es256_scalar(&[9; 32]).unwrap()
    }

    fn policy() -> TokenPolicy {
        TokenPolicy {
            issuer: "https://edge.example".into(),
            service_id: "datastore".into(),
            max_age_seconds: 300,
            skew_seconds: 30,
        }
    }

    fn claims() -> Value {
        json!({"iss": "https://edge.example", "sub": "key:9b1c04e2aa71f0c3", "aud": "datastore",
               "iat": 1_792_569_600, "exp": 1_792_569_900, "owner": "alice"})
    }

    fn header(alg: &str) -> Value {
        json!({"alg": alg, "typ": "JWT"})
    }

    fn set_for(key: &SigningKey) -> KeySet {
        KeySet::from_keys(vec![key.public_key(None)])
    }

    fn failing(token: &str, keys: &KeySet) -> Vec<CheckName> {
        inspect(token, keys, &policy(), NOW)
            .checks
            .iter()
            .filter(|c| c.outcome == Outcome::Fail)
            .map(|c| c.name)
            .collect()
    }

    #[test]
    fn p_13_the_token_of_the_key_of_alice_is_good() {
        let key = ed();
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        let verified = verify(&token, &set_for(&key), &policy(), NOW).unwrap();
        assert_eq!(verified.algorithm, Algorithm::Ed25519);
        assert_eq!(verified.claims.sub, "key:9b1c04e2aa71f0c3");
        assert_eq!(verified.claims.owner.as_deref(), Some("alice"));
        assert_eq!(verified.claims.life(), Some(300));
        assert_eq!(verified.claims.to_value(), claims());
    }

    #[test]
    fn p_9_2_es256_is_good() {
        let key = es();
        let token = sign_compact(&header("ES256"), &claims(), &key);
        assert!(verify(&token, &set_for(&key), &policy(), NOW).is_ok());
    }

    #[test]
    fn p_9_4_every_check_is_reported_in_a_fixed_order() {
        let key = ed();
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        let inspection = inspect(&token, &set_for(&key), &policy(), NOW);
        assert!(inspection.passed());
        let names: Vec<_> = inspection.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "structure",
                "header",
                "alg",
                "typ",
                "kid",
                "signature",
                "claims",
                "iss",
                "sub",
                "aud",
                "iat",
                "exp",
                "life"
            ]
        );
        let life = inspection
            .checks
            .iter()
            .find(|c| c.name == CheckName::Life)
            .unwrap();
        assert_eq!(life.detail, "life 300 s, max 300 s");
    }

    #[test]
    fn p_9_2_the_algorithm_none_is_refused() {
        let key = ed();
        for alg in ["none", "None", "NONE"] {
            let token = sign_compact(&header(alg), &claims(), &key);
            assert!(
                failing(&token, &set_for(&key)).contains(&CheckName::Alg),
                "{alg}"
            );
            assert!(verify(&token, &set_for(&key), &policy(), NOW).is_err());
        }
        // An unsigned token has an empty third part.
        let unsigned = format!("{}.{}.", b64(&header("none")), b64(&claims()));
        assert_eq!(
            failing(&unsigned, &set_for(&key)),
            vec![CheckName::Structure]
        );
    }

    fn b64(value: &Value) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn p_9_2_other_algorithms_are_refused() {
        let key = ed();
        for alg in ["EdDSA", "HS256", "RS256", "ES384", "ed25519"] {
            let token = sign_compact(&header(alg), &claims(), &key);
            let found = failing(&token, &set_for(&key));
            assert!(found.contains(&CheckName::Alg), "{alg}");
        }
    }

    #[test]
    fn p_9_4_an_algorithm_that_does_not_match_the_key_is_refused() {
        // The header says ES256, and the key is Ed25519.
        let key = ed();
        let token = sign_compact(&header("ES256"), &claims(), &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Signature]);
        // The header says Ed25519, and the key is P-256.
        let key = es();
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Signature]);
    }

    #[test]
    fn p_9_4_a_bad_signature_is_refused() {
        let key = ed();
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        let other = SigningKey::from_ed25519_seed(&[8; 32]);
        assert_eq!(
            failing(&token, &set_for(&other)),
            vec![CheckName::Signature]
        );
        // A changed payload.
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut changed = claims();
        changed["sub"] = json!("alice");
        parts[1] = b64(&changed);
        assert_eq!(
            failing(&parts.join("."), &set_for(&key)),
            vec![CheckName::Signature]
        );
    }

    #[test]
    fn p_9_2_the_header_type_must_be_jwt() {
        let key = ed();
        for typ in [json!("at+jwt"), json!("jwt"), json!(5), Value::Null] {
            let token = sign_compact(&json!({"alg": "Ed25519", "typ": typ}), &claims(), &key);
            assert_eq!(
                failing(&token, &set_for(&key)),
                vec![CheckName::Typ],
                "{typ}"
            );
        }
        let token = sign_compact(&json!({"alg": "Ed25519"}), &claims(), &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Typ]);
    }

    #[test]
    fn p_9_4_a_header_with_crit_is_refused() {
        let key = ed();
        let token = sign_compact(
            &json!({"alg": "Ed25519", "typ": "JWT", "crit": ["x"], "x": 1}),
            &claims(),
            &key,
        );
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Header]);
    }

    #[test]
    fn p_9_4_kid_rules() {
        let a = ed();
        let b = es();
        let set = KeySet::from_keys(vec![a.public_key(Some("a")), b.public_key(Some("b"))]);
        let with_kid = |kid: Value| {
            let mut h = header("Ed25519");
            h["kid"] = kid;
            sign_compact(&h, &claims(), &a)
        };
        assert!(verify(&with_kid(json!("a")), &set, &policy(), NOW).is_ok());
        assert_eq!(failing(&with_kid(json!("c")), &set), vec![CheckName::Kid]);
        assert_eq!(failing(&with_kid(json!(5)), &set), vec![CheckName::Kid]);
        // A set with two keys needs a kid in the token.
        let no_kid = sign_compact(&header("Ed25519"), &claims(), &a);
        assert_eq!(failing(&no_kid, &set), vec![CheckName::Kid]);
        // A set with one key and no kid in the key refuses a token with a kid.
        assert_eq!(
            failing(&with_kid(json!("a")), &set_for(&a)),
            vec![CheckName::Kid]
        );
        assert!(verify(&no_kid, &set_for(&a), &policy(), NOW).is_ok());
        // The kid picks the key: a token signed by `a` but marked `b` fails.
        assert_eq!(
            failing(&with_kid(json!("b")), &set),
            vec![CheckName::Signature]
        );
    }

    #[test]
    fn p_9_3_each_claim_is_mandatory() {
        let key = ed();
        for (claim, check) in [
            ("iss", CheckName::Iss),
            ("sub", CheckName::Sub),
            ("aud", CheckName::Aud),
            ("iat", CheckName::Iat),
            ("exp", CheckName::Exp),
        ] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(claim);
            let token = sign_compact(&header("Ed25519"), &c, &key);
            let found = failing(&token, &set_for(&key));
            assert!(found.contains(&check), "{claim}: {found:?}");
            assert!(found.contains(&CheckName::Claims), "{claim}");
        }
    }

    #[test]
    fn p_9_3_a_claim_of_the_wrong_type_is_refused() {
        let key = ed();
        for (claim, value) in [
            ("iss", json!(5)),
            ("sub", json!(["a"])),
            ("aud", json!(5)),
            ("iat", json!("1")),
            ("exp", json!(1.5)),
            ("exp", json!(-5)),
            ("owner", json!(5)),
            ("sub", json!("")),
        ] {
            let mut c = claims();
            c[claim] = value;
            let token = sign_compact(&header("Ed25519"), &c, &key);
            assert!(!failing(&token, &set_for(&key)).is_empty(), "{claim}");
        }
    }

    #[test]
    fn p_9_4_the_audience_is_the_service_or_an_array_that_holds_it() {
        let key = ed();
        let mut c = claims();
        c["aud"] = json!(["other", "datastore"]);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert!(verify(&token, &set_for(&key), &policy(), NOW).is_ok());
        c["aud"] = json!(["other"]);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Aud]);
        c["aud"] = json!("other");
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Aud]);
        c["aud"] = json!([]);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Aud]);
    }

    #[test]
    fn p_9_4_the_issuer_must_be_the_one_of_the_service() {
        let key = ed();
        let mut c = claims();
        c["iss"] = json!("https://other.example");
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Iss]);
    }

    #[test]
    fn p_9_4_the_life_is_not_more_than_the_maximum_age() {
        let key = ed();
        let mut c = claims();
        c["exp"] = json!(1_792_569_901);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Life]);
        c["exp"] = json!(1_792_569_900);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert!(verify(&token, &set_for(&key), &policy(), NOW).is_ok());
    }

    #[test]
    fn p_9_4_exp_before_iat_is_refused() {
        let key = ed();
        let mut c = claims();
        c["iat"] = json!(NOW + 20);
        c["exp"] = json!(NOW + 10);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Life]);
    }

    #[test]
    fn p_9_4_iat_in_the_future_is_refused_beyond_the_skew() {
        let key = ed();
        let mut c = claims();
        c["iat"] = json!(NOW + 30);
        c["exp"] = json!(NOW + 130);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert!(verify(&token, &set_for(&key), &policy(), NOW).is_ok());
        c["iat"] = json!(NOW + 31);
        c["exp"] = json!(NOW + 131);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Iat]);
    }

    #[test]
    fn p_9_4_the_skew_applies_to_exp() {
        let key = ed();
        let mut c = claims();
        c["iat"] = json!(NOW - 200);
        c["exp"] = json!(NOW - 30);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert!(verify(&token, &set_for(&key), &policy(), NOW).is_ok());
        c["exp"] = json!(NOW - 31);
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Exp]);
    }

    #[test]
    fn p_9_4_an_unknown_claim_is_ignored() {
        let key = ed();
        let mut c = claims();
        c["scope"] = json!("anything");
        c["act"] = json!({"sub": "alice"});
        let token = sign_compact(&header("Ed25519"), &c, &key);
        assert!(verify(&token, &set_for(&key), &policy(), NOW).is_ok());
    }

    #[test]
    fn p_9_4_a_duplicate_member_in_the_claims_is_refused() {
        let key = ed();
        let payload = r#"{"iss":"https://edge.example","sub":"a","sub":"b","aud":"datastore","iat":1792569600,"exp":1792569900}"#;
        let token = sign_compact_text(r#"{"alg":"Ed25519","typ":"JWT"}"#, payload, &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Structure]);
        let header = r#"{"alg":"Ed25519","alg":"ES256","typ":"JWT"}"#;
        let token = sign_compact_text(header, &claims().to_string(), &key);
        assert_eq!(failing(&token, &set_for(&key)), vec![CheckName::Structure]);
    }

    #[test]
    fn p_9_4_a_token_that_is_not_a_jws_is_refused() {
        let key = ed();
        let good = sign_compact(&header("Ed25519"), &claims(), &key);
        let set = set_for(&key);
        for bad in [
            String::new(),
            "a.b".to_owned(),
            format!("{good}.x"),
            "a.b.c".to_owned(),
            "...".to_owned(),
            format!("{good}="),
            good.replace('.', "+"),
            "x".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert_eq!(failing(&bad, &set), vec![CheckName::Structure], "{bad:.20}");
        }
        // The header and the payload must be objects.
        let t = format!("{}.{}.{}", b64(&json!([1])), b64(&claims()), "AAAA");
        assert_eq!(failing(&t, &set), vec![CheckName::Structure]);
        let t = format!(
            "{}.{}.{}",
            b64(&header("Ed25519")),
            b64(&json!("x")),
            "AAAA"
        );
        assert!(failing(&t, &set).contains(&CheckName::Claims));
    }

    #[test]
    fn p_9_4_a_token_that_fails_gives_the_first_failed_check() {
        let key = ed();
        let mut c = claims();
        c["aud"] = json!("other");
        let token = sign_compact(&header("Ed25519"), &c, &key);
        let error = verify(&token, &set_for(&key), &policy(), NOW).unwrap_err();
        assert_eq!(error.check, CheckName::Aud);
        assert_eq!(error.rule, "9.4");
        assert!(error.to_string().contains("`aud`"));
    }

    #[test]
    fn p_9_3_profile_of_the_claims() {
        let codes = |c: Value| {
            profile_findings(&c)
                .iter()
                .map(|f| f.code)
                .collect::<Vec<_>>()
        };
        assert!(codes(claims()).is_empty());
        let mut c = claims();
        c.as_object_mut().unwrap().remove("owner");
        assert_eq!(codes(c.clone()), vec!["missing_owner"]);
        c["owner"] = json!("key:abc");
        assert_eq!(codes(c), vec!["bad_owner"]);
        let mut person = claims();
        person["sub"] = json!("alice");
        assert_eq!(codes(person.clone()), vec!["owner_on_person_token"]);
        person.as_object_mut().unwrap().remove("owner");
        assert!(codes(person).is_empty());
        let mut unknown = claims();
        unknown["sub"] = json!("svc:x");
        assert_eq!(codes(unknown), vec!["unknown_subject"]);
        let mut act = claims();
        act["act"] = json!({});
        assert_eq!(codes(act), vec!["act_claim"]);
    }

    #[test]
    fn p_9_5_the_owner_is_a_claim_for_logs() {
        let parsed = Claims::from_value(&claims()).unwrap();
        assert_eq!(parsed.owner.as_deref(), Some("alice"));
        let mut c = claims();
        c.as_object_mut().unwrap().remove("owner");
        assert_eq!(Claims::from_value(&c).unwrap().owner, None);
    }

    #[test]
    fn p_9_5_a_pep_ignores_an_owner_that_is_not_a_text() {
        let key = ed();
        let set = set_for(&key);
        for owner in [json!(42), json!(""), json!(null), json!(["a"])] {
            let mut c = claims();
            c["owner"] = owner;
            let token = sign_compact(&header("Ed25519"), &c, &key);
            assert!(verify(&token, &set, &policy(), NOW).is_err());
            let verified = verify_for_pep(&token, &set, &policy(), NOW).unwrap();
            assert_eq!(verified.claims.owner, None);
        }
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        let verified = verify_for_pep(&token, &set, &policy(), NOW).unwrap();
        assert_eq!(verified.claims.owner.as_deref(), Some("alice"));
    }

    #[test]
    fn p_9_5_a_pep_check_is_as_strict_as_verify_for_every_other_claim() {
        let key = ed();
        let set = set_for(&key);
        for member in ["iss", "sub", "aud", "iat", "exp"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(member);
            let token = sign_compact(&header("Ed25519"), &c, &key);
            assert!(
                verify_for_pep(&token, &set, &policy(), NOW).is_err(),
                "{member}"
            );
        }
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        assert!(verify_for_pep(&token, &set, &policy(), 1_792_569_900 + 31).is_err());
        let other = SigningKey::from_ed25519_seed(&[8; 32]);
        let forged = sign_compact(&header("Ed25519"), &claims(), &other);
        assert!(verify_for_pep(&forged, &set, &policy(), NOW).is_err());
    }

    #[test]
    fn p_9_9_a_kept_token_is_checked_again_at_each_clock_value() {
        let key = ed();
        let token = sign_compact(&header("Ed25519"), &claims(), &key);
        let set = set_for(&key);
        assert!(verify(&token, &set, &policy(), 1_792_569_900 + 30).is_ok());
        assert!(verify(&token, &set, &policy(), 1_792_569_900 + 31).is_err());
    }
}
