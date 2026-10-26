//! Identity tokens, good and bad (protocol 9.2 and 9.3).
//!
//! A good token has a header with `alg` and `typ`, the claims of 9.3, and a
//! signature of the key. A bad token has one defect that a service must
//! refuse. The options of the command line choose the defect. The claims
//! file can hold other defects: an old `exp`, a future `iat`, a long life, an
//! absent claim or an extra claim.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use procurauth_core::finding::Severity;
use procurauth_core::identity::{TOKEN_TYPE, profile_findings};
use procurauth_core::json::parse_str;
use procurauth_core::jws::{SigningKey, sign_compact};
use serde_json::{Map, Value, json};

use crate::cli::{AlgName, Format, MakeArgs};
use crate::files::read_text;
use crate::{EXIT_FINDING, EXIT_OK, Fault, Io, emit};

/// What the header and the signature of a token look like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The name in the header `alg`. `None` means the algorithm of the key.
    pub alg: Option<AlgName>,
    /// The header `typ`. `None` means `JWT`.
    pub typ: Option<String>,
    /// The header `kid`.
    pub kid: Option<String>,
    /// The header `crit`, with one name.
    pub crit: Option<String>,
    /// True to change the first byte of the signature.
    pub bad_signature: bool,
}

/// A token that [`make_token`] made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Made {
    /// The token, in compact JWS form.
    pub token: String,
    /// The header, as JSON.
    pub header: Value,
}

/// The header that a shape gives for a key.
pub fn header_for(shape: &Shape, key: &SigningKey) -> Value {
    let alg = shape
        .alg
        .map_or_else(|| key.algorithm().as_str(), AlgName::as_str);
    let mut header = Map::new();
    header.insert("alg".into(), json!(alg));
    header.insert(
        "typ".into(),
        json!(shape.typ.as_deref().unwrap_or(TOKEN_TYPE)),
    );
    if let Some(kid) = &shape.kid {
        header.insert("kid".into(), json!(kid));
    }
    if let Some(crit) = &shape.crit {
        header.insert("crit".into(), json!([crit]));
    }
    Value::Object(header)
}

/// Make a token. The function signs with the real algorithm of the key,
/// and it writes the header as the shape says. It never reads a clock.
pub fn make_token(shape: &Shape, claims: &Value, key: &SigningKey) -> Made {
    let header = header_for(shape, key);
    let mut token = if shape.alg == Some(AlgName::None) {
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    } else {
        sign_compact(&header, claims, key)
    };
    if shape.bad_signature && shape.alg != Some(AlgName::None) {
        token = flip_signature(&token);
    }
    Made { token, header }
}

/// Change the first byte of the signature of a compact JWS.
fn flip_signature(token: &str) -> String {
    let Some((signing_input, signature)) = token.rsplit_once('.') else {
        return token.to_owned();
    };
    let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap_or_default();
    if let Some(first) = bytes.first_mut() {
        *first ^= 0x01;
    }
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn read_key(path: &std::path::Path) -> Result<SigningKey, Fault> {
    let text = read_text(path, None)?;
    SigningKey::from_pkcs8_pem(&text).map_err(|_| {
        Fault::new(format!(
            "The file `{}` is not a private key. Expected a PKCS#8 PEM key for Ed25519 or P-256.",
            path.display()
        ))
    })
}

fn non_empty(name: &str, value: Option<&String>) -> Result<(), Fault> {
    match value {
        Some(text) if text.is_empty() => Err(Fault::new(format!(
            "Option `--{name}`: expected a text that is not empty, found an empty text."
        ))),
        _ => Ok(()),
    }
}

/// Run the subcommand `make`.
///
/// # Errors
/// Returns a fault for an input that cannot be read or that is not valid.
pub fn run_make(args: &MakeArgs, io: &mut Io<'_>) -> Result<u8, Fault> {
    non_empty("typ", args.typ.as_ref())?;
    non_empty("kid", args.kid.as_ref())?;
    non_empty("crit", args.crit.as_ref())?;
    if args.bad_signature && args.alg == Some(AlgName::None) {
        return Err(Fault::new(
            "Option `--bad-signature` cannot go with `--alg none`: the token has no signature.",
        ));
    }
    let key = read_key(&args.key)?;
    let text = read_text(&args.claims, Some(&mut *io.stdin))?;
    let claims = parse_str(&text).map_err(|error| {
        Fault::new(format!(
            "The claims in `{}` are not valid JSON: {error}.",
            args.claims.display()
        ))
    })?;
    if !claims.is_object() {
        return Err(Fault::new(format!(
            "The claims in `{}`: expected one JSON object, found another JSON value.",
            args.claims.display()
        )));
    }
    let findings = profile_findings(&claims);
    let refused = !args.allow_bad_claims && findings.iter().any(|f| f.severity == Severity::Error);
    let shape = Shape {
        alg: args.alg,
        typ: args.typ.clone(),
        kid: args.kid.clone(),
        crit: args.crit.clone(),
        bad_signature: args.bad_signature,
    };
    let made = (!refused).then(|| make_token(&shape, &claims, &key));
    match args.format {
        Format::Text => {
            let mut diagnostics = String::new();
            for finding in &findings {
                diagnostics.push_str(&format!("{finding}\n"));
            }
            emit(io.stderr, &diagnostics)?;
            if let Some(made) = &made {
                emit(io.stdout, &format!("{}\n", made.token))?;
            }
        }
        Format::Json => {
            let document = json!({
                "token": made.as_ref().map(|m| &m.token),
                "header": made.as_ref().map(|m| &m.header),
                "claims": made.as_ref().map(|_| &claims),
                "findings": findings,
            });
            emit(io.stdout, &render_json(&document))?;
        }
    }
    Ok(if refused { EXIT_FINDING } else { EXIT_OK })
}

/// Render a JSON document with two spaces of indent and a line end.
pub(crate) fn render_json(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> Shape {
        Shape {
            alg: None,
            typ: None,
            kid: None,
            crit: None,
            bad_signature: false,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_ed25519_seed(&[7; 32])
    }

    #[test]
    fn p_9_2_the_default_header_has_the_algorithm_of_the_key_and_the_type_jwt() {
        assert_eq!(
            header_for(&shape(), &key()),
            json!({"alg": "Ed25519", "typ": "JWT"})
        );
    }

    #[test]
    fn p_9_2_a_shape_changes_the_members_of_the_header() {
        let shape = Shape {
            alg: Some(AlgName::Hs256),
            typ: Some("at+jwt".to_owned()),
            kid: Some("k".to_owned()),
            crit: Some("exp".to_owned()),
            bad_signature: false,
        };
        assert_eq!(
            header_for(&shape, &key()),
            json!({"alg": "HS256", "typ": "at+jwt", "kid": "k", "crit": ["exp"]})
        );
    }

    #[test]
    fn p_9_4_a_bad_signature_differs_from_the_good_one_in_the_signature_only() {
        let claims = json!({"iss": "a"});
        let good = make_token(&shape(), &claims, &key()).token;
        let bad = make_token(
            &Shape {
                bad_signature: true,
                ..shape()
            },
            &claims,
            &key(),
        )
        .token;
        let (good_input, good_signature) = good.rsplit_once('.').unwrap();
        let (bad_input, bad_signature) = bad.rsplit_once('.').unwrap();
        assert_eq!(good_input, bad_input);
        assert_ne!(good_signature, bad_signature);
        assert_eq!(good_signature.len(), bad_signature.len());
    }

    #[test]
    fn p_9_2_the_algorithm_none_gives_an_empty_signature() {
        let token = make_token(
            &Shape {
                alg: Some(AlgName::None),
                ..shape()
            },
            &json!({"iss": "a"}),
            &key(),
        )
        .token;
        assert!(token.ends_with('.'));
        assert_eq!(token.split('.').count(), 3);
    }
}
