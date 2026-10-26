//! The metadata of the PDP (AuthZEN 1.0, Policy Decision Point Metadata).
//!
//! The PEP reads `/.well-known/authzen-configuration` to find the endpoints.
//! It also reads the four members of this protocol: `procurauth_usage_max_seconds`
//! (6.9), `procurauth_idle_max_seconds` (10.7), `procurauth_evaluations_max_bytes`
//! and `procurauth_evaluations_max_items` (10.7a). A member that the PEP does not
//! know is ignored. A member that it knows and that has a bad value makes the
//! metadata not valid.
//!
//! The PEP sends the credential of the service to the endpoints only. An
//! endpoint must have the origin of the PDP. The PEP refuses an endpoint on
//! another host. Thus a bad metadata document cannot take the credential to
//! another host.

use std::fmt;

use procurauth_core::json::parse_slice;
use serde_json::Value;

use crate::url::Url;

/// The path of the metadata document (AuthZEN 1.0).
pub const METADATA_PATH: &str = "/.well-known/authzen-configuration";
/// The default path of the Access Evaluation API (AuthZEN 1.0).
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";
/// The default path of the Access Evaluations API (AuthZEN 1.0).
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";

/// Why the metadata is not valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataError(String);

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MetadataError {}

fn error(text: impl Into<String>) -> MetadataError {
    MetadataError(text.into())
}

/// The endpoints and the limits that the PDP publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdpMetadata {
    /// The endpoint of the Access Evaluation API.
    pub evaluation_endpoint: Url,
    /// The endpoint of the Access Evaluations API. It is `None` when the PDP
    /// does not support this API.
    pub evaluations_endpoint: Option<Url>,
    /// `procurauth_usage_max_seconds`: the longest time to answer a question
    /// with `context.usage` (6.9).
    pub usage_max_seconds: Option<u64>,
    /// `procurauth_idle_max_seconds`: the longest idle time of a connection (10.7).
    pub idle_max_seconds: Option<u64>,
    /// `procurauth_evaluations_max_bytes`: the largest body of an Access Evaluations request (10.7a).
    pub evaluations_max_bytes: Option<u64>,
    /// `procurauth_evaluations_max_items`: the most items of an Access Evaluations request (10.7a).
    pub evaluations_max_items: Option<u64>,
}

/// The URL of the metadata document for the PDP at this URL (AuthZEN 1.0).
/// The well-known path comes after the host, and the path of the PDP comes last.
pub fn metadata_url(base: &Url) -> Url {
    let path = base.path.trim_end_matches('/');
    base.with_path(&format!("{METADATA_PATH}{path}"))
}

impl PdpMetadata {
    /// The default endpoints, for a PDP that publishes no metadata. The limits are unknown.
    pub fn defaults(base: &Url) -> Self {
        let path = base.path.trim_end_matches('/');
        Self {
            evaluation_endpoint: base.with_path(&format!("{path}{EVALUATION_PATH}")),
            evaluations_endpoint: Some(base.with_path(&format!("{path}{EVALUATIONS_PATH}"))),
            usage_max_seconds: None,
            idle_max_seconds: None,
            evaluations_max_bytes: None,
            evaluations_max_items: None,
        }
    }

    /// Read the metadata document of the PDP at `base`.
    ///
    /// # Errors
    /// Returns an error when the body is not a JSON object. Returns an error
    /// when `policy_decision_point` is absent or is not the URL of the PDP.
    /// Returns an error when an endpoint has another origin than the PDP.
    /// Returns an error when a member of this protocol is not a whole number of 1 or more.
    pub fn parse(base: &Url, body: &[u8]) -> Result<Self, MetadataError> {
        let value =
            parse_slice(body).map_err(|e| error(format!("the body is not valid JSON: {e}")))?;
        let Value::Object(map) = &value else {
            return Err(error("the body is not a JSON object"));
        };
        let identifier = map
            .get("policy_decision_point")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                error("the member `policy_decision_point` is absent, or it is not a string")
            })?;
        let expected = base.base_text();
        if identifier.trim_end_matches('/') != expected {
            return Err(error(format!(
                "the member `policy_decision_point` is {identifier:?}, and the URL of the PDP is {expected:?}"
            )));
        }
        let defaults = Self::defaults(base);
        let endpoint = |name: &str| -> Result<Option<Url>, MetadataError> {
            match map.get(name) {
                None => Ok(None),
                Some(Value::String(text)) => {
                    let url = Url::parse(text).map_err(|e| {
                        error(format!("the member `{name}` is not a good URL: {e}"))
                    })?;
                    if !url.same_origin(base) {
                        return Err(error(format!(
                            "the member `{name}` has another origin than the PDP: {text:?}"
                        )));
                    }
                    Ok(Some(url))
                }
                Some(_) => Err(error(format!("the member `{name}` is not a string"))),
            }
        };
        let whole = |name: &str| -> Result<Option<u64>, MetadataError> {
            match map.get(name) {
                None => Ok(None),
                Some(v) => match v.as_u64() {
                    Some(n) if n >= 1 => Ok(Some(n)),
                    _ => Err(error(format!(
                        "the member `{name}` is not a whole number of 1 or more: {v}"
                    ))),
                },
            }
        };
        let evaluation_endpoint =
            endpoint("access_evaluation_endpoint")?.unwrap_or(defaults.evaluation_endpoint);
        let evaluations_endpoint = endpoint("access_evaluations_endpoint")?;
        Ok(Self {
            evaluation_endpoint,
            evaluations_endpoint,
            usage_max_seconds: whole("procurauth_usage_max_seconds")?,
            idle_max_seconds: whole("procurauth_idle_max_seconds")?,
            evaluations_max_bytes: whole("procurauth_evaluations_max_bytes")?,
            evaluations_max_items: whole("procurauth_evaluations_max_items")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("http://127.0.0.1:8181").unwrap()
    }

    #[test]
    fn p_10_0_the_well_known_url_comes_after_the_host() {
        assert_eq!(
            metadata_url(&base()).to_text(),
            "http://127.0.0.1:8181/.well-known/authzen-configuration"
        );
        let with_path = Url::parse("https://pdp.example/tenant/a/").unwrap();
        assert_eq!(
            metadata_url(&with_path).to_text(),
            "https://pdp.example/.well-known/authzen-configuration/tenant/a"
        );
    }

    #[test]
    fn p_10_0_the_default_paths_are_the_paths_of_authzen() {
        let meta = PdpMetadata::defaults(&base());
        assert_eq!(meta.evaluation_endpoint.path, "/access/v1/evaluation");
        assert_eq!(
            meta.evaluations_endpoint.unwrap().path,
            "/access/v1/evaluations"
        );
        let with_path = PdpMetadata::defaults(&Url::parse("https://p.example/t").unwrap());
        assert_eq!(
            with_path.evaluation_endpoint.path,
            "/t/access/v1/evaluation"
        );
    }

    #[test]
    fn p_10_7a_the_four_members_of_the_protocol_are_read() {
        let body = br#"{
            "policy_decision_point": "http://127.0.0.1:8181",
            "access_evaluation_endpoint": "http://127.0.0.1:8181/e1",
            "access_evaluations_endpoint": "http://127.0.0.1:8181/e2",
            "procurauth_usage_max_seconds": 5,
            "procurauth_idle_max_seconds": 30,
            "procurauth_evaluations_max_bytes": 1048576,
            "procurauth_evaluations_max_items": 100,
            "unknown_member": [1]
        }"#;
        let meta = PdpMetadata::parse(&base(), body).unwrap();
        assert_eq!(meta.evaluation_endpoint.path, "/e1");
        assert_eq!(meta.evaluations_endpoint.unwrap().path, "/e2");
        assert_eq!(meta.usage_max_seconds, Some(5));
        assert_eq!(meta.idle_max_seconds, Some(30));
        assert_eq!(meta.evaluations_max_bytes, Some(1_048_576));
        assert_eq!(meta.evaluations_max_items, Some(100));
    }

    #[test]
    fn a_missing_evaluations_endpoint_means_no_evaluations_api() {
        let body = br#"{"policy_decision_point": "http://127.0.0.1:8181"}"#;
        let meta = PdpMetadata::parse(&base(), body).unwrap();
        assert_eq!(meta.evaluation_endpoint.path, "/access/v1/evaluation");
        assert!(meta.evaluations_endpoint.is_none());
        assert_eq!(meta.usage_max_seconds, None);
    }

    #[test]
    fn a_bad_document_is_not_valid() {
        for body in [
            &br#"[]"#[..],
            br#"{"policy_decision_point": "http://other:1"}"#,
            br#"{}"#,
            br#"{"policy_decision_point": "http://127.0.0.1:8181", "access_evaluation_endpoint": "http://evil.example/e"}"#,
            br#"{"policy_decision_point": "http://127.0.0.1:8181", "access_evaluation_endpoint": 5}"#,
            br#"{"policy_decision_point": "http://127.0.0.1:8181", "procurauth_idle_max_seconds": 0}"#,
            br#"{"policy_decision_point": "http://127.0.0.1:8181", "procurauth_usage_max_seconds": "5"}"#,
            br#"{"policy_decision_point": "http://127.0.0.1:8181", "procurauth_evaluations_max_items": 1.5}"#,
            br#"{"policy_decision_point": "http://127.0.0.1:8181", "policy_decision_point": "x"}"#,
            b"not json",
        ] {
            assert!(
                PdpMetadata::parse(&base(), body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
