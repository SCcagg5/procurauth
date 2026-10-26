//! The typed model of a conformance case.
//!
//! The runner reads each case one time into these types. The reader is strict:
//! a duplicate member or an unknown member is an error. The data model is in
//! `conformance/README.md`. The schema is `schemas/conformance-case.schema.json`.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// The implementation that a case tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    /// A PEP: series U.
    Pep,
    /// A PDP: series D.
    Pdp,
    /// An edge: series E.
    Edge,
}

impl Role {
    /// The name of the role, as `--role` writes it.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Pep => "pep",
            Self::Pdp => "pdp",
            Self::Edge => "edge",
        }
    }

    /// The letter of the series of the role.
    pub(crate) fn series(self) -> char {
        match self {
            Self::Pep => 'U',
            Self::Pdp => 'D',
            Self::Edge => 'E',
        }
    }
}

/// The level of a rule in the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum Requirement {
    /// A rule with MUST.
    #[serde(rename = "MUST")]
    Must,
    /// A rule with SHOULD. A failure is a warning.
    #[serde(rename = "SHOULD")]
    Should,
}

impl Requirement {
    /// The word of the text.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Must => "MUST",
            Self::Should => "SHOULD",
        }
    }
}

/// A condition that makes the runner skip a case or a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Condition {
    /// The service has no action that lists a budget.
    NoBudgetAction,
    /// The service has no action that lists a ceiling.
    NoCeilingAction,
    /// The service does not publish the options route.
    NoOptionsRoute,
    /// The PEP keeps no answer.
    NoAnswerCache,
    /// The edge keeps no identity token.
    NoTokenCache,
    /// The service has no MCP endpoint.
    NoMcpEndpoint,
    /// The action `mcp.session` lists no budget.
    NoBudgetSession,
    /// The service has no tool that asks the client for input.
    NoInputTool,
    /// The service has no tool whose action waits for an approval.
    NoApprovalTool,
    /// The service has no use that needs two permissions.
    NoMultiAction,
    /// The key set of the edge holds one key only.
    SingleKeySet,
}

impl Condition {
    /// A sentence for the reason of a skip.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::NoBudgetAction => "the service has no action that lists a budget",
            Self::NoCeilingAction => "the service has no action that lists a ceiling",
            Self::NoOptionsRoute => "the service has no options route",
            Self::NoAnswerCache => "the PEP keeps no answer",
            Self::NoTokenCache => "the edge keeps no identity token",
            Self::NoMcpEndpoint => "the service has no MCP endpoint",
            Self::NoBudgetSession => "the action mcp.session lists no budget",
            Self::NoInputTool => "the service has no tool that asks for input",
            Self::NoApprovalTool => "the service has no tool that waits for an approval",
            Self::NoMultiAction => "the service has no use that needs two permissions",
            Self::SingleKeySet => "the key set of the edge holds one key",
        }
    }
}

/// One check of a value.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "Value")]
pub(crate) enum Matcher {
    /// The value is equal to this JSON value.
    Equals(Value),
    /// The value does not exist.
    Absent,
    /// The value exists.
    Present,
    /// The text of the value matches this expression.
    Regex(String),
    /// The value does not exist, or its text does not match this expression.
    NotRegex(String),
    /// The value is equal to one item of the list.
    OneOf(Vec<Value>),
}

impl TryFrom<Value> for Matcher {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, String> {
        let Value::Object(map) = value else {
            return Err(format!("a matcher must be an object, found {value}"));
        };
        if map.len() != 1 {
            return Err(format!(
                "a matcher must have exactly one member, found {}",
                map.len()
            ));
        }
        let Some((name, inner)) = map.into_iter().next() else {
            return Err("a matcher must have exactly one member".to_owned());
        };
        match (name.as_str(), inner) {
            ("equals", inner) => Ok(Self::Equals(inner)),
            ("absent", Value::Bool(true)) => Ok(Self::Absent),
            ("present", Value::Bool(true)) => Ok(Self::Present),
            ("regex", Value::String(text)) if !text.is_empty() => Ok(Self::Regex(text)),
            ("not_regex", Value::String(text)) if !text.is_empty() => Ok(Self::NotRegex(text)),
            ("one_of", Value::Array(items)) if !items.is_empty() => Ok(Self::OneOf(items)),
            (other, inner) => Err(format!(
                "the matcher `{other}` has a value that is not valid: {inner}"
            )),
        }
    }
}

/// The matchers of the members of a JSON document, by JSON Pointer.
pub(crate) type PointerMatchers = BTreeMap<String, Matcher>;

/// The matchers of HTTP headers, by header name.
pub(crate) type HeaderMatchers = BTreeMap<String, Matcher>;

/// A kind of use of the service under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    /// One use of an action that lists no budget.
    UsePlain,
    /// One use of an action that lists a budget.
    UseBudget,
    /// One use of an action that lists a ceiling.
    UseCeiling,
    /// One use on the service itself.
    UseService,
    /// One use that needs one more permission.
    UseMulti,
    /// A read of the action document.
    ReadActions,
    /// A read of the first level of the options route.
    ListOptions,
    /// A `tools/call` of a tool with no budget.
    McpCallPlain,
    /// A `tools/call` of a tool with a budget.
    McpCallBudget,
    /// A `tools/call` that ends with `InputRequiredResult`.
    McpCallInput,
    /// A `tools/call` of a tool that needs two permissions.
    McpCallMulti,
    /// A `tools/call` of a tool that waits for an approval.
    McpCallApproval,
    /// The approval of the call of the step before.
    McpApprove,
    /// The refusal of the approval of the call of the step before.
    McpRefuse,
}

impl Operation {
    /// Every operation, in the order of the data model.
    pub(crate) const ALL: [Self; 14] = [
        Self::UsePlain,
        Self::UseBudget,
        Self::UseCeiling,
        Self::UseService,
        Self::UseMulti,
        Self::ReadActions,
        Self::ListOptions,
        Self::McpCallPlain,
        Self::McpCallBudget,
        Self::McpCallInput,
        Self::McpCallMulti,
        Self::McpCallApproval,
        Self::McpApprove,
        Self::McpRefuse,
    ];

    /// The name in the data.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::UsePlain => "use_plain",
            Self::UseBudget => "use_budget",
            Self::UseCeiling => "use_ceiling",
            Self::UseService => "use_service",
            Self::UseMulti => "use_multi",
            Self::ReadActions => "read_actions",
            Self::ListOptions => "list_options",
            Self::McpCallPlain => "mcp_call_plain",
            Self::McpCallBudget => "mcp_call_budget",
            Self::McpCallInput => "mcp_call_input",
            Self::McpCallMulti => "mcp_call_multi",
            Self::McpCallApproval => "mcp_call_approval",
            Self::McpApprove => "mcp_approve",
            Self::McpRefuse => "mcp_refuse",
        }
    }

    /// The operation with this name.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.name() == name)
    }

    /// True for an operation of the MCP binding.
    pub(crate) fn is_mcp(self) -> bool {
        matches!(
            self,
            Self::McpCallPlain
                | Self::McpCallBudget
                | Self::McpCallInput
                | Self::McpCallMulti
                | Self::McpCallApproval
                | Self::McpApprove
                | Self::McpRefuse
        )
    }
}

/// An endpoint of the AuthZEN API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Endpoint {
    /// The Access Evaluation API.
    Evaluation,
    /// The Access Evaluations API.
    Evaluations,
    /// The metadata of the PDP.
    Metadata,
}

/// The request of a step.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestSpec {
    /// An operation, for a PEP.
    #[serde(default)]
    pub(crate) operation: Option<Operation>,
    /// An endpoint, for a PDP.
    #[serde(default)]
    pub(crate) endpoint: Option<Endpoint>,
    /// The HTTP method of a request that the case writes in full.
    #[serde(default)]
    pub(crate) method: Option<String>,
    /// The path of a request that the case writes in full.
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// The headers of the request.
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    /// The body, as JSON.
    #[serde(default)]
    pub(crate) body: Option<Value>,
    /// The body, as text.
    #[serde(default)]
    pub(crate) body_text: Option<String>,
    /// The name of a token of `given.tokens`.
    #[serde(default)]
    pub(crate) token: Option<String>,
}

/// The kind of document that `valid_as` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ValidAs {
    /// A good action document.
    ActionDocument,
    /// A good action document, and a report with no warning.
    ActionDocumentNoWarning,
    /// A good answer of the options route.
    OptionsAnswer,
    /// A good answer of the options route, and a report with no warning.
    OptionsAnswerNoWarning,
}

/// One entry of `pdp_questions`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuestionExpect {
    /// The matchers of the body of the question.
    pub(crate) json: PointerMatchers,
    /// The matchers of the headers of the question.
    #[serde(default)]
    pub(crate) headers: HeaderMatchers,
    /// The expected count. Without it, the entry expects one question.
    #[serde(default)]
    pub(crate) count: Option<Matcher>,
}

/// The member `upstream` of an expectation.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamExpect {
    /// The number of requests that reached the service.
    #[serde(default)]
    pub(crate) count: Option<Matcher>,
    /// The headers of the request that reached the service.
    #[serde(default)]
    pub(crate) headers: HeaderMatchers,
    /// The JOSE header of the identity token.
    #[serde(default)]
    pub(crate) token_header: PointerMatchers,
    /// The claims of the identity token.
    #[serde(default)]
    pub(crate) token_claims: PointerMatchers,
}

/// What a step expects.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expect {
    /// The HTTP status.
    #[serde(default)]
    pub(crate) status: Option<Matcher>,
    /// The headers of the answer.
    #[serde(default)]
    pub(crate) headers: HeaderMatchers,
    /// The body as text.
    #[serde(default)]
    pub(crate) body_text: Option<Matcher>,
    /// The members of a JSON body.
    #[serde(default)]
    pub(crate) json: PointerMatchers,
    /// The kind of document that the body must be.
    #[serde(default)]
    pub(crate) valid_as: Option<ValidAs>,
    /// The connections that the test PDP accepted.
    #[serde(default)]
    pub(crate) pdp_connections: Option<Matcher>,
    /// The questions that the test PDP received.
    #[serde(default)]
    pub(crate) pdp_questions: Vec<QuestionExpect>,
    /// The request that reached the service behind the edge.
    #[serde(default)]
    pub(crate) upstream: Option<UpstreamExpect>,
}

/// One step of a case.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    /// A short name.
    #[serde(default)]
    pub(crate) name: Option<String>,
    /// The conditions that make the runner skip this step.
    #[serde(default)]
    pub(crate) skip_if: Vec<Condition>,
    /// The request.
    pub(crate) request: RequestSpec,
    /// The expected result.
    pub(crate) expect: Expect,
}

/// A fixed clock of the case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClockSpec {
    /// The time in seconds since the Unix epoch.
    pub(crate) now: u64,
}

/// The directory of a case: a file name or the data itself.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum DirectoryRef {
    /// The name of a file in the directory `directories/`.
    Name(String),
    /// The data.
    Inline(Value),
}

/// A defect that makes an identity token bad.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Defect {
    /// The first byte of the signature changes.
    BadSignature,
    /// `exp` is past, beyond the clock skew.
    Expired,
    /// `iat` is in the future, beyond the clock skew.
    FutureIat,
    /// `exp` minus `iat` is above the maximum age.
    LongLife,
    /// The header `typ` is `at+jwt`.
    AtJwt,
    /// The header `alg` is `none`.
    AlgNone,
    /// The header `alg` is `HS256`.
    AlgHs256,
    /// The header `alg` is `EdDSA`.
    AlgEddsa,
    /// The claim `iss` is another issuer.
    WrongIssuer,
    /// The claim `aud` is another service.
    WrongAudience,
    /// The header `kid` is a key id that the key set does not hold.
    UnknownKid,
}

/// The algorithm of a good token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum TokenAlg {
    /// Ed25519.
    #[serde(rename = "Ed25519")]
    Ed25519,
    /// ES256.
    #[serde(rename = "ES256")]
    Es256,
}

impl TokenAlg {
    /// The name in the header.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Es256 => "ES256",
        }
    }
}

/// An identity token that the runner makes.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenSpec {
    /// The claim `sub`.
    pub(crate) subject: String,
    /// The claim `owner`.
    #[serde(default)]
    pub(crate) owner: Option<String>,
    /// The algorithm. The default is Ed25519.
    #[serde(default)]
    pub(crate) alg: Option<TokenAlg>,
    /// Claims to set. A `null` removes a claim.
    #[serde(default)]
    pub(crate) claims: serde_json::Map<String, Value>,
    /// Header members to set. A `null` removes a member.
    #[serde(default)]
    pub(crate) header: serde_json::Map<String, Value>,
    /// A named defect.
    #[serde(default)]
    pub(crate) defect: Option<Defect>,
}

/// The data that the runner sets up before the first step.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Given {
    /// The data of the test PDP.
    #[serde(default)]
    pub(crate) directory: Option<DirectoryRef>,
    /// A fixed clock.
    #[serde(default)]
    pub(crate) clock: Option<ClockSpec>,
    /// The first values of counters.
    #[serde(default)]
    pub(crate) counters: Vec<Value>,
    /// The tokens, by name.
    #[serde(default)]
    pub(crate) tokens: BTreeMap<String, TokenSpec>,
    /// The script of the test PDP, as JSON. A later step reads it into rules.
    #[serde(default)]
    pub(crate) pdp_script: Vec<Value>,
}

/// One conformance case.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Case {
    /// The id.
    pub(crate) id: String,
    /// The title.
    pub(crate) title: String,
    /// The role.
    pub(crate) role: Role,
    /// The paragraphs that the case tests.
    pub(crate) paragraphs: Vec<String>,
    /// The level of the rule.
    pub(crate) requirement: Requirement,
    /// The conditions that make the runner skip the case.
    #[serde(default)]
    pub(crate) skip_if: Vec<Condition>,
    /// A remark for the reader.
    #[serde(default)]
    pub(crate) notes: Option<String>,
    /// The data to set up.
    pub(crate) given: Given,
    /// The steps.
    pub(crate) steps: Vec<Step>,
}

impl Case {
    /// Read a case from the text of its file.
    ///
    /// # Errors
    /// Returns a message when the text is not JSON, has a duplicate member, or is not a case.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let value = procurauth_core::json::parse_str(text).map_err(|e| e.to_string())?;
        let case: Self = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if case.steps.is_empty() {
            return Err("the case has no step".to_owned());
        }
        for (index, step) in case.steps.iter().enumerate() {
            step.request
                .check_shape()
                .map_err(|why| format!("step {}: {why}", index + 1))?;
        }
        Ok(case)
    }
}

impl RequestSpec {
    /// Check that the request names its target in one way.
    pub(crate) fn check_shape(&self) -> Result<(), String> {
        let named = [
            self.operation.is_some(),
            self.endpoint.is_some(),
            self.method.is_some() || self.path.is_some(),
        ]
        .into_iter()
        .filter(|x| *x)
        .count();
        if named != 1 {
            return Err(
                "the request must have an operation, an endpoint, or a method with a path"
                    .to_owned(),
            );
        }
        if self.operation.is_none()
            && self.endpoint.is_none()
            && (self.method.is_none() || self.path.is_none())
        {
            return Err(
                "a request that the case writes in full needs a method and a path".to_owned(),
            );
        }
        if self.body.is_some() && self.body_text.is_some() {
            return Err("the request has a body and a body_text".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn matcher(value: Value) -> Result<Matcher, String> {
        Matcher::try_from(value)
    }

    #[test]
    fn a_matcher_has_one_of_six_forms() {
        assert_eq!(matcher(json!({"equals": 1})), Ok(Matcher::Equals(json!(1))));
        assert_eq!(matcher(json!({"absent": true})), Ok(Matcher::Absent));
        assert_eq!(matcher(json!({"present": true})), Ok(Matcher::Present));
        assert_eq!(
            matcher(json!({"regex": "a"})),
            Ok(Matcher::Regex("a".into()))
        );
        assert_eq!(
            matcher(json!({"not_regex": "a"})),
            Ok(Matcher::NotRegex("a".into()))
        );
        assert_eq!(
            matcher(json!({"one_of": [1, 2]})),
            Ok(Matcher::OneOf(vec![json!(1), json!(2)]))
        );
    }

    #[test]
    fn a_matcher_with_two_members_or_a_bad_value_is_an_error() {
        assert!(matcher(json!({"equals": 1, "absent": true})).is_err());
        assert!(matcher(json!({"absent": false})).is_err());
        assert!(matcher(json!({"one_of": []})).is_err());
        assert!(matcher(json!({"unknown": 1})).is_err());
        assert!(matcher(json!(3)).is_err());
    }

    #[test]
    fn a_case_with_an_unknown_member_is_an_error() {
        let text = r#"{"id":"U01","title":"t","role":"pep","paragraphs":["3.3"],"requirement":"MUST","given":{},"steps":[{"request":{"operation":"use_plain"},"expect":{"status":{"equals":200}}}],"extra":1}"#;
        assert!(Case::parse(text).is_err());
    }

    #[test]
    fn a_case_with_a_duplicate_member_is_an_error() {
        let text = r#"{"id":"U01","id":"U02"}"#;
        assert!(Case::parse(text).is_err());
    }

    #[test]
    fn a_request_names_its_target_in_one_way() {
        let both = RequestSpec {
            operation: Some(Operation::UsePlain),
            endpoint: Some(Endpoint::Evaluation),
            method: None,
            path: None,
            headers: BTreeMap::new(),
            body: None,
            body_text: None,
            token: None,
        };
        assert!(both.check_shape().is_err());
    }
}
