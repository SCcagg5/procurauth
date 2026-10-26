//! The profile: what the runner needs to know about the target.
//!
//! The profile is one JSON file. The schema is closed. An unknown member or a
//! duplicate member stops the program. The reader gives every error with the
//! path of the member, the expected type or range, and the value found.
//!
//! The reader parses the file one time into a [`Profile`]. A file member is a
//! path, relative to the directory of the profile. A secret comes only from
//! such a file. The schema is `schemas/conformance-profile.schema.json`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use procurauth_core::finding::{JsonPath, Report, show, type_word};
use procurauth_core::json::parse_str;
use procurauth_core::names::validate_id;
use procurauth_core::read::{Obj, Unknown};
use serde_json::Value;

use crate::http::HttpUrl;
use crate::model::{Operation, TokenAlg};

/// The rule number for the findings of the profile.
const RULE: &str = "profile";

/// The default time for one request, in seconds.
pub(crate) const DEFAULT_REQUEST_SECONDS: u64 = 10;
/// The default time for one case, in seconds.
pub(crate) const DEFAULT_CASE_SECONDS: u64 = 60;
/// The default wait before the runner counts the questions of a step, in milliseconds.
pub(crate) const DEFAULT_SETTLE_MS: u64 = 25;
/// The default number of control questions.
pub(crate) const DEFAULT_MAX_QUESTIONS: u64 = 100;

/// The time limits of the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Timeouts {
    /// The time for one request to the target.
    pub(crate) request: Duration,
    /// The time for one case.
    pub(crate) case: Duration,
    /// The wait before the runner counts questions and upstream requests.
    pub(crate) settle: Duration,
}

/// A private key that signs identity tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyFile {
    /// The algorithm of the key.
    pub(crate) alg: TokenAlg,
    /// The `kid` of the key.
    pub(crate) kid: Option<String>,
    /// The file with the key.
    pub(crate) file: PathBuf,
}

/// How a service reads the identity token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenProfile {
    /// The name of the header with the token.
    pub(crate) header: String,
    /// The value of `iss` that the service expects.
    pub(crate) iss: String,
    /// The longest life that the service accepts.
    pub(crate) max_age_seconds: u64,
    /// The clock skew of the service.
    pub(crate) skew_seconds: u64,
    /// The keys of the test edge.
    pub(crate) keys: Vec<KeyFile>,
}

/// The listener that the service calls as its PDP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PdpListen {
    /// The address of the listener.
    pub(crate) listen: SocketAddr,
    /// The file with the credential that the service sends to the PDP.
    pub(crate) credential_file: Option<PathBuf>,
}

/// A request that the runner sends before each case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResetRequest {
    /// The method.
    pub(crate) method: String,
    /// The path.
    pub(crate) path: String,
    /// The headers.
    pub(crate) headers: BTreeMap<String, String>,
}

/// The MCP endpoint of a service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McpProfile {
    /// The path of the endpoint.
    pub(crate) path: String,
    /// True when the action `mcp.session` lists a budget.
    pub(crate) session_budget: bool,
}

/// The definition of one operation.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct OpDef {
    /// The method.
    pub(crate) method: Option<String>,
    /// The path template.
    pub(crate) path: Option<String>,
    /// The headers.
    pub(crate) headers: BTreeMap<String, String>,
    /// The body template, as JSON.
    pub(crate) body: Option<Value>,
    /// The body template, as text.
    pub(crate) body_text: Option<String>,
    /// The variable `action`.
    pub(crate) action: Option<String>,
    /// The variable `resource_type`.
    pub(crate) resource_type: Option<String>,
    /// The variable `resource_id`.
    pub(crate) resource_id: Option<String>,
    /// The variable `ancestors`.
    pub(crate) ancestors: Option<Value>,
    /// The variable `tool`.
    pub(crate) tool: Option<String>,
    /// The variable `ceiling`.
    pub(crate) ceiling: Option<String>,
    /// The variable `ceiling_value`.
    pub(crate) ceiling_value: Option<u64>,
    /// The arguments of the tool of an MCP call.
    pub(crate) arguments: Option<Value>,
    /// Names for members of the JSON body of the answer to the step before, by JSON Pointer.
    pub(crate) capture: BTreeMap<String, String>,
}

/// The profile of a PEP.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PepProfile {
    /// The id of the service.
    pub(crate) service: String,
    /// The identity token.
    pub(crate) token: TokenProfile,
    /// The test PDP.
    pub(crate) pdp: PdpListen,
    /// True when the PEP keeps answers.
    pub(crate) answer_cache: bool,
    /// A request that clears the state of the service before each case.
    pub(crate) reset: Option<ResetRequest>,
    /// The type of the nodes at the first level of the options route.
    pub(crate) options_type: Option<String>,
    /// The MCP endpoint.
    pub(crate) mcp: Option<McpProfile>,
    /// The operations.
    pub(crate) operations: BTreeMap<Operation, OpDef>,
}

/// How the runner proves that the PDP holds the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryCheck {
    /// True to ask control questions.
    pub(crate) enabled: bool,
    /// The most control questions.
    pub(crate) max_questions: usize,
}

/// A request that loads the data of a case in the PDP under test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoadHook {
    /// The URL.
    pub(crate) url: HttpUrl,
    /// The method: `PUT` or `POST`.
    pub(crate) method: String,
}

/// The profile of a PDP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PdpProfile {
    /// True to start `fake-pdp` in the process, with the directory of each case.
    pub(crate) spawn_fake_pdp: bool,
    /// The file with the credential that the PDP asks for.
    pub(crate) credential_file: Option<PathBuf>,
    /// The check of the directory.
    pub(crate) directory_check: DirectoryCheck,
    /// A request that loads the data of a case.
    pub(crate) load: Option<LoadHook>,
    /// A request that puts the counters back to their first values.
    pub(crate) reset_url: Option<HttpUrl>,
    /// The URL that sets the clock of the PDP.
    pub(crate) clock_admin_url: Option<HttpUrl>,
}

/// The public keys of the edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustProfile {
    /// The value of `iss`.
    pub(crate) iss: String,
    /// The longest life of a token.
    pub(crate) max_age_seconds: u64,
    /// The clock skew.
    pub(crate) skew_seconds: u64,
    /// A JWK Set file.
    pub(crate) jwks_file: Option<PathBuf>,
    /// Public keys in PEM form.
    pub(crate) pem_keys: Vec<(PathBuf, Option<String>)>,
}

/// The key that the edge accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidKey {
    /// The file with the text of the key.
    pub(crate) text_file: PathBuf,
    /// The subject id of the key.
    pub(crate) subject: String,
    /// The owner of the key.
    pub(crate) owner: String,
}

/// The data of the PDP that the edge calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DirectorySource {
    /// The name of a file of the directory `directories/`.
    Named(String),
    /// A path.
    File(PathBuf),
}

/// The PDP that the edge calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EdgePdp {
    /// The address of the listener.
    pub(crate) listen: SocketAddr,
    /// The data.
    pub(crate) directory: DirectorySource,
    /// The file with the credential that the edge sends to the PDP.
    pub(crate) credential_file: Option<PathBuf>,
}

/// The profile of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EdgeProfile {
    /// The id of the service behind the edge.
    pub(crate) service: String,
    /// The name of the header with the identity token.
    pub(crate) token_header: String,
    /// The public keys of the edge.
    pub(crate) trust: TrustProfile,
    /// The key that the edge accepts.
    pub(crate) valid_key: ValidKey,
    /// The file with the text of a key whose subject has no `access`.
    pub(crate) no_access_key_file: PathBuf,
    /// The file with the text of a key that the edge does not know.
    pub(crate) unknown_key_file: PathBuf,
    /// The address of the listener for the service behind the edge.
    pub(crate) upstream_listen: SocketAddr,
    /// The PDP.
    pub(crate) pdp: EdgePdp,
    /// The path of the MCP endpoint.
    pub(crate) mcp_path: Option<String>,
    /// True when the edge keeps identity tokens.
    pub(crate) token_cache: bool,
}

/// The whole profile.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Profile {
    /// The time limits.
    pub(crate) timeouts: Timeouts,
    /// The profile of a PEP.
    pub(crate) pep: Option<PepProfile>,
    /// The profile of a PDP.
    pub(crate) pdp: Option<PdpProfile>,
    /// The profile of an edge.
    pub(crate) edge: Option<EdgeProfile>,
    /// The JSON of the file. The effective configuration reads it.
    pub(crate) raw: Value,
}

const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

struct Reader {
    report: Report,
    base: PathBuf,
}

impl Reader {
    fn error(&mut self, path: &JsonPath, message: String) {
        self.report.error(path, RULE, "profile", message);
    }

    fn obj<'a>(&mut self, value: &'a Value, path: &JsonPath) -> Option<Obj<'a>> {
        Obj::new(value, path, RULE, Unknown::Error, &mut self.report)
    }

    fn string(&mut self, obj: &mut Obj<'_>, key: &'static str) -> Option<String> {
        let path = obj.member_path(key);
        let text = obj.string(key, &mut self.report)?;
        self.non_empty(&path, key, text)
    }

    fn string_opt(&mut self, obj: &mut Obj<'_>, key: &'static str) -> Option<String> {
        let path = obj.member_path(key);
        let text = obj.string_opt(key, &mut self.report)?;
        self.non_empty(&path, key, text)
    }

    fn non_empty(&mut self, path: &JsonPath, key: &str, text: &str) -> Option<String> {
        if text.is_empty() {
            self.error(
                path,
                format!("Member `{key}`: expected a text that is not empty, found an empty text."),
            );
            None
        } else {
            Some(text.to_owned())
        }
    }

    fn range(
        &mut self,
        obj: &mut Obj<'_>,
        key: &'static str,
        low: u64,
        high: u64,
        required: bool,
    ) -> Option<u64> {
        let path = obj.member_path(key);
        let number = if required {
            obj.whole(key, &mut self.report)?
        } else {
            obj.whole_opt(key, &mut self.report)?
        };
        if (low..=high).contains(&number) {
            Some(number)
        } else {
            self.error(
                &path,
                format!(
                    "Member `{key}`: expected a whole number from {low} to {high}, found {number}."
                ),
            );
            None
        }
    }

    fn boolean(&mut self, obj: &mut Obj<'_>, key: &'static str) -> Option<bool> {
        obj.boolean_opt(key, &mut self.report)
    }

    /// A path to a file. The path is relative to the directory of the profile.
    fn file(&mut self, obj: &mut Obj<'_>, key: &'static str, required: bool) -> Option<PathBuf> {
        let text = if required {
            self.string(obj, key)
        } else {
            self.string_opt(obj, key)
        }?;
        Some(self.base.join(text))
    }

    fn address(&mut self, obj: &mut Obj<'_>, key: &'static str) -> Option<SocketAddr> {
        let path = obj.member_path(key);
        let text = obj.string(key, &mut self.report)?;
        match text.parse::<SocketAddr>() {
            Ok(address) => Some(address),
            Err(_) => {
                self.error(
                    &path,
                    format!(
                        "Member `{key}`: expected an address and a port, as ADDRESS:PORT with a numeric address, found \"{text}\"."
                    ),
                );
                None
            }
        }
    }

    fn url(&mut self, obj: &mut Obj<'_>, key: &'static str) -> Option<HttpUrl> {
        let path = obj.member_path(key);
        let text = obj.string_opt(key, &mut self.report)?;
        match HttpUrl::parse(text) {
            Ok(url) => Some(url),
            Err(why) => {
                self.error(
                    &path,
                    format!("Member `{key}`: expected an http URL, found \"{text}\": {why}."),
                );
                None
            }
        }
    }

    fn service_id(&mut self, obj: &mut Obj<'_>) -> Option<String> {
        let path = obj.member_path("service");
        let text = self.string(obj, "service")?;
        match validate_id(&text) {
            Ok(()) => Some(text),
            Err(why) => {
                self.error(
                    &path,
                    format!("Member `service`: expected an id of 1 to 256 bytes with no control character, found \"{text}\": {why}."),
                );
                None
            }
        }
    }

    fn header_name(&mut self, obj: &mut Obj<'_>, key: &'static str) -> Option<String> {
        let path = obj.member_path(key);
        let text = self.string(obj, key)?;
        let token = text.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        let forbidden = ["authorization", "proxy-authorization", "cookie"]
            .contains(&text.to_ascii_lowercase().as_str());
        if token && !forbidden {
            Some(text)
        } else {
            self.error(
                &path,
                format!(
                    "Member `{key}`: expected a header name of letters, digits and hyphens, and not Authorization, Proxy-Authorization or Cookie (protocol 9.4), found \"{text}\"."
                ),
            );
            None
        }
    }

    fn url_path(&mut self, obj: &mut Obj<'_>, key: &'static str, required: bool) -> Option<String> {
        let path = obj.member_path(key);
        let text = if required {
            self.string(obj, key)
        } else {
            self.string_opt(obj, key)
        }?;
        if text.starts_with('/') && !text.contains(char::is_whitespace) {
            Some(text)
        } else {
            self.error(
                &path,
                format!(
                    "Member `{key}`: expected a path that starts with a slash, found \"{text}\"."
                ),
            );
            None
        }
    }

    fn strings_map(&mut self, obj: &mut Obj<'_>, key: &'static str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let path = obj.member_path(key);
        let Some(value) = obj.optional(key) else {
            return out;
        };
        let Some(map) = value.as_object() else {
            self.error(
                &path,
                format!(
                    "Member `{key}`: expected an object of strings, found {}: {}.",
                    type_word(value),
                    show(value)
                ),
            );
            return out;
        };
        for (name, item) in map {
            match item.as_str() {
                Some(text) => {
                    out.insert(name.clone(), text.to_owned());
                }
                None => self.error(
                    &path.key(name),
                    format!(
                        "Member `{name}`: expected a string, found {}: {}.",
                        type_word(item),
                        show(item)
                    ),
                ),
            }
        }
        out
    }
}

fn read_timeouts(r: &mut Reader, obj: &mut Obj<'_>) -> Timeouts {
    let mut request = DEFAULT_REQUEST_SECONDS;
    let mut case = DEFAULT_CASE_SECONDS;
    let mut settle = DEFAULT_SETTLE_MS;
    if let Some(mut t) = obj.object_opt("timeouts", RULE, Unknown::Error, &mut r.report) {
        request = r
            .range(&mut t, "request_seconds", 1, 600, false)
            .unwrap_or(request);
        case = r
            .range(&mut t, "case_seconds", 1, 3600, false)
            .unwrap_or(case);
        settle = r
            .range(&mut t, "settle_ms", 0, 10_000, false)
            .unwrap_or(settle);
        t.finish(&mut r.report);
    }
    Timeouts {
        request: Duration::from_secs(request),
        case: Duration::from_secs(case),
        settle: Duration::from_millis(settle),
    }
}

fn read_token(r: &mut Reader, obj: &mut Obj<'_>) -> Option<TokenProfile> {
    let mut t = obj.object("token", RULE, Unknown::Error, &mut r.report)?;
    let header = r.header_name(&mut t, "header");
    let iss = r.string(&mut t, "iss");
    let max_age = r.range(&mut t, "max_age_seconds", 1, 31_536_000, true);
    let skew = r.range(&mut t, "skew_seconds", 0, 86_400, true);
    let mut keys = Vec::new();
    let keys_path = t.member_path("keys");
    if let Some(items) = t.array("keys", &mut r.report) {
        if items.is_empty() {
            r.error(
                &keys_path,
                "Member `keys`: expected an array of 1 to 2 keys, found an empty array.".to_owned(),
            );
        }
        if items.len() > 2 {
            r.error(
                &keys_path,
                format!(
                    "Member `keys`: expected an array of 1 to 2 keys, found {} keys.",
                    items.len()
                ),
            );
        }
        for (index, item) in items.iter().enumerate() {
            let path = keys_path.index(index);
            let Some(mut k) = r.obj(item, &path) else {
                continue;
            };
            let alg_path = k.member_path("alg");
            let alg = match k.string("alg", &mut r.report) {
                Some("Ed25519") => Some(TokenAlg::Ed25519),
                Some("ES256") => Some(TokenAlg::Es256),
                Some(other) => {
                    r.error(
                        &alg_path,
                        format!(
                            "Member `alg`: expected \"Ed25519\" or \"ES256\", found \"{other}\"."
                        ),
                    );
                    None
                }
                None => None,
            };
            let kid = r.string_opt(&mut k, "kid");
            let file = r.file(&mut k, "file", true);
            k.finish(&mut r.report);
            if let (Some(alg), Some(file)) = (alg, file) {
                if keys.iter().any(|existing: &KeyFile| existing.alg == alg) {
                    r.error(
                        &alg_path,
                        format!(
                            "Member `alg`: expected a different algorithm for each key, found \"{}\" two times.",
                            alg.name()
                        ),
                    );
                } else {
                    keys.push(KeyFile { alg, kid, file });
                }
            }
        }
    }
    t.finish(&mut r.report);
    Some(TokenProfile {
        header: header?,
        iss: iss?,
        max_age_seconds: max_age?,
        skew_seconds: skew?,
        keys,
    })
}

fn read_pointer_map(r: &mut Reader, obj: &mut Obj<'_>) -> BTreeMap<String, String> {
    let map = r.strings_map(obj, "capture");
    let path = obj.member_path("capture");
    for (name, pointer) in &map {
        let name_ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !name_ok {
            r.error(
                &path.key(name),
                format!("Member `{name}`: expected a name of lower-case letters, digits and underscores."),
            );
        }
        if !(pointer.is_empty() || pointer.starts_with('/')) {
            r.error(
                &path.key(name),
                format!("Member `{name}`: expected a JSON Pointer, found \"{pointer}\"."),
            );
        }
    }
    map
}

fn read_ancestors(r: &mut Reader, obj: &mut Obj<'_>) -> Option<Value> {
    let path = obj.member_path("ancestors");
    let value = obj.optional("ancestors")?;
    let Some(items) = value.as_array() else {
        r.error(
            &path,
            format!(
                "Member `ancestors`: expected an array of objects with `type` and `id`, found {}: {}.",
                type_word(value),
                show(value)
            ),
        );
        return None;
    };
    let mut good = true;
    for (index, item) in items.iter().enumerate() {
        let ok = item.as_object().is_some_and(|m| {
            m.len() == 2
                && m.get("type").is_some_and(Value::is_string)
                && m.get("id").is_some_and(Value::is_string)
        });
        if !ok {
            good = false;
            r.error(
                &path.index(index),
                format!(
                    "Expected an object with the string members `type` and `id` only, found {}.",
                    show(item)
                ),
            );
        }
    }
    good.then(|| value.clone())
}

fn read_operation(
    r: &mut Reader,
    operation: Operation,
    value: &Value,
    path: &JsonPath,
) -> Option<OpDef> {
    let mut o = r.obj(value, path)?;
    let method_path = o.member_path("method");
    let method = match o.string_opt("method", &mut r.report) {
        Some(m) if METHODS.contains(&m) => Some(m.to_owned()),
        Some(m) => {
            r.error(
                &method_path,
                format!(
                    "Member `method`: expected one of {}, found \"{m}\".",
                    METHODS.join(", ")
                ),
            );
            None
        }
        None => None,
    };
    let path_path = o.member_path("path");
    let target = match o.string_opt("path", &mut r.report) {
        Some(p) if p.starts_with('/') || p.starts_with("{{") => Some(p.to_owned()),
        Some(p) => {
            r.error(
                &path_path,
                format!("Member `path`: expected a path that starts with a slash or a variable, found \"{p}\"."),
            );
            None
        }
        None => None,
    };
    let headers = r.strings_map(&mut o, "headers");
    let body = o.optional("body").cloned();
    let body_text = o.string_opt("body_text", &mut r.report).map(str::to_owned);
    if body.is_some() && body_text.is_some() {
        r.error(
            path,
            "Members `body` and `body_text` contradict each other: give only one.".to_owned(),
        );
    }
    let def = OpDef {
        method,
        path: target,
        headers,
        body,
        body_text,
        action: r.string_opt(&mut o, "action"),
        resource_type: r.string_opt(&mut o, "resource_type"),
        resource_id: r.string_opt(&mut o, "resource_id"),
        ancestors: read_ancestors(r, &mut o),
        tool: r.string_opt(&mut o, "tool"),
        ceiling: r.string_opt(&mut o, "ceiling"),
        ceiling_value: r.range(&mut o, "ceiling_value", 0, u64::MAX, false),
        arguments: o.optional("arguments").cloned(),
        capture: read_pointer_map(r, &mut o),
    };
    o.finish(&mut r.report);
    check_operation(r, operation, &def, path);
    Some(def)
}

/// The members that an operation needs.
fn check_operation(r: &mut Reader, operation: Operation, def: &OpDef, path: &JsonPath) {
    use Operation::{
        ListOptions, McpApprove, McpCallApproval, McpCallBudget, McpCallInput, McpCallMulti,
        McpCallPlain, McpRefuse, ReadActions, UseBudget, UseCeiling, UseMulti, UsePlain,
        UseService,
    };
    let mut need = |present: bool, name: &str| {
        if !present {
            r.report.error(
                path,
                RULE,
                "profile",
                format!(
                    "Operation `{}`: member `{name}` is absent, and the operation needs it.",
                    operation.name()
                ),
            );
        }
    };
    match operation {
        UsePlain | UseBudget | UseCeiling | UseMulti => {
            need(def.method.is_some(), "method");
            need(def.path.is_some(), "path");
            need(def.action.is_some(), "action");
            need(def.resource_type.is_some(), "resource_type");
            need(def.resource_id.is_some(), "resource_id");
            need(def.ancestors.is_some(), "ancestors");
            if operation == UseCeiling {
                need(def.ceiling.is_some(), "ceiling");
                need(def.ceiling_value.is_some(), "ceiling_value");
            }
        }
        UseService => {
            need(def.method.is_some(), "method");
            need(def.path.is_some(), "path");
            need(def.action.is_some(), "action");
        }
        McpCallPlain | McpCallBudget | McpCallInput | McpCallMulti | McpCallApproval => {
            need(def.tool.is_some(), "tool");
            need(def.action.is_some(), "action");
        }
        McpApprove | McpRefuse => {
            need(def.body.is_some() || def.body_text.is_some(), "body");
        }
        ReadActions | ListOptions => {}
    }
}

fn read_pep(r: &mut Reader, value: &Value, path: &JsonPath) -> Option<PepProfile> {
    let mut obj = r.obj(value, path)?;
    let service = r.service_id(&mut obj);
    let token = read_token(r, &mut obj);
    let pdp = read_pdp_listen(r, &mut obj, "pdp");
    let answer_cache = r.boolean(&mut obj, "answer_cache").unwrap_or(false);
    let reset = read_reset(r, &mut obj);
    let options_type = r.string_opt(&mut obj, "options_type");
    let mcp = read_mcp(r, &mut obj);
    let mut operations = BTreeMap::new();
    let ops_path = obj.member_path("operations");
    if let Some(mut ops) = obj.object("operations", RULE, Unknown::Ignore, &mut r.report) {
        // The reader of the operations reads each name by itself, to report an unknown name.
        let entries: Vec<(String, Value)> = match value.get("operations").and_then(Value::as_object)
        {
            Some(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            None => Vec::new(),
        };
        let _ = &mut ops;
        for (name, item) in &entries {
            let item_path = ops_path.key(name);
            match Operation::from_name(name) {
                Some(operation) => {
                    if let Some(def) = read_operation(r, operation, item, &item_path) {
                        operations.insert(operation, def);
                    }
                }
                None => r.error(
                    &item_path,
                    format!(
                        "Member `{name}` is not an operation. Expected one of {}.",
                        Operation::ALL.map(Operation::name).join(", ")
                    ),
                ),
            }
        }
    }
    obj.finish(&mut r.report);
    // Rules between members.
    if mcp.is_none()
        && let Some(op) = operations.keys().find(|op| op.is_mcp())
    {
        r.error(
            &ops_path.key(op.name()),
            format!(
                "Operation `{}` needs the member `mcp`, and the profile has none.",
                op.name()
            ),
        );
    }
    if options_type.is_none() && operations.contains_key(&Operation::ListOptions) {
        r.error(
            &ops_path.key("list_options"),
            "Operation `list_options` needs the member `options_type`, and the profile has none."
                .to_owned(),
        );
    }
    Some(PepProfile {
        service: service?,
        token: token?,
        pdp: pdp?,
        answer_cache,
        reset,
        options_type,
        mcp,
        operations,
    })
}

fn read_pdp_listen(r: &mut Reader, obj: &mut Obj<'_>, key: &'static str) -> Option<PdpListen> {
    let mut p = obj.object(key, RULE, Unknown::Error, &mut r.report)?;
    let listen = r.address(&mut p, "listen");
    let credential_file = r.file(&mut p, "credential_file", false);
    p.finish(&mut r.report);
    Some(PdpListen {
        listen: listen?,
        credential_file,
    })
}

fn read_reset(r: &mut Reader, obj: &mut Obj<'_>) -> Option<ResetRequest> {
    let mut x = obj.object_opt("reset", RULE, Unknown::Error, &mut r.report)?;
    let method_path = x.member_path("method");
    let method = match x.string("method", &mut r.report) {
        Some(m) if METHODS.contains(&m) => Some(m.to_owned()),
        Some(m) => {
            r.error(
                &method_path,
                format!(
                    "Member `method`: expected one of {}, found \"{m}\".",
                    METHODS.join(", ")
                ),
            );
            None
        }
        None => None,
    };
    let path = r.url_path(&mut x, "path", true);
    let headers = r.strings_map(&mut x, "headers");
    x.finish(&mut r.report);
    Some(ResetRequest {
        method: method?,
        path: path?,
        headers,
    })
}

fn read_mcp(r: &mut Reader, obj: &mut Obj<'_>) -> Option<McpProfile> {
    let mut m = obj.object_opt("mcp", RULE, Unknown::Error, &mut r.report)?;
    let path = r.url_path(&mut m, "path", true);
    let session_budget = r.boolean(&mut m, "session_budget").unwrap_or(false);
    m.finish(&mut r.report);
    Some(McpProfile {
        path: path?,
        session_budget,
    })
}

fn read_pdp(r: &mut Reader, value: &Value, path: &JsonPath) -> Option<PdpProfile> {
    let mut obj = r.obj(value, path)?;
    let spawn = r.boolean(&mut obj, "spawn_fake_pdp").unwrap_or(false);
    let credential_file = r.file(&mut obj, "credential_file", false);
    let mut check = DirectoryCheck {
        enabled: true,
        max_questions: DEFAULT_MAX_QUESTIONS as usize,
    };
    if let Some(mut c) = obj.object_opt("directory_check", RULE, Unknown::Error, &mut r.report) {
        let mode_path = c.member_path("mode");
        match c.string_opt("mode", &mut r.report) {
            Some("control_questions") => {}
            Some("none") => check.enabled = false,
            Some(other) => r.error(
                &mode_path,
                format!(
                    "Member `mode`: expected \"control_questions\" or \"none\", found \"{other}\"."
                ),
            ),
            None => {}
        }
        if let Some(n) = r.range(&mut c, "max_questions", 1, 10_000, false) {
            check.max_questions = usize::try_from(n).unwrap_or(10_000);
        }
        c.finish(&mut r.report);
    }
    let load = read_load(r, &mut obj);
    let reset_url = r.url(&mut obj, "reset_url");
    let clock_admin_url = r.url(&mut obj, "clock_admin_url");
    obj.finish(&mut r.report);
    if spawn {
        for (name, present) in [
            ("load", load.is_some()),
            ("reset_url", reset_url.is_some()),
            ("clock_admin_url", clock_admin_url.is_some()),
        ] {
            if present {
                r.error(
                    &path.key(name),
                    format!("Members `spawn_fake_pdp` and `{name}` contradict each other: the PDP that the runner starts needs no `{name}`."),
                );
            }
        }
    }
    Some(PdpProfile {
        spawn_fake_pdp: spawn,
        credential_file,
        directory_check: check,
        load,
        reset_url,
        clock_admin_url,
    })
}

fn read_load(r: &mut Reader, obj: &mut Obj<'_>) -> Option<LoadHook> {
    let mut l = obj.object_opt("load", RULE, Unknown::Error, &mut r.report)?;
    let url = r.url(&mut l, "url");
    if url.is_none() && !l.has("url") {
        r.error(
            l.path(),
            "Member `url` is absent, and the member `load` needs it.".to_owned(),
        );
    }
    let method_path = l.member_path("method");
    let method = match l.string_opt("method", &mut r.report) {
        Some(m @ ("PUT" | "POST")) => m.to_owned(),
        Some(other) => {
            r.error(
                &method_path,
                format!("Member `method`: expected \"PUT\" or \"POST\", found \"{other}\"."),
            );
            "PUT".to_owned()
        }
        None => "PUT".to_owned(),
    };
    l.finish(&mut r.report);
    Some(LoadHook { url: url?, method })
}

fn read_trust(r: &mut Reader, obj: &mut Obj<'_>, path: &JsonPath) -> Option<TrustProfile> {
    let mut t = obj.object("trust", RULE, Unknown::Error, &mut r.report)?;
    let iss = r.string(&mut t, "iss");
    let max_age = r.range(&mut t, "max_age_seconds", 1, 31_536_000, true);
    let skew = r.range(&mut t, "skew_seconds", 0, 86_400, true);
    let jwks_file = r.file(&mut t, "jwks_file", false);
    let mut pem_keys = Vec::new();
    let pem_path = t.member_path("pem_keys");
    if let Some(items) = t.array_opt("pem_keys", &mut r.report) {
        for (index, item) in items.iter().enumerate() {
            let item_path = pem_path.index(index);
            let Some(mut k) = r.obj(item, &item_path) else {
                continue;
            };
            let file = r.file(&mut k, "file", true);
            let kid = r.string_opt(&mut k, "kid");
            k.finish(&mut r.report);
            if let Some(file) = file {
                pem_keys.push((file, kid));
            }
        }
    }
    t.finish(&mut r.report);
    if jwks_file.is_none() && pem_keys.is_empty() {
        r.error(
            &path.key("trust"),
            "Expected at least one public key: give `jwks_file` or a non-empty `pem_keys`."
                .to_owned(),
        );
    }
    Some(TrustProfile {
        iss: iss?,
        max_age_seconds: max_age?,
        skew_seconds: skew?,
        jwks_file,
        pem_keys,
    })
}

fn read_edge(r: &mut Reader, value: &Value, path: &JsonPath) -> Option<EdgeProfile> {
    let mut obj = r.obj(value, path)?;
    let service = r.service_id(&mut obj);
    let token_header = r.header_name(&mut obj, "token_header");
    let trust = read_trust(r, &mut obj, path);
    let keys_path = obj.member_path("keys");
    let (mut valid, mut no_access, mut unknown) = (None, None, None);
    if let Some(mut k) = obj.object("keys", RULE, Unknown::Error, &mut r.report) {
        if let Some(mut v) = k.object("valid", RULE, Unknown::Error, &mut r.report) {
            let text_file = r.file(&mut v, "text_file", true);
            let subject = r.string(&mut v, "subject");
            let owner = r.string(&mut v, "owner");
            v.finish(&mut r.report);
            if let (Some(text_file), Some(subject), Some(owner)) = (text_file, subject, owner) {
                valid = Some(ValidKey {
                    text_file,
                    subject,
                    owner,
                });
            }
        }
        for (name, slot) in [("no_access", &mut no_access), ("unknown", &mut unknown)] {
            if let Some(mut v) = k.object(name, RULE, Unknown::Error, &mut r.report) {
                *slot = r.file(&mut v, "text_file", true);
                v.finish(&mut r.report);
            }
        }
        k.finish(&mut r.report);
    }
    let _ = keys_path;
    let mut upstream_listen = None;
    if let Some(mut u) = obj.object("upstream", RULE, Unknown::Error, &mut r.report) {
        upstream_listen = r.address(&mut u, "listen");
        u.finish(&mut r.report);
    }
    let pdp = read_edge_pdp(r, &mut obj, path);
    let mcp_path = r.url_path(&mut obj, "mcp_path", false);
    let token_cache = r.boolean(&mut obj, "token_cache").unwrap_or(false);
    obj.finish(&mut r.report);
    Some(EdgeProfile {
        service: service?,
        token_header: token_header?,
        trust: trust?,
        valid_key: valid?,
        no_access_key_file: no_access?,
        unknown_key_file: unknown?,
        upstream_listen: upstream_listen?,
        pdp: pdp?,
        mcp_path,
        token_cache,
    })
}

fn read_edge_pdp(r: &mut Reader, obj: &mut Obj<'_>, path: &JsonPath) -> Option<EdgePdp> {
    let mut p = obj.object("pdp", RULE, Unknown::Error, &mut r.report)?;
    let listen = r.address(&mut p, "listen");
    let name = r.string_opt(&mut p, "directory");
    let file = r.file(&mut p, "directory_file", false);
    let credential_file = r.file(&mut p, "credential_file", false);
    p.finish(&mut r.report);
    let directory = match (name, file) {
        (Some(name), None) => Some(DirectorySource::Named(name)),
        (None, Some(file)) => Some(DirectorySource::File(file)),
        (Some(_), Some(_)) => {
            r.error(
                &path.key("pdp"),
                "Members `directory` and `directory_file` contradict each other: give only one."
                    .to_owned(),
            );
            None
        }
        (None, None) => {
            r.error(
                &path.key("pdp"),
                "Expected one of the members `directory` and `directory_file`, found none."
                    .to_owned(),
            );
            None
        }
    };
    Some(EdgePdp {
        listen: listen?,
        directory: directory?,
        credential_file,
    })
}

impl Profile {
    /// Read a profile from JSON text. The directory `base` resolves the relative paths.
    ///
    /// # Errors
    /// Returns every error of the profile, each with the path of its member.
    pub(crate) fn parse(text: &str, base: &Path) -> Result<Self, Vec<String>> {
        let value = parse_str(text)
            .map_err(|e| vec![format!("{}: the text is not valid JSON: {e}", e.path)])?;
        let mut r = Reader {
            report: Report::new(),
            base: base.to_path_buf(),
        };
        let root = JsonPath::root();
        let mut profile = None;
        if let Some(mut obj) = r.obj(&value, &root) {
            let timeouts = read_timeouts(&mut r, &mut obj);
            let mut pep = None;
            let mut pdp = None;
            let mut edge = None;
            if let Some(v) = obj.optional("pep") {
                pep = read_pep(&mut r, v, &root.key("pep"));
            }
            if let Some(v) = obj.optional("pdp") {
                pdp = read_pdp(&mut r, v, &root.key("pdp"));
            }
            if let Some(v) = obj.optional("edge") {
                edge = read_edge(&mut r, v, &root.key("edge"));
            }
            obj.finish(&mut r.report);
            profile = Some(Self {
                timeouts,
                pep,
                pdp,
                edge,
                raw: value.clone(),
            });
        }
        if r.report.has_errors() {
            return Err(r
                .report
                .findings()
                .iter()
                .map(|f| format!("{}: {}", f.path, f.message))
                .collect());
        }
        profile.ok_or_else(|| vec!["$: the profile is empty".to_owned()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pep_value() -> Value {
        json!({
            "service": "datastore",
            "token": {
                "header": "X-Identity-Token",
                "iss": "https://edge.example",
                "max_age_seconds": 300,
                "skew_seconds": 30,
                "keys": [{"alg": "Ed25519", "file": "key.pem"}]
            },
            "pdp": {"listen": "127.0.0.1:8181"},
            "operations": {
                "use_plain": {
                    "method": "GET", "path": "/t/{{resource_id}}",
                    "action": "data.read", "resource_type": "table", "resource_id": "orders",
                    "ancestors": [{"type": "service", "id": "datastore"}]
                }
            }
        })
    }

    fn parse(value: &Value) -> Result<Profile, Vec<String>> {
        Profile::parse(&value.to_string(), Path::new("/base"))
    }

    #[test]
    fn a_good_pep_profile_is_read_once_with_defaults() {
        let profile = parse(&json!({"pep": pep_value()})).unwrap();
        let pep = profile.pep.unwrap();
        assert_eq!(pep.service, "datastore");
        assert_eq!(pep.token.keys[0].file, PathBuf::from("/base/key.pem"));
        assert!(!pep.answer_cache);
        assert_eq!(profile.timeouts.request, Duration::from_secs(10));
        assert_eq!(profile.timeouts.settle, Duration::from_millis(25));
        assert!(pep.operations.contains_key(&Operation::UsePlain));
    }

    #[test]
    fn an_unknown_member_stops_the_program_with_its_path() {
        let mut pep = pep_value();
        pep["extra"] = json!(1);
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("$.pep"), "{errors:?}");
        assert!(errors[0].contains("`extra`"), "{errors:?}");
    }

    #[test]
    fn a_duplicate_member_stops_the_program() {
        let text = r#"{"pep": {}, "pep": {}}"#;
        let errors = Profile::parse(text, Path::new("/b")).unwrap_err();
        assert!(errors[0].contains("duplicate"), "{errors:?}");
    }

    #[test]
    fn an_error_names_the_key_the_expected_range_and_the_value() {
        let mut pep = pep_value();
        pep["token"]["max_age_seconds"] = json!(0);
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert_eq!(
            errors,
            vec!["$.pep.token.max_age_seconds: Member `max_age_seconds`: expected a whole number from 1 to 31536000, found 0.".to_owned()]
        );
        let mut pep = pep_value();
        pep["pdp"]["listen"] = json!("localhost:80");
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert!(errors[0].contains("\"localhost:80\""), "{errors:?}");
        assert!(errors[0].contains("ADDRESS:PORT"), "{errors:?}");
    }

    #[test]
    fn a_value_is_never_changed_to_make_it_fit() {
        let errors = parse(&json!({"timeouts": {"request_seconds": 100_000}})).unwrap_err();
        assert!(errors[0].contains("found 100000"), "{errors:?}");
        let errors = parse(&json!({"timeouts": {"request_seconds": "5"}})).unwrap_err();
        assert!(errors[0].contains("a string"), "{errors:?}");
        let errors = parse(&json!({"timeouts": {"request_seconds": 5.0}})).unwrap_err();
        assert!(errors[0].contains("a number"), "{errors:?}");
    }

    #[test]
    fn every_error_is_reported() {
        let mut pep = pep_value();
        pep["service"] = json!(5);
        pep["token"]["header"] = json!("Authorization");
        pep["pdp"] = json!({});
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert!(errors.len() >= 3, "{errors:?}");
    }

    #[test]
    fn a_secret_has_no_form_but_a_file() {
        let mut pep = pep_value();
        pep["pdp"]["credential"] = json!("s3cret");
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert!(errors[0].contains("`credential`"), "{errors:?}");
        assert!(!errors[0].contains("s3cret"), "{errors:?}");
    }

    #[test]
    fn an_operation_needs_its_members() {
        let mut pep = pep_value();
        pep["operations"]["use_budget"] = json!({"method": "GET", "path": "/x"});
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("`action`")), "{errors:?}");
        let mut pep = pep_value();
        pep["operations"]["use_nothing"] = json!({});
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert!(errors[0].contains("not an operation"), "{errors:?}");
    }

    #[test]
    fn an_mcp_operation_needs_the_member_mcp() {
        let mut pep = pep_value();
        pep["operations"]["mcp_call_plain"] = json!({"tool": "t", "action": "a"});
        let errors = parse(&json!({"pep": pep})).unwrap_err();
        assert!(errors[0].contains("needs the member `mcp`"), "{errors:?}");
        let mut pep = pep_value();
        pep["mcp"] = json!({"path": "/mcp"});
        pep["operations"]["mcp_call_plain"] = json!({"tool": "t", "action": "a"});
        assert!(parse(&json!({"pep": pep})).is_ok());
    }

    #[test]
    fn two_keys_for_one_algorithm_contradict_each_other() {
        let mut pep = pep_value();
        pep["token"]["keys"] = json!([
            {"alg": "Ed25519", "file": "a"}, {"alg": "Ed25519", "file": "b"}
        ]);
        assert!(parse(&json!({"pep": pep})).is_err());
    }

    #[test]
    fn a_spawned_pdp_contradicts_the_admin_urls() {
        let value = json!({"pdp": {"spawn_fake_pdp": true, "reset_url": "http://127.0.0.1:1/r"}});
        let errors = parse(&value).unwrap_err();
        assert!(errors[0].contains("contradict"), "{errors:?}");
        let value = json!({"pdp": {"spawn_fake_pdp": true}});
        assert!(parse(&value).is_ok());
    }

    #[test]
    fn the_directory_check_has_a_default_and_a_closed_mode() {
        let profile = parse(&json!({"pdp": {}})).unwrap();
        let check = profile.pdp.unwrap().directory_check;
        assert!(check.enabled);
        assert_eq!(check.max_questions, 100);
        let errors = parse(&json!({"pdp": {"directory_check": {"mode": "maybe"}}})).unwrap_err();
        assert!(errors[0].contains("\"maybe\""), "{errors:?}");
        let profile = parse(&json!({"pdp": {"directory_check": {"mode": "none"}}})).unwrap();
        assert!(!profile.pdp.unwrap().directory_check.enabled);
    }

    fn edge_value() -> Value {
        json!({
            "service": "datastore",
            "token_header": "X-Identity-Token",
            "trust": {"iss": "https://edge.example", "max_age_seconds": 300, "skew_seconds": 30, "jwks_file": "jwks.json"},
            "keys": {
                "valid": {"text_file": "valid.txt", "subject": "key:ann-k1", "owner": "ann"},
                "no_access": {"text_file": "noaccess.txt"},
                "unknown": {"text_file": "unknown.txt"}
            },
            "upstream": {"listen": "127.0.0.1:9000"},
            "pdp": {"listen": "127.0.0.1:8181", "directory": "access.json"}
        })
    }

    #[test]
    fn a_good_edge_profile_is_read() {
        let profile = parse(&json!({"edge": edge_value()})).unwrap();
        let edge = profile.edge.unwrap();
        assert_eq!(edge.valid_key.owner, "ann");
        assert_eq!(
            edge.pdp.directory,
            DirectorySource::Named("access.json".into())
        );
        assert!(!edge.token_cache);
        assert!(edge.mcp_path.is_none());
    }

    #[test]
    fn an_edge_needs_a_key_for_the_trust_and_one_source_of_the_directory() {
        let mut edge = edge_value();
        edge["trust"].as_object_mut().unwrap().remove("jwks_file");
        assert!(parse(&json!({"edge": edge})).is_err());
        let mut edge = edge_value();
        edge["pdp"]["directory_file"] = json!("d.json");
        let errors = parse(&json!({"edge": edge})).unwrap_err();
        assert!(errors[0].contains("contradict"), "{errors:?}");
        let mut edge = edge_value();
        edge["pdp"].as_object_mut().unwrap().remove("directory");
        assert!(parse(&json!({"edge": edge})).is_err());
    }
}
