//! The run of a case: the setup, each step, and the cleanup.
//!
//! A [`Runner`] holds what the run needs: the profile of the role, the test
//! listeners, the clock and the variables. [`Runner::validate`] reads each case
//! as far as it can without a request. Thus a bad profile stops the program
//! before the first request.

use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::Instant;

use fake_pdp::{Options as FakeOptions, RunningServer, Server as FakeServer};
use serde_json::{Value, json};

use crate::catalog::Catalog;
use crate::check::{Observed, check};
use crate::http::{Authority, ClientRequest, HttpUrl, Reply, send};
use crate::model::{Case, Condition, Endpoint, Expect, Operation, Role, Step, TokenSpec};
use crate::ops::{self, has_header, put_header};
use crate::pdpcheck::{controls, same_answer};
use crate::profile::{EdgeProfile, PdpProfile, PepProfile, Timeouts};
use crate::report::{CaseResult, Failure};
use crate::testpdp::{Rule, TestPdp};
use crate::tokens::{MintError, Signer, Verifier};
use crate::upstream::Upstream;
use crate::vars::Vars;

/// The path of the metadata of a PDP.
pub(crate) const METADATA_PATH: &str = "/.well-known/authzen-configuration";
/// The path of the Access Evaluation API.
pub(crate) const EVALUATION_PATH: &str = "/access/v1/evaluation";
/// The path of the Access Evaluations API.
pub(crate) const EVALUATIONS_PATH: &str = "/access/v1/evaluations";

/// The conditions that hold for the target.
#[derive(Clone, Debug, Default)]
pub(crate) struct Capabilities {
    held: BTreeSet<Condition>,
}

impl Capabilities {
    /// The conditions of a PEP, from its profile.
    pub(crate) fn for_pep(profile: &PepProfile) -> Self {
        let has = |op: Operation| profile.operations.contains_key(&op);
        let mut held = BTreeSet::new();
        let mut add = |condition: Condition, holds: bool| {
            if holds {
                held.insert(condition);
            }
        };
        add(Condition::NoBudgetAction, !has(Operation::UseBudget));
        add(Condition::NoCeilingAction, !has(Operation::UseCeiling));
        add(Condition::NoOptionsRoute, profile.options_type.is_none());
        add(Condition::NoAnswerCache, !profile.answer_cache);
        add(Condition::NoTokenCache, true);
        add(Condition::NoMcpEndpoint, profile.mcp.is_none());
        add(
            Condition::NoBudgetSession,
            profile.mcp.as_ref().is_none_or(|m| !m.session_budget),
        );
        add(Condition::NoInputTool, !has(Operation::McpCallInput));
        add(Condition::NoApprovalTool, !has(Operation::McpCallApproval));
        add(
            Condition::NoMultiAction,
            !has(Operation::UseMulti) && !has(Operation::McpCallMulti),
        );
        add(Condition::SingleKeySet, false);
        Self { held }
    }

    /// The conditions of an edge, from its profile and its key set.
    pub(crate) fn for_edge(profile: &EdgeProfile, key_count: usize) -> Self {
        let mut held = BTreeSet::new();
        for condition in [
            Condition::NoBudgetAction,
            Condition::NoCeilingAction,
            Condition::NoOptionsRoute,
            Condition::NoAnswerCache,
            Condition::NoBudgetSession,
            Condition::NoInputTool,
            Condition::NoApprovalTool,
            Condition::NoMultiAction,
        ] {
            held.insert(condition);
        }
        if profile.mcp_path.is_none() {
            held.insert(Condition::NoMcpEndpoint);
        }
        if !profile.token_cache {
            held.insert(Condition::NoTokenCache);
        }
        if key_count == 1 {
            held.insert(Condition::SingleKeySet);
        }
        Self { held }
    }

    /// The conditions of a PDP: none holds.
    pub(crate) fn for_pdp() -> Self {
        Self::default()
    }

    /// True when the condition holds.
    pub(crate) fn holds(&self, condition: Condition) -> bool {
        self.held.contains(&condition)
    }

    /// The first condition of a list that holds.
    pub(crate) fn first_held(&self, list: &[Condition]) -> Option<Condition> {
        list.iter().copied().find(|c| self.holds(*c))
    }
}

/// The test listeners and the profile of a PEP run.
pub(crate) struct PepEnv {
    /// The profile.
    pub(crate) profile: PepProfile,
    /// The test edge.
    pub(crate) signer: Signer,
    /// The test PDP.
    pub(crate) pdp: TestPdp,
}

/// The listeners and the profile of an edge run.
pub(crate) struct EdgeEnv {
    /// The profile.
    pub(crate) profile: EdgeProfile,
    /// The checks of the identity token.
    pub(crate) verifier: Verifier,
    /// The service behind the edge.
    pub(crate) upstream: Upstream,
    /// The PDP that the edge calls.
    pub(crate) pdp: RunningServer,
}

/// The URLs of the endpoints of a PDP.
#[derive(Clone, Debug)]
pub(crate) struct Endpoints {
    /// The Access Evaluation API.
    pub(crate) evaluation: HttpUrl,
    /// The Access Evaluations API.
    pub(crate) evaluations: HttpUrl,
    /// The metadata.
    pub(crate) metadata: HttpUrl,
}

impl Endpoints {
    /// The default paths on an authority.
    pub(crate) fn on(authority: &Authority) -> Self {
        let url = |target: &str| HttpUrl {
            authority: authority.clone(),
            target: target.to_owned(),
        };
        Self {
            evaluation: url(EVALUATION_PATH),
            evaluations: url(EVALUATIONS_PATH),
            metadata: url(METADATA_PATH),
        }
    }
}

/// The profile and the target of a PDP run.
pub(crate) struct PdpEnv {
    /// The profile.
    pub(crate) profile: PdpProfile,
    /// The text of the credential, when the profile has one.
    pub(crate) credential: Option<String>,
    /// The endpoints of the PDP under test. `None` when the runner starts `fake-pdp`.
    pub(crate) external: Option<Endpoints>,
}

/// The role-specific part of a runner.
pub(crate) enum Env {
    /// A PEP under test.
    Pep(PepEnv),
    /// An edge under test.
    Edge(EdgeEnv),
    /// A PDP under test.
    Pdp(PdpEnv),
}

/// A reason to skip a case, or an error of the case.
enum Prep {
    Skip(String),
    Error(String),
}

/// A step that is ready to send.
struct Prepared {
    authority: Authority,
    request: ClientRequest,
    expect: Expect,
}

static DEFAULT_OPERATION: std::sync::LazyLock<crate::profile::OpDef> =
    std::sync::LazyLock::new(crate::profile::OpDef::default);

/// The result of the steps of a case.
struct StepsOutcome {
    /// The failed checks.
    failures: Vec<Failure>,
    /// Why the case does not apply: no step could run with this profile.
    skip: Option<String>,
}

/// What a PDP case needs from the PDP.
struct Needs {
    clock: bool,
    counters: bool,
    usage: bool,
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => map.contains_key(key) || map.values().any(|v| contains_key(v, key)),
        Value::Array(items) => items.iter().any(|v| contains_key(v, key)),
        _ => false,
    }
}

fn needs_of(case: &Case) -> Needs {
    let usage = case.steps.iter().any(|s| {
        s.request
            .body
            .as_ref()
            .is_some_and(|b| contains_key(b, "usage"))
    });
    Needs {
        clock: case.given.clock.is_some() || !case.given.counters.is_empty() || usage,
        counters: !case.given.counters.is_empty(),
        usage,
    }
}

/// The runner.
pub(crate) struct Runner<'a> {
    /// The cases and the directories.
    pub(crate) catalog: &'a Catalog,
    /// The time limits.
    pub(crate) timeouts: Timeouts,
    /// The target of a PEP run and of an edge run.
    pub(crate) target: Option<Authority>,
    /// The clock, in seconds since the Unix epoch.
    pub(crate) now: &'a dyn Fn() -> u64,
    /// The conditions that hold.
    pub(crate) caps: Capabilities,
    /// The variables that do not depend on a case.
    pub(crate) global: Vars,
    /// The role-specific part.
    pub(crate) env: Env,
    /// Notes for the standard error: what the runner could not check.
    pub(crate) notes: std::sync::Mutex<Vec<String>>,
}

fn failure(step: Option<&str>, message: impl Into<String>) -> Failure {
    Failure {
        step: step.map(str::to_owned),
        message: message.into(),
    }
}

fn step_name(step: &Step, index: usize) -> String {
    step.name
        .clone()
        .unwrap_or_else(|| format!("step {}", index + 1))
}

impl Runner<'_> {
    fn role(&self) -> Role {
        match self.env {
            Env::Pep(_) => Role::Pep,
            Env::Edge(_) => Role::Edge,
            Env::Pdp(_) => Role::Pdp,
        }
    }

    /// The definition of an operation. The reads of the action document and of the options
    /// route have a default, so the profile needs no entry for them.
    fn pep_def(&self, operation: Operation) -> Option<&crate::profile::OpDef> {
        let Env::Pep(env) = &self.env else {
            return None;
        };
        let default = match operation {
            Operation::ReadActions => true,
            Operation::ListOptions => env.profile.options_type.is_some(),
            _ => false,
        };
        env.profile
            .operations
            .get(&operation)
            .or_else(|| default.then(|| &*DEFAULT_OPERATION))
    }

    fn service(&self) -> &str {
        match &self.env {
            Env::Pep(env) => &env.profile.service,
            Env::Edge(env) => &env.profile.service,
            Env::Pdp(_) => "",
        }
    }

    /// The variables of a case: the global ones, the ones of the first operations, and the tokens.
    fn case_vars(&self, case: &Case, tokens: &BTreeMap<String, String>) -> Vars {
        let mut vars = self.global.clone();
        let mut from_ops = Vars::new();
        for step in &case.steps {
            if let Some(operation) = step.request.operation
                && let Some(def) = self.pep_def(operation)
            {
                from_ops.extend_missing(&ops::op_vars(operation, def, self.service()));
            }
        }
        vars.extend(&from_ops);
        for (name, text) in tokens {
            vars.set(&format!("token_{name}"), Value::String(text.clone()));
        }
        vars
    }

    fn token_spec(spec: &TokenSpec, vars: &Vars) -> Result<TokenSpec, String> {
        let unknown = |name: String| format!("the variable `{name}` has no value");
        let mut out = spec.clone();
        out.subject = vars.text(&spec.subject, false).map_err(unknown)?;
        if let Some(owner) = &spec.owner {
            out.owner = Some(vars.text(owner, false).map_err(unknown)?);
        }
        let claims = vars
            .value(&Value::Object(spec.claims.clone()))
            .map_err(unknown)?;
        let header = vars
            .value(&Value::Object(spec.header.clone()))
            .map_err(unknown)?;
        if let (Value::Object(c), Value::Object(h)) = (claims, header) {
            out.claims = c;
            out.header = h;
        }
        Ok(out)
    }

    /// The texts of the tokens of a case. A dry run gives a fixed text and makes no token.
    fn tokens(&self, case: &Case, dry: bool) -> Result<BTreeMap<String, String>, Prep> {
        let mut out = BTreeMap::new();
        if case.given.tokens.is_empty() {
            return Ok(out);
        }
        let vars = self.case_vars(case, &BTreeMap::new());
        for (name, spec) in &case.given.tokens {
            let spec = Self::token_spec(spec, &vars)
                .map_err(|why| Prep::Error(format!("token `{name}`: {why}")))?;
            let text = match (&self.env, dry) {
                (Env::Pep(_), true) => "dry.run.token".to_owned(),
                (Env::Pep(env), false) => {
                    env.signer
                        .mint(&spec, (self.now)())
                        .map_err(|MintError::NoKey(alg)| {
                            Prep::Skip(format!(
                                "the profile has no {} key for the token `{name}`",
                                alg.name()
                            ))
                        })?
                }
                _ => {
                    return Err(Prep::Error(format!(
                        "the case has the token `{name}`, and the role {} cannot send it",
                        self.role().name()
                    )));
                }
            };
            out.insert(name.clone(), text);
        }
        Ok(out)
    }

    fn resolve_expect(expect: &Expect, vars: &Vars) -> Result<Expect, String> {
        let unknown = |name: String| format!("the variable `{name}` has no value");
        let matchers = |map: &BTreeMap<String, crate::model::Matcher>| -> Result<BTreeMap<String, crate::model::Matcher>, String> {
            let mut out = BTreeMap::new();
            for (key, matcher) in map {
                out.insert(vars.text(key, false).map_err(unknown)?, vars.matcher(matcher)?);
            }
            Ok(out)
        };
        let one =
            |m: &Option<crate::model::Matcher>| -> Result<Option<crate::model::Matcher>, String> {
                m.as_ref().map(|m| vars.matcher(m)).transpose()
            };
        let mut out = expect.clone();
        out.status = one(&expect.status)?;
        out.headers = matchers(&expect.headers)?;
        out.body_text = one(&expect.body_text)?;
        out.json = matchers(&expect.json)?;
        out.pdp_connections = one(&expect.pdp_connections)?;
        out.pdp_questions = expect
            .pdp_questions
            .iter()
            .map(|entry| {
                Ok(crate::model::QuestionExpect {
                    json: matchers(&entry.json)?,
                    headers: matchers(&entry.headers)?,
                    count: one(&entry.count)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        out.upstream = expect
            .upstream
            .as_ref()
            .map(|u| {
                Ok::<_, String>(crate::model::UpstreamExpect {
                    count: one(&u.count)?,
                    headers: matchers(&u.headers)?,
                    token_header: matchers(&u.token_header)?,
                    token_claims: matchers(&u.token_claims)?,
                })
            })
            .transpose()?;
        Ok(out)
    }

    /// Make the request and the expectation of a step.
    fn prepare_step(
        &self,
        step: &Step,
        case_vars: &Vars,
        endpoints: Option<&Endpoints>,
        previous: Option<&Value>,
        dry: bool,
    ) -> Result<Prepared, Prep> {
        let unknown = |name: String| Prep::Error(format!("the variable `{name}` has no value"));
        let mut vars = case_vars.clone();
        let spec = &step.request;
        let mut authority = self.target.clone();
        let parts = if let Some(operation) = spec.operation {
            let Some(def) = self.pep_def(operation) else {
                return Err(Prep::Skip(format!(
                    "the profile has no operation {}",
                    operation.name()
                )));
            };
            vars.extend(&ops::op_vars(operation, def, self.service()));
            for (name, pointer) in &def.capture {
                let value = if dry {
                    Some(Value::String("dry".to_owned()))
                } else {
                    previous.and_then(|p| p.pointer(pointer)).cloned()
                };
                match value {
                    Some(value) => vars.set(name, value),
                    None => {
                        return Err(Prep::Error(format!(
                            "the capture `{name}` has no value: the answer of the step before has no member at \"{pointer}\""
                        )));
                    }
                }
            }
            let mut parts = ops::build(operation, def, &vars).map_err(Prep::Error)?;
            for (name, value) in &spec.headers {
                let name = vars.text(name, false).map_err(unknown)?;
                let value = vars.text(value, false).map_err(unknown)?;
                put_header(&mut parts.headers, &name, &value);
            }
            parts
        } else {
            let (method, target) = if let Some(endpoint) = spec.endpoint {
                let Some(endpoints) = endpoints else {
                    return Err(Prep::Error(
                        "the step names an endpoint, and the role has no PDP".to_owned(),
                    ));
                };
                let (method, url) = match endpoint {
                    Endpoint::Evaluation => ("POST", &endpoints.evaluation),
                    Endpoint::Evaluations => ("POST", &endpoints.evaluations),
                    Endpoint::Metadata => ("GET", &endpoints.metadata),
                };
                authority = Some(url.authority.clone());
                (method.to_owned(), url.target.clone())
            } else {
                let path = spec.path.clone().unwrap_or_default();
                let target = vars.text(&path, false).map_err(unknown)?;
                if !target.starts_with('/') {
                    return Err(Prep::Error(format!(
                        "the path must start with a slash, found \"{target}\""
                    )));
                }
                (spec.method.clone().unwrap_or_default(), target)
            };
            let mut headers = Vec::new();
            for (name, value) in &spec.headers {
                let name = vars.text(name, false).map_err(unknown)?;
                let value = vars.text(value, false).map_err(unknown)?;
                put_header(&mut headers, &name, &value);
            }
            let body = match (&spec.body, &spec.body_text) {
                (Some(body), _) => {
                    let value = vars.value(body).map_err(unknown)?;
                    if !has_header(&headers, "content-type") {
                        put_header(&mut headers, "Content-Type", "application/json");
                    }
                    Some(value.to_string().into_bytes())
                }
                (None, Some(text)) => Some(vars.text(text, false).map_err(unknown)?.into_bytes()),
                (None, None) => None,
            };
            ops::Parts {
                method,
                target,
                headers,
                body,
            }
        };
        let mut parts = parts;
        if let Some(name) = &spec.token {
            if !matches!(self.env, Env::Pep(_)) {
                return Err(Prep::Error(format!(
                    "the step sends the token `{name}`, and the role {} cannot send it",
                    self.role().name()
                )));
            }
            let text = vars
                .get(&format!("token_{name}"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Prep::Error(format!(
                        "the step names the token `{name}`, and the case does not define it"
                    ))
                })?
                .to_owned();
            let header = vars
                .get("token_header")
                .and_then(Value::as_str)
                .ok_or_else(|| Prep::Error("the variable `token_header` has no value".to_owned()))?
                .to_owned();
            if !has_header(&parts.headers, &header) {
                put_header(&mut parts.headers, &header, &text);
            }
        }
        if let Env::Pdp(env) = &self.env
            && let Some(credential) = &env.credential
            && !has_header(&parts.headers, "authorization")
        {
            put_header(
                &mut parts.headers,
                "Authorization",
                &format!("Bearer {credential}"),
            );
        }
        let expect = Self::resolve_expect(&step.expect, &vars).map_err(Prep::Error)?;
        let authority = authority.ok_or_else(|| Prep::Error("the run has no target".to_owned()))?;
        Ok(Prepared {
            authority,
            request: ClientRequest {
                method: parts.method,
                target: parts.target,
                headers: parts.headers,
                body: parts.body,
            },
            expect,
        })
    }

    /// Read each case as far as possible with no request. Return the problems.
    pub(crate) fn validate(&self, cases: &[&Case]) -> Vec<String> {
        let mut problems = Vec::new();
        for case in cases {
            let endpoints = match &self.env {
                Env::Pdp(env) => Some(
                    env.external
                        .clone()
                        .unwrap_or_else(|| Endpoints::on(&dummy_authority())),
                ),
                _ => None,
            };
            let tokens = match self.tokens(case, true) {
                Ok(tokens) => tokens,
                Err(Prep::Skip(_)) => BTreeMap::new(),
                Err(Prep::Error(why)) => {
                    problems.push(format!("Case {}: {why}.", case.id));
                    continue;
                }
            };
            let vars = self.case_vars(case, &tokens);
            if self.caps.first_held(&case.skip_if).is_some() {
                continue;
            }
            for (index, step) in case.steps.iter().enumerate() {
                if self.caps.first_held(&step.skip_if).is_some() {
                    continue;
                }
                match self.prepare_step(step, &vars, endpoints.as_ref(), None, true) {
                    Ok(_) | Err(Prep::Skip(_)) => {}
                    Err(Prep::Error(why)) => problems.push(format!(
                        "Case {}, {}: {why}.",
                        case.id,
                        step_name(step, index)
                    )),
                }
            }
            if matches!(self.env, Env::Pep(_)) {
                match script_rules(case, &vars) {
                    Ok(_) => {}
                    Err(why) => problems.push(format!("Case {}: pdp_script: {why}.", case.id)),
                }
            } else if !case.given.pdp_script.is_empty() {
                problems.push(format!(
                    "Case {}: the case has a pdp_script, and the role {} has no scripted PDP.",
                    case.id,
                    self.role().name()
                ));
            }
        }
        problems
    }

    fn request_deadline(&self, case_deadline: Instant) -> Instant {
        (Instant::now() + self.timeouts.request).min(case_deadline)
    }

    fn send_one(&self, prepared: &Prepared, case_deadline: Instant) -> Result<Reply, String> {
        send(
            &prepared.authority,
            &prepared.request,
            self.request_deadline(case_deadline),
        )
    }

    /// Run the cases, in order.
    ///
    /// # Errors
    /// Returns the problems that stop the run: for example a PDP that does not hold a directory.
    pub(crate) fn run(&self, cases: &[&Case]) -> Result<Vec<CaseResult>, Vec<String>> {
        let mut results = Vec::new();
        let mut verified: BTreeSet<String> = BTreeSet::new();
        for case in cases {
            results.push(self.run_case(case, &mut verified)?);
        }
        Ok(results)
    }

    fn run_case(
        &self,
        case: &Case,
        verified: &mut BTreeSet<String>,
    ) -> Result<CaseResult, Vec<String>> {
        if let Some(condition) = self.caps.first_held(&case.skip_if) {
            return Ok(CaseResult::skipped(case, condition.reason()));
        }
        // Skip the case when every step skips.
        let mut live = 0;
        let mut first_reason = None;
        for step in &case.steps {
            match self.caps.first_held(&step.skip_if) {
                Some(condition) => {
                    first_reason.get_or_insert_with(|| condition.reason().to_owned());
                }
                None => live += 1,
            }
        }
        if live == 0 {
            return Ok(CaseResult::skipped(
                case,
                first_reason.unwrap_or_else(|| "the case has no step to run".to_owned()),
            ));
        }
        let tokens = match self.tokens(case, false) {
            Ok(tokens) => tokens,
            Err(Prep::Skip(reason)) => return Ok(CaseResult::skipped(case, reason)),
            Err(Prep::Error(why)) => return Ok(CaseResult::failed(case, vec![failure(None, why)])),
        };
        let vars = self.case_vars(case, &tokens);
        let deadline = Instant::now() + self.timeouts.case;
        match &self.env {
            Env::Pep(env) => Ok(self.run_pep(case, env, &vars, deadline)),
            Env::Edge(env) => Ok(self.run_edge(case, env, &vars, deadline)),
            Env::Pdp(env) => self.run_pdp(case, env, &vars, deadline, verified),
        }
    }

    /// Run the steps of a case. The hooks read the state of the test listeners.
    fn steps(
        &self,
        case: &Case,
        vars: &Vars,
        endpoints: Option<&Endpoints>,
        deadline: Instant,
        hooks: &mut dyn Hooks,
    ) -> StepsOutcome {
        let mut failures = Vec::new();
        let mut previous: Option<Value> = None;
        let mut ran = 0;
        let mut skip: Option<String> = None;
        for (index, step) in case.steps.iter().enumerate() {
            if self.caps.first_held(&step.skip_if).is_some() {
                continue;
            }
            let name = step_name(step, index);
            if Instant::now() >= deadline {
                failures.push(failure(
                    Some(&name),
                    format!(
                        "the case took more than {} seconds",
                        self.timeouts.case.as_secs()
                    ),
                ));
                break;
            }
            let prepared = match self.prepare_step(step, vars, endpoints, previous.as_ref(), false)
            {
                Ok(prepared) => prepared,
                Err(Prep::Skip(reason)) => {
                    skip.get_or_insert(reason);
                    continue;
                }
                Err(Prep::Error(why)) => {
                    failures.push(failure(Some(&name), why));
                    break;
                }
            };
            ran += 1;
            hooks.before();
            let sent = self.send_one(&prepared, deadline);
            let (reply, send_error) = match sent {
                Ok(reply) => (Some(reply), None),
                Err(why) => (None, Some(why)),
            };
            previous = reply
                .as_ref()
                .and_then(|r| serde_json::from_slice::<Value>(&r.body).ok());
            if let Some(why) = send_error {
                failures.push(failure(Some(&name), format!("the request failed: {why}")));
            }
            self.settle(&prepared.expect);
            for message in hooks.after(&prepared, reply.as_ref()) {
                failures.push(failure(Some(&name), message));
            }
        }
        StepsOutcome {
            failures,
            skip: if ran == 0 { skip } else { None },
        }
    }

    fn settle(&self, expect: &Expect) {
        if (!expect.pdp_questions.is_empty()
            || expect.pdp_connections.is_some()
            || expect.upstream.is_some())
            && !self.timeouts.settle.is_zero()
        {
            thread::sleep(self.timeouts.settle);
        }
    }

    fn run_pep(&self, case: &Case, env: &PepEnv, vars: &Vars, deadline: Instant) -> CaseResult {
        let rules = match script_rules(case, vars) {
            Ok(rules) => rules,
            Err(why) => {
                return CaseResult::failed(case, vec![failure(None, format!("pdp_script: {why}"))]);
            }
        };
        // A case with a directory lets a fake PDP answer the questions that no rule matches.
        let mut fake: Option<RunningServer> = None;
        let mut fallback = None;
        if case.given.directory.is_some() {
            let started = self.catalog.data_of(case).and_then(|data| {
                FakeServer::from_value(&data, FakeOptions::default())
                    .map_err(|e| e.to_string())
                    .and_then(|s| s.start("127.0.0.1:0").map_err(|e| e.to_string()))
            });
            match started {
                Ok(server) => {
                    fallback = Some(Authority {
                        host: "127.0.0.1".to_owned(),
                        port: server.local_addr().port(),
                    });
                    fake = Some(server);
                }
                Err(why) => {
                    return CaseResult::failed(
                        case,
                        vec![failure(None, format!("the directory of the case: {why}"))],
                    );
                }
            }
        }
        env.pdp.begin_case(rules, fallback);
        let mut failures = Vec::new();
        let mut skip = None;
        if let Some(reset) = &env.profile.reset
            && let Some(target) = &self.target
        {
            let mut headers = Vec::new();
            for (name, value) in &reset.headers {
                put_header(&mut headers, name, value);
            }
            let request = ClientRequest {
                method: reset.method.clone(),
                target: reset.path.clone(),
                headers,
                body: None,
            };
            match send(target, &request, self.request_deadline(deadline)) {
                Ok(reply) if (200..300).contains(&reply.status) => {}
                Ok(reply) => failures.push(failure(
                    None,
                    format!(
                        "the reset request must give a status from 200 to 299, found {}",
                        reply.status
                    ),
                )),
                Err(why) => {
                    failures.push(failure(None, format!("the reset request failed: {why}")))
                }
            }
        }
        if failures.is_empty() {
            let mut hooks = PepHooks {
                pdp: &env.pdp,
                mark: 0,
                now: self.now,
            };
            let outcome = self.steps(case, vars, None, deadline, &mut hooks);
            skip = outcome.skip;
            failures = outcome.failures;
            for fault in env.pdp.faults() {
                failures.push(failure(None, format!("fault of the case: {fault}")));
            }
        }
        env.pdp.end_case();
        if let Some(server) = fake {
            server.shutdown();
        }
        match skip {
            Some(reason) if failures.is_empty() => CaseResult::skipped(case, reason),
            _ => CaseResult::from_failures(case, failures),
        }
    }

    fn run_edge(&self, case: &Case, env: &EdgeEnv, vars: &Vars, deadline: Instant) -> CaseResult {
        env.upstream.begin_case();
        let mut hooks = EdgeHooks {
            env,
            mark: 0,
            now: self.now,
        };
        let outcome = self.steps(case, vars, None, deadline, &mut hooks);
        match outcome.skip {
            Some(reason) if outcome.failures.is_empty() => CaseResult::skipped(case, reason),
            _ => CaseResult::from_failures(case, outcome.failures),
        }
    }

    /// The client of a PDP under test.
    fn post_admin(
        &self,
        env: &PdpEnv,
        url: &HttpUrl,
        method: &str,
        body: Option<&Value>,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut headers = Vec::new();
        if body.is_some() {
            put_header(&mut headers, "Content-Type", "application/json");
        }
        if let Some(credential) = &env.credential {
            put_header(
                &mut headers,
                "Authorization",
                &format!("Bearer {credential}"),
            );
        }
        let request = ClientRequest {
            method: method.to_owned(),
            target: url.target.clone(),
            headers,
            body: Some(body.map(|b| b.to_string().into_bytes()).unwrap_or_default()),
        };
        let reply = send(&url.authority, &request, self.request_deadline(deadline))?;
        if (200..300).contains(&reply.status) {
            Ok(())
        } else {
            Err(format!(
                "the request {method} {} must give a status from 200 to 299, found {}",
                url.target, reply.status
            ))
        }
    }

    /// Ask the control questions of a directory. Return the answers that differ.
    ///
    /// # Errors
    /// Returns a message when a question cannot be sent or the directory is not valid.
    pub(crate) fn directory_mismatches(
        &self,
        env: &PdpEnv,
        endpoints: &Endpoints,
        directory: &Value,
    ) -> Result<Vec<String>, String> {
        let has_credentials = directory
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|list| list.iter().any(|s| s.get("credential_sha256").is_some()));
        if has_credentials && env.credential.is_none() {
            self.notes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(
                    "A directory has services with credentials, and the profile has no credential. The control questions are skipped for it."
                        .to_owned(),
                );
            return Ok(Vec::new());
        }
        let list = controls(directory, env.profile.directory_check.max_questions)?;
        let mut mismatches = Vec::new();
        for control in &list {
            let mut headers = Vec::new();
            put_header(&mut headers, "Content-Type", "application/json");
            if let Some(credential) = &env.credential {
                put_header(
                    &mut headers,
                    "Authorization",
                    &format!("Bearer {credential}"),
                );
            }
            let request = ClientRequest {
                method: "POST".to_owned(),
                target: endpoints.evaluation.target.clone(),
                headers,
                body: Some(control.question.to_string().into_bytes()),
            };
            let until = Instant::now() + self.timeouts.request;
            let reply = send(&endpoints.evaluation.authority, &request, until)
                .map_err(|why| format!("a control question failed: {why}"))?;
            let actual: Value = if reply.status == 200 {
                serde_json::from_slice(&reply.body).unwrap_or(Value::Null)
            } else {
                json!({"http_status": reply.status})
            };
            if !same_answer(&control.expected, &actual) {
                mismatches.push(format!(
                    "{}: expected {}, found {}",
                    control.label,
                    summary_of(&control.expected),
                    summary_of(&actual)
                ));
            }
        }
        Ok(mismatches)
    }

    /// Check that the PDP under test holds the directory of each case, before the run.
    ///
    /// # Errors
    /// Returns the list of directories that the PDP does not hold.
    pub(crate) fn preflight_directories(&self, cases: &[&Case]) -> Result<(), Vec<String>> {
        let Env::Pdp(env) = &self.env else {
            return Ok(());
        };
        let Some(endpoints) = &env.external else {
            return Ok(());
        };
        if env.profile.load.is_some() || !env.profile.directory_check.enabled {
            return Ok(());
        }
        let mut by_directory: BTreeMap<String, (Value, Vec<String>)> = BTreeMap::new();
        for case in cases {
            let Some(reference) = &case.given.directory else {
                continue;
            };
            let name = match reference {
                crate::model::DirectoryRef::Name(name) => format!("directory `{name}`"),
                crate::model::DirectoryRef::Inline(_) => {
                    format!("the inline directory of {}", case.id)
                }
            };
            let value = self
                .catalog
                .directory_of(case)
                .map_err(|why| vec![format!("Case {}: {why}.", case.id)])?;
            by_directory
                .entry(name)
                .or_insert_with(|| (value, Vec::new()))
                .1
                .push(case.id.clone());
        }
        let mut problems = Vec::new();
        for (name, (value, ids)) in &by_directory {
            let mismatches = self
                .directory_mismatches(env, endpoints, value)
                .map_err(|why| {
                    vec![format!(
                        "The control questions for the {name} stopped: {why}."
                    )]
                })?;
            if !mismatches.is_empty() {
                let shown: Vec<&String> = mismatches.iter().take(5).collect();
                problems.push(format!(
                    "The PDP under test does not hold the {name} (cases {}). {} control questions have another answer. First: {}.",
                    ids.join(", "),
                    mismatches.len(),
                    shown
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    fn run_pdp(
        &self,
        case: &Case,
        env: &PdpEnv,
        vars: &Vars,
        deadline: Instant,
        verified: &mut BTreeSet<String>,
    ) -> Result<CaseResult, Vec<String>> {
        let needs = needs_of(case);
        let mut spawned: Option<RunningServer> = None;
        let endpoints: Endpoints;
        if env.profile.spawn_fake_pdp {
            let data = match self.catalog.data_of(case) {
                Ok(data) => data,
                Err(why) => {
                    return Ok(CaseResult::failed(
                        case,
                        vec![failure(None, format!("the directory of the case: {why}"))],
                    ));
                }
            };
            let mut options = FakeOptions::default();
            if let Some(credential) = &env.credential {
                match fake_pdp::Credential::from_file_text(credential, "the profile") {
                    Ok(c) => options.credential = Some(c),
                    Err(e) => {
                        return Ok(CaseResult::failed(
                            case,
                            vec![failure(None, format!("the credential: {e}"))],
                        ));
                    }
                }
            }
            let started = FakeServer::from_value(&data, options)
                .map_err(|e| e.to_string())
                .and_then(|s| s.start("127.0.0.1:0").map_err(|e| e.to_string()));
            match started {
                Ok(server) => {
                    endpoints = Endpoints::on(&Authority {
                        host: "127.0.0.1".to_owned(),
                        port: server.local_addr().port(),
                    });
                    spawned = Some(server);
                }
                Err(why) => {
                    return Ok(CaseResult::failed(
                        case,
                        vec![failure(None, format!("fake-pdp: {why}"))],
                    ));
                }
            }
        } else {
            let Some(external) = &env.external else {
                return Ok(CaseResult::failed(
                    case,
                    vec![failure(None, "the run has no PDP")],
                ));
            };
            endpoints = external.clone();
            let p = &env.profile;
            let clock_control = p.load.is_some() || p.clock_admin_url.is_some();
            let counter_reset = p.load.is_some() || p.reset_url.is_some();
            if needs.counters && p.load.is_none() {
                return Ok(CaseResult::skipped(
                    case,
                    "the profile has no load request, and the case sets counters",
                ));
            }
            if needs.clock && !clock_control {
                return Ok(CaseResult::skipped(
                    case,
                    "the profile gives no control of the clock of the PDP",
                ));
            }
            if needs.usage && !counter_reset {
                return Ok(CaseResult::skipped(
                    case,
                    "the profile gives no reset of the counters of the PDP",
                ));
            }
            let data = self.catalog.data_of(case).ok();
            let mut setup: Result<(), String> = Ok(());
            if let (Some(load), Some(data)) = (&p.load, &data) {
                setup = self.post_admin(env, &load.url, &load.method, Some(data), deadline);
                if setup.is_ok() && p.directory_check.enabled {
                    let key = match &case.given.directory {
                        Some(crate::model::DirectoryRef::Name(name)) => name.clone(),
                        _ => format!("inline:{}", case.id),
                    };
                    if verified.insert(key.clone())
                        && let Ok(directory) = self.catalog.directory_of(case)
                    {
                        let mismatches = self
                            .directory_mismatches(env, &endpoints, &directory)
                            .map_err(|why| {
                                vec![format!("The control questions for `{key}` stopped: {why}.")]
                            })?;
                        if !mismatches.is_empty() {
                            return Err(vec![format!(
                                "The PDP under test does not hold the directory `{key}` after the load request of case {}. {} control questions have another answer. First: {}.",
                                case.id,
                                mismatches.len(),
                                mismatches[0]
                            )]);
                        }
                    }
                }
            } else if let Some(reset) = &p.reset_url {
                setup = self.post_admin(env, reset, "POST", None, deadline);
            }
            if setup.is_ok()
                && needs.clock
                && let Some(url) = &p.clock_admin_url
                && let Some(now) = case.given.clock.map(|c| c.now).or_else(|| {
                    data.as_ref()
                        .and_then(|d| d.pointer("/clock/now"))
                        .and_then(Value::as_u64)
                })
            {
                setup = self.post_admin(env, url, "POST", Some(&json!({"set": now})), deadline);
            }
            if let Err(why) = setup {
                return Ok(CaseResult::failed(
                    case,
                    vec![failure(None, format!("setup of the PDP: {why}"))],
                ));
            }
        }
        let mut hooks = PdpHooks;
        let outcome = self.steps(case, vars, Some(&endpoints), deadline, &mut hooks);
        if let Some(server) = spawned {
            server.shutdown();
        }
        Ok(match outcome.skip {
            Some(reason) if outcome.failures.is_empty() => CaseResult::skipped(case, reason),
            _ => CaseResult::from_failures(case, outcome.failures),
        })
    }
}

/// A short text for an answer, in a message.
fn summary_of(answer: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(status) = answer.get("http_status") {
        return format!("HTTP {status}");
    }
    match answer.get("decision") {
        Some(decision) => parts.push(format!("decision {decision}")),
        None => parts.push("no decision".to_owned()),
    }
    if let Some(reason) = answer.pointer("/context/reason") {
        parts.push(format!("reason {reason}"));
    }
    if let Some(limits) = answer.pointer("/context/limits") {
        parts.push(format!("limits {limits}"));
    }
    parts.join(", ")
}

/// What a role reads from its listeners around a step.
trait Hooks {
    /// Called before the request of a step.
    fn before(&mut self);
    /// Called after the answer. Return the messages of the failed checks.
    fn after(&mut self, prepared: &Prepared, reply: Option<&Reply>) -> Vec<String>;
}

struct PepHooks<'a> {
    pdp: &'a TestPdp,
    mark: usize,
    now: &'a dyn Fn() -> u64,
}

impl Hooks for PepHooks<'_> {
    fn before(&mut self) {
        self.mark = self.pdp.mark();
    }

    fn after(&mut self, prepared: &Prepared, reply: Option<&Reply>) -> Vec<String> {
        let questions = self.pdp.questions_since(self.mark);
        check(
            &prepared.expect,
            &Observed {
                reply,
                questions: Some(&questions),
                connections: Some(self.pdp.connections()),
                upstream: None,
                verifier: None,
                token_header: None,
                now: (self.now)(),
            },
        )
    }
}

struct EdgeHooks<'a> {
    env: &'a EdgeEnv,
    mark: usize,
    now: &'a dyn Fn() -> u64,
}

impl Hooks for EdgeHooks<'_> {
    fn before(&mut self) {
        self.mark = self.env.upstream.mark();
    }

    fn after(&mut self, prepared: &Prepared, reply: Option<&Reply>) -> Vec<String> {
        let received = self.env.upstream.since(self.mark);
        check(
            &prepared.expect,
            &Observed {
                reply,
                questions: None,
                connections: None,
                upstream: Some(&received),
                verifier: Some(&self.env.verifier),
                token_header: Some(&self.env.profile.token_header),
                now: (self.now)(),
            },
        )
    }
}

struct PdpHooks;

impl Hooks for PdpHooks {
    fn before(&mut self) {}

    fn after(&mut self, prepared: &Prepared, reply: Option<&Reply>) -> Vec<String> {
        check(
            &prepared.expect,
            &Observed {
                reply,
                questions: None,
                connections: None,
                upstream: None,
                verifier: None,
                token_header: None,
                now: 0,
            },
        )
    }
}

fn dummy_authority() -> Authority {
    Authority {
        host: "127.0.0.1".to_owned(),
        port: 1,
    }
}

/// The rules of the script of a case, after the replacement of the variables.
fn script_rules(case: &Case, vars: &Vars) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    for (index, raw) in case.given.pdp_script.iter().enumerate() {
        let value = vars
            .value(raw)
            .map_err(|name| format!("rule {}: the variable `{name}` has no value", index + 1))?;
        rules.push(Rule::parse(&value).map_err(|why| format!("rule {}: {why}", index + 1))?);
    }
    Ok(rules)
}
