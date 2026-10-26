//! The test PDP of a PEP case: a listener that follows the script of the case.
//!
//! The PEP under test calls this listener as its PDP. The listener reads each
//! rule of the script in order. The first rule whose `when` matches a
//! question gives the answer. The listener keeps each question for the checks
//! of the step. A question that no rule matches goes to a fake PDP when the
//! case has a directory. Without a directory, the question is a fault of the case.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use procurauth_core::authzen::Resource;
use procurauth_core::json::parse_slice;
use procurauth_core::path::NodePath;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::{
    Authority, ClientRequest, Handler, Headers, HttpServer, Outcome, Request, Response, send,
};

/// The path of the metadata of the PDP.
const METADATA_PATH: &str = "/.well-known/authzen-configuration";
/// The path of the Access Evaluation API.
const EVALUATION_PATH: &str = "/access/v1/evaluation";
/// The path of the Access Evaluations API.
const EVALUATIONS_PATH: &str = "/access/v1/evaluations";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WhenSpec {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    usage: Option<bool>,
    #[serde(default, rename = "match")]
    match_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodySpec {
    #[serde(default)]
    status: Option<u16>,
    body: Value,
    #[serde(default)]
    delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoAnswerSpec {
    no_answer: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RespondSpec {
    Body(BodySpec),
    NoAnswer(NoAnswerSpec),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    when: WhenSpec,
    respond: RespondSpec,
}

/// What a rule does.
#[derive(Clone, Debug)]
enum Reaction {
    Body {
        status: u16,
        body: Value,
        delay: Duration,
    },
    NoAnswer,
}

/// One rule of the script.
#[derive(Clone, Debug)]
pub(crate) struct Rule {
    subject: Option<String>,
    action: Option<String>,
    resource: Option<NodePath>,
    usage: Option<bool>,
    match_mode: Option<String>,
    reaction: Reaction,
}

impl Rule {
    /// Read a rule from JSON, after the runner replaced the variables.
    ///
    /// # Errors
    /// Returns a message when the rule is not valid.
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let spec: RuleSpec = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        let resource = match &spec.when.resource {
            Some(text) => Some(
                NodePath::parse(text)
                    .map_err(|e| format!("the resource `{text}` is not a path: {e}"))?,
            ),
            None => None,
        };
        let reaction = match spec.respond {
            RespondSpec::Body(body) => {
                let status = body.status.unwrap_or(200);
                if !(100..=599).contains(&status) {
                    return Err(format!(
                        "the status of a rule must be from 100 to 599, found {status}"
                    ));
                }
                Reaction::Body {
                    status,
                    body: body.body,
                    delay: Duration::from_millis(body.delay_ms.unwrap_or(0)),
                }
            }
            RespondSpec::NoAnswer(no) => {
                if !no.no_answer {
                    return Err("no_answer must be true".to_owned());
                }
                Reaction::NoAnswer
            }
        };
        Ok(Self {
            subject: spec.when.subject,
            action: spec.when.action,
            resource,
            usage: spec.when.usage,
            match_mode: spec.when.match_mode,
            reaction,
        })
    }

    fn matches(&self, question: &Value) -> bool {
        if let Some(subject) = &self.subject
            && question.pointer("/subject/id").and_then(Value::as_str) != Some(subject)
        {
            return false;
        }
        if let Some(action) = &self.action
            && question.pointer("/action/name").and_then(Value::as_str) != Some(action)
        {
            return false;
        }
        if let Some(path) = &self.resource
            && node_path_of(question).as_ref() != Some(path)
        {
            return false;
        }
        if let Some(usage) = self.usage
            && question.pointer("/context/usage").is_some() != usage
        {
            return false;
        }
        if let Some(mode) = &self.match_mode
            && question.pointer("/context/match").and_then(Value::as_str) != Some(mode)
        {
            return false;
        }
        true
    }
}

/// The node path of the resource of a question, when the chain is good.
fn node_path_of(question: &Value) -> Option<NodePath> {
    let resource = question.get("resource")?;
    Resource {
        resource_type: resource.get("type")?.as_str()?.to_owned(),
        id: resource.get("id")?.as_str()?.to_owned(),
        properties: resource
            .get("properties")
            .and_then(Value::as_object)
            .cloned(),
    }
    .node_path()
    .ok()
}

/// A question that the test PDP received.
#[derive(Clone, Debug)]
pub(crate) struct Question {
    /// The headers of the HTTP request that carried the question.
    pub(crate) headers: Headers,
    /// The question, as JSON. For a request with items, the item with the defaults of the request.
    pub(crate) json: Value,
}

#[derive(Default)]
struct Inner {
    rules: Vec<Rule>,
    fallback: Option<Authority>,
    questions: Vec<Question>,
    faults: Vec<String>,
    connections: std::collections::BTreeSet<usize>,
}

struct Core {
    inner: Mutex<Inner>,
    credential: Option<String>,
    address: SocketAddr,
}

/// What the PDP does with one question.
enum Answer {
    Body(u16, Value, Duration),
    Silent,
    Fallback,
    None,
}

impl Core {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn answer(&self, question: &Value) -> Answer {
        let inner = self.lock();
        for rule in &inner.rules {
            if rule.matches(question) {
                return match &rule.reaction {
                    Reaction::Body {
                        status,
                        body,
                        delay,
                    } => Answer::Body(*status, body.clone(), *delay),
                    Reaction::NoAnswer => Answer::Silent,
                };
            }
        }
        if inner.fallback.is_some() {
            Answer::Fallback
        } else {
            Answer::None
        }
    }

    fn metadata(&self, request: &Request) -> Response {
        let host = request
            .header("host")
            .filter(|h| {
                !h.is_empty()
                    && h.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')
                    })
            })
            .unwrap_or_else(|| self.address.to_string());
        let base = format!("http://{host}");
        Response::json(
            200,
            &json!({
                "policy_decision_point": base,
                "access_evaluation_endpoint": format!("{base}{EVALUATION_PATH}"),
                "access_evaluations_endpoint": format!("{base}{EVALUATIONS_PATH}"),
                "procurauth_usage_max_seconds": 5,
                "procurauth_idle_max_seconds": 30,
                "procurauth_evaluations_max_bytes": 1_048_576,
                "procurauth_evaluations_max_items": 100,
            }),
        )
    }

    fn authorized(&self, request: &Request) -> bool {
        match &self.credential {
            None => true,
            Some(credential) => {
                request.header("authorization").as_deref() == Some(&format!("Bearer {credential}"))
            }
        }
    }

    fn forward(&self, request: &Request) -> Response {
        let Some(target) = self.lock().fallback.clone() else {
            return Response::error(500, "no fake PDP");
        };
        let mut headers: Headers = Vec::new();
        for name in ["content-type", "authorization"] {
            if let Some(value) = request.header(name) {
                headers.push((name.to_owned(), value));
            }
        }
        let outgoing = ClientRequest {
            method: request.method.clone(),
            target: request.target.clone(),
            headers,
            body: Some(request.body.clone()),
        };
        match send(&target, &outgoing, Instant::now() + Duration::from_secs(10)) {
            Ok(reply) => Response {
                status: reply.status,
                headers: vec![(
                    "Content-Type".to_owned(),
                    reply
                        .header("content-type")
                        .unwrap_or_else(|| "application/json".to_owned()),
                )],
                body: reply.body,
            },
            Err(why) => Response::error(502, &why),
        }
    }

    fn fault(&self, question: &Value) {
        self.lock().faults.push(format!(
            "no rule of pdp_script matches the question {question}"
        ));
    }

    fn record(&self, request: &Request, json: Value) {
        self.lock().questions.push(Question {
            headers: request.headers.clone(),
            json,
        });
    }

    fn evaluation(&self, request: &Request, body: &Value) -> Outcome {
        self.record(request, body.clone());
        match self.answer(body) {
            Answer::Body(status, answer, delay) => {
                sleep(delay);
                Outcome::Respond(Response::json(status, &answer))
            }
            Answer::Silent => Outcome::Hold,
            Answer::Fallback => Outcome::Respond(self.forward(request)),
            Answer::None => {
                self.fault(body);
                Outcome::Respond(Response::error(500, "no rule"))
            }
        }
    }

    fn evaluations(&self, request: &Request, body: &Value) -> Outcome {
        let items = body
            .get("evaluations")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty());
        let Some(items) = items else {
            // A request with no items is one question (protocol 6.11).
            return self.evaluation(request, body);
        };
        let questions: Vec<Value> = items.iter().map(|item| effective(body, item)).collect();
        for question in &questions {
            self.record(request, question.clone());
        }
        // Protocol 6.11: a request with items and a `context.usage` is not valid.
        let usage_at_top = body.pointer("/context/usage").is_some();
        let usage_in_item = items
            .iter()
            .any(|item| item.pointer("/context/usage").is_some());
        if usage_at_top || usage_in_item {
            return Outcome::Respond(Response::error(400, "Bad Request"));
        }
        let mut bodies = Vec::new();
        let mut delay = Duration::ZERO;
        for question in &questions {
            match self.answer(question) {
                Answer::Body(status, answer, wait) => {
                    if status != 200 {
                        sleep(wait);
                        return Outcome::Respond(Response::json(status, &answer));
                    }
                    delay = delay.max(wait);
                    bodies.push(answer);
                }
                Answer::Silent => return Outcome::Hold,
                Answer::Fallback => return Outcome::Respond(self.forward(request)),
                Answer::None => {
                    self.fault(question);
                    return Outcome::Respond(Response::error(500, "no rule"));
                }
            }
        }
        sleep(delay);
        Outcome::Respond(Response::json(200, &json!({ "evaluations": bodies })))
    }
}

fn sleep(time: Duration) {
    if !time.is_zero() {
        thread::sleep(time);
    }
}

/// The question of an item: the members of the item, and the defaults of the request.
fn effective(request: &Value, item: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for name in ["subject", "action", "resource", "context"] {
        if let Some(value) = item.get(name).or_else(|| request.get(name)) {
            out.insert(name.to_owned(), value.clone());
        }
    }
    Value::Object(out)
}

impl Handler for Core {
    fn handle(&self, request: &Request) -> Outcome {
        self.lock().connections.insert(request.connection);
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", METADATA_PATH) => Outcome::Respond(self.metadata(request)),
            ("POST", EVALUATION_PATH | EVALUATIONS_PATH) => {
                if !self.authorized(request) {
                    return Outcome::Respond(Response::error(401, "Unauthorized"));
                }
                let Ok(body) = parse_slice(&request.body) else {
                    return Outcome::Respond(Response::error(400, "Bad Request"));
                };
                if !body.is_object() {
                    return Outcome::Respond(Response::error(400, "Bad Request"));
                }
                if request.path == EVALUATION_PATH {
                    self.evaluation(request, &body)
                } else {
                    self.evaluations(request, &body)
                }
            }
            _ => Outcome::Respond(Response::error(404, "Not Found")),
        }
    }
}

/// The test PDP.
pub(crate) struct TestPdp {
    server: HttpServer,
    core: Arc<Core>,
}

impl TestPdp {
    /// Start the listener. With a credential, the PDP asks for it as a Bearer credential.
    ///
    /// # Errors
    /// Returns a message when the address cannot open.
    pub(crate) fn start(address: SocketAddr, credential: Option<String>) -> Result<Self, String> {
        // The core needs its own address for the metadata, so bind first with a placeholder.
        let core = Arc::new(Core {
            inner: Mutex::new(Inner::default()),
            credential,
            address,
        });
        let server = HttpServer::start(address, Arc::clone(&core) as Arc<dyn Handler>)?;
        Ok(Self { server, core })
    }

    /// The address of the listener.
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// Start a case: new rules, no question, no fault and no connection.
    pub(crate) fn begin_case(&self, rules: Vec<Rule>, fallback: Option<Authority>) {
        self.server.release_held();
        {
            let mut inner = self.core.lock();
            inner.rules = rules;
            inner.fallback = fallback;
            inner.questions.clear();
            inner.faults.clear();
            inner.connections.clear();
        }
    }

    /// End a case: close the connections that the PDP holds with no answer.
    pub(crate) fn end_case(&self) {
        self.server.release_held();
    }

    /// The number of questions so far. A step uses it as a mark.
    pub(crate) fn mark(&self) -> usize {
        self.core.lock().questions.len()
    }

    /// The questions that came after a mark.
    pub(crate) fn questions_since(&self, mark: usize) -> Vec<Question> {
        let inner = self.core.lock();
        inner.questions.iter().skip(mark).cloned().collect()
    }

    /// The faults of the case: questions that no rule matched.
    pub(crate) fn faults(&self) -> Vec<String> {
        self.core.lock().faults.clone()
    }

    /// The connections that carried a request since the start of the case.
    pub(crate) fn connections(&self) -> usize {
        self.core.lock().connections.len()
    }

    /// Stop the listener.
    pub(crate) fn shutdown(self) {
        self.server.release_held();
        self.server.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Authority, ClientRequest, send};

    fn rule(value: Value) -> Rule {
        Rule::parse(&value).unwrap()
    }

    fn post(pdp: &TestPdp, path: &str, body: &Value, headers: Headers) -> crate::http::Reply {
        let authority = Authority {
            host: "127.0.0.1".to_owned(),
            port: pdp.local_addr().port(),
        };
        send(
            &authority,
            &ClientRequest {
                method: "POST".to_owned(),
                target: path.to_owned(),
                headers,
                body: Some(body.to_string().into_bytes()),
            },
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
    }

    fn question(sub: &str, usage: bool) -> Value {
        let mut q = json!({
            "subject": {"type": "user", "id": sub},
            "action": {"name": "data.read"},
            "resource": {"type": "database", "id": "d1", "properties": {"ancestors": [
                {"type": "service", "id": "datastore"}, {"type": "host", "id": "prod"}]}},
        });
        if usage {
            q["context"] = json!({"usage": {"units": 1}});
        }
        q
    }

    fn start() -> TestPdp {
        TestPdp::start("127.0.0.1:0".parse().unwrap(), None).unwrap()
    }

    #[test]
    fn the_first_rule_that_matches_gives_the_answer() {
        let pdp = start();
        pdp.begin_case(
            vec![
                rule(json!({"when": {"usage": true}, "respond": {"body": {"decision": true, "context": {"usage": {"units": 1}}}}})),
                rule(json!({"when": {}, "respond": {"body": {"decision": false}}})),
            ],
            None,
        );
        let a = post(&pdp, EVALUATION_PATH, &question("alice", true), vec![]);
        assert_eq!(a.status, 200);
        assert!(a.text().contains("\"units\":1"));
        let b = post(&pdp, EVALUATION_PATH, &question("alice", false), vec![]);
        assert_eq!(b.text(), "{\"decision\":false}");
        assert_eq!(pdp.questions_since(0).len(), 2);
        assert_eq!(pdp.questions_since(1).len(), 1);
        assert!(pdp.faults().is_empty());
        pdp.shutdown();
    }

    #[test]
    fn a_rule_matches_the_subject_the_action_the_resource_and_the_match() {
        let pdp = start();
        pdp.begin_case(
            vec![
                rule(json!({"when": {"subject": "bob"}, "respond": {"body": {"decision": false}}})),
                rule(json!({"when": {"action": "other"}, "respond": {"body": {"decision": false}}})),
                rule(json!({"when": {"resource": "service:datastore/host:prod/database:d1", "match": "subtree"},
                    "respond": {"status": 201, "body": {"decision": true}}})),
                rule(json!({"when": {}, "respond": {"body": {"decision": false, "context": {"reason": "x"}}}})),
            ],
            None,
        );
        let mut q = question("alice", false);
        q["context"] = json!({"match": "subtree"});
        assert_eq!(post(&pdp, EVALUATION_PATH, &q, vec![]).status, 201);
        assert!(
            post(&pdp, EVALUATION_PATH, &question("bob", false), vec![])
                .text()
                .contains("false")
        );
        let plain = post(&pdp, EVALUATION_PATH, &question("alice", false), vec![]);
        assert!(plain.text().contains("\"reason\":\"x\""));
        pdp.shutdown();
    }

    #[test]
    fn a_question_that_no_rule_matches_is_a_fault_of_the_case() {
        let pdp = start();
        pdp.begin_case(vec![], None);
        let reply = post(&pdp, EVALUATION_PATH, &question("alice", false), vec![]);
        assert_eq!(reply.status, 500);
        assert_eq!(pdp.faults().len(), 1);
        pdp.shutdown();
    }

    #[test]
    fn a_request_with_items_and_usage_gets_http_400_and_counts_its_items() {
        let pdp = start();
        pdp.begin_case(
            vec![rule(
                json!({"when": {}, "respond": {"body": {"decision": true}}}),
            )],
            None,
        );
        let mut body = json!({
            "subject": {"type": "user", "id": "alice"},
            "action": {"name": "data.read"},
            "context": {"usage": {"units": 1}},
            "evaluations": [
                {"resource": {"type": "service", "id": "datastore"}},
                {"resource": {"type": "service", "id": "datastore"}}
            ]
        });
        let reply = post(&pdp, EVALUATIONS_PATH, &body, vec![]);
        assert_eq!(reply.status, 400);
        let questions = pdp.questions_since(0);
        assert_eq!(questions.len(), 2);
        assert_eq!(questions[0].json["subject"]["id"], "alice");
        assert_eq!(questions[0].json["context"]["usage"]["units"], 1);
        // The same request with no usage gets one answer for each item.
        body.as_object_mut().unwrap().remove("context");
        let reply = post(&pdp, EVALUATIONS_PATH, &body, vec![]);
        assert_eq!(reply.status, 200);
        let answer: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(answer["evaluations"].as_array().unwrap().len(), 2);
        pdp.shutdown();
    }

    #[test]
    fn a_request_without_items_is_one_question() {
        let pdp = start();
        pdp.begin_case(
            vec![rule(
                json!({"when": {}, "respond": {"body": {"decision": true}}}),
            )],
            None,
        );
        let body = question("alice", true);
        let reply = post(&pdp, EVALUATIONS_PATH, &body, vec![]);
        assert_eq!(reply.status, 200);
        assert_eq!(reply.text(), "{\"decision\":true}");
        assert_eq!(pdp.questions_since(0).len(), 1);
        pdp.shutdown();
    }

    #[test]
    fn the_credential_is_checked_when_the_pdp_has_one() {
        let pdp =
            TestPdp::start("127.0.0.1:0".parse().unwrap(), Some("s3cret".to_owned())).unwrap();
        pdp.begin_case(
            vec![rule(
                json!({"when": {}, "respond": {"body": {"decision": true}}}),
            )],
            None,
        );
        let no = post(&pdp, EVALUATION_PATH, &question("a", false), vec![]);
        assert_eq!(no.status, 401);
        let yes = post(
            &pdp,
            EVALUATION_PATH,
            &question("a", false),
            vec![("Authorization".to_owned(), "Bearer s3cret".to_owned())],
        );
        assert_eq!(yes.status, 200);
        // Only the question that was authorized is kept.
        let kept = pdp.questions_since(0);
        assert_eq!(kept.len(), 1);
        assert_eq!(
            crate::http::header_value(&kept[0].headers, "authorization").as_deref(),
            Some("Bearer s3cret")
        );
        pdp.shutdown();
    }

    #[test]
    fn a_rule_can_give_a_status_a_delay_or_no_answer() {
        let pdp = start();
        pdp.begin_case(
            vec![
                rule(json!({"when": {"subject": "slow"}, "respond": {"body": {"decision": true}, "delay_ms": 150}})),
                rule(json!({"when": {"subject": "mute"}, "respond": {"no_answer": true}})),
                rule(json!({"when": {}, "respond": {"status": 429, "body": {"error": "x"}}})),
            ],
            None,
        );
        let started = Instant::now();
        assert_eq!(
            post(&pdp, EVALUATION_PATH, &question("slow", false), vec![]).status,
            200
        );
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert_eq!(
            post(&pdp, EVALUATION_PATH, &question("other", false), vec![]).status,
            429
        );
        let authority = Authority {
            host: "127.0.0.1".to_owned(),
            port: pdp.local_addr().port(),
        };
        let silent = send(
            &authority,
            &ClientRequest {
                method: "POST".to_owned(),
                target: EVALUATION_PATH.to_owned(),
                headers: vec![],
                body: Some(question("mute", false).to_string().into_bytes()),
            },
            Instant::now() + Duration::from_millis(200),
        );
        assert!(silent.is_err());
        pdp.end_case();
        pdp.shutdown();
    }

    #[test]
    fn the_metadata_names_the_endpoints() {
        let pdp = start();
        let authority = Authority {
            host: "127.0.0.1".to_owned(),
            port: pdp.local_addr().port(),
        };
        let reply = send(
            &authority,
            &ClientRequest {
                method: "GET".to_owned(),
                target: METADATA_PATH.to_owned(),
                headers: vec![],
                body: None,
            },
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert!(
            body["access_evaluation_endpoint"]
                .as_str()
                .unwrap()
                .ends_with(EVALUATION_PATH)
        );
        assert_eq!(body["procurauth_evaluations_max_items"], 100);
        // The metadata is not a question and not a connection that a case counts after a reset.
        assert!(pdp.questions_since(0).is_empty());
        pdp.shutdown();
    }

    #[test]
    fn a_rule_that_is_not_valid_is_an_error() {
        assert!(Rule::parse(&json!({"when": {"x": 1}, "respond": {"body": {}}})).is_err());
        assert!(Rule::parse(&json!({"when": {}, "respond": {"status": 99, "body": {}}})).is_err());
        assert!(
            Rule::parse(&json!({"when": {"resource": "nope"}, "respond": {"body": {}}})).is_err()
        );
        assert!(Rule::parse(&json!({"when": {}, "respond": {"no_answer": false}})).is_err());
    }
}
