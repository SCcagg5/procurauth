//! The questions to the PDP: the requests, the retries and the answers (10.0 to 10.7a).
//!
//! This module sends a question through a [`PdpTransport`], and it reads
//! the answer. It also reads the metadata of the PDP. It follows the
//! published limits. The first limit is the time to wait for a question with
//! `context.usage` (6.9, 10.6). The second is the idle time of a connection
//! (10.7). The third is the largest request (10.7a).
//!
//! A question with `context.usage` is not idempotent. The module sends it
//! again only when the request did not leave the PEP (10.6).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use procurauth_core::authzen::{Decision, EvaluationRequest, MatchMode, Resource};
use procurauth_core::json::parse_slice;
use procurauth_core::path::NodePath;
use serde_json::{Map, Value, json};

use crate::clock::Clock;
use crate::config::{PdpConfig, Secret};
use crate::metadata::{PdpMetadata, metadata_url};
use crate::refusal::UnavailableCause;
use crate::transport::{HttpResponse, PdpTransport};
use crate::url::Url;

struct MetaState {
    meta: Option<PdpMetadata>,
    /// The time to read the metadata again, in milliseconds since the Unix epoch.
    refresh_at_ms: u64,
}

/// After a failed read, the PEP waits this long before it tries again (when it still has old metadata).
const RETRY_AFTER_FAILURE_MS: u64 = 5_000;

pub(crate) struct PdpClient {
    base: Url,
    credential: Secret,
    request_timeout: Duration,
    usage_wait_margin: Duration,
    idle_close_after: Duration,
    evaluations_max_bytes: u64,
    evaluations_max_items: u64,
    max_response_bytes: u64,
    plain_retries: u32,
    metadata_max_age_ms: u64,
    transport: Arc<dyn PdpTransport>,
    clock: Arc<dyn Clock>,
    state: Mutex<MetaState>,
}

/// The limits of one Access Evaluations request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BatchLimits {
    pub(crate) max_items: usize,
    pub(crate) max_bytes: usize,
}

fn transport_failure(text: impl ToString) -> UnavailableCause {
    UnavailableCause::Transport(text.to_string())
}

/// Read one answer. A `context.limits` in a `false` answer is not read: the PEP ignores it (7.6).
pub(crate) fn decision_from_value(value: &Value) -> Result<Decision, UnavailableCause> {
    let mut copy = value.clone();
    if copy.get("decision") == Some(&Value::Bool(false))
        && let Some(context) = copy.get_mut("context").and_then(Value::as_object_mut)
    {
        context.remove("limits");
    }
    Decision::from_value(&copy).map_err(|findings| {
        let first = findings
            .first()
            .map_or_else(String::new, |f| format!("{} {}", f.path, f.message));
        UnavailableCause::Answer(first)
    })
}

impl PdpClient {
    pub(crate) fn new(
        config: &PdpConfig,
        transport: Arc<dyn PdpTransport>,
        clock: Arc<dyn Clock>,
        base: Url,
    ) -> Self {
        Self {
            base,
            credential: config.credential.clone(),
            request_timeout: config.request_timeout,
            usage_wait_margin: config.usage_wait_margin,
            idle_close_after: config.idle_close_after,
            evaluations_max_bytes: config.evaluations_max_bytes,
            evaluations_max_items: config.evaluations_max_items,
            max_response_bytes: config.max_response_bytes,
            plain_retries: config.plain_retries,
            metadata_max_age_ms: u64::try_from(config.metadata_max_age.as_millis())
                .unwrap_or(u64::MAX),
            transport,
            clock,
            state: Mutex::new(MetaState {
                meta: None,
                refresh_at_ms: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MetaState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The metadata. The PEP reads it at the first use and when it is older
    /// than `metadata_max_age`. When a new read fails, the old metadata stays.
    pub(crate) fn metadata(&self) -> Result<PdpMetadata, UnavailableCause> {
        let now = self.clock.now_millis();
        let stale = {
            let state = self.lock();
            match &state.meta {
                Some(meta) if now < state.refresh_at_ms => return Ok(meta.clone()),
                other => other.clone(),
            }
        };
        match self.refresh() {
            Ok(meta) => Ok(meta),
            Err(error) => match stale {
                Some(meta) => {
                    // Keep the old metadata, and do not read again at each question.
                    let wait = self.metadata_max_age_ms.min(RETRY_AFTER_FAILURE_MS);
                    self.lock().refresh_at_ms = now.saturating_add(wait);
                    Ok(meta)
                }
                None => Err(error),
            },
        }
    }

    /// Read the metadata now, and keep it.
    pub(crate) fn refresh(&self) -> Result<PdpMetadata, UnavailableCause> {
        let url = metadata_url(&self.base).to_text();
        // A read of the metadata changes nothing, so the PEP can repeat it after a lost connection.
        let mut retries = self.plain_retries;
        let response = loop {
            match self.transport.get_json(&url, &[], self.request_timeout) {
                Ok(response) => break response,
                Err(error) if error.can_repeat_plain_question() && retries > 0 => retries -= 1,
                Err(error) => return Err(transport_failure(error)),
            }
        };
        self.check_size(&response)?;
        let meta = match response.status {
            200 => PdpMetadata::parse(&self.base, &response.body)
                .map_err(|e| UnavailableCause::Metadata(e.to_string()))?,
            // A PDP with no metadata document uses the default paths (10.0, step 4).
            404 | 405 | 410 | 501 => PdpMetadata::defaults(&self.base),
            other => return Err(UnavailableCause::Status(other)),
        };
        let idle = match meta.idle_max_seconds {
            Some(seconds) => self
                .idle_close_after
                .min(Duration::from_millis(seconds.saturating_mul(500))),
            None => self.idle_close_after,
        };
        self.transport.set_idle_close(idle);
        let mut state = self.lock();
        state.meta = Some(meta.clone());
        state.refresh_at_ms = self
            .clock
            .now_millis()
            .saturating_add(self.metadata_max_age_ms);
        Ok(meta)
    }

    fn check_size(&self, response: &HttpResponse) -> Result<(), UnavailableCause> {
        if u64::try_from(response.body.len()).unwrap_or(u64::MAX) > self.max_response_bytes {
            return Err(UnavailableCause::Answer(
                "the answer is larger than `pdp.max_response_bytes`".to_owned(),
            ));
        }
        Ok(())
    }

    /// The longest wait for an answer to a question with `context.usage` (10.6).
    /// It is the time that the PDP publishes plus a margin. It is at least the
    /// normal timeout.
    fn usage_timeout(&self, meta: &PdpMetadata) -> Duration {
        match meta.usage_max_seconds {
            Some(seconds) => {
                (Duration::from_secs(seconds) + self.usage_wait_margin).max(self.request_timeout)
            }
            None => self.request_timeout,
        }
    }

    pub(crate) fn batch_limits(&self, meta: &PdpMetadata) -> BatchLimits {
        let items = meta
            .evaluations_max_items
            .map_or(self.evaluations_max_items, |m| {
                m.min(self.evaluations_max_items)
            });
        let bytes = meta
            .evaluations_max_bytes
            .map_or(self.evaluations_max_bytes, |m| {
                m.min(self.evaluations_max_bytes)
            });
        BatchLimits {
            max_items: usize::try_from(items).unwrap_or(usize::MAX),
            max_bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
        }
    }

    /// Send a POST request with the retry rules of 10.6.
    fn post(
        &self,
        url: &Url,
        body: &[u8],
        timeout: Duration,
        has_usage: bool,
    ) -> Result<HttpResponse, UnavailableCause> {
        let headers = [(
            "Authorization".to_owned(),
            format!("Bearer {}", self.credential.expose()),
        )];
        let mut not_sent_retries = 1_u32;
        let mut plain_retries = self.plain_retries;
        loop {
            match self
                .transport
                .post_json(&url.to_text(), &headers, body, timeout)
            {
                Ok(response) => {
                    self.check_size(&response)?;
                    return if response.status == 200 {
                        Ok(response)
                    } else {
                        Err(UnavailableCause::Status(response.status))
                    };
                }
                Err(error) => {
                    // 10.6: after a timeout, a lost answer or a connection error,
                    // never send a question with `context.usage` again. The one
                    // exception is a request that did not leave the PEP.
                    let again = if error.request_was_not_sent() && not_sent_retries > 0 {
                        not_sent_retries -= 1;
                        true
                    } else if !has_usage && error.can_repeat_plain_question() && plain_retries > 0 {
                        plain_retries -= 1;
                        true
                    } else {
                        false
                    };
                    if !again {
                        return Err(transport_failure(error));
                    }
                }
            }
        }
    }

    /// Ask one question. `question` has `context.usage` when it is a use.
    pub(crate) fn ask(
        &self,
        question: &EvaluationRequest,
        has_usage: bool,
    ) -> Result<Decision, UnavailableCause> {
        let meta = self.metadata()?;
        let body = question.to_value().to_string().into_bytes();
        let timeout = if has_usage {
            self.usage_timeout(&meta)
        } else {
            self.request_timeout
        };
        let response = self.post(&meta.evaluation_endpoint, &body, timeout, has_usage)?;
        let value = parse_slice(&response.body)
            .map_err(|e| UnavailableCause::Answer(format!("the body is not valid JSON: {e}")))?;
        decision_from_value(&value)
    }

    /// Ask many questions without `context.usage`, for one subject, with one
    /// `context.match`. The PEP sends them in Access Evaluations requests that
    /// stay within the maxima of the PDP (10.7a). The answers come in the order of the questions.
    pub(crate) fn ask_many(
        &self,
        subject: &str,
        mode: MatchMode,
        items: &[(&str, &NodePath)],
    ) -> Result<Vec<Decision>, UnavailableCause> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let meta = self.metadata()?;
        let Some(endpoint) = meta.evaluations_endpoint.clone() else {
            // The PDP has no Access Evaluations API: one request for each question.
            let mut out = Vec::with_capacity(items.len());
            for (action, node) in items {
                let mut question = EvaluationRequest::new(subject, action, node);
                if mode == MatchMode::Subtree {
                    question = question.with_match(mode);
                }
                out.push(self.ask(&question, false)?);
            }
            return Ok(out);
        };
        let limits = self.batch_limits(&meta);
        let envelope = envelope(subject, mode);
        let mut out = Vec::with_capacity(items.len());
        for chunk in split(&envelope, items, limits)? {
            let body = chunk.to_string().into_bytes();
            let count = chunk["evaluations"].as_array().map_or(0, Vec::len);
            let response = self.post(&endpoint, &body, self.request_timeout, false)?;
            let value = parse_slice(&response.body).map_err(|e| {
                UnavailableCause::Answer(format!("the body is not valid JSON: {e}"))
            })?;
            let list = value
                .get("evaluations")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    UnavailableCause::Answer("the member `evaluations` is absent".to_owned())
                })?;
            if list.len() != count {
                return Err(UnavailableCause::Answer(format!(
                    "the PDP gave {} answers for {count} questions",
                    list.len()
                )));
            }
            for item in list {
                out.push(decision_from_value(item)?);
            }
        }
        Ok(out)
    }
}

/// The part of an Access Evaluations request that all items share: the
/// subject and `context.match`.
fn envelope(subject: &str, mode: MatchMode) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("subject".into(), json!({"type": "user", "id": subject}));
    if mode == MatchMode::Subtree {
        map.insert("context".into(), json!({"match": mode.as_str()}));
    }
    map
}

fn item_value(action: &str, node: &NodePath) -> Value {
    let resource = Resource::from_path(node);
    let mut res = Map::new();
    res.insert("type".into(), json!(resource.resource_type));
    res.insert("id".into(), json!(resource.id));
    if let Some(properties) = resource.properties {
        res.insert("properties".into(), Value::Object(properties));
    }
    json!({"action": {"name": action}, "resource": Value::Object(res)})
}

/// Split the items into requests that do not pass the maxima (10.7a).
fn split(
    envelope: &Map<String, Value>,
    items: &[(&str, &NodePath)],
    limits: BatchLimits,
) -> Result<Vec<Value>, UnavailableCause> {
    let overhead = {
        let mut empty = envelope.clone();
        empty.insert("evaluations".into(), Value::Array(Vec::new()));
        Value::Object(empty).to_string().len()
    };
    let mut requests = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    let mut size = overhead;
    for (action, node) in items {
        let item = item_value(action, node);
        let item_size = item.to_string().len() + 1;
        if overhead + item_size > limits.max_bytes {
            return Err(UnavailableCause::Transport(format!(
                "one question needs {} bytes, and the PDP reads at most {} bytes in one request",
                overhead + item_size,
                limits.max_bytes
            )));
        }
        if !current.is_empty()
            && (current.len() >= limits.max_items || size + item_size > limits.max_bytes)
        {
            requests.push(make_request(envelope, std::mem::take(&mut current)));
            size = overhead;
        }
        size += item_size;
        current.push(item);
    }
    if !current.is_empty() {
        requests.push(make_request(envelope, current));
    }
    Ok(requests)
}

fn make_request(envelope: &Map<String, Value>, items: Vec<Value>) -> Value {
    let mut map = envelope.clone();
    map.insert("evaluations".into(), Value::Array(items));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_core::path::NodeRef;

    fn node(id: &str) -> NodePath {
        NodePath::from_nodes(vec![NodeRef::service("s"), NodeRef::new("host", id)]).unwrap()
    }

    #[test]
    fn p_7_6_a_false_answer_with_a_bad_limits_member_is_still_read() {
        let value = json!({"decision": false, "context": {"limits": {"max_rows": "x"}}});
        let decision = decision_from_value(&value).unwrap();
        assert!(!decision.decision);
        assert!(decision.context.limits.is_empty());
        // A true answer with the same member is not valid.
        let value = json!({"decision": true, "context": {"limits": {"max_rows": "x"}}});
        assert!(decision_from_value(&value).is_err());
    }

    #[test]
    fn p_10_3_an_answer_that_is_not_valid_is_refused() {
        for value in [
            json!({}),
            json!("true"),
            json!({"decision": null}),
            json!({"decision": 1}),
            json!([]),
            json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 0}}),
            json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": "12"}}),
            json!({"decision": false, "context": {"reason": "budget_exceeded"}}),
            json!({"decision": true, "context": {"usage": {"units": 2}}}),
        ] {
            assert!(decision_from_value(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn p_10_7a_a_request_never_passes_the_maximum_number_of_items() {
        let nodes: Vec<NodePath> = (0..7).map(|i| node(&format!("h{i}"))).collect();
        let items: Vec<(&str, &NodePath)> = nodes.iter().map(|n| ("a.read", n)).collect();
        let requests = split(
            &envelope("alice", MatchMode::Subtree),
            &items,
            BatchLimits {
                max_items: 3,
                max_bytes: 1_000_000,
            },
        )
        .unwrap();
        let counts: Vec<usize> = requests
            .iter()
            .map(|r| r["evaluations"].as_array().unwrap().len())
            .collect();
        assert_eq!(counts, [3, 3, 1]);
        for request in &requests {
            assert_eq!(request["subject"]["id"], "alice");
            assert_eq!(request["context"]["match"], "subtree");
            assert!(request["evaluations"][0]["action"]["name"] == "a.read");
        }
    }

    #[test]
    fn p_10_7a_a_request_never_passes_the_maximum_number_of_bytes() {
        let nodes: Vec<NodePath> = (0..10).map(|i| node(&format!("h{i}"))).collect();
        let items: Vec<(&str, &NodePath)> = nodes.iter().map(|n| ("a.read", n)).collect();
        let limit = 400;
        let requests = split(
            &envelope("alice", MatchMode::Node),
            &items,
            BatchLimits {
                max_items: 100,
                max_bytes: limit,
            },
        )
        .unwrap();
        assert!(requests.len() > 1);
        let total: usize = requests
            .iter()
            .map(|r| {
                assert!(r.to_string().len() <= limit, "{}", r.to_string().len());
                r["evaluations"].as_array().unwrap().len()
            })
            .sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn p_10_7a_one_question_above_the_maximum_is_an_error() {
        let n = node("h");
        let error = split(
            &envelope("alice", MatchMode::Node),
            &[("a.read", &n)],
            BatchLimits {
                max_items: 10,
                max_bytes: 20,
            },
        )
        .unwrap_err();
        assert!(matches!(error, UnavailableCause::Transport(_)));
    }

    #[test]
    fn p_6_11_a_request_with_items_has_no_context_usage() {
        let n = node("h");
        let requests = split(
            &envelope("alice", MatchMode::Subtree),
            &[("a.read", &n)],
            BatchLimits {
                max_items: 10,
                max_bytes: 10_000,
            },
        )
        .unwrap();
        let text = requests[0].to_string();
        assert!(!text.contains("usage"), "{text}");
    }
}
