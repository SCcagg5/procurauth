//! The questions of the PEP, the use of a budget and the map of the refusals.
//! The paragraphs are 3.3, 4.1, 5.5a, 6.4, 6.12, 7.5, 7.6, 10.0 to 10.3 and 10.6.
//! The transport of the tests records each request and answers from a script.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use procurauth_core::path::NodePath;
use procurauth_pep::operation::{Operation, node};
use procurauth_pep::refusal::{DenialCause, UnavailableCause};
use procurauth_pep::transport::TransportError;
use procurauth_pep::{Identity, Outcome, Pep, Refusal};
use serde_json::{Value, json};

const URL: &str = "http://pdp.test";

fn table(host: &str, database: &str, name: &str) -> NodePath {
    node(
        SERVICE,
        &[("host", host), ("database", database), ("table", name)],
    )
    .unwrap()
}

fn orders() -> NodePath {
    table("prod", "test2", "orders")
}

fn database(name: &str) -> NodePath {
    node(SERVICE, &[("host", "prod"), ("database", name)]).unwrap()
}

fn setup(transport: Arc<Scripted>) -> (Pep, Identity, Edge) {
    setup_with(transport, |_| {})
}

fn setup_with(
    transport: Arc<Scripted>,
    tweak: impl FnOnce(&mut procurauth_pep::config::PepConfig),
) -> (Pep, Identity, Edge) {
    let edge = Edge::new();
    let (pep, _) = pep(transport, &edge, URL, tweak);
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    (pep, who, edge)
}

fn read(node: NodePath) -> Operation {
    Operation::new("data.read", node)
}

fn refusal(outcome: Outcome) -> Refusal {
    outcome.into_result().unwrap_err()
}

// ---- The form of the question -------------------------------------------------

#[test]
fn p_3_3_the_question_has_the_subject_type_user_and_the_sub_as_id() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    assert!(
        pep.decide(&who, &Operation::new("data.read", orders()))
            .is_allowed()
    );
    let body = t.posts()[0].body.clone().unwrap();
    assert_eq!(body["subject"], json!({"type": "user", "id": "alice"}));
}

#[test]
fn p_9_6_the_question_holds_no_claim_other_than_sub() {
    let t = yes_to_all();
    let edge = Edge::new();
    let (pep, _) = pep(t.clone(), &edge, URL, |_| {});
    let mut claims = edge.claims(KEY_ALICE, Some("alice"));
    claims["email"] = json!("alice@example.org");
    claims["groups"] = json!(["staff"]);
    let who = pep
        .authenticate([(HEADER, edge.sign(&claims).as_str())])
        .unwrap();
    assert!(pep.decide(&who, &read(orders())).is_allowed());
    let text = t.posts()[0].body.clone().unwrap().to_string();
    for word in [
        "alice@example.org",
        "staff",
        "owner",
        "\"alice\"",
        "email",
        "groups",
        "claims",
    ] {
        assert!(!text.contains(word), "{word} in {text}");
    }
    assert!(text.contains(KEY_ALICE));
}

#[test]
fn p_4_1_the_question_has_the_chain_from_the_service_down() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    pep.decide(&who, &read(orders())).into_result().unwrap();
    let body = t.posts()[0].body.clone().unwrap();
    assert_eq!(body["resource"]["type"], "table");
    assert_eq!(body["resource"]["id"], "orders");
    assert_eq!(
        body["resource"]["properties"]["ancestors"],
        json!([
            {"type": "service", "id": "datastore"},
            {"type": "host", "id": "prod"},
            {"type": "database", "id": "test2"}
        ])
    );
    assert_eq!(body["action"], json!({"name": "data.read"}));
}

#[test]
fn p_4_1_the_service_has_no_chain() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    let service = node(SERVICE, &[]).unwrap();
    pep.decide(&who, &Operation::new("data.read", service))
        .into_result()
        .unwrap();
    let body = t.posts()[0].body.clone().unwrap();
    assert_eq!(
        body["resource"],
        json!({"type": "service", "id": "datastore"})
    );
}

#[test]
fn p_10_0_the_question_goes_to_the_default_path_with_the_credential() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    pep.decide(&who, &read(orders())).into_result().unwrap();
    let seen = t.seen();
    // The first request reads the metadata. It sends no credential.
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].path(), "/.well-known/authzen-configuration");
    assert!(seen[0].header("authorization").is_none());
    assert_eq!(seen[1].path(), "/access/v1/evaluation");
    assert_eq!(
        seen[1].header("authorization"),
        Some("Bearer test-credential-of-the-service")
    );
}

#[test]
fn p_8_3_the_pep_never_asks_for_the_action_access() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    let refusal = refusal(pep.decide(&who, &Operation::new("access", node(SERVICE, &[]).unwrap())));
    assert!(matches!(refusal, Refusal::Internal(_)), "{refusal:?}");
    assert!(t.posts().is_empty());
}

#[test]
fn p_5_1_a_read_of_the_action_document_asks_no_question() {
    let t = yes_to_all();
    let (pep, _, _) = setup(t.clone());
    let reply = pep.actions_reply("GET");
    assert_eq!(reply.status, 200);
    assert!(t.seen().is_empty());
}

#[test]
fn p_4_5_an_operation_that_the_document_does_not_allow_is_a_mistake_of_the_service() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    for operation in [
        Operation::new("data.unknown", orders()),
        // A table below another service.
        Operation::new("data.read", node("other", &[("host", "a")]).unwrap()),
        // A type that does not follow the parents.
        Operation::new("data.read", node(SERVICE, &[("table", "x")]).unwrap()),
        // A type that the document does not declare.
        Operation::new("data.read", node(SERVICE, &[("nothing", "x")]).unwrap()),
    ] {
        let r = refusal(pep.decide(&who, &operation));
        assert_eq!(r.status(), 500, "{r}");
    }
    assert!(t.posts().is_empty());
}

// ---- Budgets ------------------------------------------------------------------

#[test]
fn p_6_4_a_use_of_an_action_with_a_budget_sends_one_question_with_usage_1() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    let allowed = pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!(allowed.units(), 1);
    let posts = t.posts();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].path(), "/access/v1/evaluation");
    assert_eq!(
        posts[0].body.as_ref().unwrap()["context"],
        json!({"usage": {"units": 1}})
    );
}

#[test]
fn p_10_1_the_pep_does_not_send_the_same_question_without_usage_before() {
    let t = yes_to_all();
    let (pep, who, _) = setup_with(t.clone(), |c| {
        c.cache_ttl = std::time::Duration::from_secs(60)
    });
    pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!((t.usage_posts(), t.plain_posts()), (1, 0));
}

#[test]
fn p_6_4_a_use_of_an_action_without_a_budget_sends_no_usage() {
    // The document has no action without a budget, so build one.
    let edge = Edge::new();
    let t = yes_to_all();
    let mut data = datastore_data();
    data["services"][0]["document"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": "data.inspect", "resource_types": ["service", "host", "database", "table"],
            "description": "Inspect data.", "limits": ["max_duration"]
        }));
    let clock = procurauth_pep::clock::ManualClock::at_seconds(NOW);
    let pep = Pep::with_clock(
        config(URL, &edge),
        document_of(&data),
        t.clone(),
        Arc::new(clock),
    )
    .unwrap();
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let allowed = pep
        .decide(&who, &Operation::new("data.inspect", orders()))
        .into_result()
        .unwrap();
    assert_eq!(allowed.units(), 0);
    assert_eq!((t.usage_posts(), t.plain_posts()), (0, 1));
}

#[test]
fn p_6_12_a_true_answer_without_units_counts_as_false() {
    let t = Scripted::answering(|_| yes(json!({}), None));
    let (pep, who, _) = setup(t.clone());
    let r = refusal(pep.decide(&who, &read(orders())));
    assert_eq!(r.status(), 403);
    assert!(matches!(
        r,
        Refusal::Forbidden {
            cause: DenialCause::NoUsageUnits,
            ..
        }
    ));
    assert_eq!(t.usage_posts(), 1);
}

#[test]
fn p_6_12_a_true_answer_with_units_0_lets_the_use_run() {
    let t = Scripted::answering(|_| yes(json!({}), Some(0)));
    let (pep, who, _) = setup(t);
    let allowed = pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!(allowed.units(), 0);
}

#[test]
fn p_6_5_budget_exceeded_gives_a_429_with_the_retry_after_of_the_answer() {
    for seconds in [1, 12, 86_400] {
        let t = Scripted::answering(move |_| budget_exceeded(seconds));
        let (pep, who, _) = setup(t);
        let r = refusal(pep.decide(&who, &read(orders())));
        assert_eq!(
            r,
            Refusal::RateLimited {
                retry_after: seconds
            }
        );
        let reply = r.to_http();
        assert_eq!(reply.status, 429);
        assert_eq!(
            reply.header("Retry-After"),
            Some(seconds.to_string().as_str())
        );
    }
}

#[test]
fn p_10_3_budget_exceeded_with_a_bad_retry_after_is_a_503() {
    for answer in [
        json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 0}}),
        json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": "12"}}),
        json!({"decision": false, "context": {"reason": "budget_exceeded"}}),
        json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 1.5}}),
    ] {
        let t = Scripted::answering(move |_| answer.clone());
        let (pep, who, _) = setup(t);
        assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
    }
}

// ---- The map of the refusals (10.3) -----------------------------------------------

#[test]
fn p_10_3_a_false_answer_gives_403_and_the_reason_never_reaches_the_client() {
    for reason in [
        None,
        Some("unknown_subject"),
        Some("invalid_resource"),
        Some("invalid_request"),
        Some("other_reason"),
    ] {
        let answer = match reason {
            None => no(),
            Some(r) => json!({"decision": false, "context": {"reason": r}}),
        };
        let t = Scripted::answering(move |_| answer.clone());
        let (pep, who, _) = setup(t);
        let r = refusal(pep.decide(&who, &read(orders())));
        assert_eq!(r.status(), 403);
        let body = String::from_utf8(r.to_http().body).unwrap();
        if let Some(reason) = reason {
            assert!(!body.contains(reason), "{body}");
        }
        // The log text has the reason.
        if let Some(reason) = reason {
            assert!(r.to_string().contains(reason));
        }
    }
}

#[test]
fn p_10_3_a_status_other_than_200_gives_503() {
    for status in [400, 401, 403, 404, 429, 500, 502, 503, 301] {
        let t = Scripted::new(move |seen| {
            Ok(if seen.method == "GET" {
                json_response(404, &json!({}))
            } else {
                json_response(status, &json!({"decision": true}))
            })
        });
        let (pep, who, _) = setup(t);
        let r = refusal(pep.decide(&who, &read(orders())));
        assert_eq!(
            r,
            Refusal::Unavailable(UnavailableCause::Status(status)),
            "{status}"
        );
        assert_eq!(r.status(), 503);
    }
}

#[test]
fn p_10_3_an_answer_that_is_not_valid_gives_503() {
    let bodies: Vec<&[u8]> = vec![
        b"",
        b"true",
        b"[]",
        b"{}",
        br#"{"decision":"yes"}"#,
        br#"{"decision":null}"#,
        br#"{"decision":1}"#,
        b"not json",
        br#"{"decision":true,"decision":false}"#,
        br#"{"decision":true,"context":{"usage":{"units":5}}}"#,
    ];
    for body in bodies {
        let t = Scripted::new(move |seen| {
            Ok(if seen.method == "GET" {
                json_response(404, &json!({}))
            } else {
                procurauth_pep::transport::HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: body.to_vec(),
                }
            })
        });
        let (pep, who, _) = setup(t);
        let r = refusal(pep.decide(&who, &read(orders())));
        assert_eq!(r.status(), 503, "{}", String::from_utf8_lossy(body));
    }
}

#[test]
fn p_10_3_no_answer_gives_503() {
    for error in [
        TransportError::Timeout,
        TransportError::Lost("closed".into()),
        TransportError::NotSent("refused".into()),
        TransportError::Malformed("x".into()),
        TransportError::TooLarge,
    ] {
        let t = Scripted::new(move |seen| {
            if seen.method == "GET" {
                Ok(json_response(404, &json!({})))
            } else {
                Err(error.clone())
            }
        });
        let (pep, who, _) = setup(t);
        assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
    }
}

#[test]
fn p_10_3_an_answer_with_too_many_bytes_gives_503() {
    let t = Scripted::answering(
        |_| json!({"decision": true, "context": {"reason": "x".repeat(2_000_000)}}),
    );
    let (pep, who, _) = setup(t);
    assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
}

// ---- The retry rules (10.6) -----------------------------------------------------------

fn failing_pdp(error: TransportError, failures: usize) -> Arc<Scripted> {
    let left = Mutex::new(failures);
    Scripted::new(move |seen| {
        if seen.method == "GET" {
            return Ok(json_response(404, &json!({})));
        }
        let mut left = left.lock().unwrap();
        if *left > 0 {
            *left -= 1;
            return Err(error.clone());
        }
        let usage = seen.has_usage();
        Ok(json_response(200, &yes(json!({}), usage.then_some(1))))
    })
}

#[test]
fn p_10_6_a_lost_answer_to_a_question_with_usage_is_not_sent_again() {
    for error in [
        TransportError::Lost("closed".into()),
        TransportError::Timeout,
    ] {
        let t = failing_pdp(error, 1);
        let (pep, who, _) = setup(t.clone());
        let r = refusal(pep.decide(&who, &read(orders())));
        assert_eq!(r.status(), 503);
        assert_eq!(t.usage_posts(), 1, "one question only");
    }
}

#[test]
fn p_10_6_a_request_that_was_not_sent_can_go_again_one_time() {
    let t = failing_pdp(TransportError::NotSent("refused".into()), 1);
    let (pep, who, _) = setup(t.clone());
    let allowed = pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!(allowed.units(), 1);
    assert_eq!(t.usage_posts(), 2);
    // Two failures: the PEP stops.
    let t = failing_pdp(TransportError::NotSent("refused".into()), 2);
    let (pep, who, _) = setup(t.clone());
    assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
    assert_eq!(t.usage_posts(), 2);
}

#[test]
fn p_10_6_a_question_without_usage_goes_again_after_a_lost_connection_but_not_after_a_timeout() {
    let t = failing_pdp(TransportError::Lost("closed".into()), 1);
    let (pep, who, _) = setup(t.clone());
    let service = node(SERVICE, &[]).unwrap();
    assert!(
        pep.check(&who, &Operation::new("data.read", service.clone()))
            .is_allowed()
    );
    assert_eq!(t.plain_posts(), 2);

    let t = failing_pdp(TransportError::Timeout, 1);
    let (pep, who, _) = setup(t.clone());
    assert_eq!(
        refusal(pep.check(&who, &Operation::new("data.read", service))).status(),
        503
    );
    assert_eq!(t.plain_posts(), 1);
}

#[test]
fn p_10_6_the_pep_waits_longer_than_the_time_that_the_pdp_publishes() {
    let t = Scripted::new(|seen| {
        Ok(if seen.method == "GET" {
            json_response(
                200,
                &json!({
                    "policy_decision_point": URL,
                    "procurauth_usage_max_seconds": 8
                }),
            )
        } else {
            let usage = seen.has_usage();
            json_response(200, &yes(json!({}), usage.then_some(1)))
        })
    });
    let (pep, who, _) = setup_with(t.clone(), |c| {
        c.pdp.request_timeout = std::time::Duration::from_secs(3);
        c.pdp.usage_wait_margin = std::time::Duration::from_secs(2);
    });
    pep.decide(&who, &read(orders())).into_result().unwrap();
    pep.check(&who, &read(orders())).into_result().unwrap();
    let posts = t.posts();
    assert_eq!(posts[0].timeout, std::time::Duration::from_secs(10));
    assert_eq!(posts[1].timeout, std::time::Duration::from_secs(3));
}

// ---- Ceilings (7.3, 7.5, 7.6) -------------------------------------------------------------

#[test]
fn p_7_3_the_ceilings_of_the_answer_go_to_the_caller() {
    let t = Scripted::answering(|_| yes(json!({"max_rows": 100, "max_duration": 30}), Some(1)));
    let (pep, who, _) = setup(t);
    let allowed = pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!(allowed.ceilings().get("max_rows"), Some(100));
    assert_eq!(allowed.ceilings().get("max_duration"), Some(30));
    assert_eq!(allowed.ceilings().cap("max_rows", 5000).value, 100);
}

#[test]
fn p_7_5_a_ceiling_that_the_pep_cannot_apply_makes_the_answer_false() {
    // `max_conformance_unknown` is not in the document.
    let t = Scripted::answering(|_| yes(json!({"max_conformance_unknown": 5}), Some(1)));
    let (pep, who, _) = setup(t);
    let r = refusal(pep.decide(&who, &read(orders())));
    assert!(
        matches!(r, Refusal::Forbidden { cause: DenialCause::UnknownCeiling(ref n), .. } if n == "max_conformance_unknown"),
        "{r:?}"
    );
    assert_eq!(r.status(), 403);
}

#[test]
fn p_7_5_a_ceiling_that_the_action_does_not_list_makes_the_answer_false() {
    // `data.write` does not list `max_rows`.
    let t = Scripted::answering(|_| yes(json!({"max_rows": 5}), Some(1)));
    let (pep, who, _) = setup(t);
    let r = refusal(pep.decide(&who, &Operation::new("data.write", orders())));
    assert_eq!(r.status(), 403);
}

#[test]
fn p_7_3_a_budget_in_the_limits_of_an_answer_is_not_a_valid_answer() {
    let t = Scripted::answering(|_| yes(json!({"requests": 5}), Some(1)));
    let (pep, who, _) = setup(t);
    assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
}

#[test]
fn p_7_5_a_ceiling_value_that_is_not_a_whole_number_is_not_a_valid_answer() {
    for value in [json!("100"), json!(1.5), json!(-1), json!(null)] {
        let t = Scripted::answering(move |_| yes(json!({"max_rows": value.clone()}), Some(1)));
        let (pep, who, _) = setup(t);
        assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
    }
}

#[test]
fn p_7_6_the_pep_ignores_context_limits_in_a_false_answer() {
    let t = Scripted::answering(
        |_| json!({"decision": false, "context": {"limits": {"max_conformance_unknown": 5, "max_rows": "x"}}}),
    );
    let (pep, who, _) = setup(t);
    let r = refusal(pep.decide(&who, &read(orders())));
    assert!(
        matches!(
            r,
            Refusal::Forbidden {
                cause: DenialCause::Decision,
                ..
            }
        ),
        "{r:?}"
    );
}

#[test]
fn p_7_5_the_pep_sends_no_opt_in_member_and_no_context_limits() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    pep.decide(&who, &read(orders())).into_result().unwrap();
    let text = t.posts()[0].body.clone().unwrap().to_string();
    assert!(!text.contains("supported_mandatory_extensions"));
    assert!(!text.contains("limits"));
}

// ---- Other permissions and several actions (5.5a, 10.1) ---------------------------------------

fn copy(from: &str, to: &str) -> Operation {
    Operation::new("data.write", database(to)).also("data.read", table("prod", from, "orders"))
}

#[test]
fn p_5_5a_the_other_permission_is_asked_first_without_usage_then_the_use_with_usage() {
    let t = Scripted::answering(|q| {
        let usage = q.pointer("/context/usage").is_some();
        match q["action"]["name"].as_str().unwrap() {
            "data.read" => yes(json!({"max_rows": 1000}), None),
            _ => yes(json!({"max_duration": 10}), usage.then_some(1)),
        }
    });
    let (pep, who, _) = setup(t.clone());
    let allowed = pep
        .decide(&who, &copy("test1", "test2"))
        .into_result()
        .unwrap();
    let posts = t.posts();
    assert_eq!(posts.len(), 2);
    assert!(!posts[0].has_usage());
    assert_eq!(
        posts[0].body.as_ref().unwrap()["action"]["name"],
        "data.read"
    );
    assert!(posts[1].has_usage());
    assert_eq!(
        posts[1].body.as_ref().unwrap()["action"]["name"],
        "data.write"
    );
    // 10.1a: max_rows 1000 applies to the read, and max_duration 10 applies to the write.
    assert_eq!(allowed.units(), 1);
    assert_eq!(allowed.used().action, "data.write");
    assert_eq!(allowed.ceilings().get("max_duration"), Some(10));
    assert_eq!(allowed.ceilings().get("max_rows"), None);
    assert_eq!(allowed.others().len(), 1);
    assert_eq!(allowed.others()[0].ceilings.get("max_rows"), Some(1000));
    let source = table("prod", "test1", "orders");
    assert_eq!(
        allowed
            .ceilings_for("data.read", &source)
            .unwrap()
            .get("max_rows"),
        Some(1000)
    );
}

#[test]
fn p_10_1a_when_the_other_permission_is_false_no_question_has_usage() {
    let t = Scripted::answering(|q| {
        if q["action"]["name"] == "data.read" {
            no()
        } else {
            yes(json!({}), Some(1))
        }
    });
    let (pep, who, _) = setup(t.clone());
    let r = refusal(pep.decide(&who, &copy("test1", "test2")));
    assert_eq!(r.status(), 403);
    assert_eq!(t.usage_posts(), 0);
    assert_eq!(t.plain_posts(), 1);
}

#[test]
fn p_5_5a_only_one_action_of_the_operation_takes_units() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    pep.decide(&who, &copy("test1", "test2"))
        .into_result()
        .unwrap();
    assert_eq!(t.usage_posts(), 1);
}

#[test]
fn p_5_5a_the_ceilings_of_each_permission_come_from_its_own_answer() {
    // The other permission has an unknown ceiling: the whole operation is refused.
    let t = Scripted::answering(|q| {
        let usage = q.pointer("/context/usage").is_some();
        if q["action"]["name"] == "data.read" {
            yes(json!({"max_unknown": 1}), None)
        } else {
            yes(json!({}), usage.then_some(1))
        }
    });
    let (pep, who, _) = setup(t.clone());
    assert_eq!(
        refusal(pep.decide(&who, &copy("test1", "test2"))).status(),
        403
    );
    assert_eq!(t.usage_posts(), 0);
}

#[test]
fn p_5_5a_several_other_permissions_go_in_one_evaluations_request() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    let operation = Operation::new("data.write", database("test2"))
        .also("data.read", table("prod", "test1", "orders"))
        .also("data.read", table("prod", "test1", "customers"));
    pep.decide(&who, &operation).into_result().unwrap();
    let posts = t.posts();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].path(), "/access/v1/evaluations");
    assert_eq!(
        posts[0].body.as_ref().unwrap()["evaluations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(!posts[0].has_usage());
    assert_eq!(posts[1].path(), "/access/v1/evaluation");
    assert!(posts[1].has_usage());
}

#[test]
fn p_10_1_an_other_permission_equal_to_the_use_is_not_asked_without_usage() {
    let t = yes_to_all();
    let (pep, who, _) = setup(t.clone());
    let operation = read(orders()).also("data.read", orders());
    pep.decide(&who, &operation).into_result().unwrap();
    assert_eq!((t.usage_posts(), t.plain_posts()), (1, 0));
}

#[test]
fn p_10_1_several_actions_are_asked_in_order_and_the_search_stops_at_the_first_true() {
    let t = Scripted::answering(|q| {
        let usage = q.pointer("/context/usage").is_some();
        if q["action"]["name"] == "data.write" {
            no()
        } else {
            yes(json!({"max_rows": 7}), usage.then_some(1))
        }
    });
    let (pep, who, _) = setup(t.clone());
    let operation = Operation::new("data.write", orders()).or_else_use("data.read", orders());
    let allowed = pep.decide(&who, &operation).into_result().unwrap();
    assert_eq!(allowed.used().action, "data.read");
    assert_eq!(allowed.units(), 1);
    let names: Vec<_> = t
        .posts()
        .iter()
        .map(|p| p.body.clone().unwrap()["action"]["name"].clone())
        .collect();
    assert_eq!(names, [json!("data.write"), json!("data.read")]);
    assert_eq!(t.usage_posts(), 2);
}

#[test]
fn p_10_1_the_search_stops_at_the_first_budget_exceeded() {
    let t = Scripted::answering(|q| {
        if q["action"]["name"] == "data.write" {
            budget_exceeded(9)
        } else {
            yes(json!({}), Some(1))
        }
    });
    let (pep, who, _) = setup(t.clone());
    let operation = Operation::new("data.write", orders()).or_else_use("data.read", orders());
    assert_eq!(
        refusal(pep.decide(&who, &operation)),
        Refusal::RateLimited { retry_after: 9 }
    );
    assert_eq!(t.posts().len(), 1);
}

#[test]
fn p_10_1_when_all_actions_are_false_the_refusal_is_403() {
    let t = Scripted::answering(|_| no());
    let (pep, who, _) = setup(t.clone());
    let operation = Operation::new("data.write", orders()).or_else_use("data.read", orders());
    assert_eq!(refusal(pep.decide(&who, &operation)).status(), 403);
    assert_eq!(t.posts().len(), 2);
}

#[test]
fn p_13_a_false_answer_of_the_first_action_is_kept_and_the_next_run_costs_one_call() {
    let t = Scripted::answering(|q| {
        let usage = q.pointer("/context/usage").is_some();
        if q["action"]["name"] == "data.write" {
            no()
        } else {
            yes(json!({}), usage.then_some(1))
        }
    });
    let (pep, who, _) = setup_with(t.clone(), |c| {
        c.cache_ttl = std::time::Duration::from_secs(30)
    });
    let operation = Operation::new("data.write", orders()).or_else_use("data.read", orders());
    pep.decide(&who, &operation).into_result().unwrap();
    assert_eq!(t.posts().len(), 2);
    t.clear();
    pep.decide(&who, &operation).into_result().unwrap();
    assert_eq!(
        t.posts().len(),
        1,
        "the next run within cache_ttl costs one call"
    );
    assert_eq!(
        t.posts()[0].body.as_ref().unwrap()["action"]["name"],
        "data.read"
    );
}

// ---- The kept answers (10.1) -----------------------------------------------------------------------

fn counting_pdp() -> (Arc<Scripted>, Arc<Mutex<Vec<Value>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let copy = Arc::clone(&sent);
    let t = Scripted::answering(move |q| {
        copy.lock().unwrap().push(q.clone());
        let usage = q.pointer("/context/usage").is_some();
        match q["subject"]["id"].as_str().unwrap() {
            "bob" => no(),
            _ if q["action"]["name"] == "data.read" => {
                yes(json!({"max_rows": 10}), usage.then_some(1))
            }
            _ => yes(json!({}), usage.then_some(1)),
        }
    });
    (t, sent)
}

fn ttl(seconds: u64) -> impl FnOnce(&mut procurauth_pep::config::PepConfig) {
    move |c| c.cache_ttl = std::time::Duration::from_secs(seconds)
}

fn use_service() -> Operation {
    Operation::new("data.read", node(SERVICE, &[]).unwrap())
}

#[test]
fn p_10_1_without_cache_ttl_each_check_asks_the_pdp() {
    let (t, sent) = counting_pdp();
    let (pep, who, _) = setup(t);
    for _ in 0..3 {
        pep.check(&who, &use_service()).into_result().unwrap();
    }
    assert_eq!(sent.lock().unwrap().len(), 3);
    assert_eq!(pep.kept_answers(), 0);
}

#[test]
fn p_10_1_a_kept_answer_lives_for_cache_ttl_at_most() {
    let (t, sent) = counting_pdp();
    let edge = Edge::new();
    let (pep, clock) = pep(t, &edge, URL, ttl(5));
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    for _ in 0..3 {
        pep.check(&who, &use_service()).into_result().unwrap();
    }
    assert_eq!(sent.lock().unwrap().len(), 1);
    clock.advance_millis(4_999);
    pep.check(&who, &use_service()).into_result().unwrap();
    assert_eq!(sent.lock().unwrap().len(), 1);
    clock.advance_millis(2);
    pep.check(&who, &use_service()).into_result().unwrap();
    assert_eq!(sent.lock().unwrap().len(), 2);
}

#[test]
fn p_10_1_a_kept_answer_keeps_its_ceilings() {
    let (t, _) = counting_pdp();
    let (pep, who, _) = setup_with(t, ttl(5));
    for _ in 0..2 {
        let allowed = pep.check(&who, &use_service()).into_result().unwrap();
        assert_eq!(allowed.ceilings().get("max_rows"), Some(10));
    }
}

#[test]
fn p_10_1_a_kept_answer_applies_only_to_the_same_subject() {
    let (t, sent) = counting_pdp();
    let edge = Edge::new();
    let (pep, _) = pep(t, &edge, URL, ttl(60));
    let alice = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let bob = pep
        .authenticate([(HEADER, edge.token("bob").as_str())])
        .unwrap();
    assert!(pep.check(&alice, &use_service()).is_allowed());
    assert!(!pep.check(&bob, &use_service()).is_allowed());
    assert!(pep.check(&alice, &use_service()).is_allowed());
    assert!(!pep.check(&bob, &use_service()).is_allowed());
    assert_eq!(sent.lock().unwrap().len(), 2);
}

#[test]
fn p_10_1_a_kept_answer_applies_only_to_the_same_action_and_the_same_resource_with_its_chain() {
    let (t, sent) = counting_pdp();
    let (pep, who, _) = setup_with(t, ttl(60));
    pep.check(&who, &read(table("prod", "test2", "orders")))
        .into_result()
        .unwrap();
    pep.check(&who, &read(table("prod", "test2", "orders")))
        .into_result()
        .unwrap();
    assert_eq!(sent.lock().unwrap().len(), 1);
    // Another table, another database, another host, another action: one question each.
    pep.check(&who, &read(table("prod", "test2", "other")))
        .into_result()
        .unwrap();
    pep.check(&who, &read(table("prod", "test1", "orders")))
        .into_result()
        .unwrap();
    pep.check(&who, &read(table("staging", "test2", "orders")))
        .into_result()
        .unwrap();
    pep.check(
        &who,
        &Operation::new("data.write", table("prod", "test2", "orders")),
    )
    .into_result()
    .unwrap();
    assert_eq!(sent.lock().unwrap().len(), 5);
}

#[test]
fn p_10_1_a_kept_false_answer_refuses_a_use_with_no_question() {
    let (t, sent) = counting_pdp();
    let edge = Edge::new();
    let (pep, _) = pep(t, &edge, URL, ttl(60));
    let bob = pep
        .authenticate([(HEADER, edge.token("bob").as_str())])
        .unwrap();
    assert!(!pep.check(&bob, &read(orders())).is_allowed());
    // The use of an action with a budget: the kept `false` answer refuses it with no question.
    let r = refusal(pep.decide(&bob, &read(orders())));
    assert_eq!(r.status(), 403);
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[test]
fn p_10_1_a_kept_true_answer_never_starts_a_use_of_an_action_with_a_budget() {
    let (t, sent) = counting_pdp();
    let (pep, who, _) = setup_with(t, ttl(60));
    // The check keeps a `true` answer without usage (an approval or a call for input).
    pep.check(&who, &read(orders())).into_result().unwrap();
    assert_eq!(sent.lock().unwrap().len(), 1);
    // The run asks again, with usage.
    let allowed = pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!(allowed.units(), 1);
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert!(sent[1].pointer("/context/usage").is_some());
}

#[test]
fn p_10_1_the_pep_never_keeps_a_true_answer_with_units_above_0() {
    let (t, sent) = counting_pdp();
    let (pep, who, _) = setup_with(t, ttl(60));
    for _ in 0..3 {
        assert_eq!(
            pep.decide(&who, &read(orders()))
                .into_result()
                .unwrap()
                .units(),
            1
        );
    }
    assert_eq!(sent.lock().unwrap().len(), 3);
    assert_eq!(pep.kept_answers(), 0);
}

#[test]
fn p_10_1_a_true_answer_with_units_0_can_be_kept_for_cache_ttl() {
    let sent = Arc::new(Mutex::new(0_usize));
    let copy = Arc::clone(&sent);
    let t = Scripted::answering(move |_| {
        *copy.lock().unwrap() += 1;
        yes(json!({"max_rows": 3}), Some(0))
    });
    let edge = Edge::new();
    let (pep, clock) = pep(t, &edge, URL, ttl(5));
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    for _ in 0..3 {
        let allowed = pep.decide(&who, &read(orders())).into_result().unwrap();
        assert_eq!(allowed.units(), 0);
        assert_eq!(allowed.ceilings().get("max_rows"), Some(3));
    }
    assert_eq!(*sent.lock().unwrap(), 1);
    clock.advance_seconds(6);
    pep.decide(&who, &read(orders())).into_result().unwrap();
    assert_eq!(*sent.lock().unwrap(), 2);
}

#[test]
fn p_10_1_a_kept_budget_exceeded_answer_gives_a_retry_after_that_does_not_grow() {
    let sent = Arc::new(Mutex::new(0_usize));
    let copy = Arc::clone(&sent);
    let t = Scripted::answering(move |_| {
        *copy.lock().unwrap() += 1;
        budget_exceeded(12)
    });
    let edge = Edge::new();
    let (pep, clock) = pep(t, &edge, URL, ttl(30));
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    assert_eq!(
        refusal(pep.decide(&who, &read(orders()))).retry_after(),
        Some(12)
    );
    clock.advance_millis(3_400);
    assert_eq!(
        refusal(pep.decide(&who, &read(orders()))).retry_after(),
        Some(9)
    );
    clock.advance_millis(8_000);
    assert_eq!(
        refusal(pep.decide(&who, &read(orders()))).retry_after(),
        Some(1)
    );
    assert_eq!(
        *sent.lock().unwrap(),
        1,
        "the kept answer refuses with no question"
    );
    // After the window, the PEP asks again.
    clock.advance_millis(1_000);
    assert_eq!(
        refusal(pep.decide(&who, &read(orders()))).retry_after(),
        Some(12)
    );
    assert_eq!(*sent.lock().unwrap(), 2);
}

#[test]
fn p_10_1_a_kept_budget_exceeded_answer_lives_for_the_lower_of_retry_after_and_cache_ttl() {
    let sent = Arc::new(Mutex::new(0_usize));
    let copy = Arc::clone(&sent);
    let t = Scripted::answering(move |_| {
        *copy.lock().unwrap() += 1;
        budget_exceeded(60)
    });
    let edge = Edge::new();
    let (pep, clock) = pep(t, &edge, URL, ttl(2));
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    pep.decide(&who, &read(orders()));
    pep.decide(&who, &read(orders()));
    assert_eq!(*sent.lock().unwrap(), 1);
    clock.advance_millis(2_001);
    pep.decide(&who, &read(orders()));
    assert_eq!(*sent.lock().unwrap(), 2);
}

#[test]
fn p_10_1_a_false_answer_to_a_question_with_usage_is_kept_as_an_answer_without_usage() {
    let (t, sent) = counting_pdp();
    let edge = Edge::new();
    let (pep, _) = pep(t, &edge, URL, ttl(60));
    let bob = pep
        .authenticate([(HEADER, edge.token("bob").as_str())])
        .unwrap();
    assert_eq!(refusal(pep.decide(&bob, &read(orders()))).status(), 403);
    assert_eq!(sent.lock().unwrap().len(), 1);
    // The same question without usage gets the kept answer.
    assert!(!pep.check(&bob, &read(orders())).is_allowed());
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[test]
fn p_10_1_when_a_kept_true_answer_is_wrong_the_pep_deletes_the_answers_of_the_subject_and_the_node()
{
    // The PDP says `true` without usage, then `false` with usage: the rights changed.
    let flip = Arc::new(Mutex::new(false));
    let copy = Arc::clone(&flip);
    let t = Scripted::answering(move |q| {
        let usage = q.pointer("/context/usage").is_some();
        if usage {
            *copy.lock().unwrap() = true;
            no()
        } else if *copy.lock().unwrap() {
            no()
        } else {
            yes(json!({}), None)
        }
    });
    let edge = Edge::new();
    let (pep, _) = pep(t, &edge, URL, ttl(60));
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    // A kept `true` answer for another action on the same node.
    pep.check(&who, &Operation::new("data.write", orders()))
        .into_result()
        .unwrap();
    pep.check(&who, &read(orders())).into_result().unwrap();
    assert_eq!(pep.kept_answers(), 2);
    // A question with usage gets `false`. The PEP drops the kept answers of the subject and the node.
    // The `false` answer is kept as the answer to the plain question of the same action.
    assert_eq!(
        refusal(pep.decide(&who, &Operation::new("data.write", orders()))).status(),
        403
    );
    assert!(pep.kept_answers() <= 1);
    assert!(
        !pep.check(&who, &Operation::new("data.write", orders()))
            .is_allowed()
    );
}

#[test]
fn p_10_1b_the_number_of_kept_answers_has_a_fixed_bound() {
    let (t, _) = counting_pdp();
    let (pep, who, _) = setup_with(t, |c| {
        c.cache_ttl = std::time::Duration::from_secs(60);
        c.cache_max_entries = 3;
    });
    for i in 0..10 {
        pep.check(&who, &read(table("prod", "test2", &format!("t{i}"))))
            .into_result()
            .unwrap();
    }
    assert_eq!(pep.kept_answers(), 3);
}

// ---- Questions for a display (4.4, 6.6, 6.11) -------------------------------------------------------------

#[test]
fn p_4_4_a_display_question_has_match_subtree_and_no_usage_and_never_lets_a_use_run() {
    let t = Scripted::answering(|q| {
        if q.pointer("/context/match") == Some(&json!("subtree")) {
            yes(json!({}), None)
        } else {
            no()
        }
    });
    let (pep, who, _) = setup(t.clone());
    let permissions = [procurauth_pep::operation::Permission::new(
        "data.read",
        database("test1"),
    )];
    assert_eq!(pep.display(&who, &permissions).unwrap(), [true]);
    let body = t.posts()[0].body.clone().unwrap();
    assert_eq!(body["context"], json!({"match": "subtree"}));
    assert!(!t.posts()[0].has_usage());
    // The use asks its own question.
    assert_eq!(
        refusal(pep.decide(&who, &read(database("test1")))).status(),
        403
    );
}

#[test]
fn p_4_4_display_questions_go_in_one_evaluations_request_with_the_subject_and_the_match_once() {
    let t = Scripted::answering(|q| {
        if q["resource"]["id"] == "test2" {
            no()
        } else {
            yes(json!({}), None)
        }
    });
    let (pep, who, _) = setup(t.clone());
    let permissions: Vec<_> = ["test1", "test2", "test3"]
        .iter()
        .map(|d| procurauth_pep::operation::Permission::new("data.read", database(d)))
        .collect();
    assert_eq!(
        pep.display(&who, &permissions).unwrap(),
        [true, false, true]
    );
    let posts = t.posts();
    assert_eq!(posts.len(), 1);
    let body = posts[0].body.clone().unwrap();
    assert_eq!(posts[0].path(), "/access/v1/evaluations");
    assert_eq!(body["subject"], json!({"type": "user", "id": "alice"}));
    assert_eq!(body["context"], json!({"match": "subtree"}));
    assert_eq!(body["evaluations"].as_array().unwrap().len(), 3);
    assert!(body["evaluations"][0].get("subject").is_none());
}

#[test]
fn p_10_7a_display_questions_split_at_the_maxima_of_the_metadata() {
    let t = Scripted::new(|seen| {
        if seen.method == "GET" {
            return Ok(json_response(
                200,
                &json!({
                    "policy_decision_point": URL,
                    "access_evaluations_endpoint": "http://pdp.test/access/v1/evaluations",
                    "procurauth_evaluations_max_items": 2,
                }),
            ));
        }
        let body = seen.body.clone().unwrap();
        let n = body["evaluations"].as_array().unwrap().len();
        assert!(n <= 2, "{n} items");
        Ok(json_response(
            200,
            &json!({"evaluations": vec![yes(json!({}), None); n]}),
        ))
    });
    let (pep, who, _) = setup(t.clone());
    let permissions: Vec<_> = (0..5)
        .map(|i| {
            procurauth_pep::operation::Permission::new("data.read", database(&format!("d{i}")))
        })
        .collect();
    assert_eq!(pep.display(&who, &permissions).unwrap(), [true; 5]);
    assert_eq!(t.posts().len(), 3);
}

#[test]
fn p_10_7a_the_configured_maximum_applies_when_it_is_lower_than_the_published_one() {
    let t = Scripted::new(|seen| {
        if seen.method == "GET" {
            return Ok(json_response(
                200,
                &json!({
                    "policy_decision_point": URL,
                    "access_evaluations_endpoint": "http://pdp.test/access/v1/evaluations",
                    "procurauth_evaluations_max_items": 100,
                }),
            ));
        }
        let n = seen.body.clone().unwrap()["evaluations"]
            .as_array()
            .unwrap()
            .len();
        assert!(n <= 4);
        Ok(json_response(
            200,
            &json!({"evaluations": vec![yes(json!({}), None); n]}),
        ))
    });
    let (pep, who, _) = setup_with(t.clone(), |c| c.pdp.evaluations_max_items = 4);
    let permissions: Vec<_> = (0..9)
        .map(|i| {
            procurauth_pep::operation::Permission::new("data.read", database(&format!("d{i}")))
        })
        .collect();
    assert_eq!(pep.display(&who, &permissions).unwrap().len(), 9);
    assert_eq!(t.posts().len(), 3);
}

#[test]
fn p_10_7a_without_an_evaluations_endpoint_each_question_goes_alone() {
    let t = Scripted::new(|seen| {
        Ok(if seen.method == "GET" {
            // AuthZEN 1.0: a PDP with no Access Evaluations API omits the endpoint.
            json_response(200, &json!({"policy_decision_point": URL}))
        } else {
            json_response(200, &yes(json!({}), None))
        })
    });
    let (pep, who, _) = setup(t.clone());
    let permissions: Vec<_> = (0..3)
        .map(|i| {
            procurauth_pep::operation::Permission::new("data.read", database(&format!("d{i}")))
        })
        .collect();
    assert_eq!(pep.display(&who, &permissions).unwrap(), [true; 3]);
    let posts = t.posts();
    assert_eq!(posts.len(), 3);
    assert!(posts.iter().all(|p| p.path() == "/access/v1/evaluation"));
    assert!(
        posts
            .iter()
            .all(|p| p.body.as_ref().unwrap()["context"]["match"] == "subtree")
    );
}

#[test]
fn p_10_3_an_evaluations_answer_with_the_wrong_number_of_items_gives_503() {
    let t = Scripted::new(|seen| {
        Ok(if seen.method == "GET" {
            json_response(404, &json!({}))
        } else {
            json_response(200, &json!({"evaluations": [yes(json!({}), None)]}))
        })
    });
    let (pep, who, _) = setup(t);
    let permissions: Vec<_> = (0..3)
        .map(|i| {
            procurauth_pep::operation::Permission::new("data.read", database(&format!("d{i}")))
        })
        .collect();
    assert_eq!(pep.display(&who, &permissions).unwrap_err().status(), 503);
}

// ---- The metadata ---------------------------------------------------------------------------------------------

#[test]
fn p_10_0_the_endpoints_of_the_metadata_are_used() {
    let t = Scripted::new(|seen| {
        Ok(match (seen.method, seen.path()) {
            ("GET", "/.well-known/authzen-configuration") => json_response(
                200,
                &json!({
                    "policy_decision_point": URL,
                    "access_evaluation_endpoint": "http://pdp.test/v9/one",
                    "access_evaluations_endpoint": "http://pdp.test/v9/many",
                }),
            ),
            ("POST", "/v9/one") => json_response(200, &yes(json!({}), Some(1))),
            ("POST", "/v9/many") => json_response(
                200,
                &json!({"evaluations": [yes(json!({}), None), yes(json!({}), None)]}),
            ),
            _ => json_response(404, &json!({})),
        })
    });
    let (pep, who, _) = setup(t.clone());
    pep.decide(&who, &read(orders())).into_result().unwrap();
    let permissions: Vec<_> = (0..2)
        .map(|i| {
            procurauth_pep::operation::Permission::new("data.read", database(&format!("d{i}")))
        })
        .collect();
    assert_eq!(pep.display(&who, &permissions).unwrap(), [true, true]);
    let paths: Vec<_> = t.posts().iter().map(|p| p.path().to_owned()).collect();
    assert_eq!(paths, ["/v9/one", "/v9/many"]);
}

#[test]
fn p_10_0_an_endpoint_on_another_origin_makes_the_metadata_not_valid() {
    let t = Scripted::new(|seen| {
        Ok(if seen.method == "GET" {
            json_response(
                200,
                &json!({
                    "policy_decision_point": URL,
                    "access_evaluation_endpoint": "http://evil.example/steal",
                }),
            )
        } else {
            panic!("the PEP must not send a question");
        })
    });
    let (pep, who, _) = setup(t.clone());
    let r = refusal(pep.decide(&who, &read(orders())));
    assert!(
        matches!(r, Refusal::Unavailable(UnavailableCause::Metadata(_))),
        "{r:?}"
    );
    assert!(t.posts().is_empty());
}

#[test]
fn p_10_0_a_failed_metadata_read_gives_503_and_the_next_question_reads_it_again() {
    let reads = Arc::new(Mutex::new(0));
    let copy = Arc::clone(&reads);
    let t = Scripted::new(move |seen| {
        if seen.method == "GET" {
            let mut n = copy.lock().unwrap();
            *n += 1;
            return if *n == 1 {
                Err(TransportError::Timeout)
            } else {
                Ok(json_response(404, &json!({})))
            };
        }
        Ok(json_response(200, &yes(json!({}), Some(1))))
    });
    let (pep, who, _) = setup(t);
    assert_eq!(refusal(pep.decide(&who, &read(orders()))).status(), 503);
    assert!(pep.decide(&who, &read(orders())).is_allowed());
    assert!(pep.decide(&who, &read(orders())).is_allowed());
    assert_eq!(
        *reads.lock().unwrap(),
        2,
        "the metadata is read one time after it is good"
    );
}

#[test]
fn p_10_0_the_metadata_is_read_again_after_its_age_and_the_old_one_stays_when_the_read_fails() {
    let reads = Arc::new(Mutex::new(0));
    let copy = Arc::clone(&reads);
    let t = Scripted::new(move |seen| {
        if seen.method == "GET" {
            let mut n = copy.lock().unwrap();
            *n += 1;
            return match *n {
                1 => Ok(json_response(
                    200,
                    &json!({"policy_decision_point": URL, "procurauth_usage_max_seconds": 7}),
                )),
                _ => Err(TransportError::Timeout),
            };
        }
        let usage = seen.has_usage();
        Ok(json_response(200, &yes(json!({}), usage.then_some(1))))
    });
    let edge = Edge::new();
    let (pep, clock) = pep(t.clone(), &edge, URL, |c| {
        c.pdp.metadata_max_age = std::time::Duration::from_secs(60);
    });
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    assert!(pep.decide(&who, &read(orders())).is_allowed());
    clock.advance_seconds(59);
    assert!(pep.decide(&who, &read(orders())).is_allowed());
    assert_eq!(*reads.lock().unwrap(), 1);
    clock.advance_seconds(2);
    // The new read fails, and the PEP keeps the old metadata: the wait for a use stays 7 s + the margin.
    assert!(pep.decide(&who, &read(orders())).is_allowed());
    assert_eq!(
        *reads.lock().unwrap(),
        2,
        "one new read, and it fails with a timeout"
    );
    assert_eq!(
        t.posts().last().unwrap().timeout,
        std::time::Duration::from_secs(8)
    );
}

#[test]
fn p_10_7_the_pep_tells_the_transport_the_idle_time_from_the_metadata() {
    use procurauth_pep::transport::{HttpResponse, PdpTransport};
    struct Idle {
        inner: Arc<Scripted>,
        idle: Mutex<Vec<std::time::Duration>>,
    }
    impl PdpTransport for Idle {
        fn supports_scheme(&self, s: &str) -> bool {
            self.inner.supports_scheme(s)
        }
        fn post_json(
            &self,
            u: &str,
            h: &[(String, String)],
            b: &[u8],
            t: std::time::Duration,
        ) -> Result<HttpResponse, TransportError> {
            self.inner.post_json(u, h, b, t)
        }
        fn get_json(
            &self,
            u: &str,
            h: &[(String, String)],
            t: std::time::Duration,
        ) -> Result<HttpResponse, TransportError> {
            self.inner.get_json(u, h, t)
        }
        fn set_idle_close(&self, d: std::time::Duration) {
            self.idle.lock().unwrap().push(d);
        }
    }
    let inner = Scripted::new(|seen| {
        Ok(if seen.method == "GET" {
            json_response(
                200,
                &json!({"policy_decision_point": URL, "procurauth_idle_max_seconds": 6}),
            )
        } else {
            json_response(200, &yes(json!({}), Some(1)))
        })
    });
    let transport = Arc::new(Idle {
        inner,
        idle: Mutex::new(Vec::new()),
    });
    let edge = Edge::new();
    let (pep, _) = pep(transport.clone(), &edge, URL, |c| {
        c.pdp.idle_close_after = std::time::Duration::from_secs(30)
    });
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    pep.decide(&who, &read(orders())).into_result().unwrap();
    // The PEP closes an idle connection after half of the published time.
    assert_eq!(
        *transport.idle.lock().unwrap(),
        [std::time::Duration::from_secs(3)]
    );
}

#[test]
fn p_10_0_the_pep_stops_at_start_when_the_transport_has_no_tls_for_an_https_link() {
    struct Plain;
    impl procurauth_pep::transport::PdpTransport for Plain {
        fn supports_scheme(&self, s: &str) -> bool {
            s == "http"
        }
        fn post_json(
            &self,
            _: &str,
            _: &[(String, String)],
            _: &[u8],
            _: std::time::Duration,
        ) -> Result<procurauth_pep::transport::HttpResponse, TransportError> {
            unreachable!()
        }
        fn get_json(
            &self,
            _: &str,
            _: &[(String, String)],
            _: std::time::Duration,
        ) -> Result<procurauth_pep::transport::HttpResponse, TransportError> {
            unreachable!()
        }
    }
    let edge = Edge::new();
    let mut cfg = config("https://pdp.example", &edge);
    cfg.pdp.allow_insecure_pdp_link = false;
    let errors = Pep::new(cfg, datastore_document(), Arc::new(Plain)).unwrap_err();
    assert_eq!(errors[0].key, "pdp.url");
}

#[test]
fn p_10_0_the_pep_refuses_a_document_for_another_service() {
    let edge = Edge::new();
    let mut cfg = config(URL, &edge);
    cfg.service_id = "other".into();
    let errors = Pep::new(cfg, datastore_document(), yes_to_all()).unwrap_err();
    assert_eq!(errors[0].key, "action_document.server");
}

#[test]
fn p_10_0_the_pep_refuses_an_http_link_without_the_flag() {
    let edge = Edge::new();
    let mut cfg = config(URL, &edge);
    cfg.pdp.allow_insecure_pdp_link = false;
    let errors = Pep::new(cfg, datastore_document(), yes_to_all()).unwrap_err();
    assert_eq!(errors[0].key, "pdp.url");
}
