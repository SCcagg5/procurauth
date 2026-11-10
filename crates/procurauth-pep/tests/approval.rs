//! The approval of an effect: the steps of 17.7, the narrow API of 17.4 and what the PEP
//! never reads (17.12). The PDP is a script, so each answer is exact.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use procurauth_core::effect::{effect_hash, resource_text};
use procurauth_pep::approval::{ApprovalCall, ApprovalRefusal, Control, Verdict};
use procurauth_pep::clock::ManualClock;
use procurauth_pep::operation::{Operation, node};
use procurauth_pep::refusal::UnavailableCause;
use procurauth_pep::{Identity, Outcome, Pep, Refusal};
use serde_json::{Value, json};

const ACTION: &str = "data.write";

fn op() -> Value {
    json!({"tool": "append_rows", "table": "orders", "rows": "[{\"id\":1}]"})
}

fn view() -> Value {
    json!({"title": "Add rows", "fields": [["Table", "/table"]], "body": "/rows"})
}

fn call(control: Control) -> ApprovalCall {
    ApprovalCall {
        op: op(),
        view: view(),
        control: Some(control),
        supersedes: None,
        wait_seconds: None,
    }
}

/// Follow the steps of 17.7 for the operation of the tests, with `call` as the command.
fn run(pep: &Pep, who: &Identity, call: ApprovalCall) -> Outcome {
    pep.decide_approval(who, &operation(), move || Ok(call))
}

fn operation() -> Operation {
    Operation::new(
        ACTION,
        node(SERVICE, &[("host", "prod"), ("database", "test2")]).unwrap(),
    )
}

fn effect() -> String {
    effect_hash(
        SERVICE,
        ACTION,
        &resource_text(&operation().uses()[0].node),
        &op(),
    )
    .unwrap()
}

/// A PEP for the document of the tests. Each action follows section 17, so no member marks an action.
fn rig(
    handler: impl FnMut(
        &Seen,
    ) -> Result<
        procurauth_pep::transport::HttpResponse,
        procurauth_pep::transport::TransportError,
    > + Send
    + 'static,
) -> (Pep, Arc<Scripted>, Identity, ManualClock) {
    let edge = Edge::new();
    let transport = Scripted::new(handler);
    let document = datastore_document();
    let clock = ManualClock::at_seconds(NOW);
    let pep = Pep::with_clock(
        config("http://pdp.test", &edge),
        document,
        transport.clone(),
        Arc::new(clock.clone()),
    )
    .unwrap();
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    (pep, transport, who, clock)
}

fn evaluation(body: &Value) -> Value {
    let _ = body;
    json!({"decision": false, "context": {"reason": "approval_required", "evaluation_id": "ev_1"}})
}

/// A PDP that answers the questions with `question` and the approval API with `api`.
fn pdp(
    mut question: impl FnMut(&Value) -> Value + Send + 'static,
    mut api: impl FnMut(&Seen) -> (u16, Value) + Send + 'static,
) -> impl FnMut(
    &Seen,
) -> Result<
    procurauth_pep::transport::HttpResponse,
    procurauth_pep::transport::TransportError,
> + Send
+ 'static {
    move |seen| {
        if seen.path().starts_with("/approval/v1/requests") {
            let (status, body) = api(seen);
            Ok(json_response(status, &body))
        } else if seen.method == "POST" {
            let body = seen.body.as_ref().unwrap();
            // A question with no effect gets `approval_required` (17.1): the PDP asks for an approval.
            let answer = if body.pointer("/context/approval").is_none() {
                json!({"decision": false, "context": {"reason": "approval_required"}})
            } else {
                question(body)
            };
            Ok(json_response(200, &answer))
        } else {
            Ok(json_response(404, &json!({})))
        }
    }
}

fn submitted() -> (u16, Value) {
    (
        201,
        json!({"request_id": "apr_1", "code": "K7QF", "verdict": "pending"}),
    )
}

fn questions(t: &Scripted) -> Vec<Value> {
    t.posts()
        .into_iter()
        .filter(|s| s.path().starts_with("/access/"))
        .map(|s| s.body.unwrap())
        .collect()
}

fn api_calls(t: &Scripted) -> Vec<Seen> {
    t.seen()
        .into_iter()
        .filter(|s| s.path().starts_with("/approval/"))
        .collect()
}

#[test]
fn p_17_7_step_4_a_question_with_the_effect_and_a_submission_make_a_request_that_waits() {
    let (pep, t, who, _) = rig(pdp(evaluation, |_| submitted()));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    let Outcome::ApprovalRequired(pending) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        (pending.request_id.as_str(), pending.code.as_str()),
        ("apr_1", "K7QF")
    );
    let asked = questions(&t);
    // Step 1: a question with no effect. Step 3: a question with the effect.
    assert_eq!(asked.len(), 2);
    assert!(asked[0].pointer("/context/approval").is_none());
    assert_eq!(
        asked[1]["context"],
        json!({"approval": {"effect": effect()}})
    );
    // The question never has op or view (17.1).
    assert!(!asked[1].to_string().contains("append_rows"));
    // The submission has the members of 17.4 and no other.
    let calls = api_calls(&t);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        (calls[0].method, calls[0].path()),
        ("POST", "/approval/v1/requests")
    );
    assert_eq!(
        calls[0].body.clone().unwrap(),
        json!({"evaluation_id": "ev_1", "effect": effect(), "op": op(), "view": view(), "lease_s": 900})
    );
    assert!(
        calls[0]
            .header("authorization")
            .unwrap()
            .starts_with("Bearer ")
    );
}

#[test]
fn p_17_7_step_6_after_true_the_pep_asks_with_usage_and_the_same_effect() {
    let (pep, t, who, _) = rig(pdp(
        |q| {
            if q.pointer("/context/usage").is_some() {
                json!({"decision": true, "context": {"usage": {"units": 1}}})
            } else {
                json!({"decision": true})
            }
        },
        |_| panic!("no call of the approval API"),
    ));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    let allowed = outcome.into_result().unwrap();
    assert_eq!(allowed.units(), 1);
    let asked = questions(&t);
    assert_eq!(asked.len(), 3);
    assert!(asked[0].pointer("/context/approval").is_none());
    assert!(asked[1].pointer("/context/usage").is_none());
    assert_eq!(asked[2]["context"]["usage"], json!({"units": 1}));
    assert_eq!(asked[2]["context"]["approval"]["effect"], effect());
    // The PEP keeps no answer to a question with an effect (17.7): a second call asks again.
    let again = run(&pep, &who, call(Control::LeaseSeconds(900)));
    assert!(again.is_allowed());
    assert_eq!(questions(&t).len(), 6);
    assert_eq!(pep.kept_answers(), 0);
}

#[test]
fn p_17_7_step_5_a_refused_or_void_approval_sends_no_question_with_usage() {
    for (reason, expected) in [
        ("approval_denied", ApprovalRefusal::Denied),
        ("approval_expired", ApprovalRefusal::Expired),
    ] {
        let (pep, t, who, _) = rig(pdp(
            move |_| json!({"decision": false, "context": {"reason": reason, "comment": "canary"}}),
            |_| panic!("no call of the approval API"),
        ));
        let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
        assert_eq!(outcome.refusal(), Some(&Refusal::Approval(expected)));
        assert!(!outcome.refusal().unwrap().to_string().contains("canary"));
        assert!(questions(&t).iter().all(|q| {
            q.pointer("/context/usage").is_none() || q.pointer("/context/approval").is_none()
        }));
        assert!(api_calls(&t).is_empty());
    }
}

#[test]
fn p_17_7_a_budget_that_refuses_the_use_gives_rate_limited() {
    let (pep, _, who, _) = rig(pdp(
        |q| {
            if q.pointer("/context/usage").is_some() {
                json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 12}})
            } else {
                json!({"decision": true})
            }
        },
        |_| panic!("no call"),
    ));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    assert_eq!(
        outcome.refusal(),
        Some(&Refusal::RateLimited { retry_after: 12 })
    );
}

#[test]
fn p_17_7_a_true_answer_with_usage_and_no_units_counts_as_false() {
    let (pep, _, who, _) = rig(pdp(|_| json!({"decision": true}), |_| panic!("no call")));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    assert!(matches!(outcome.refusal(), Some(Refusal::Forbidden { .. })));
}

#[test]
fn p_17_7_without_an_evaluation_id_the_pep_cannot_submit_and_it_fails_closed() {
    let (pep, t, who, _) = rig(pdp(
        |_| json!({"decision": false, "context": {"reason": "approval_required"}}),
        |_| panic!("no call"),
    ));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    assert!(matches!(outcome.refusal(), Some(Refusal::Forbidden { .. })));
    assert!(api_calls(&t).is_empty());
}

#[test]
fn p_17_7_a_caller_that_does_not_know_approvals_gets_the_refusal_of_a_false_answer() {
    let (pep, _, who, _) = rig(pdp(evaluation, |_| submitted()));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    let refusal = outcome.into_result().unwrap_err();
    assert_eq!(refusal.status(), 403);
}

#[test]
fn p_17_3_an_op_that_the_effect_refuses_gives_invalid_argument_and_no_question() {
    let (pep, t, who, _) = rig(pdp(evaluation, |_| submitted()));
    let mut bad = call(Control::LeaseSeconds(900));
    bad.op = json!({"tool": "t", "table": "orders", "rows": "x", "limit": 1.5});
    let outcome = run(&pep, &who, bad);
    assert_eq!(
        outcome.refusal(),
        Some(&Refusal::Approval(ApprovalRefusal::InvalidArgument))
    );
    // The PEP asked the question with no effect, and nothing more: no effect, no submission.
    assert_eq!(questions(&t).len(), 1);
    assert!(api_calls(&t).is_empty());
}

#[test]
fn p_17_9_a_view_with_a_pointer_that_names_no_value_is_a_mistake_of_the_service() {
    let (pep, t, who, _) = rig(pdp(evaluation, |_| submitted()));
    let mut bad = call(Control::LeaseSeconds(900));
    bad.view = json!({"body": "/nothing"});
    let outcome = run(&pep, &who, bad);
    assert!(matches!(outcome.refusal(), Some(Refusal::Internal(_))));
    assert_eq!(questions(&t).len(), 1);
    assert!(api_calls(&t).is_empty());
}

#[test]
fn p_17_7_step_1_a_true_answer_ends_the_flow_and_the_command_is_never_built() {
    let (pep, t, who, _) = rig(|seen: &Seen| {
        if seen.method == "POST" {
            let usage = seen
                .body
                .as_ref()
                .unwrap()
                .pointer("/context/usage")
                .is_some();
            let answer = if usage {
                json!({"decision": true, "context": {"usage": {"units": 1}}})
            } else {
                json!({"decision": true})
            };
            Ok(json_response(200, &answer))
        } else {
            Ok(json_response(404, &json!({})))
        }
    });
    let outcome = pep.decide_approval(&who, &operation(), || -> Result<ApprovalCall, _> {
        panic!("the PEP builds op and view only when the PDP asks for an approval")
    });
    assert!(outcome.is_allowed(), "{outcome:?}");
    let asked = questions(&t);
    assert_eq!(asked.len(), 1);
    assert!(asked[0].pointer("/context/approval").is_none());
}

#[test]
fn p_17_7_step_1_a_false_answer_with_another_reason_is_refused_as_10_3_says() {
    let (pep, t, who, _) = rig(|seen: &Seen| {
        if seen.method == "POST" {
            Ok(json_response(200, &json!({"decision": false})))
        } else {
            Ok(json_response(404, &json!({})))
        }
    });
    let outcome = pep.decide_approval(&who, &operation(), || -> Result<ApprovalCall, _> {
        panic!("no command")
    });
    assert!(matches!(outcome.refusal(), Some(Refusal::Forbidden { .. })));
    assert_eq!(questions(&t).len(), 1);
}

#[test]
fn p_17_3a_an_error_of_the_command_refuses_only_a_call_that_needs_an_approval() {
    let (pep, t, who, _) = rig(pdp(evaluation, |_| submitted()));
    let outcome = pep.decide_approval(&who, &operation(), || Err(ApprovalRefusal::InvalidArgument));
    assert_eq!(
        outcome.refusal(),
        Some(&Refusal::Approval(ApprovalRefusal::InvalidArgument))
    );
    // The PEP asked the question with no effect, and nothing more.
    assert_eq!(questions(&t).len(), 1);
    assert!(api_calls(&t).is_empty());
}

#[test]
fn p_17_7_a_call_with_no_control_cannot_submit_and_gets_invalid_argument() {
    let (pep, t, who, _) = rig(pdp(evaluation, |_| submitted()));
    let mut none = call(Control::LeaseSeconds(900));
    none.control = None;
    let outcome = run(&pep, &who, none);
    assert_eq!(
        outcome.refusal(),
        Some(&Refusal::Approval(ApprovalRefusal::InvalidArgument))
    );
    assert!(api_calls(&t).is_empty());
    // The PEP sent the question with the effect, and no question with usage and the effect.
    assert!(questions(&t).iter().all(|q| {
        q.pointer("/context/usage").is_none() || q.pointer("/context/approval").is_none()
    }));
}

#[test]
fn p_17_7a_a_call_that_cannot_wait_gets_403_and_the_code_approval_cannot_wait() {
    // A plain route calls `decide`. It sends no effect and submits nothing.
    let (pep, t, who, _) = rig(pdp(evaluation, |_| submitted()));
    let refusal = pep.decide(&who, &operation()).into_result().unwrap_err();
    let reply = refusal.to_http();
    assert_eq!(reply.status, 403);
    assert_eq!(
        String::from_utf8(reply.body).unwrap(),
        r#"{"error":"approval_cannot_wait"}"#
    );
    assert!(api_calls(&t).is_empty());
    assert!(
        questions(&t)
            .iter()
            .all(|q| q.pointer("/context/approval").is_none())
    );
}

#[test]
fn p_10_1_the_pep_keeps_no_answer_with_a_reason_of_17_1() {
    let edge = Edge::new();
    let transport = Scripted::new(pdp(evaluation, |_| submitted()));
    let (pep, _) = common::pep(transport.clone(), &edge, "http://pdp.test", |config| {
        config.cache_ttl = std::time::Duration::from_secs(60);
    });
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let _ = pep.decide(&who, &operation());
    let _ = pep.decide(&who, &operation());
    assert_eq!(pep.kept_answers(), 0);
    assert_eq!(questions(&transport).len(), 2);
}

#[test]
fn p_17_4_the_controls_go_to_the_submission_as_the_agent_gave_them() {
    let seen_bodies = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen_bodies);
    let (pep, _, who, _) = rig(pdp(evaluation, move |s| {
        sink.lock().unwrap().push(s.body.clone().unwrap());
        submitted()
    }));
    let mut with_ref = call(Control::Reference("ref_opaque_0001".into()));
    with_ref.supersedes = Some("apr_0".into());
    let _ = run(&pep, &who, with_ref);
    let _ = run(
        &pep,
        &who,
        call(Control::Until("2030-01-01T00:00:00Z".into())),
    );
    let bodies = seen_bodies.lock().unwrap().clone();
    assert_eq!(bodies[0]["approval_ref"], "ref_opaque_0001");
    assert_eq!(bodies[0]["supersedes"], "apr_0");
    assert!(bodies[0].get("lease_s").is_none() && bodies[0].get("until").is_none());
    assert_eq!(bodies[1]["until"], "2030-01-01T00:00:00Z");
    assert!(bodies[1].get("approval_ref").is_none());
    let stats = pep.approval_stats();
    assert_eq!(
        (
            stats.submissions,
            stats.approval_refs_sent,
            stats.evaluation_ids_sent
        ),
        (2, 1, 2)
    );
}

#[test]
fn p_17_12_the_pep_reads_only_the_verdict_the_id_and_the_code() {
    let (pep, _, who, _) = rig(pdp(evaluation, |s| {
        if s.method == "POST" {
            (
                201,
                json!({"request_id": "apr_1", "code": "K7QF", "verdict": "pending",
                    "explanation": "SECRET", "intent": "SECRET", "lease": 900, "owner": "alice"}),
            )
        } else {
            (
                200,
                json!({"verdict": "denied", "comment": "SECRET", "answered_by": "alice"}),
            )
        }
    }));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    let Outcome::ApprovalRequired(pending) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(!format!("{pending:?}").contains("SECRET"));
    assert_eq!(pep.approval_status(&who, "apr_1").unwrap(), Verdict::Denied);
    let stats = pep.approval_stats();
    assert_eq!(stats.members_read, 3 + 1);
    assert_eq!(stats.members_ignored, 4 + 2);
    assert_eq!((stats.pending, stats.denied), (1, 1));
}

#[test]
fn p_17_7_a_verdict_that_the_pep_does_not_know_is_void() {
    let (pep, _, who, _) = rig(pdp(evaluation, |_| {
        (200, json!({"verdict": "approved_by_alice"}))
    }));
    assert_eq!(pep.approval_status(&who, "apr_1").unwrap(), Verdict::Void);
    let stats = pep.approval_stats();
    assert_eq!((stats.void, stats.unknown_verdicts), (1, 1));
}

#[test]
fn p_17_4_a_status_read_renews_with_the_subject_and_a_keepalive_posts_the_subject() {
    let (pep, t, who, _) = rig(pdp(evaluation, |_| (200, json!({"verdict": "pending"}))));
    assert_eq!(
        pep.approval_status(&who, "apr 1/x").unwrap(),
        Verdict::Pending
    );
    assert_eq!(
        pep.approval_keepalive(&who, "apr_1").unwrap(),
        Verdict::Pending
    );
    let calls = api_calls(&t);
    assert_eq!(calls[0].method, "GET");
    assert_eq!(
        calls[0].url,
        "http://pdp.test/approval/v1/requests/apr%201%2Fx?subject=alice&renew=true"
    );
    assert_eq!(calls[1].path(), "/approval/v1/requests/apr_1/keepalive");
    assert_eq!(calls[1].body.clone().unwrap(), json!({"subject": "alice"}));
    // No call renews on its own: the PEP sends nothing at each question.
    let stats = pep.approval_stats();
    assert_eq!((stats.status_reads, stats.keepalives), (1, 1));
}

#[test]
fn p_17_4_each_error_of_the_approval_api_has_its_refusal() {
    let cases: [(u16, Value, Refusal); 9] = [
        (
            429,
            json!({"error": "rate_limited", "retry_after": 60}),
            Refusal::Approval(ApprovalRefusal::RateLimited { retry_after: 60 }),
        ),
        (
            409,
            json!({"error": "no_device"}),
            Refusal::Approval(ApprovalRefusal::NoDevice),
        ),
        (
            413,
            json!({"error": "command_too_large"}),
            Refusal::Approval(ApprovalRefusal::InvalidArgument),
        ),
        (
            422,
            json!({"error": "invalid_lease"}),
            Refusal::Approval(ApprovalRefusal::InvalidArgument),
        ),
        (
            422,
            json!({"error": "lease_required"}),
            Refusal::Approval(ApprovalRefusal::InvalidArgument),
        ),
        (
            422,
            json!({"error": "invalid_argument"}),
            Refusal::Approval(ApprovalRefusal::InvalidArgument),
        ),
        // A cause that the binding does not list is a failure of the API: HTTP 503.
        (
            422,
            json!({"error": "effect_mismatch"}),
            Refusal::Unavailable(UnavailableCause::Status(422)),
        ),
        (
            409,
            json!({"error": "cannot_supersede"}),
            Refusal::Unavailable(UnavailableCause::Status(409)),
        ),
        (
            500,
            json!({}),
            Refusal::Unavailable(UnavailableCause::Status(500)),
        ),
    ];
    for (status, body, expected) in cases {
        let reply = body.clone();
        let (pep, _, who, _) = rig(pdp(evaluation, move |_| (status, reply.clone())));
        let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
        assert_eq!(outcome.refusal(), Some(&expected), "{status} {body}");
    }
}

#[test]
fn p_17_4_an_unknown_request_gives_invalid_argument_on_a_read_and_a_wrong_answer_gives_503() {
    let (pep, _, who, _) = rig(pdp(evaluation, |_| (404, json!({"error": "not_found"}))));
    assert_eq!(
        pep.approval_status(&who, "apr_x").unwrap_err(),
        Refusal::Approval(ApprovalRefusal::InvalidArgument)
    );
    let (pep, _, who, _) = rig(pdp(evaluation, |_| (200, json!({"status": "ok"}))));
    assert!(matches!(
        pep.approval_status(&who, "apr_x").unwrap_err(),
        Refusal::Unavailable(UnavailableCause::Answer(_))
    ));
}

#[test]
fn p_17_4_a_submission_with_a_bad_answer_is_not_a_request_that_waits() {
    let (pep, _, who, _) = rig(pdp(evaluation, |_| (201, json!({"request_id": "apr_1"}))));
    let outcome = run(&pep, &who, call(Control::LeaseSeconds(900)));
    assert!(matches!(
        outcome.refusal(),
        Some(Refusal::Unavailable(UnavailableCause::Answer(_)))
    ));
}

#[test]
fn p_17_5_a_wait_reads_the_verdict_with_wait_and_without_renewal_and_stays_pending() {
    let (pep, t, who, _) = rig(pdp(evaluation, |s| {
        if s.method == "POST" {
            submitted()
        } else {
            (200, json!({"verdict": "pending"}))
        }
    }));
    let mut waiting = call(Control::LeaseSeconds(900));
    waiting.wait_seconds = Some(1000);
    let outcome = run(&pep, &who, waiting);
    assert!(matches!(outcome, Outcome::ApprovalRequired(_)));
    let calls = api_calls(&t);
    assert_eq!(calls.len(), 2);
    // The wait is bounded by the PEP, and a call that has no request to name does not renew.
    assert_eq!(
        calls[1].url,
        "http://pdp.test/approval/v1/requests/apr_1?subject=alice&wait=25"
    );
    assert!(calls[1].timeout > std::time::Duration::from_secs(25));
}

#[test]
fn p_17_5_a_wait_that_ends_with_approved_asks_again_from_the_start() {
    let mut round = 0;
    let (pep, t, who, _) = rig(pdp(
        move |q| {
            if q.pointer("/context/usage").is_some() {
                json!({"decision": true, "context": {"usage": {"units": 1}}})
            } else {
                round += 1;
                if round == 1 {
                    evaluation(q)
                } else {
                    json!({"decision": true})
                }
            }
        },
        |s| {
            if s.method == "POST" {
                submitted()
            } else {
                (200, json!({"verdict": "approved"}))
            }
        },
    ));
    let mut waiting = call(Control::LeaseSeconds(900));
    waiting.wait_seconds = Some(5);
    let outcome = run(&pep, &who, waiting);
    assert!(outcome.is_allowed(), "{outcome:?}");
    // The question with no effect, two questions with the effect and the question with usage.
    assert_eq!(questions(&t).len(), 4);
    assert_eq!(api_calls(&t).len(), 2);
}

#[test]
fn p_17_5_a_failed_read_during_a_wait_leaves_the_result_it_waits() {
    let (pep, _, who, _) = rig(pdp(evaluation, |s| {
        if s.method == "POST" {
            submitted()
        } else {
            (500, json!({}))
        }
    }));
    let mut waiting = call(Control::LeaseSeconds(900));
    waiting.wait_seconds = Some(5);
    assert!(matches!(
        run(&pep, &who, waiting),
        Outcome::ApprovalRequired(_)
    ));
}

#[test]
fn p_17_7_a_wait_that_ends_with_denied_or_void_refuses() {
    for (verdict, expected) in [
        ("denied", ApprovalRefusal::Denied),
        ("void", ApprovalRefusal::Expired),
    ] {
        let (pep, _, who, _) = rig(pdp(evaluation, move |s| {
            if s.method == "POST" {
                submitted()
            } else {
                (200, json!({"verdict": verdict}))
            }
        }));
        let mut waiting = call(Control::LeaseSeconds(900));
        waiting.wait_seconds = Some(5);
        let outcome = run(&pep, &who, waiting);
        assert_eq!(outcome.refusal(), Some(&Refusal::Approval(expected)));
    }
}
