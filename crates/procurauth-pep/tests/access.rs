//! The question of an edge (protocol 8.3), against the test PDP and against a script.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use fake_pdp::{Options, Server};
use procurauth_core::authzen::Reason;
use procurauth_pep::access::{ACCESS_ACTION, Access, AccessGate};
use procurauth_pep::clock::ManualClock;
use procurauth_pep::config::PdpConfig;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use procurauth_pep::refusal::UnavailableCause;
use serde_json::json;

fn pdp_config(url: &str) -> PdpConfig {
    config(url, &Edge::new()).pdp
}

fn gate_for(transport: Arc<Scripted>) -> AccessGate {
    AccessGate::new(
        SERVICE,
        &pdp_config("http://127.0.0.1:1"),
        transport,
        Arc::new(ManualClock::at_seconds(NOW)),
    )
    .unwrap()
}

#[test]
fn p_8_3_the_question_asks_the_action_access_on_the_service() {
    let transport = Scripted::answering(|_| json!({"decision": true}));
    let gate = gate_for(Arc::clone(&transport));
    assert_eq!(gate.check(KEY_ALICE).unwrap(), Access::Granted);
    let seen = transport.seen();
    let question = seen.iter().find(|s| s.method == "POST").unwrap();
    let body = question.body.as_ref().unwrap();
    assert_eq!(body["subject"], json!({"type": "user", "id": KEY_ALICE}));
    assert_eq!(body["action"]["name"], ACCESS_ACTION);
    assert_eq!(body["resource"]["type"], "service");
    assert_eq!(body["resource"]["id"], SERVICE);
    assert!(!question.has_usage(), "{body}");
    assert_eq!(
        question.header("authorization"),
        Some("Bearer test-credential-of-the-service")
    );
}

#[test]
fn p_8_3_a_false_answer_is_denied_with_its_reason() {
    let transport = Scripted::answering(
        |_| json!({"decision": false, "context": {"reason": "unknown_subject"}}),
    );
    let gate = gate_for(transport);
    let answer = gate.check("key:nobody").unwrap();
    assert!(!answer.is_granted());
    assert!(matches!(
        answer,
        Access::Denied(Some(Reason::UnknownSubject))
    ));
}

#[test]
fn p_10_3_a_pdp_that_gives_no_valid_answer_is_a_cause_and_not_a_denial() {
    let transport = Scripted::answering(|_| json!({"nothing": 1}));
    let gate = gate_for(transport);
    assert!(matches!(
        gate.check(KEY_ALICE),
        Err(UnavailableCause::Answer(_))
    ));
}

#[test]
fn p_10_0_the_gate_refuses_an_http_url_without_the_flag_and_a_bad_service_id() {
    let mut pdp = pdp_config("http://127.0.0.1:1");
    pdp.allow_insecure_pdp_link = false;
    let transport = Scripted::answering(|_| json!({"decision": true}));
    let clock = Arc::new(ManualClock::at_seconds(NOW));
    let errors = AccessGate::new(SERVICE, &pdp, transport.clone(), clock.clone()).unwrap_err();
    assert_eq!(errors[0].key, "pdp.url");
    let errors =
        AccessGate::new("", &pdp_config("http://127.0.0.1:1"), transport, clock).unwrap_err();
    assert_eq!(errors[0].key, "service_id");
}

#[test]
fn p_8_3_the_gate_follows_the_data_of_the_test_pdp_with_real_http() {
    let data = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../conformance/directories/access.json"
    ))
    .unwrap();
    let server = Server::from_value(&data, Options::default())
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap();
    let pdp = pdp_config(&server.url());
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&pdp)));
    let gate = AccessGate::new(
        SERVICE,
        &pdp,
        transport,
        Arc::new(ManualClock::at_seconds(NOW)),
    )
    .unwrap();
    assert!(gate.check("key:ann-k1").unwrap().is_granted());
    assert!(!gate.check("key:ann-k2").unwrap().is_granted());
    assert!(!gate.check("key:unknown").unwrap().is_granted());
    assert!(gate.check("ann").unwrap().is_granted());
    server.shutdown();
}
