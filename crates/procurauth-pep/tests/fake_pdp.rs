//! The PEP against the test PDP `fake-pdp`. The test starts the PDP in the same process.
//! The exchange is real HTTP on the loopback address. The tests cover the example of
//! section 13, budgets across windows and nested counters. They also cover failures, bounds,
//! kept answers, retries and keys against persons.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use fake_pdp::config::Credential;
use fake_pdp::faults::read_faults_str;
use fake_pdp::{Options, RunningServer, Server};
use procurauth_core::path::NodePath;
use procurauth_pep::clock::ManualClock;
use procurauth_pep::config::PepConfig;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use procurauth_pep::operation::{Operation, Permission, node};
use procurauth_pep::{Identity, Pep, Refusal};
use serde_json::{Value, json};

fn start_with(data: &Value, options: Options) -> RunningServer {
    Server::from_value(data, options)
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap()
}

struct Rig {
    server: RunningServer,
    pep: Pep,
    edge: Edge,
    clock: ManualClock,
    transport: Arc<HttpTransport>,
}

fn rig(data: &Value, tweak: impl FnOnce(&mut PepConfig)) -> Rig {
    rig_with(data, Options::default(), tweak)
}

fn rig_with(data: &Value, options: Options, tweak: impl FnOnce(&mut PepConfig)) -> Rig {
    let server = start_with(data, options);
    let edge = Edge::new();
    let mut cfg = config(&server.url(), &edge);
    tweak(&mut cfg);
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&cfg.pdp)));
    let clock = ManualClock::at_seconds(NOW);
    let pep = Pep::with_clock(
        cfg,
        document_of(data),
        transport.clone(),
        Arc::new(clock.clone()),
    )
    .unwrap();
    Rig {
        server,
        pep,
        edge,
        clock,
        transport,
    }
}

impl Rig {
    fn person(&self, sub: &str) -> Identity {
        self.pep
            .authenticate([(HEADER, self.edge.token(sub).as_str())])
            .unwrap()
    }

    fn key(&self, sub: &str, owner: &str) -> Identity {
        self.pep
            .authenticate([(HEADER, self.edge.token_for_key(sub, owner).as_str())])
            .unwrap()
    }

    /// Move the clock of the PDP and the clock of the PEP together.
    fn advance(&self, seconds: u64) {
        self.server.clock().advance(seconds).unwrap();
        self.clock.advance_seconds(seconds);
    }

    fn used(&self, subject: &str, limit: &str, window: &str) -> Option<u64> {
        self.server
            .counters()
            .iter()
            .find(|c| c.subject == subject && c.limit == limit && c.window.as_str() == window)
            .map(|c| c.used)
    }

    fn questions(&self) -> usize {
        self.server.log().len()
    }
}

fn db(name: &str) -> NodePath {
    node(SERVICE, &[("host", "prod"), ("database", name)]).unwrap()
}

fn orders(database: &str) -> NodePath {
    node(
        SERVICE,
        &[
            ("host", "prod"),
            ("database", database),
            ("table", "orders"),
        ],
    )
    .unwrap()
}

fn read(path: NodePath) -> Operation {
    Operation::new("data.read", path)
}

fn write(path: NodePath) -> Operation {
    Operation::new("data.write", path)
}

fn faults(text: &str) -> Vec<fake_pdp::Fault> {
    read_faults_str(text).unwrap()
}

// ---- The example of section 13 ---------------------------------------------------------------------

#[test]
fn p_13_alice_reads_the_table_orders_and_the_ceilings_are_the_lowest_values() {
    let r = rig(&datastore_data(), |_| {});
    let alice = r.person("alice");
    let allowed = r
        .pep
        .decide(&alice, &read(orders("test2")))
        .into_result()
        .unwrap();
    assert_eq!(allowed.units(), 1);
    assert_eq!(allowed.ceilings().get("max_rows"), Some(100));
    assert_eq!(allowed.ceilings().get("max_duration"), Some(30));
    // The grant of `data.write` on `test2` is not a grant of the asked action: its value 10 does not apply (7.3).
    assert_eq!(allowed.ceilings().iter().count(), 2);
    // Each use takes one unit from the counters of the second and of the minute (6.7).
    assert_eq!(r.used("alice", "requests", "second"), Some(1));
    assert_eq!(r.used("alice", "requests", "minute"), Some(1));
}

#[test]
fn p_13_the_other_answers_of_alice() {
    let r = rig(&datastore_data(), |_| {});
    let alice = r.person("alice");
    let write_test2 = r
        .pep
        .decide(&alice, &write(db("test2")))
        .into_result()
        .unwrap();
    assert_eq!(write_test2.ceilings().get("max_duration"), Some(10));
    let read_test1 = r
        .pep
        .decide(&alice, &read(db("test1")))
        .into_result()
        .unwrap();
    assert_eq!(read_test1.ceilings().get("max_rows"), Some(1000));
    assert_eq!(r.used("alice", "requests", "second"), Some(2));
    // `data.write` on `test1` and `data.read` on the host: false with no reason. No unit.
    let refused = r
        .pep
        .decide(&alice, &write(db("test1")))
        .into_result()
        .unwrap_err();
    assert_eq!(refused.status(), 403);
    let host = node(SERVICE, &[("host", "prod")]).unwrap();
    assert_eq!(
        r.pep
            .decide(&alice, &read(host))
            .into_result()
            .unwrap_err()
            .status(),
        403
    );
    assert_eq!(r.used("alice", "requests", "second"), Some(2));
}

#[test]
fn p_13_the_key_of_alice_never_has_more_than_alice() {
    let r = rig(&datastore_data(), |_| {});
    let key = r.key(KEY_ALICE, "alice");
    let allowed = r
        .pep
        .decide(&key, &read(db("test2")))
        .into_result()
        .unwrap();
    // The key has 10000, and Alice has 5000: the lowest value applies (8.4).
    assert_eq!(allowed.ceilings().get("max_rows"), Some(5000));
    assert_eq!(allowed.ceilings().get("max_duration"), Some(30));
    // One unit from the minute of the key, and one from each counter of Alice (6.7).
    assert_eq!(r.used(KEY_ALICE, "requests", "minute"), Some(1));
    assert_eq!(r.used("alice", "requests", "second"), Some(1));
    assert_eq!(r.used("alice", "requests", "minute"), Some(1));
    // The key has no grant of `data.write`.
    assert_eq!(
        r.pep
            .decide(&key, &write(db("test2")))
            .into_result()
            .unwrap_err()
            .status(),
        403
    );
}

#[test]
fn p_3_5_a_key_has_a_right_only_when_its_owner_has_it_too() {
    let r = rig(&datastore_data(), |_| {});
    let bob = r.person("bob");
    let key = r.key(KEY_BOB, "bob");
    // The key of Bob has a grant on `test2`, and Bob has none: the key gets nothing.
    assert_eq!(
        r.pep
            .decide(&key, &read(db("test2")))
            .into_result()
            .unwrap_err()
            .status(),
        403
    );
    // Bob has a grant on `test1`, and his key has none.
    assert_eq!(
        r.pep
            .decide(&key, &read(db("test1")))
            .into_result()
            .unwrap_err()
            .status(),
        403
    );
    assert!(r.pep.decide(&bob, &read(db("test1"))).is_allowed());
}

#[test]
fn p_4_4_a_display_question_for_a_key_needs_one_node_that_both_cover() {
    let r = rig(&datastore_data(), |_| {});
    let key = r.key(KEY_BOB, "bob");
    let service = node(SERVICE, &[]).unwrap();
    // The key has `data.read` on `test2`, and Bob has it on `test1` only: `subtree` gives false.
    let seen = r
        .pep
        .display(&key, &[Permission::new("data.read", service.clone())])
        .unwrap();
    assert_eq!(seen, [false]);
    let bob = r.person("bob");
    assert_eq!(
        r.pep
            .display(&bob, &[Permission::new("data.read", service)])
            .unwrap(),
        [true]
    );
}

#[test]
fn p_8_3_an_unknown_subject_gets_403_and_the_reason_stays_in_the_log() {
    let r = rig(&datastore_data(), |_| {});
    for sub in ["robot:7", "nobody", "key:unknown"] {
        let who = r.person(sub);
        let refusal = r
            .pep
            .decide(&who, &read(db("test1")))
            .into_result()
            .unwrap_err();
        assert_eq!(refusal.status(), 403);
        assert!(refusal.to_string().contains("unknown_subject"), "{refusal}");
        assert!(
            !String::from_utf8(refusal.to_http().body)
                .unwrap()
                .contains("unknown")
        );
    }
}

#[test]
fn p_11_1_the_service_is_the_only_service_of_the_chain() {
    // A resource below another service gets `invalid_resource` from the PDP. The PEP builds the chain itself.
    let r = rig(&datastore_data(), |_| {});
    let alice = r.person("alice");
    assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
}

// ---- Budgets across windows (6.3, 6.5, 6.7) -------------------------------------------------------------------

#[test]
fn p_6_3_the_budget_of_a_window_comes_back_in_the_next_window() {
    let data = budgets_data();
    let r = rig(&data, |_| {});
    let duo = r.person("duo"); // 2 each second, 5 each minute. The minute ends in 12 s.
    let service = node(SERVICE, &[]).unwrap();
    let op = || read(service.clone());
    assert!(r.pep.decide(&duo, &op()).is_allowed());
    assert!(r.pep.decide(&duo, &op()).is_allowed());
    let refusal = r.pep.decide(&duo, &op()).into_result().unwrap_err();
    assert_eq!(refusal, Refusal::RateLimited { retry_after: 1 });
    assert_eq!(refusal.to_http().header("Retry-After"), Some("1"));
    r.advance(1);
    assert!(r.pep.decide(&duo, &op()).is_allowed());
    assert!(r.pep.decide(&duo, &op()).is_allowed());
    r.advance(1);
    assert!(r.pep.decide(&duo, &op()).is_allowed()); // 5 of 5 in the minute
    // The second is free (1 of 2), and the minute is spent: the minute ends in 12 - 2 = 10 s.
    assert_eq!(
        r.pep.decide(&duo, &op()).into_result().unwrap_err(),
        Refusal::RateLimited { retry_after: 10 }
    );
    r.advance(10);
    assert!(r.pep.decide(&duo, &op()).is_allowed());
}

#[test]
fn p_11_1_when_two_windows_refuse_retry_after_is_the_later_end() {
    let data = budgets_data();
    let r = rig(&data, |_| {});
    let quad = r.person("quad"); // 1 each second, minute, hour and day.
    let service = node(SERVICE, &[]).unwrap();
    assert!(r.pep.decide(&quad, &read(service.clone())).is_allowed());
    let refusal = r
        .pep
        .decide(&quad, &read(service))
        .into_result()
        .unwrap_err();
    // The time to the end of the day is the latest end.
    let day = 86_400 - (NOW % 86_400);
    assert_eq!(refusal, Refusal::RateLimited { retry_after: day });
}

#[test]
fn p_6_5_a_refused_use_takes_no_unit_from_any_counter() {
    let data = budgets_data();
    let r = rig(&data, |_| {});
    let atom = r.person("atom"); // requests: 10 a minute, 9 used. write_requests: 1 a minute, 1 used.
    let service = node(SERVICE, &[]).unwrap();
    let refusal = r
        .pep
        .decide(&atom, &write(service.clone()))
        .into_result()
        .unwrap_err();
    assert_eq!(refusal.status(), 429);
    assert_eq!(
        r.used("atom", "requests", "minute"),
        Some(9),
        "no unit taken from requests"
    );
    assert_eq!(r.used("atom", "write_requests", "minute"), Some(1));
    // A read takes the tenth unit of `requests`.
    assert!(r.pep.decide(&atom, &read(service.clone())).is_allowed());
    assert_eq!(r.used("atom", "requests", "minute"), Some(10));
    assert_eq!(
        r.pep
            .decide(&atom, &read(service))
            .into_result()
            .unwrap_err()
            .status(),
        429
    );
}

#[test]
fn p_6_7_a_use_by_a_key_takes_units_from_the_counters_of_its_owner() {
    let data = budgets_data();
    let r = rig(&data, |_| {});
    let service = node(SERVICE, &[]).unwrap();
    let owner = r.person("olga"); // 3 a minute
    let wide = r.key("key:olga-wide", "olga"); // 5 a minute for itself
    assert!(r.pep.decide(&wide, &read(service.clone())).is_allowed());
    assert!(r.pep.decide(&owner, &read(service.clone())).is_allowed());
    assert!(r.pep.decide(&wide, &read(service.clone())).is_allowed());
    // The owner has spent 3 units, and the key has spent 2 of 5: the counters of the owner bound the key.
    assert_eq!(
        r.pep
            .decide(&wide, &read(service.clone()))
            .into_result()
            .unwrap_err()
            .status(),
        429
    );
    assert_eq!(
        r.pep
            .decide(&owner, &read(service.clone()))
            .into_result()
            .unwrap_err()
            .status(),
        429
    );
    assert_eq!(r.used("olga", "requests", "minute"), Some(3));
    assert_eq!(r.used("key:olga-wide", "requests", "minute"), Some(2));
    // A key with no budget of its own is also bound by its owner.
    let bare = r.key("key:olga-bare", "olga");
    assert_eq!(
        r.pep
            .decide(&bare, &read(service))
            .into_result()
            .unwrap_err()
            .status(),
        429
    );
}

#[test]
fn p_6_7_the_budget_of_a_key_below_the_budget_of_its_owner_bounds_the_key() {
    let data = budgets_data();
    let r = rig(&data, |_| {});
    let service = node(SERVICE, &[]).unwrap();
    let small = r.key("key:owen-small", "owen"); // 2 a minute, and its owner has 5
    assert!(r.pep.decide(&small, &read(service.clone())).is_allowed());
    assert!(r.pep.decide(&small, &read(service.clone())).is_allowed());
    assert_eq!(
        r.pep
            .decide(&small, &read(service.clone()))
            .into_result()
            .unwrap_err()
            .status(),
        429
    );
    // The owner still has 3 units.
    let owen = r.person("owen");
    for _ in 0..3 {
        assert!(r.pep.decide(&owen, &read(service.clone())).is_allowed());
    }
    assert_eq!(
        r.pep
            .decide(&owen, &read(service))
            .into_result()
            .unwrap_err()
            .status(),
        429
    );
}

#[test]
fn p_6_12_a_subject_without_a_budget_gets_units_0() {
    let data = budgets_data();
    let r = rig(&data, |_| {});
    let service = node(SERVICE, &[]).unwrap();
    let nolimit = r.person("nolimit");
    for _ in 0..5 {
        let allowed = r
            .pep
            .decide(&nolimit, &read(service.clone()))
            .into_result()
            .unwrap();
        assert_eq!(allowed.units(), 0);
    }
    assert!(r.server.counters().iter().all(|c| c.subject != "nolimit"));
}

// ---- Failures (6.9, 6.12, 10.3, 10.6) -----------------------------------------------------------------------------

#[test]
fn p_6_9_a_503_of_the_pdp_gives_503_and_counts_nothing() {
    let r = rig_with(
        &datastore_data(),
        Options {
            extra_faults: faults(r#"{"failures":[{"kind":"error_503","when":{"usage":true}}]}"#),
            ..Options::default()
        },
        |_| {},
    );
    let alice = r.person("alice");
    let refusal = r
        .pep
        .decide(&alice, &read(db("test1")))
        .into_result()
        .unwrap_err();
    assert_eq!(refusal.status(), 503);
    assert!(r.server.counters().is_empty());
    assert_eq!(r.questions(), 1, "the PEP does not send the question again");
}

#[test]
fn p_10_6_a_lost_answer_is_not_sent_again_and_the_unit_stays_counted() {
    for kind in ["no_answer", "close", "invalid_json"] {
        let mut data = datastore_data();
        // The PEP waits longer than the time that the PDP publishes (10.6): 1 s and a margin of 100 ms.
        data["metadata"] = json!({"usage_max_seconds": 1});
        let r = rig_with(
            &data,
            Options {
                extra_faults: faults(&format!(
                    r#"{{"failures":[{{"kind":"{kind}","when":{{"usage":true}},"times":1}}]}}"#
                )),
                ..Options::default()
            },
            |c| {
                c.pdp.request_timeout = Duration::from_millis(400);
                c.pdp.usage_wait_margin = Duration::from_millis(100);
            },
        );
        let alice = r.person("alice");
        let started = Instant::now();
        let refusal = r
            .pep
            .decide(&alice, &read(db("test1")))
            .into_result()
            .unwrap_err();
        assert_eq!(refusal.status(), 503, "{kind}");
        assert_eq!(r.questions(), 1, "{kind}: one question with usage");
        assert_eq!(
            r.used("alice", "requests", "second"),
            Some(1),
            "{kind}: the unit stays counted"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        if kind == "no_answer" {
            assert!(
                started.elapsed() >= Duration::from_millis(1000),
                "the PEP waits for the published time"
            );
        }
        // The next use works and takes one more unit.
        assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
        assert_eq!(r.used("alice", "requests", "second"), Some(2), "{kind}");
    }
}

#[test]
fn p_6_12_a_true_answer_without_units_is_a_refusal_and_the_unit_stays_counted() {
    let r = rig_with(
        &datastore_data(),
        Options {
            extra_faults: faults(
                r#"{"failures":[{"kind":"no_units","when":{"usage":true},"times":1}]}"#,
            ),
            ..Options::default()
        },
        |_| {},
    );
    let alice = r.person("alice");
    assert_eq!(
        r.pep
            .decide(&alice, &read(db("test1")))
            .into_result()
            .unwrap_err()
            .status(),
        403
    );
    assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
}

#[test]
fn p_6_9_a_delay_within_the_timeout_is_not_an_error_and_a_longer_one_is() {
    let r = rig_with(
        &datastore_data(),
        Options {
            extra_faults: faults(
                r#"{"failures":[{"kind":"delay","delay_ms":300,"when":{"usage":true}}]}"#,
            ),
            ..Options::default()
        },
        |c| c.pdp.request_timeout = Duration::from_millis(1500),
    );
    let alice = r.person("alice");
    let started = Instant::now();
    assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
    assert!(started.elapsed() >= Duration::from_millis(250));
    let mut data = datastore_data();
    data["metadata"] = json!({"usage_max_seconds": 1});
    let slow = rig_with(
        &data,
        Options {
            extra_faults: faults(
                r#"{"failures":[{"kind":"delay","delay_ms":2500,"when":{"usage":true}}]}"#,
            ),
            ..Options::default()
        },
        |c| {
            c.pdp.request_timeout = Duration::from_millis(300);
            c.pdp.usage_wait_margin = Duration::from_millis(100);
        },
    );
    let alice = slow.person("alice");
    // The question with usage waits for 2.5 s, and the PEP gives up after 1.1 s.
    assert_eq!(
        slow.pep
            .decide(&alice, &read(db("test1")))
            .into_result()
            .unwrap_err()
            .status(),
        503
    );
}

#[test]
fn p_10_6_a_question_without_usage_goes_again_after_a_closed_connection() {
    let r = rig_with(
        &datastore_data(),
        Options {
            extra_faults: faults(
                r#"{"failures":[{"kind":"close","when":{"usage":false,"endpoint":"evaluation"},"times":1}]}"#,
            ),
            ..Options::default()
        },
        |_| {},
    );
    let alice = r.person("alice");
    let allowed = r
        .pep
        .check(&alice, &read(db("test1")))
        .into_result()
        .unwrap();
    assert_eq!(allowed.units(), 0);
    assert_eq!(r.questions(), 2);
}

#[test]
fn p_10_3_a_pdp_that_is_down_gives_503() {
    let r = rig(&datastore_data(), |_| {});
    let alice = r.person("alice");
    let Rig { server, pep, .. } = r;
    server.shutdown();
    let refusal = pep
        .decide(&alice, &read(db("test1")))
        .into_result()
        .unwrap_err();
    assert_eq!(refusal.status(), 503);
}

// ---- The credential (10.0) ------------------------------------------------------------------------------------------

#[test]
fn p_10_0_the_credential_of_the_service_opens_the_pdp_and_another_one_does_not() {
    let options = || Options {
        credential: Some(
            Credential::from_file_text("test-credential-of-the-service\n", "file:/x").unwrap(),
        ),
        ..Options::default()
    };
    let good = rig_with(&datastore_data(), options(), |_| {});
    let alice = good.person("alice");
    assert!(good.pep.decide(&alice, &read(db("test1"))).is_allowed());

    let bad = rig_with(&datastore_data(), options(), |c| {
        c.pdp.credential = procurauth_pep::config::Secret::new("another-credential");
    });
    let alice = bad.person("alice");
    // The PDP answers HTTP 401: the PEP gives 503 (10.3).
    assert_eq!(
        bad.pep
            .decide(&alice, &read(db("test1")))
            .into_result()
            .unwrap_err()
            .status(),
        503
    );
}

// ---- Bounds and connections (10.7, 10.7a) ------------------------------------------------------------------------------

fn many_databases(n: usize) -> Vec<Permission> {
    (0..n)
        .map(|i| Permission::new("data.read", db(&format!("db{i}"))))
        .collect()
}

#[test]
fn p_10_7a_the_pep_splits_its_questions_at_the_maxima_of_the_pdp() {
    let mut data = datastore_data();
    data["metadata"] = json!({"evaluations_max_items": 3});
    let r = rig(&data, |_| {});
    let alice = r.person("alice");
    // The PDP gives HTTP 400 to a request with more than 3 items, so a good answer shows the split.
    let seen = r.pep.display(&alice, &many_databases(10)).unwrap();
    assert_eq!(seen.len(), 10);
    assert_eq!(r.questions(), 10);
}

#[test]
fn p_10_7a_the_pep_splits_its_questions_at_the_maximum_size_of_the_body() {
    let mut data = datastore_data();
    data["metadata"] = json!({"evaluations_max_bytes": 700});
    let r = rig(&data, |_| {});
    let alice = r.person("alice");
    // The PDP gives HTTP 413 to a body above 700 bytes.
    let seen = r.pep.display(&alice, &many_databases(12)).unwrap();
    assert_eq!(seen.len(), 12);
}

#[test]
fn p_10_7_the_pep_keeps_its_connection_between_questions() {
    let r = rig(&datastore_data(), |_| {});
    let alice = r.person("alice");
    for _ in 0..6 {
        assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
    }
    assert_eq!(r.transport.open_connections(), 1);
}

#[test]
fn p_10_7_the_pep_closes_an_idle_connection_before_the_pdp_does() {
    let mut data = datastore_data();
    data["metadata"] = json!({"idle_max_seconds": 1});
    let r = rig(&data, |_| {});
    let alice = r.person("alice");
    assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
    assert_eq!(r.transport.open_connections(), 1);
    // After half of the time of the PDP, 500 ms, the idle connection is gone at the next use.
    std::thread::sleep(Duration::from_millis(700));
    assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
    assert_eq!(r.transport.open_connections(), 1);
}

#[test]
fn p_10_7_many_threads_share_a_small_fixed_number_of_connections() {
    let r = rig(&datastore_data(), |c| c.pdp.max_connections = 2);
    let r = Arc::new(r);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let r = Arc::clone(&r);
            std::thread::spawn(move || {
                let alice = r.person("alice");
                for _ in 0..3 {
                    // The budget of the second is 10, so some uses can get 429. Both results are fine.
                    let outcome = r.pep.check(&alice, &read(db("test1")));
                    assert!(outcome.is_allowed());
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert!(r.transport.open_connections() <= 2);
}

// ---- Kept answers with a real PDP (10.1) ----------------------------------------------------------------------------------

#[test]
fn p_10_1_a_kept_answer_saves_the_question_and_a_revoked_right_shows_after_cache_ttl() {
    let r = rig(&datastore_data(), |c| c.cache_ttl = Duration::from_secs(5));
    let bob = r.person("bob");
    assert!(r.pep.check(&bob, &read(db("test1"))).is_allowed());
    let before = r.questions();
    assert!(r.pep.check(&bob, &read(db("test1"))).is_allowed());
    assert_eq!(r.questions(), before, "the kept answer needs no question");
    r.clock.advance_seconds(6);
    assert!(r.pep.check(&bob, &read(db("test1"))).is_allowed());
    assert_eq!(r.questions(), before + 1);
}

#[test]
fn p_10_1_budget_uses_are_never_kept() {
    let r = rig(&datastore_data(), |c| c.cache_ttl = Duration::from_secs(60));
    let alice = r.person("alice");
    for _ in 0..3 {
        assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
    }
    assert_eq!(r.used("alice", "requests", "second"), Some(3));
    assert_eq!(r.questions(), 3);
}

#[test]
fn p_10_1_a_kept_budget_exceeded_answer_saves_questions_while_the_budget_is_spent() {
    let data = budgets_data();
    let r = rig(&data, |c| c.cache_ttl = Duration::from_secs(30));
    let once = r.person("once"); // 1 each minute, on `test1` only
    let test1 = db("test1");
    assert!(r.pep.decide(&once, &read(test1.clone())).is_allowed());
    let refusal = r
        .pep
        .decide(&once, &read(test1.clone()))
        .into_result()
        .unwrap_err();
    assert_eq!(refusal, Refusal::RateLimited { retry_after: 12 });
    let questions = r.questions();
    r.clock.advance_seconds(3);
    let refusal = r
        .pep
        .decide(&once, &read(test1.clone()))
        .into_result()
        .unwrap_err();
    assert_eq!(refusal, Refusal::RateLimited { retry_after: 9 });
    assert_eq!(
        r.questions(),
        questions,
        "no question while the answer is kept"
    );
}

// ---- Keys against persons -----------------------------------------------------------------------------------------------------

#[test]
fn p_3_8_a_key_has_its_own_grants_and_its_own_counters() {
    let r = rig(&datastore_data(), |_| {});
    let alice = r.person("alice");
    let key = r.key(KEY_ALICE, "alice");
    // Alice has `data.read` on `test1`. Her key has a grant on `test2` only.
    assert!(r.pep.decide(&alice, &read(db("test1"))).is_allowed());
    assert_eq!(
        r.pep
            .decide(&key, &read(db("test1")))
            .into_result()
            .unwrap_err()
            .status(),
        403
    );
    assert!(r.pep.decide(&key, &read(db("test2"))).is_allowed());
}

#[test]
fn p_9_5_the_owner_claim_changes_nothing_in_the_decision() {
    let r = rig(&datastore_data(), |_| {});
    // The same subject with another owner in the token gets the same answer: the PDP knows the owner (3.4).
    let a = r.key(KEY_ALICE, "alice");
    let b = r.key(KEY_ALICE, "bob");
    let one = r.pep.decide(&a, &read(db("test2"))).into_result().unwrap();
    let two = r.pep.decide(&b, &read(db("test2"))).into_result().unwrap();
    assert_eq!(one.ceilings(), two.ceilings());
    assert_eq!(r.used("alice", "requests", "second"), Some(2));
    assert_eq!(r.used("bob", "requests", "second"), None);
}

// ---- The metadata with a real PDP (6.9, 10.7, 10.7a) ------------------------------------------------------------------------------

#[test]
fn p_10_7a_the_pep_reads_the_four_members_of_the_metadata() {
    let mut data = datastore_data();
    data["metadata"] = json!({
        "usage_max_seconds": 2, "idle_max_seconds": 7,
        "evaluations_max_bytes": 4096, "evaluations_max_items": 10
    });
    let r = rig(&data, |_| {});
    let meta = r.pep.metadata().unwrap();
    assert_eq!(meta.usage_max_seconds, Some(2));
    assert_eq!(meta.idle_max_seconds, Some(7));
    assert_eq!(meta.evaluations_max_bytes, Some(4096));
    assert_eq!(meta.evaluations_max_items, Some(10));
    assert_eq!(meta.evaluation_endpoint.path, "/access/v1/evaluation");
}
