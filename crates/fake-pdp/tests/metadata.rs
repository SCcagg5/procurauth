//! The metadata document (AuthZEN 1.0, Policy Decision Point Metadata; protocol 6.9, 10.7, 10.7a).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::json;

const PATH: &str = "/.well-known/authzen-configuration";

#[test]
fn p_10_7a_the_metadata_gives_the_endpoints_and_the_defaults() {
    let server = start(&datastore());
    let reply = Client::connect(server.local_addr()).get(PATH);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    // The client sends `Host: test`.
    assert_eq!(
        reply.json(),
        json!({
            "policy_decision_point": "http://test",
            "access_evaluation_endpoint": "http://test/access/v1/evaluation",
            "access_evaluations_endpoint": "http://test/access/v1/evaluations",
            "procurauth_usage_max_seconds": 5,
            "procurauth_idle_max_seconds": 30,
            "procurauth_evaluations_max_bytes": 1_048_576,
            "procurauth_evaluations_max_items": 100
        })
    );
}

#[test]
fn p_6_9_the_metadata_takes_its_values_from_the_data_file() {
    let mut data = datastore();
    data["metadata"] = json!({
        "usage_max_seconds": 2, "idle_max_seconds": 7,
        "evaluations_max_bytes": 4096, "evaluations_max_items": 10
    });
    let server = start(&data);
    let body = Client::connect(server.local_addr()).get(PATH).json();
    assert_eq!(body["procurauth_usage_max_seconds"], 2);
    assert_eq!(body["procurauth_idle_max_seconds"], 7);
    assert_eq!(body["procurauth_evaluations_max_bytes"], 4096);
    assert_eq!(body["procurauth_evaluations_max_items"], 10);
    assert_eq!(server.settings().evaluations_max_items, 10);
}

#[test]
fn the_policy_decision_point_follows_the_host_header_and_falls_back_to_the_bound_address() {
    let server = start(&datastore());
    let addr = server.local_addr();
    let reply = once(addr, "GET", PATH, &[], None);
    assert_eq!(reply.json()["policy_decision_point"], "http://test");
    // A host header with odd characters is not used.
    let mut client = Client::connect(addr);
    client.write_raw(b"GET /.well-known/authzen-configuration HTTP/1.1\r\nHost: a<b>\r\n\r\n");
    let reply = client.read_reply().unwrap();
    assert_eq!(
        reply.json()["policy_decision_point"],
        format!("http://{addr}")
    );
    // No host header at all.
    let mut client = Client::connect(addr);
    client.write_raw(b"GET /.well-known/authzen-configuration HTTP/1.1\r\n\r\n");
    let reply = client.read_reply().unwrap();
    assert_eq!(
        reply.json()["policy_decision_point"],
        format!("http://{addr}")
    );
}
