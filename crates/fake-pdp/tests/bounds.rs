//! Bounds and HTTP details: body size, items, head size, timeouts, routes (10.7, 10.7a).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use fake_pdp::Options;
use serde_json::json;

#[test]
fn p_10_7a_a_body_above_the_maximum_gets_http_413_before_the_body_arrives() {
    let mut data = datastore();
    data["metadata"] = json!({"evaluations_max_bytes": 600});
    let server = start(&data);
    let mut client = Client::connect(server.local_addr());
    // A small question is good.
    let good = client.post_json(EVALUATION, &question("alice", "data.read", TEST1, false));
    assert_eq!(good.status, 200);
    // A body of 10 MB is refused after the head: the client sends no body.
    client.write_raw(
        b"POST /access/v1/evaluations HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 10000000\r\n\r\n",
    );
    let reply = client.read_reply().expect("an answer");
    assert_eq!(reply.status, 413);
    assert_eq!(reply.header("connection"), Some("close"));
    assert_eq!(reply.json(), json!({"error": "Content Too Large"}));
    assert_eq!(client.probe(1000), Probe::Closed);
}

#[test]
fn p_10_7a_the_maximum_applies_to_the_exact_size() {
    let mut data = datastore();
    let body = question("alice", "data.read", TEST1, false).to_string();
    data["metadata"] = json!({"evaluations_max_bytes": body.len()});
    let server = start(&data);
    let reply = Client::connect(server.local_addr()).send(
        "POST",
        EVALUATION,
        &[("Content-Type", "application/json")],
        Some(body.as_bytes()),
    );
    assert_eq!(reply.status, 200, "a body of exactly the maximum is good");
    let longer = format!("{body} ");
    let reply = Client::connect(server.local_addr()).send(
        "POST",
        EVALUATION,
        &[("Content-Type", "application/json")],
        Some(longer.as_bytes()),
    );
    assert_eq!(reply.status, 413);
}

#[test]
fn p_10_7a_more_items_than_the_maximum_get_http_400() {
    let mut data = datastore();
    data["metadata"] = json!({"evaluations_max_items": 3});
    let server = start(&data);
    let item = question("alice", "data.read", TEST1, false);
    for (count, status) in [(1, 200), (3, 200), (4, 400)] {
        let body = json!({"evaluations": vec![item.clone(); count]});
        assert_eq!(
            once_json(server.local_addr(), EVALUATIONS, &body).status,
            status,
            "{count}"
        );
    }
}

#[test]
fn p_10_7a_the_defaults_apply_without_metadata_in_the_data_file() {
    let server = start(&datastore());
    let item = question("alice", "data.read", TEST1, false);
    for (count, status) in [(100, 200), (101, 400)] {
        let body = json!({"evaluations": vec![item.clone(); count]});
        assert_eq!(
            once_json(server.local_addr(), EVALUATIONS, &body).status,
            status,
            "{count}"
        );
    }
}

#[test]
fn a_head_above_the_maximum_gets_http_431() {
    let server = start(&datastore());
    let mut client = Client::connect(server.local_addr());
    let big = "a".repeat(20_000);
    client.write_raw(format!("GET /x HTTP/1.1\r\nHost: t\r\nX-Big: {big}\r\n\r\n").as_bytes());
    assert_eq!(client.read_reply().unwrap().status, 431);
}

#[test]
fn a_chunked_body_gets_http_501_and_a_bad_head_gets_http_400() {
    let server = start(&datastore());
    let mut client = Client::connect(server.local_addr());
    client.write_raw(
        b"POST /access/v1/evaluation HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    assert_eq!(client.read_reply().unwrap().status, 501);
    for (bad, status) in [
        ("GARBAGE\r\n\r\n", 400),
        ("GET /x HTTP/2.0\r\nHost: t\r\n\r\n", 505),
        (
            "POST /access/v1/evaluation HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
            400,
        ),
        ("GET x HTTP/1.1\r\n\r\n", 400),
    ] {
        let mut client = Client::connect(server.local_addr());
        client.write_raw(bad.as_bytes());
        assert_eq!(client.read_reply().unwrap().status, status, "{bad}");
    }
}

#[test]
fn a_slow_request_gets_http_408() {
    let server = start_with(
        &datastore(),
        Options {
            read_timeout: Duration::from_millis(300),
            ..Options::default()
        },
    );
    let mut client = Client::connect(server.local_addr());
    client.write_raw(b"POST /access/v1/evaluation HTTP/1.1\r\nHost: t\r\n");
    let started = Instant::now();
    assert_eq!(client.read_reply().unwrap().status, 408);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn p_10_7_the_server_closes_an_idle_connection_after_the_published_time() {
    let mut data = datastore();
    data["metadata"] = json!({"idle_max_seconds": 1});
    let server = start(&data);
    let mut client = Client::connect(server.local_addr());
    let reply = client.get("/.well-known/authzen-configuration");
    assert_eq!(reply.header("keep-alive"), Some("timeout=1"));
    assert_eq!(
        client.probe(300),
        Probe::Silent,
        "the connection is still open"
    );
    let started = Instant::now();
    assert_eq!(client.probe(3000), Probe::Closed);
    assert!(started.elapsed() < Duration::from_millis(2500));
}

#[test]
fn a_request_can_arrive_in_pieces_and_two_can_arrive_together() {
    let server = start(&datastore());
    let body = question("alice", "data.read", TEST1, false).to_string();
    let request = format!(
        "POST {EVALUATION} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut client = Client::connect(server.local_addr());
    for piece in request.as_bytes().chunks(7) {
        client.write_raw(piece);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(client.read_reply().unwrap().status, 200);
    client.write_raw(format!("{request}{request}").as_bytes());
    assert_eq!(client.read_reply().unwrap().status, 200);
    assert_eq!(client.read_reply().unwrap().status, 200);
}

#[test]
fn a_client_that_sends_expect_100_continue_gets_the_interim_answer() {
    let server = start(&datastore());
    let body = question("alice", "data.read", TEST1, false).to_string();
    let mut client = Client::connect(server.local_addr());
    client.write_raw(
        format!(
            "POST {EVALUATION} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    assert_eq!(client.probe(1000), Probe::Data, "the interim answer");
    client.write_raw(body.as_bytes());
    // The probe read the first bytes of "HTTP/1.1 100 Continue": the final answer follows.
    let mut rest = Vec::new();
    use std::io::Read;
    client
        .stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut chunk = [0_u8; 1024];
    while !String::from_utf8_lossy(&rest).contains("\"decision\"") {
        match client.stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => rest.extend_from_slice(&chunk[..n]),
        }
    }
    assert!(
        String::from_utf8_lossy(&rest).contains("200 OK"),
        "{}",
        String::from_utf8_lossy(&rest)
    );
}

#[test]
fn the_routes_give_404_and_405() {
    let server = start(&datastore());
    let addr = server.local_addr();
    assert_eq!(once(addr, "GET", "/", &[], None).status, 404);
    assert_eq!(
        once(addr, "GET", "/access/v1/search/subject", &[], None).status,
        404
    );
    assert_eq!(
        once(addr, "GET", "/__fake/clock", &[], None).status,
        404,
        "admin is off"
    );
    let reply = once(addr, "GET", EVALUATION, &[], None);
    assert_eq!(reply.status, 405);
    assert_eq!(reply.header("allow"), Some("POST"));
    let reply = once(
        addr,
        "POST",
        "/.well-known/authzen-configuration",
        &[],
        Some(b"{}"),
    );
    assert_eq!(reply.status, 405);
    assert_eq!(reply.header("allow"), Some("GET"));
    // A query string is ignored.
    assert_eq!(
        once(
            addr,
            "GET",
            "/.well-known/authzen-configuration?x=1",
            &[],
            None
        )
        .status,
        200
    );
}

#[test]
fn a_fixed_pool_serves_more_connections_than_it_has_workers() {
    let server = start_with(
        &datastore(),
        Options {
            workers: 2,
            ..Options::default()
        },
    );
    // Each one-shot connection frees its worker when it closes.
    for _ in 0..20 {
        let reply = once(
            server.local_addr(),
            "GET",
            "/.well-known/authzen-configuration",
            &[("Connection", "close")],
            None,
        );
        assert_eq!(reply.status, 200);
    }
}

#[test]
fn the_workers_must_be_in_range() {
    for workers in [0, 257] {
        let error = fake_pdp::Server::from_value(
            &datastore(),
            Options {
                workers,
                ..Options::default()
            },
        )
        .err()
        .unwrap();
        let message = error.to_string();
        assert!(
            message.contains("--workers") && message.contains("1 to 256"),
            "{message}"
        );
        assert!(message.contains(&workers.to_string()));
    }
}
