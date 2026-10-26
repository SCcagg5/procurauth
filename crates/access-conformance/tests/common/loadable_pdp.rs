//! A PDP that a runner can load: a test double for a real PDP with a load request.
//!
//! The server holds one `fake-pdp` at a time. The request `PUT /__load` with a
//! data document replaces it. Each other request goes to the current `fake-pdp`.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake_pdp::{Options, RunningServer, Server as FakeServer};
use serde_json::{Value, json};

use super::http::{Req, Resp, Server, call};

pub struct LoadablePdp {
    pub addr: SocketAddr,
    pub loads: Arc<Mutex<Vec<Value>>>,
    server: Server,
}

fn start_fake(data: &Value) -> RunningServer {
    FakeServer::from_value(
        data,
        Options {
            admin: true,
            ..Options::default()
        },
    )
    .unwrap()
    .start("127.0.0.1:0")
    .unwrap()
}

impl LoadablePdp {
    pub fn start() -> Self {
        let current: Arc<Mutex<Option<RunningServer>>> = Arc::new(Mutex::new(None));
        let loads = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&current);
        let seen = Arc::clone(&loads);
        let server = Server::start("127.0.0.1:0", move |req: Req| {
            if req.path == "/__load" && matches!(req.method.as_str(), "PUT" | "POST") {
                let Ok(data) = serde_json::from_slice::<Value>(&req.body) else {
                    return Resp::json(400, &json!({"error": "not JSON"}));
                };
                let fresh = start_fake(&data);
                seen.lock().unwrap().push(data);
                if let Some(old) = held.lock().unwrap().replace(fresh) {
                    old.shutdown();
                }
                return Resp::json(200, &json!({"loaded": true}));
            }
            let target = held.lock().unwrap().as_ref().map(RunningServer::local_addr);
            let Some(target) = target else {
                return Resp::json(503, &json!({"error": "no data"}));
            };
            let mut headers: Vec<(&str, &str)> = Vec::new();
            if let Some(v) = req.header("content-type") {
                headers.push(("Content-Type", v));
            }
            if let Some(v) = req.header("authorization") {
                headers.push(("Authorization", v));
            }
            let body = (!req.body.is_empty()).then_some(req.body.as_slice());
            match call(
                target,
                &req.method,
                &req.target,
                &headers,
                body,
                Duration::from_secs(5),
            ) {
                Some(reply) => Resp {
                    status: reply.status,
                    headers: vec![(
                        "Content-Type".to_owned(),
                        reply
                            .header("content-type")
                            .unwrap_or("application/json")
                            .to_owned(),
                    )],
                    body: reply.body,
                },
                None => Resp::new(502),
            }
        });
        Self {
            addr: server.addr,
            loads,
            server,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}
