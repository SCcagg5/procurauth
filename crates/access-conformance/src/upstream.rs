//! The service behind an edge, for the cases of the series E.
//!
//! The edge under test sends the requests that it accepts to this listener.
//! The listener keeps each request for the checks of the step. It answers
//! HTTP 200 with a small JSON body.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::http::{Handler, Headers, HttpServer, Outcome, Request, Response};

/// A request that reached the service behind the edge.
#[derive(Clone, Debug)]
pub(crate) struct Received {
    /// The headers.
    pub(crate) headers: Headers,
}

struct Core {
    log: Mutex<Vec<Received>>,
}

impl Handler for Core {
    fn handle(&self, request: &Request) -> Outcome {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Received {
                headers: request.headers.clone(),
            });
        Outcome::Respond(Response::json(200, &json!({"upstream": "conformance"})))
    }
}

/// The listener of the service behind the edge.
pub(crate) struct Upstream {
    server: HttpServer,
    core: Arc<Core>,
}

impl Upstream {
    /// Start the listener.
    ///
    /// # Errors
    /// Returns a message when the address cannot open.
    pub(crate) fn start(address: SocketAddr) -> Result<Self, String> {
        let core = Arc::new(Core {
            log: Mutex::new(Vec::new()),
        });
        let server = HttpServer::start(address, Arc::clone(&core) as Arc<dyn Handler>)?;
        Ok(Self { server, core })
    }

    /// Start a case: forget the requests.
    pub(crate) fn begin_case(&self) {
        self.core
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// The number of requests so far. A step uses it as a mark.
    pub(crate) fn mark(&self) -> usize {
        self.core
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// The requests that came after a mark.
    pub(crate) fn since(&self, mark: usize) -> Vec<Received> {
        self.core
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .skip(mark)
            .cloned()
            .collect()
    }

    /// Stop the listener.
    pub(crate) fn shutdown(self) {
        self.server.shutdown();
    }
}
