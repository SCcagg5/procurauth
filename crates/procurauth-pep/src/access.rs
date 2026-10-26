//! The question of an edge: may this subject use this service? (protocol 8.3)
//!
//! An edge gives an identity token for a service only to a subject with a `true`
//! decision for the action `access` on that service. The PEP of a service never
//! asks for this action (8.3). This module is the part of the library for an
//! edge. It uses the same link to the PDP as the PEP: the metadata, the
//! credential, the timeouts and the connections.
//!
//! The question has no `context.usage`. It changes no counter. Thus a question
//! that fails can go again after a lost connection (10.6).

use std::sync::Arc;

use procurauth_core::authzen::{Decision, EvaluationRequest, Reason};
use procurauth_core::path::NodePath;

use crate::clock::Clock;
use crate::config::{ConfigError, PdpConfig};
use crate::pdp_client::PdpClient;
use crate::refusal::UnavailableCause;
use crate::transport::PdpTransport;
use crate::url::Url;

/// The name of the action that an edge asks (8.3).
pub const ACCESS_ACTION: &str = "access";

/// The answer of the PDP to the question of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// The decision is `true`: the edge can give a token.
    Granted,
    /// The decision is `false`. The reason is for the log of the edge. The client never gets it.
    Denied(Option<Reason>),
}

impl Access {
    /// True when the edge can give a token.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

/// The question of an edge for one service.
pub struct AccessGate {
    client: PdpClient,
    service: NodePath,
}

impl std::fmt::Debug for AccessGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessGate")
            .field("service", &self.service.service_id())
            .finish_non_exhaustive()
    }
}

impl AccessGate {
    /// Build the gate for the service with this id.
    ///
    /// # Errors
    /// Returns every error of [`PdpConfig::check`]. Returns an error when the
    /// id is not a good id (4.1), or when the transport cannot use the scheme of the URL.
    pub fn new(
        service_id: &str,
        pdp: &PdpConfig,
        transport: Arc<dyn PdpTransport>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Vec<ConfigError>> {
        pdp.check()?;
        procurauth_core::names::validate_id(service_id).map_err(|error| {
            vec![ConfigError {
                key: "service_id".to_owned(),
                expected: format!("an id of 1 to 256 bytes with no control character ({error})"),
                found: format!("{service_id:?}"),
            }]
        })?;
        let base = Url::parse(&pdp.url).map_err(|error| {
            vec![ConfigError {
                key: "pdp.url".to_owned(),
                expected: "a URL".to_owned(),
                found: error.to_string(),
            }]
        })?;
        if !transport.supports_scheme(base.scheme.as_str()) {
            return Err(vec![ConfigError {
                key: "pdp.url".to_owned(),
                expected: "a scheme that the transport can use".to_owned(),
                found: format!("the scheme `{}`", base.scheme.as_str()),
            }]);
        }
        Ok(Self {
            client: PdpClient::new(pdp, transport, clock, base),
            service: NodePath::service(service_id),
        })
    }

    /// Ask the PDP if the subject can use the service. The subject has the type
    /// `user`, and its id is the subject id of the person or of the key (3.3).
    ///
    /// # Errors
    /// Returns the cause when the PDP gives no valid answer. The edge then
    /// does not give a token.
    pub fn check(&self, subject: &str) -> Result<Access, UnavailableCause> {
        let question = EvaluationRequest::new(subject, ACCESS_ACTION, &self.service);
        let Decision { decision, context } = self.client.ask(&question, false)?;
        Ok(if decision {
            Access::Granted
        } else {
            Access::Denied(context.reason)
        })
    }
}
