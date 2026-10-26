//! The PEP: the seven steps of paragraph 10.0 as one object.
//!
//! A [`Pep`] checks the identity token (steps 1 and 2). It asks the PDP for
//! each operation (steps 3 and 4). It takes units for a use that lists a
//! budget (step 5). It gives the ceilings to apply (step 6). It maps each
//! refusal (step 7).
//!
//! The object does not write to a client. It gives the status and the
//! headers, and the application sends them.
//!
//! # The rules that the object follows
//!
//! - A question with `context.usage` is the question of the use (6.4, 10.1).
//!   The PEP never sends the same question without `context.usage` before it.
//! - The PEP never sends a question with `context.usage` again after a
//!   timeout, a lost answer or a connection error (10.6).
//! - A `true` answer to a question with `context.usage` that has no
//!   `context.usage.units` counts as `false` (6.12).
//! - A ceiling that the action does not list counts as a ceiling that the PEP
//!   cannot apply. The answer then counts as `false` (7.5).
//! - A `false` answer has no effect on the ceilings (7.6).
//! - The PEP never gives `context.reason` to the client (10.3).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use procurauth_core::action_document::{ActionDocument, LimitKind};
use procurauth_core::authzen::{Decision, EvaluationRequest, MatchMode, Reason};
use procurauth_core::identity::{TokenPolicy, verify_for_pep};
use procurauth_core::jws::KeySet;
use procurauth_core::path::NodePath;

use crate::cache::{AnswerCache, Key};
use crate::ceilings::Ceilings;
use crate::clock::{Clock, SystemClock};
use crate::config::{ConfigError, PepConfig};
use crate::document::ServedDocument;
use crate::identity::Identity;
use crate::metadata::PdpMetadata;
use crate::operation::{Operation, Permission};
use crate::pdp_client::PdpClient;
use crate::refusal::{AuthFailure, DenialCause, Refusal, UnavailableCause};
use crate::reply::HttpReply;
use crate::transport::PdpTransport;
use crate::url::Url;

/// A permission that the PDP granted, with the ceilings to apply to the part that it lets run (5.5a, 7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Granted {
    /// The action and the node.
    pub permission: Permission,
    /// The ceilings of the answer.
    pub ceilings: Ceilings,
}

/// The operation may run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowed {
    units: u64,
    used: Granted,
    others: Vec<Granted>,
}

impl Allowed {
    /// The units that the PDP took for the use: 1, or 0 when no budget applies
    /// to the subject (6.12). It is 0 for an action without a budget.
    pub fn units(&self) -> u64 {
        self.units
    }

    /// The action of the use, and its node.
    pub fn used(&self) -> &Permission {
        &self.used.permission
    }

    /// The ceilings that apply to the use (6.4, 7.5).
    pub fn ceilings(&self) -> &Ceilings {
        &self.used.ceilings
    }

    /// The other permissions of the operation, each with its own ceilings (5.5a).
    pub fn others(&self) -> &[Granted] {
        &self.others
    }

    /// The ceilings of one permission of the operation, the use or another one.
    pub fn ceilings_for(&self, action: &str, node: &NodePath) -> Option<&Ceilings> {
        std::iter::once(&self.used)
            .chain(self.others.iter())
            .find(|g| g.permission.action == action && &g.permission.node == node)
            .map(|g| &g.ceilings)
    }
}

/// The result of an operation: it runs, or the PEP refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The operation may run. Apply the ceilings.
    Allowed(Allowed),
    /// The operation must not run. Map the refusal with [`Refusal::to_http`].
    Refused(Refusal),
}

impl Outcome {
    /// The outcome as a `Result`.
    ///
    /// # Errors
    /// Returns the refusal when the operation must not run.
    pub fn into_result(self) -> Result<Allowed, Refusal> {
        match self {
            Self::Allowed(allowed) => Ok(allowed),
            Self::Refused(refusal) => Err(refusal),
        }
    }

    /// True when the operation may run.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    /// The refusal, when the operation must not run.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            Self::Allowed(_) => None,
        }
    }
}

/// A PEP for one service.
pub struct Pep {
    service_id: String,
    token_header: String,
    policy: TokenPolicy,
    keys: KeySet,
    document: ActionDocument,
    served: ServedDocument,
    client: PdpClient,
    cache: Mutex<AnswerCache>,
    clock: Arc<dyn Clock>,
    display_max_questions: usize,
}

impl std::fmt::Debug for Pep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pep")
            .field("service_id", &self.service_id)
            .field("token_header", &self.token_header)
            .finish_non_exhaustive()
    }
}

fn config_error(key: &str, expected: &str, found: String) -> Vec<ConfigError> {
    vec![ConfigError {
        key: key.to_owned(),
        expected: expected.to_owned(),
        found,
    }]
}

impl Pep {
    /// Build the PEP with the clock of the system.
    ///
    /// # Errors
    /// Returns every error of [`PepConfig::check`]. Returns an error when the
    /// document is not good. Returns an error when its `server` is not the id
    /// of the service. Returns an error when the transport cannot use the
    /// scheme of the URL of the PDP.
    pub fn new(
        config: PepConfig,
        document: ActionDocument,
        transport: Arc<dyn PdpTransport>,
    ) -> Result<Self, Vec<ConfigError>> {
        Self::with_clock(config, document, transport, Arc::new(SystemClock))
    }

    /// Build the PEP with a clock that the caller gives, for example a [`crate::clock::ManualClock`].
    ///
    /// # Errors
    /// Returns the same errors as [`Pep::new`].
    pub fn with_clock(
        config: PepConfig,
        document: ActionDocument,
        transport: Arc<dyn PdpTransport>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Vec<ConfigError>> {
        config.check()?;
        let served = ServedDocument::new(&document).map_err(|findings| {
            config_error(
                "action_document",
                "a document that follows 5.2, 5.3 and 6.1",
                findings
                    .first()
                    .map_or_else(String::new, ToString::to_string),
            )
        })?;
        if document.server != config.service_id {
            return Err(config_error(
                "action_document.server",
                &format!(
                    "the id of the service, {:?} (contradiction with `service_id`)",
                    config.service_id
                ),
                format!("{:?}", document.server),
            ));
        }
        let base = Url::parse(&config.pdp.url)
            .map_err(|e| config_error("pdp.url", "a URL", e.to_string()))?;
        if !transport.supports_scheme(base.scheme.as_str()) {
            return Err(config_error(
                "pdp.url",
                "a scheme that the transport can use",
                format!("the scheme `{}`", base.scheme.as_str()),
            ));
        }
        let ttl_ms = u64::try_from(config.cache_ttl.as_millis()).unwrap_or(u64::MAX);
        Ok(Self {
            policy: TokenPolicy {
                issuer: config.issuer,
                service_id: config.service_id.clone(),
                max_age_seconds: config.max_token_age_seconds,
                skew_seconds: config.clock_skew_seconds,
            },
            keys: config.trusted_keys,
            service_id: config.service_id,
            token_header: config.token_header,
            document,
            served,
            client: PdpClient::new(&config.pdp, transport, Arc::clone(&clock), base),
            cache: Mutex::new(AnswerCache::new(ttl_ms, config.cache_max_entries)),
            clock,
            display_max_questions: config.display_max_questions,
        })
    }

    /// The id of the service.
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// The name of the header with the identity token.
    pub fn token_header(&self) -> &str {
        &self.token_header
    }

    /// The action document.
    pub fn document(&self) -> &ActionDocument {
        &self.document
    }

    /// The most questions that one request to the options route asks (5.6).
    pub fn display_max_questions(&self) -> usize {
        self.display_max_questions
    }

    /// The number of kept answers now (10.1b).
    pub fn kept_answers(&self) -> usize {
        self.lock_cache().len()
    }

    /// The reply for a read of the action document at `/.well-known/procurauth/actions`.
    /// This route needs no identity token and asks no question (5.1, 10.1).
    pub fn actions_reply(&self, method: &str) -> HttpReply {
        self.served.reply(method)
    }

    fn lock_cache(&self) -> MutexGuard<'_, AnswerCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ---- Steps 1 and 2: the identity token ------------------------------------

    /// Check the identity token of a request (9.4) and return the identity.
    ///
    /// `headers` holds the name and the value of each header of the request. The
    /// PEP reads the header that the configuration names, and no other header: it
    /// never reads `Authorization` or a cookie. A request that has this header
    /// more than one time gets a refusal.
    ///
    /// # Errors
    /// Returns [`Refusal::Unauthenticated`] when the request has no token, or a
    /// token that fails a check. The caller answers HTTP 401 (10.3).
    pub fn authenticate<'a, I>(&self, headers: I) -> Result<Identity, Refusal>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut found: Option<&str> = None;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case(&self.token_header) {
                if found.is_some() {
                    return Err(Refusal::Unauthenticated(AuthFailure::DuplicateHeader));
                }
                found = Some(value);
            }
        }
        let token = found.ok_or(Refusal::Unauthenticated(AuthFailure::NoToken))?;
        self.authenticate_token(token)
    }

    /// Check the text of an identity token (9.4).
    ///
    /// # Errors
    /// Returns [`Refusal::Unauthenticated`] when the token fails a check.
    pub fn authenticate_token(&self, token: &str) -> Result<Identity, Refusal> {
        let now = self.clock.now_seconds();
        match verify_for_pep(token, &self.keys, &self.policy, now) {
            Ok(verified) => {
                let claims = verified.claims;
                Ok(Identity::new(
                    claims.sub,
                    claims.owner,
                    claims.iat,
                    claims.exp,
                ))
            }
            Err(error) => Err(Refusal::Unauthenticated(AuthFailure::Token {
                check: error.check.as_str().to_owned(),
                rule: error.rule,
                detail: error.detail,
            })),
        }
    }

    // ---- Steps 3 to 7: the questions ------------------------------------------

    /// Ask the PDP for one operation, and take the units of the use (10.1).
    ///
    /// For each other permission, the PEP first asks without `context.usage`
    /// (5.5a, 10.1a). When one answer is `false`, the PEP refuses and sends no
    /// question with `context.usage`. Then it asks the use. When the action of the
    /// use lists a budget, this question has `context.usage` (6.4). With several
    /// actions for the use, the PEP asks them in order. It stops at the first
    /// `true` answer or at the first `budget_exceeded` (10.1).
    pub fn decide(&self, who: &Identity, operation: &Operation) -> Outcome {
        self.run(who, operation, true)
    }

    /// Ask the PDP about an operation, and take no unit. Use it for a call that
    /// is not yet a use. Two examples are a call that asks the client for input,
    /// and a call that waits for an approval (binding 3.5, 3.5a). The PEP sends no question with
    /// `context.usage`. The answer never starts a use of an action that lists a
    /// budget (10.1). Call [`Pep::decide`] for the run.
    pub fn check(&self, who: &Identity, operation: &Operation) -> Outcome {
        self.run(who, operation, false)
    }

    fn run(&self, who: &Identity, operation: &Operation, usage_allowed: bool) -> Outcome {
        match self.run_inner(who, operation, usage_allowed) {
            Ok(allowed) => Outcome::Allowed(allowed),
            Err(refusal) => Outcome::Refused(refusal),
        }
    }

    fn run_inner(
        &self,
        who: &Identity,
        operation: &Operation,
        usage_allowed: bool,
    ) -> Result<Allowed, Refusal> {
        for permission in operation.uses().iter().chain(operation.others()) {
            self.validate(permission, true)?;
        }
        // The other permissions come first, without `context.usage` (5.5a, 10.1a).
        // A permission that is also an alternative for the use is not asked twice (10.1).
        let others: Vec<&Permission> = operation
            .others()
            .iter()
            .filter(|p| !operation.uses().contains(p))
            .collect();
        let mut granted_others = Vec::with_capacity(others.len());
        if !others.is_empty() {
            let answers = self.ask_plain(who.sub(), &others, MatchMode::Node)?;
            for (permission, decision) in others.iter().zip(answers) {
                if !decision.decision {
                    return Err(denied(&decision));
                }
                granted_others.push(Granted {
                    permission: (*permission).clone(),
                    ceilings: self.ceilings_of(&permission.action, &decision)?,
                });
            }
        }
        let (units, used) = self.run_use(who.sub(), operation.uses(), usage_allowed)?;
        Ok(Allowed {
            units,
            used,
            others: granted_others,
        })
    }

    /// Check one permission against the action document. A mistake here is a
    /// mistake of the service, not of the client. For a use, the action must list
    /// the type of the node (5.2). A display question has no such rule, because
    /// `subtree` also looks below the node (4.4).
    fn validate(&self, permission: &Permission, for_use: bool) -> Result<(), Refusal> {
        let mistake = |text: String| Err(Refusal::Internal(text));
        let Some(action) = self.document.action(&permission.action) else {
            return mistake(format!(
                "the action `{}` is not in the action document",
                permission.action
            ));
        };
        if let Err(error) = self.document.check_path(&permission.node) {
            return mistake(format!("the node does not follow the document: {error}"));
        }
        let node_type = &permission.node.node().node_type;
        if for_use && !action.resource_types.contains(node_type) {
            return mistake(format!(
                "the action `{}` is not valid on the type `{node_type}`",
                permission.action
            ));
        }
        Ok(())
    }

    /// The ceilings of a `true` answer, for the action that was asked (7.3, 7.5).
    fn ceilings_of(&self, action: &str, decision: &Decision) -> Result<Ceilings, Refusal> {
        let listed = self.document.action(action).map(|a| &a.limits);
        for name in decision.context.limits.keys() {
            let declaration = self.document.limit(name);
            let applies = declaration.is_some_and(|d| d.kind == LimitKind::Ceiling)
                && listed.is_some_and(|l| l.contains(name));
            if applies {
                continue;
            }
            if declaration.is_some_and(|d| d.kind == LimitKind::Budget) {
                // A budget value never appears in an answer (7.3): the answer is not valid.
                return Err(Refusal::Unavailable(UnavailableCause::Answer(format!(
                    "`context.limits` has the budget `{name}`"
                ))));
            }
            return Err(Refusal::Forbidden {
                reason: None,
                cause: DenialCause::UnknownCeiling(name.clone()),
            });
        }
        Ok(Ceilings::from_map(decision.context.limits.clone()))
    }

    /// Ask permissions without `context.usage`, with the kept answers (10.1).
    fn ask_plain(
        &self,
        subject: &str,
        permissions: &[&Permission],
        mode: MatchMode,
    ) -> Result<Vec<Decision>, Refusal> {
        let now = self.clock.now_millis();
        let mut results: Vec<Option<Decision>> = vec![None; permissions.len()];
        let mut misses = Vec::new();
        {
            let mut cache = self.lock_cache();
            for (index, permission) in permissions.iter().enumerate() {
                let key = Key::new(subject, &permission.action, &permission.node, mode, false);
                match cache.get(&key, now) {
                    Some(kept) => results[index] = Some(kept.decision),
                    None => misses.push(index),
                }
            }
        }
        if !misses.is_empty() {
            let answers = if let [index] = misses.as_slice() {
                let permission = permissions[*index];
                let mut question =
                    EvaluationRequest::new(subject, &permission.action, &permission.node);
                if mode == MatchMode::Subtree {
                    question = question.with_match(mode);
                }
                vec![
                    self.client
                        .ask(&question, false)
                        .map_err(Refusal::Unavailable)?,
                ]
            } else {
                let items: Vec<(&str, &NodePath)> = misses
                    .iter()
                    .map(|&i| (permissions[i].action.as_str(), &permissions[i].node))
                    .collect();
                self.client
                    .ask_many(subject, mode, &items)
                    .map_err(Refusal::Unavailable)?
            };
            let mut cache = self.lock_cache();
            let ttl = cache.ttl_ms();
            for (&index, decision) in misses.iter().zip(answers) {
                let permission = permissions[index];
                let key = Key::new(subject, &permission.action, &permission.node, mode, false);
                cache.put(key, decision.clone(), now, ttl);
                results[index] = Some(decision);
            }
        }
        Ok(results.into_iter().flatten().collect())
    }

    /// Run the use: one action, or several actions in the order of preference.
    fn run_use(
        &self,
        subject: &str,
        alternatives: &[Permission],
        usage_allowed: bool,
    ) -> Result<(u64, Granted), Refusal> {
        let mut last_denial: Option<Refusal> = None;
        for permission in alternatives {
            let lists_budget = self.document.action_lists_budget(&permission.action);
            let step = if lists_budget && usage_allowed {
                self.use_with_usage(subject, permission)?
            } else {
                self.use_plain(subject, permission)?
            };
            match step {
                Step::Granted(units, granted) => return Ok((units, granted)),
                Step::Denied(refusal) => last_denial = Some(refusal),
            }
        }
        Err(last_denial.unwrap_or_else(|| Refusal::Internal("the operation has no use".to_owned())))
    }

    fn use_plain(&self, subject: &str, permission: &Permission) -> Result<Step, Refusal> {
        let answers = self.ask_plain(subject, &[permission], MatchMode::Node)?;
        let Some(decision) = answers.into_iter().next() else {
            return Err(Refusal::Internal("no answer for a question".to_owned()));
        };
        if decision.decision {
            let ceilings = self.ceilings_of(&permission.action, &decision)?;
            Ok(Step::Granted(
                0,
                Granted {
                    permission: permission.clone(),
                    ceilings,
                },
            ))
        } else {
            Ok(Step::Denied(denied(&decision)))
        }
    }

    fn use_with_usage(&self, subject: &str, permission: &Permission) -> Result<Step, Refusal> {
        let now = self.clock.now_millis();
        let key = |usage_side: bool| {
            Key::new(
                subject,
                &permission.action,
                &permission.node,
                MatchMode::Node,
                usage_side,
            )
        };
        let (plain_key, usage_key) = (key(false), key(true));
        // The kept answers of the use (10.1). A kept `true` answer without usage never starts a use.
        let kept = {
            let mut cache = self.lock_cache();
            match cache.get(&usage_key, now) {
                Some(kept) => Some((kept.decision, kept.retry_after)),
                // A kept `false` answer refuses the use with no question.
                None => cache
                    .get(&plain_key, now)
                    .filter(|kept| !kept.decision.decision)
                    .map(|kept| (kept.decision, None)),
            }
        };
        if let Some((decision, retry_after)) = kept {
            return self.read_usage_answer(permission, &decision, retry_after);
        }
        let question =
            EvaluationRequest::new(subject, &permission.action, &permission.node).with_usage();
        let decision = self
            .client
            .ask(&question, true)
            .map_err(Refusal::Unavailable)?;
        {
            let mut cache = self.lock_cache();
            let ttl = cache.ttl_ms();
            if decision.decision {
                // The PEP never keeps a `true` answer with units above 0 (10.1).
                if decision.context.usage_units == Some(0) {
                    cache.put(usage_key, decision.clone(), now, ttl);
                }
            } else if decision.context.reason == Some(Reason::BudgetExceeded) {
                if let Some(seconds) = decision.context.retry_after {
                    cache.put(
                        usage_key,
                        decision.clone(),
                        now,
                        seconds.saturating_mul(1000),
                    );
                }
            } else {
                // A `false` answer without `budget_exceeded` counted nothing. Keep it as an
                // answer to the same question without usage. A kept `true` answer to that
                // question is not true any more: delete the answers for this subject and node (10.1).
                if cache
                    .get(&plain_key, now)
                    .is_some_and(|kept| kept.decision.decision)
                {
                    cache.forget_subject_and_resource(&plain_key);
                }
                cache.put(plain_key, decision.clone(), now, ttl);
            }
        }
        self.read_usage_answer(permission, &decision, None)
    }

    /// Read the answer to a question with `context.usage`, or a kept answer to it.
    /// `kept_retry_after` is the time that remains for a kept `budget_exceeded` answer.
    fn read_usage_answer(
        &self,
        permission: &Permission,
        decision: &Decision,
        kept_retry_after: Option<u64>,
    ) -> Result<Step, Refusal> {
        if decision.decision {
            // 6.12: a `true` answer without `context.usage.units` counts as `false`.
            let Some(units) = decision.context.usage_units else {
                return Err(Refusal::Forbidden {
                    reason: None,
                    cause: DenialCause::NoUsageUnits,
                });
            };
            let ceilings = self.ceilings_of(&permission.action, decision)?;
            return Ok(Step::Granted(
                units,
                Granted {
                    permission: permission.clone(),
                    ceilings,
                },
            ));
        }
        if decision.context.reason == Some(Reason::BudgetExceeded) {
            let retry_after = kept_retry_after
                .or(decision.context.retry_after)
                .unwrap_or(1);
            // 10.1: the first `budget_exceeded` ends the search among several actions.
            return Err(Refusal::RateLimited { retry_after });
        }
        Ok(Step::Denied(denied(decision)))
    }

    /// Ask a question for a display, with `context.match` equal to `subtree` (4.4).
    /// Use it for the options route (5.6) and for the list of the tools (binding 4.1).
    /// The answer is for the display only. It never lets an operation run.
    /// The PEP sends the questions without `context.usage` (6.6, 6.11), in
    /// requests that stay within the maxima of the PDP (10.7a).
    ///
    /// # Errors
    /// Returns [`Refusal::Unavailable`] when the PDP gives no valid answer,
    /// and [`Refusal::Internal`] when a permission does not follow the action document.
    pub fn display(
        &self,
        who: &Identity,
        permissions: &[Permission],
    ) -> Result<Vec<bool>, Refusal> {
        for permission in permissions {
            self.validate(permission, false)?;
        }
        let refs: Vec<&Permission> = permissions.iter().collect();
        let answers = self.ask_plain(who.sub(), &refs, MatchMode::Subtree)?;
        Ok(answers.iter().map(|d| d.decision).collect())
    }

    // ---- The metadata -----------------------------------------------------------

    /// The metadata of the PDP. The PEP reads it at the first question. Call this
    /// at start to find a bad link before the service serves.
    ///
    /// # Errors
    /// Returns [`Refusal::Unavailable`] when the PDP gives no valid metadata.
    pub fn metadata(&self) -> Result<PdpMetadata, Refusal> {
        self.client.metadata().map_err(Refusal::Unavailable)
    }

    /// Read the metadata again now.
    ///
    /// # Errors
    /// Returns [`Refusal::Unavailable`] when the PDP gives no valid metadata.
    pub fn refresh_metadata(&self) -> Result<PdpMetadata, Refusal> {
        self.client.refresh().map_err(Refusal::Unavailable)
    }
}

enum Step {
    Granted(u64, Granted),
    Denied(Refusal),
}

/// The refusal for a `false` answer without `budget_exceeded`.
fn denied(decision: &Decision) -> Refusal {
    Refusal::Forbidden {
        reason: decision.context.reason.clone(),
        cause: DenialCause::Decision,
    }
}
