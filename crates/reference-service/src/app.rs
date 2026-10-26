//! The routes of the service.
//!
//! The service follows the seven steps of paragraph 10.0 with the library
//! `procurauth-pep`. For each route except the route of the action document,
//! it checks the identity token first (step 2). Then it builds the operation from
//! its own data (4.5), asks the PDP, applies the ceilings and maps the refusals.
//!
//! The routes are in `PROFILE.md`. The operations of the conformance cases map to
//! them.

use std::io::Write;
use std::sync::{Mutex, PoisonError};

use procurauth_core::names::validate_id;
use procurauth_pep::ceilings::Ceilings;
use procurauth_pep::operation::{Operation, node};
use procurauth_pep::options::OptionsQuery;
use procurauth_pep::reply::HttpReply;
use procurauth_pep::{Allowed, Identity, Outcome, Pep, Refusal};
use serde_json::{Value, json};

use crate::data::Store;
use crate::document::{INSPECT, READ, WRITE};
use crate::http::{Request, percent_decode};

/// The path of the action document (5.1).
pub const ACTIONS_PATH: &str = "/.well-known/procurauth/actions";
/// The path of the options route (5.6).
pub const OPTIONS_PATH: &str = "/.well-known/procurauth/resources";
/// The number of rows of a read that has no `limit`.
pub const DEFAULT_LIMIT: u64 = 100;
/// The most rows of one write.
pub const MAX_WRITE_ROWS: usize = 1000;

/// A reply, and a note for the log. The note can hold the cause of a refusal.
/// The client never gets the note.
pub struct Routed {
    /// The reply to send.
    pub reply: HttpReply,
    /// The cause for the log.
    pub note: Option<String>,
}

impl Routed {
    pub(crate) fn plain(reply: HttpReply) -> Self {
        Self { reply, note: None }
    }

    pub(crate) fn json(status: u16, body: &Value) -> Self {
        Self::plain(HttpReply::json(status, body))
    }

    /// The reply for a refusal of the PEP (10.3). A 401 has an empty body.
    pub(crate) fn refused(refusal: &Refusal) -> Self {
        let reply = if matches!(refusal, Refusal::Unauthenticated(_)) {
            HttpReply::empty(401)
        } else {
            refusal.to_http()
        };
        Self {
            reply,
            note: Some(refusal.to_string()),
        }
    }

    pub(crate) fn error(status: u16, word: &str) -> Self {
        Self::json(status, &json!({"error": word}))
    }
}

/// The service: the PEP, the data and the log.
pub struct App {
    pub(crate) pep: Pep,
    pub(crate) store: Store,
    #[cfg_attr(not(feature = "mcp"), allow(dead_code))]
    mcp_path: Option<String>,
    #[cfg(feature = "mcp")]
    pub(crate) tools: procurauth_pep::mcp::ToolMap,
    log: Mutex<Box<dyn Write + Send>>,
}

impl App {
    /// A service. `mcp_path` is the path of the MCP endpoint, when it is on.
    ///
    /// # Errors
    /// Returns an error when the map of the tools does not agree with the action
    /// document. An example is an action of a tool that the document does not declare.
    pub fn new(
        pep: Pep,
        store: Store,
        mcp_path: Option<String>,
        log: Box<dyn Write + Send>,
    ) -> Result<Self, String> {
        #[cfg(feature = "mcp")]
        let tools = {
            let tools = crate::mcp_app::tool_map().map_err(|e| e.to_string())?;
            tools
                .check_against(pep.document())
                .map_err(|e| e.to_string())?;
            tools
        };
        Ok(Self {
            pep,
            store,
            mcp_path,
            #[cfg(feature = "mcp")]
            tools,
            log: Mutex::new(log),
        })
    }

    /// The PEP of the service.
    pub fn pep(&self) -> &Pep {
        &self.pep
    }

    /// Handle one request, and write one line to the log. The line has the
    /// method, the path and the status. It never has a header, a query or a body.
    pub fn handle(&self, request: &Request) -> HttpReply {
        let routed = self.route(request);
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let note = routed
            .note
            .as_deref()
            .map_or(String::new(), |n| format!(" ({})", printable(n)));
        let _ = writeln!(
            log,
            "{} {} {}{note}",
            request.method,
            printable(&request.path),
            routed.reply.status
        );
        routed.reply
    }

    fn route(&self, request: &Request) -> Routed {
        if request.path == ACTIONS_PATH {
            // 5.1, 9.4: this route needs no token, and it asks no question.
            return Routed::plain(self.pep.actions_reply(&request.method));
        }
        // Step 2: refuse each other request that has no valid identity token.
        let who = match self.pep.authenticate(request.header_pairs()) {
            Ok(who) => who,
            Err(refusal) => return Routed::refused(&refusal),
        };
        #[cfg(feature = "mcp")]
        if self.mcp_path.as_deref() == Some(request.path.as_str()) {
            return if request.method == "POST" {
                self.mcp(request, &who)
            } else {
                method_not_allowed("POST")
            };
        }
        if request.path == OPTIONS_PATH {
            return if request.method == "GET" {
                self.options(request, &who)
            } else {
                method_not_allowed("GET")
            };
        }
        self.data_route(request, &who)
    }

    fn data_route(&self, request: &Request, who: &Identity) -> Routed {
        let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
        let decoded: Option<Vec<String>> = segments.iter().map(|s| percent_decode(s)).collect();
        let Some(parts) = decoded else {
            return Routed::error(404, "not_found");
        };
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        match (request.method.as_str(), parts.as_slice()) {
            ("GET", ["hosts"]) => self.hosts(who),
            ("POST", ["copy"]) => self.copy(request, who),
            (
                method,
                [
                    "hosts",
                    host,
                    "databases",
                    database,
                    "tables",
                    table,
                    last @ ("schema" | "rows"),
                ],
            ) => {
                let target = Target {
                    host,
                    database,
                    table,
                };
                match (method, *last) {
                    ("GET", "schema") => self.schema(who, &target),
                    ("GET", "rows") => self.read_rows(request, who, &target),
                    ("POST", "rows") => self.write_rows(request, who, &target),
                    (_, "schema") => method_not_allowed("GET"),
                    _ => method_not_allowed("GET, POST"),
                }
            }
            (_, ["hosts"]) => method_not_allowed("GET"),
            (_, ["copy"]) => method_not_allowed("POST"),
            _ => Routed::error(404, "not_found"),
        }
    }

    /// Ask the PDP, and give the answer or the reply for the refusal.
    fn allow(&self, who: &Identity, operation: &Operation) -> Result<Allowed, Routed> {
        match self.pep.decide(who, operation) {
            Outcome::Allowed(allowed) => Ok(allowed),
            Outcome::Refused(refusal) => Err(Routed::refused(&refusal)),
        }
    }

    fn hosts(&self, who: &Identity) -> Routed {
        // A request that runs no action of the document uses an action on the type `service` (15, item 6).
        let Ok(service) = node(self.pep.service_id(), &[]) else {
            return Routed::error(500, "internal_error");
        };
        match self.allow(who, &Operation::new(INSPECT, service)) {
            Ok(_) => Routed::json(200, &json!({"hosts": self.store.hosts()})),
            Err(routed) => routed,
        }
    }

    fn schema(&self, who: &Identity, target: &Target<'_>) -> Routed {
        let Some(path) = target.node(self.pep.service_id()) else {
            return Routed::error(404, "not_found");
        };
        match self.allow(who, &Operation::new(INSPECT, path)) {
            Err(routed) => routed,
            Ok(_) => match self
                .store
                .row_count(target.host, target.database, target.table)
            {
                None => Routed::error(404, "not_found"),
                Some(rows) => Routed::json(
                    200,
                    &json!({
                        "columns": [{"name": "id", "type": "integer"}, {"name": "value", "type": "text"}],
                        "rows": rows,
                    }),
                ),
            },
        }
    }

    fn read_rows(&self, request: &Request, who: &Identity, target: &Target<'_>) -> Routed {
        let Ok(params) = Params::parse(&request.query, &["limit", "timeout_seconds"]) else {
            return Routed::error(400, "bad_request");
        };
        let (Ok(limit), Ok(timeout)) = (params.whole("limit"), params.whole("timeout_seconds"))
        else {
            return Routed::error(400, "bad_request");
        };
        let Some(path) = target.node(self.pep.service_id()) else {
            return Routed::error(404, "not_found");
        };
        let allowed = match self.allow(who, &Operation::new(READ, path)) {
            Ok(allowed) => allowed,
            Err(routed) => return routed,
        };
        // Step 6: apply each ceiling. `max_rows` lowers the request. `max_duration` lowers the run time.
        let ceilings = allowed.ceilings();
        let rows_limit = ceilings
            .cap("max_rows", limit.unwrap_or(DEFAULT_LIMIT))
            .value;
        let timeout = ceilings.cap_or_ceiling("max_duration", timeout);
        let wanted = usize::try_from(rows_limit).unwrap_or(usize::MAX);
        match self
            .store
            .read(target.host, target.database, target.table, wanted)
        {
            None => Routed::error(404, "not_found"),
            Some((rows, total)) => Routed::json(
                200,
                &json!({
                    "rows": rows,
                    "count": rows.len(),
                    "limit": rows_limit,
                    "truncated": total > rows.len(),
                    "timeout_seconds": timeout,
                }),
            ),
        }
    }

    fn write_rows(&self, request: &Request, who: &Identity, target: &Target<'_>) -> Routed {
        let Ok(params) = Params::parse(&request.query, &["timeout_seconds"]) else {
            return Routed::error(400, "bad_request");
        };
        let Ok(timeout) = params.whole("timeout_seconds") else {
            return Routed::error(400, "bad_request");
        };
        let Some(rows) = parse_rows(&request.body) else {
            return Routed::error(400, "bad_request");
        };
        let Some(path) = target.node(self.pep.service_id()) else {
            return Routed::error(404, "not_found");
        };
        let allowed = match self.allow(who, &Operation::new(WRITE, path)) {
            Ok(allowed) => allowed,
            Err(routed) => return routed,
        };
        // Step 6: this route refuses a request above the ceiling, as an example of `Ceilings::check`.
        if let Some(seconds) = timeout
            && let Err(error) = allowed.ceilings().check("max_duration", seconds)
        {
            return Routed::json(
                422,
                &json!({"error": "ceiling_exceeded", "name": error.name, "limit": error.ceiling}),
            );
        }
        let appended = rows.len();
        match self
            .store
            .append(target.host, target.database, target.table, rows, false)
        {
            None => Routed::error(404, "not_found"),
            Some(total) => Routed::json(200, &json!({"appended": appended, "total": total})),
        }
    }

    fn copy(&self, request: &Request, who: &Identity) -> Routed {
        let Some(copy) = parse_copy(&request.body) else {
            return Routed::error(400, "bad_request");
        };
        let service = self.pep.service_id();
        let (Some(from), Some(to)) = (copy.source().node(service), copy.to_node(service)) else {
            return Routed::error(404, "not_found");
        };
        // 10.1a: the read of the source is an other permission. The write of the target is the use.
        let operation = Operation::new(WRITE, to).also(READ, from.clone());
        let allowed = match self.allow(who, &operation) {
            Ok(allowed) => allowed,
            Err(routed) => return routed,
        };
        let empty = Ceilings::default();
        let read_ceilings = allowed.ceilings_for(READ, &from).unwrap_or(&empty);
        let wanted =
            usize::try_from(read_ceilings.cap("max_rows", u64::MAX).value).unwrap_or(usize::MAX);
        let Some((rows, total)) = self.store.read(
            &copy.from_host,
            &copy.from_database,
            &copy.from_table,
            wanted,
        ) else {
            return Routed::error(404, "not_found");
        };
        let copied = rows.len();
        match self.store.append(
            &copy.to_host,
            &copy.to_database,
            &copy.from_table,
            rows,
            true,
        ) {
            None => Routed::error(404, "not_found"),
            Some(_) => Routed::json(200, &json!({"copied": copied, "truncated": total > copied})),
        }
    }

    fn options(&self, request: &Request, who: &Identity) -> Routed {
        let query = match OptionsQuery::parse(&request.query, self.pep.document()) {
            Ok(query) => query,
            Err(_) => return Routed::error(400, "bad_request"),
        };
        match self.pep.options(who, &query, None, &self.store) {
            Ok(answer) => Routed::json(200, &answer.to_value()),
            Err(refusal) => Routed::refused(&refusal),
        }
    }
}

fn method_not_allowed(allow: &str) -> Routed {
    Routed::plain(HttpReply::empty(405).with_header("Allow", allow))
}

/// A text for the log: a character that is not visible ASCII becomes `?`.
/// A space stays. Thus a client cannot add a line to the log.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_for_the_log_has_no_line_end() {
        assert_eq!(printable("a\r\nb\u{e9} c"), "a??b? c");
    }
}

/// The ids of a table in the path of a request.
pub(crate) struct Target<'a> {
    pub(crate) host: &'a str,
    pub(crate) database: &'a str,
    pub(crate) table: &'a str,
}

impl Target<'_> {
    /// The node of the table with its chain. It is `None` when an id is not valid (4.1).
    pub(crate) fn node(&self, service: &str) -> Option<procurauth_pep::operation::NodePath> {
        for id in [self.host, self.database, self.table] {
            validate_id(id).ok()?;
        }
        node(
            service,
            &[
                ("host", self.host),
                ("database", self.database),
                ("table", self.table),
            ],
        )
        .ok()
    }
}

/// The query parameters of a request. A parameter that occurs two times is not valid.
pub(crate) struct Params(Vec<(String, String)>);

impl Params {
    /// Read the parameters that the route knows. The route ignores each other parameter.
    pub(crate) fn parse(query: &str, known: &[&str]) -> Result<Self, ()> {
        let mut out: Vec<(String, String)> = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if !known.contains(&name) {
                continue;
            }
            if out.iter().any(|(n, _)| n == name) {
                return Err(());
            }
            out.push((name.to_owned(), percent_decode(value).ok_or(())?));
        }
        Ok(Self(out))
    }

    /// A whole number from 1, or nothing. A value that is not a whole number from 1 is an error.
    pub(crate) fn whole(&self, name: &str) -> Result<Option<u64>, ()> {
        match self.0.iter().find(|(n, _)| n == name) {
            None => Ok(None),
            Some((_, value)) => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(());
                }
                match value.parse::<u64>() {
                    Ok(n) if n >= 1 => Ok(Some(n)),
                    _ => Err(()),
                }
            }
        }
    }
}

fn parse_rows(body: &[u8]) -> Option<Vec<Value>> {
    let value = procurauth_core::json::parse_slice(body).ok()?;
    let rows = value.get("rows")?.as_array()?;
    if rows.len() > MAX_WRITE_ROWS || !rows.iter().all(Value::is_object) {
        return None;
    }
    Some(rows.clone())
}

/// The body of a copy: the source table and the target database.
pub(crate) struct CopyRequest {
    from_host: String,
    from_database: String,
    from_table: String,
    to_host: String,
    to_database: String,
}

fn text<'v>(value: &'v Value, name: &str) -> Option<&'v str> {
    value.get(name)?.as_str()
}

fn parse_copy(body: &[u8]) -> Option<CopyRequest> {
    let value = procurauth_core::json::parse_slice(body).ok()?;
    let (from, to) = (value.get("from")?, value.get("to")?);
    Some(CopyRequest {
        from_host: text(from, "host")?.to_owned(),
        from_database: text(from, "database")?.to_owned(),
        from_table: text(from, "table")?.to_owned(),
        to_host: text(to, "host")?.to_owned(),
        to_database: text(to, "database")?.to_owned(),
    })
}

impl CopyRequest {
    fn source(&self) -> Target<'_> {
        Target {
            host: &self.from_host,
            database: &self.from_database,
            table: &self.from_table,
        }
    }

    /// The node of the target database. It is `None` when an id is not valid (4.1).
    fn to_node(&self, service: &str) -> Option<procurauth_pep::operation::NodePath> {
        for id in [&self.to_host, &self.to_database] {
            validate_id(id).ok()?;
        }
        node(
            service,
            &[("host", &self.to_host), ("database", &self.to_database)],
        )
        .ok()
    }
}
