//! The action document of the reference service (section 5, section 13).
//!
//! The service is the `datastore` example, with two more actions. The action
//! `data.inspect` lists no limit, so a use of it sends no question with
//! `context.usage` (6.4). The action `mcp.session` is for the MCP methods that
//! have no tool (binding 3.6a).

use procurauth_pep::document::{ActionDocument, ActionDocumentBuilder};

/// The action to read rows. It lists a budget and two ceilings.
pub const READ: &str = "data.read";
/// The action to change data. It lists a budget and one ceiling.
pub const WRITE: &str = "data.write";
/// The action to read the structure of the data. It lists no limit.
pub const INSPECT: &str = "data.inspect";
/// The action for the MCP methods that have no tool (binding 3.6a).
pub const SESSION: &str = "mcp.session";

/// The action document of the service with this id.
///
/// # Errors
/// Returns the findings as text when the document is not good. The document is
/// fixed, and a test checks it.
pub fn reference_document(service_id: &str) -> Result<ActionDocument, String> {
    reference_document_with(service_id, false)
}

/// The action document of the service, with an option for the action `mcp.session`.
/// When `session_budget` is true, this action lists the budget `requests`, so that
/// each MCP method with no tool is one use (binding 3.6a). The option has no effect
/// when the program has no MCP endpoint.
///
/// # Errors
/// Returns the findings as text when the document is not good. The document is
/// fixed, and a test checks it.
pub fn reference_document_with(
    service_id: &str,
    session_budget: bool,
) -> Result<ActionDocument, String> {
    let all = ["service", "host", "database", "table"];
    let mut builder = ActionDocumentBuilder::new(service_id)
        .resource_type("host", "service", "One database server.")
        .resource_type("database", "host", "One database.")
        .resource_type("table", "database", "One table.")
        .action(
            READ,
            &all,
            "Read data.",
            &["requests", "max_rows", "max_duration"],
        )
        .action(WRITE, &all, "Change data.", &["requests", "max_duration"])
        .action(INSPECT, &all, "Read the structure of the data.", &[]);
    if cfg!(feature = "mcp") {
        builder = builder.action(
            SESSION,
            &["service"],
            "Use the MCP endpoint without a tool.",
            if session_budget { &["requests"] } else { &[] },
        );
    }
    builder
        .budget("requests", "Requests", "Requests that run.", "request")
        .ceiling(
            "max_rows",
            "Most rows",
            "The most rows that one read gives.",
            "row",
            1,
            1_000_000,
        )
        .ceiling(
            "max_duration",
            "Longest run",
            "The longest run of one use, in seconds.",
            "second",
            1,
            600,
        )
        .resource("host:prod", Some("Production"))
        .build()
        .map_err(|findings| {
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_5_2_the_document_is_good_for_any_service_id() {
        for id in ["datastore", "other-service"] {
            let document = reference_document(id).unwrap();
            assert_eq!(document.server, id);
            assert!(document.action_lists_budget(READ));
            assert!(document.action_lists_budget(WRITE));
            assert!(!document.action_lists_budget(INSPECT));
        }
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn the_session_action_is_the_action_of_the_binding() {
        assert_eq!(SESSION, procurauth_pep::mcp::SESSION_ACTION);
        assert!(
            reference_document("datastore")
                .unwrap()
                .action(SESSION)
                .is_some()
        );
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn mcp_3_6a_the_session_action_lists_a_budget_only_when_the_option_is_on() {
        let off = reference_document_with("datastore", false).unwrap();
        assert!(!off.action_lists_budget(SESSION));
        let on = reference_document_with("datastore", true).unwrap();
        assert!(on.action_lists_budget(SESSION));
    }

    #[test]
    fn p_5_3c_the_document_stays_within_the_numbers_of_the_reader() {
        let document = reference_document("datastore").unwrap();
        assert!(document.actions.len() <= 64);
        assert!(document.resource_types.len() <= 16);
        assert!(document.limits.len() <= 16);
        assert!(document.to_value().to_string().len() < 64 * 1024);
    }
}
