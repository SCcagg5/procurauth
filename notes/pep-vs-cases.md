# Library functions for each case of the series U

This file tells which function of `procurauth-pep` each case of the series U needs. The reference service uses these functions.

The test `crates/reference-service/tests/u_cases.rs` is a small local runner. It reads the cases, makes the tokens, starts a test PDP with the script of the case, and sends the operations as `crates/reference-service/PROFILE.md` says. It runs 98 of the 99 cases against the reference service, and all of them pass. The runner `access-conformance` does the same work for any service.

The case U95 is skipped. It needs a budget on the action `mcp.session`, and the action of the service lists none (condition `no_budget_session`). The library test `mcp_3_6a_a_method_with_no_tool_asks_mcp_session_and_gets_a_result` covers the use of this action with no budget. The library follows 6.4 for each action. Thus a budget on this action gives a question with `context.usage`, as for another action.

The column Service tells how the service covers the case. The conditions to skip, for the reference service, are in `PROFILE.md`.

## Table

| Case | Paragraphs | Library | Service |
| --- | --- | --- | --- |
| U01 | 3.3, 9.6 | `Pep::authenticate`, `Identity::subject`, `Pep::decide` | Passes |
| U02 | 4.1 | `operation::node`, `Operation`, `Pep::decide` | Passes |
| U03 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U04 | 6.4, 10.3, 11.1 | `Pep::decide`, `Refusal::RateLimited`, `Refusal::to_http` | Passes |
| U05 | 5.6 | `Pep::options`, `Pep::display` | Passes |
| U06 | 10.3 | `Pep::decide`, `Refusal::Unavailable`, `PdpTransport` | Passes |
| U07 | 3.3 | `Pep::authenticate`, `Identity::subject`, `Pep::decide` | Passes |
| U08 | 3.3, 11.1 | `Pep::decide`, `Refusal::Forbidden`, `Refusal::to_http` | Passes |
| U09 | 3.4, 9.6 | `Pep::authenticate`, `Identity::subject`, `Pep::decide` | Passes |
| U10 | 9.5 | `identity::verify_for_pep` (added to the core), `Identity::owner` | Passes |
| U11 | 4.1 | `operation::node`, `Operation`, `Pep::decide` | Passes |
| U12 | 4.4 | `Pep::display`, `Pep::decide` | Passes |
| U13 | 5.1 | `Pep::actions_reply` | Passes |
| U14 | 5.1, 9.4 | `Pep::actions_reply` | Passes |
| U15 | 5.1, 10.1 | `Pep::actions_reply` | Passes |
| U16 | 5.2, 6.1, 6.2 | `ActionDocumentBuilder`, `ServedDocument` | Passes |
| U17 | 5.3c, 7.1 | `ActionDocumentBuilder`, `ServedDocument` | Passes |
| U18 | mcp:3.4, mcp:3.5, mcp:3.6, 6.4 | `McpGate::call`, `Stage::Ask`, `Stage::Run`, `McpGate::list_tools` | Passes |
| U19 | 6.4 | `Pep::decide` | Passes |
| U20 | 6.4 | `Pep::decide` | Passes |
| U21 | 10.1 | `Pep::decide` | Passes |
| U22 | 6.4, 10.1 | `Pep::decide` | Passes |
| U23 | mcp:5.1, mcp:5.3, mcp:5.4, 10.3 | `refusal_reply`, `budget_tool_error` | Passes |
| U24 | 6.11 | `Pep::decide` | Passes |
| U25 | mcp:1.3 | `check_version` | Passes |
| U26 | mcp:4.1, mcp:4.2, mcp:5.1 | `McpGate::list_tools`, `McpGate::call`, `refusal_reply`, `unknown_tool_reply` | Passes |
| U27 | mcp:3.3, mcp:3.3a, mcp:5.2, mcp:5.6a | `Pep::authenticate`, `refusal_reply` (HTTP 401, empty body) | Passes |
| U28 | mcp:5.1, mcp:5.5 | `refusal_reply` (HTTP 503, `-32603`) | Passes |
| U29 | mcp:3.6a, mcp:5.1, mcp:5.1b | `McpGate::session`, `refusal_reply` | Passes |
| U30 | mcp:3.5a | `McpGate::call`, `Stage::Ask`, `Stage::Run`, `McpGate::list_tools` | Passes |
| U31 | mcp:5.1b | `McpGate::session`, `refusal_reply` | Passes |
| U32 | 6.12, 10.3 | `Pep::decide` (`DenialCause::NoUsageUnits`) | Passes |
| U33 | 6.12 | `Pep::decide` (`DenialCause::NoUsageUnits`) | Passes |
| U34 | 5.5, 5.5a, 10.1a | `Operation::also`, `Pep::decide` | Passes |
| U35 | 5.5a, 10.1a | `Operation::also`, `Pep::decide` | Passes |
| U36 | 7.5, 10.2, 10.3 | `Pep::decide`, `Ceilings` | Passes |
| U37 | 7.3, 7.5, 10.2 | `Pep::decide`, `Ceilings` | Passes |
| U38 | 7.6 | `Pep::decide`, `Ceilings` | Passes |
| U39 | 7.5 | `Pep::decide`, `Ceilings` | Passes |
| U40 | 8.3 | `Pep::decide` (the document has no action `access`) | Passes |
| U41 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U42 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U43 | 9.3, 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U44 | 9.3, 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U45 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U46 | 9.3, 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U47 | 9.3, 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U48 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U49 | 9.3, 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U50 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U51 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U52 | 9.4 | `Pep::authenticate`, `identity::verify_for_pep` of the core | Passes |
| U53 | 9.4, 10.0 | `Pep::authenticate` | Passes |
| U54 | 9.4 | `Pep::authenticate` | Passes |
| U55 | 9.7 | `Pep::decide`, `Refusal::Forbidden`, `Refusal::to_http` | Passes |
| U56 | 10.0 | `PdpClient` (`Authorization: Bearer`), `Secret` | Passes |
| U57 | 10.1 | `Pep::decide`, `Pep::check`, the cache of answers (`cache_ttl`) | Passes with the default `cache_ttl_seconds` of 0. The library tests cover the kept path |
| U58 | 10.1, 10.3 | `Pep::decide`, `Pep::check`, the cache of answers (`cache_ttl`) | Passes with the default `cache_ttl_seconds` of 0. The library tests cover the kept path |
| U59 | 10.1, 10.0 | `Pep::decide` | Passes |
| U60 | 10.3, 11.2 | `Pep::decide`, `Refusal::Forbidden`, `Refusal::to_http` | Passes |
| U61 | 10.3, 11.1 | `Pep::decide`, `Refusal::Forbidden`, `Refusal::to_http` | Passes |
| U62 | 10.3, 11.1 | `Pep::decide`, `Refusal::RateLimited`, `Refusal::to_http` | Passes |
| U63 | 10.3, 11.1 | `Pep::decide`, `Refusal::RateLimited`, `Refusal::to_http` | Passes |
| U64 | 10.3 | `Pep::decide`, `Refusal::Unavailable`, `PdpTransport` | Passes |
| U65 | 10.3 | `Pep::decide`, `Refusal::Unavailable`, `PdpTransport` | Passes |
| U66 | 10.3 | `Pep::decide`, `Refusal::Unavailable`, `PdpTransport` | Passes |
| U67 | 10.3, 11.1 | `Pep::decide`, `Refusal::Unavailable`, `PdpTransport` | Passes |
| U68 | 10.6 | `PdpTransport`, `TransportError`, `Pep::decide` (no second question) | Passes |
| U69 | 10.7 | `HttpTransport` (pool of connections) | Passes |
| U70 | 5.6, 4.1 | `Pep::options`, `Pep::display` | Passes |
| U71 | 5.6, 5.7 | `Pep::options`, `OptionsQuery`, `OptionsSource` | Passes |
| U72 | 5.6, 5.8 | `Pep::options`, `OptionsQuery`, `OptionsSource` | Passes |
| U73 | 5.8 | `Pep::options`, `OptionsQuery`, `OptionsSource` | Passes |
| U74 | 5.6, 10.3 | `Pep::options`, `Refusal::Unavailable` | Passes |
| U75 | 5.7, 9.4 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U76 | 5.7 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U77 | 5.7 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U78 | 5.7 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U79 | 5.7 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U80 | 5.7 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U81 | 5.7 | `OptionsQuery::parse`, `Pep::authenticate` | Passes |
| U82 | 5.7, 5.8 | `Pep::options`, `OptionsQuery`, `OptionsSource` | Passes |
| U83 | 5.6, 10.1 | `Pep::options`, `Pep::display` | Passes |
| U84 | 15, 10.1 | `operation::node`, `Operation`, `Pep::decide` | Passes |
| U85 | mcp:3.3, 9.4 | `Pep::authenticate`, `refusal_reply` (HTTP 401, empty body) | Passes |
| U86 | mcp:3.3a, mcp:5.2, mcp:5.6a | `Pep::authenticate`, `refusal_reply` (HTTP 401, empty body) | Passes |
| U87 | mcp:3.2, 4.1 | `ToolMap`, `McpGate::call`, `operation::node` | Passes |
| U88 | mcp:4.1 | `McpGate::list_tools` | Passes |
| U89 | mcp:4.2, mcp:5.1 | `McpGate::list_tools`, `McpGate::call`, `refusal_reply`, `unknown_tool_reply` | Passes |
| U90 | mcp:5.1, 10.3 | `McpGate::list_tools`, `McpGate::call`, `refusal_reply`, `unknown_tool_reply` | Passes |
| U91 | mcp:5.1, mcp:5.5 | `refusal_reply` (HTTP 503, `-32603`) | Passes |
| U92 | mcp:5.1a, 6.12, 7.5 | `refusal_reply`, `Pep::decide` | Passes |
| U93 | mcp:5.3, mcp:5.3a | `budget_tool_error` | Passes |
| U94 | mcp:5.6, mcp:5.1 | `refusal_reply`, `unknown_tool_reply` | Passes |
| U95 | mcp:3.6a, 6.4 | `McpGate::session`, `refusal_reply` | Skipped: `no_budget_session` |
| U96 | mcp:3.7, 5.5a | `McpGate::call`, `Operation::also` | Passes |
| U97 | mcp:3.7, mcp:5.1 | `McpGate::call`, `Operation::also` | Passes |
| U98 | mcp:7.3 | `Pep::authenticate` (reads only the token header) | Passes |
| U99 | mcp:7.3, 9.4 | `Pep::authenticate`, `refusal_reply` (HTTP 401, empty body) | Passes |

## Library tests of the same rules

| Rule | Test file |
| --- | --- |
| The identity token (9.3 to 9.7) | `crates/procurauth-pep/tests/p_9_authenticate.rs` |
| The questions, the refusals, the retries, the ceilings, the kept answers | `crates/procurauth-pep/tests/p_10_decide.rs` |
| Budgets across windows, nested counters, failures, bounds, keys | `crates/procurauth-pep/tests/fake_pdp.rs` |
| The options route | `crates/procurauth-pep/tests/options.rs` |
| The MCP binding | `crates/procurauth-pep/tests/mcp.rs` |
