# Profile of the reference service for access-conformance

This file maps each operation of the conformance cases to a request of the reference service. The runner `access-conformance` reads a profile of the service under test. The author of the profile writes it from this file.

The service is the `datastore` example. Its action document is in `src/document.rs`. Its test data is in `examples/pdp-data.json`.

## Setup

| Item | Value |
| --- | --- |
| Configuration | `examples/conformance.json` |
| Credential of the service for the PDP | The variable `PROCURAUTH_PDP_CREDENTIAL`. The test PDP of the runner accepts the same value. |
| Address of the service | `127.0.0.1:8080`. The key `listen` of the configuration changes it. |
| Address of the test PDP | `http://127.0.0.1:8181`. The key `pdp.url` of the configuration changes it. |
| Header of the identity token | `X-Identity-Token` |
| Issuer (`iss`) | `https://edge.example` |
| Audience (`aud`) | `datastore` |
| Keys of the test edge | Ed25519 with the `kid` `edge-ed25519`, and ES256 with the `kid` `edge-es256`. The files are in `crates/access-token/examples/`. |
| Maximum age of a token | 300 seconds |
| Clock skew | 30 seconds |

The configuration trusts two keys, so each token needs a `kid` in its header. The defect `unknown_kid` of a token gives a `kid` that the set does not hold.

The configuration sets `pdp.request_timeout_ms` to 1000. A case with a PDP that does not answer then ends in about one second.

## Variables

| Variable | Value |
| --- | --- |
| `service` | `datastore` |
| `mcp_path` | `/mcp` |
| `options_type` | `host` |
| `token_header` | `X-Identity-Token` |

## Operations

Each token goes in the header `X-Identity-Token`. The paths hold ids that the service decodes with the percent-encoding of RFC 3986.

The table gives the request of each operation. The columns after it give the variables of the cases: `action`, `resource_type`, `resource_id` and `ancestors`. The chain `ancestors` of a table is the service, the host `prod` and the database `test2`.

| Operation | Method and path | Body |
| --- | --- | --- |
| `use_plain` | `GET /hosts/prod/databases/test2/tables/orders/schema` | none |
| `use_budget` | `GET /hosts/prod/databases/test2/tables/orders/rows?limit=1` | none |
| `use_ceiling` | `GET /hosts/prod/databases/test2/tables/orders/rows?limit=1` | none |
| `use_service` | `GET /hosts` | none |
| `use_multi` | `POST /copy` | `{"from": {"host": "prod", "database": "test1", "table": "orders"}, "to": {"host": "prod", "database": "test2"}}` |
| `read_actions` | `GET /.well-known/procurauth/actions` | none |
| `list_options` | `GET /.well-known/procurauth/resources?type=host` | none |

| Operation | `action` | `resource_type` | `resource_id` | `ancestors` |
| --- | --- | --- | --- | --- |
| `use_plain` | `data.inspect` | `table` | `orders` | service `datastore`, host `prod`, database `test2` |
| `use_budget` | `data.read` | `table` | `orders` | service `datastore`, host `prod`, database `test2` |
| `use_ceiling` | `data.read` | `table` | `orders` | service `datastore`, host `prod`, database `test2` |
| `use_service` | `data.inspect` | `service` | `datastore` | none |
| `use_multi` | `data.write` | `database` | `test2` | service `datastore`, host `prod` |

For `use_ceiling`, the variable `ceiling` is `max_rows`. The variable `ceiling_value` is a whole number from 1 to 1000000, for example 100.

For `use_multi`, the use is the write on the database `test2`. The other permission is the read of the table `orders` of `test1`, without `context.usage`.

For `read_actions` and `list_options`, no variable of the operation applies.

### MCP operations

Each MCP operation is a `POST` to `{{mcp_path}}` with these headers:

| Header | Value |
| --- | --- |
| `Content-Type` | `application/json` |
| `Accept` | `application/json, text/event-stream` |
| `MCP-Protocol-Version` | `2026-07-28` |

The body is a JSON-RPC request with the id 7 and the method `tools/call`. The member `params._meta` has `"io.modelcontextprotocol/protocolVersion": "2026-07-28"`. The members `params.name` and `params.arguments` are in the table.

| Operation | `params.name` | `params.arguments` | Extra member of `params` |
| --- | --- | --- | --- |
| `mcp_call_plain` | `list_tables` | `{"host": "prod", "database": "test2"}` | none |
| `mcp_call_budget` | `read_rows` | `{"host": "prod", "database": "test2", "table": "orders", "limit": 1}` | none |
| `mcp_call_input` | `query_table` | `{"host": "prod", "database": "test2"}` | none |
| `mcp_call_multi` | `copy_table` | `{"from": {"host": "prod", "database": "test1", "table": "orders"}, "to": {"host": "prod", "database": "test2"}}` | none |
| `mcp_call_approval` | `write_rows` | `{"host": "prod", "database": "test2", "table": "orders", "rows": [{"id": 1}]}` | none |
| `mcp_approve` | `write_rows` | The same as `mcp_call_approval` | `"inputResponses": {"approval": {"action": "accept"}}` |
| `mcp_refuse` | `write_rows` | The same as `mcp_call_approval` | `"inputResponses": {"approval": {"action": "decline"}}` |

| Operation | `tool` | `action` | `resource_type` | `resource_id` | `ancestors` |
| --- | --- | --- | --- | --- | --- |
| `mcp_call_plain` | `list_tables` | `data.inspect` | `database` | `test2` | service `datastore`, host `prod` |
| `mcp_call_budget` | `read_rows` | `data.read` | `table` | `orders` | service `datastore`, host `prod`, database `test2` |
| `mcp_call_input` | `query_table` | `data.read` | `database` | `test2` | service `datastore`, host `prod` |
| `mcp_call_multi` | `copy_table` | `data.write` | `database` | `test2` | service `datastore`, host `prod` |
| `mcp_call_approval` | `write_rows` | `data.write` | `table` | `orders` | service `datastore`, host `prod`, database `test2` |

For `mcp_call_input`, the first question has the resource of the database. The service asks the client for the table. A later call that gives the table is a use of `data.read` on the table.

## What the service answers

| Operation | Good answer |
| --- | --- |
| `use_*` | HTTP 200 with a JSON body. |
| `read_actions` | HTTP 200 with the action document. |
| `list_options` | HTTP 200 with `{"items": [...], "next": ...}`. |
| `mcp_call_plain`, `mcp_call_budget`, `mcp_call_multi`, `mcp_approve` | HTTP 200 with a JSON-RPC result that has `resultType` `complete`. |
| `mcp_call_input`, `mcp_call_approval` | HTTP 200 with a result that has `resultType` `input_required`. |
| `mcp_refuse` | HTTP 200 with a tool error: `isError` is true and the code is `approval_refused`. |

The form of the request for input follows the draft of the MCP revision 2026-07-28. The MCP binding does not define it. The reference service gives `inputRequests` in the result and reads `inputResponses` in the next call. The service ignores `requestState`.

## Conditions to skip

| Condition | Value for the reference service |
| --- | --- |
| `no_budget_action` | false |
| `no_ceiling_action` | false |
| `no_options_route` | false |
| `no_answer_cache` | true with the default `cache_ttl_seconds` of 0. The service keeps no answer. |
| `no_mcp_endpoint` | false |
| `no_budget_session` | true. The action `mcp.session` lists no budget. |
| `no_input_tool` | false |
| `no_approval_tool` | false |
| `no_multi_action` | false |
| `no_token_cache` | Not for a service. This condition is for an edge. |
| `single_key_set` | false. The configuration trusts two keys. |

## Other requests that the cases write in full

| Request | Answer |
| --- | --- |
| `GET /.well-known/procurauth/resources?type=host&limit=1` | At most one item. |
| `GET /.well-known/procurauth/resources` with no `type` | HTTP 400. |
| Any route with no valid token | HTTP 401 with an empty body, and no question to the PDP. |
| `POST {{mcp_path}}` with a body that is not JSON and no token | HTTP 401 with an empty body. |

The cases that send `tools/list`, `ping` or `server/discover` use the MCP headers of the table above.
