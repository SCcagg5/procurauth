# procurauth-pep

`procurauth-pep` is the reference PEP library of ProcurAuth. A service that follows the protocol is a PEP (policy enforcement point). The library gives the seven steps of paragraph 10.0 as a small API.

The API does not depend on a web framework. The application gives the headers of a request. The library gives back the identity, the ceilings to apply, or the refusal with its HTTP status.

The crate `reference-service` is a small service that uses this library. It is the test subject of the series U of the conformance cases.

## Build and test

Build with Docker only. Do not install Rust on the host.

```text
scripts/cargo.sh build -p procurauth-pep
scripts/cargo.sh test -p procurauth-pep
scripts/cargo.sh test -p procurauth-pep --no-default-features
```

The tests start the test PDP `fake-pdp` in the same process. They use real HTTP on the loopback address only.

## The seven steps

| Step | What the PEP does | Where |
| --- | --- | --- |
| 1 | Check the identity token, and send `sub` as the subject. | `Pep::authenticate` |
| 2 | Refuse a request with no valid token. | `Refusal::to_http` |
| 3 | Give each use one action and one resource with its chain. | `Operation`, `ActionDocumentBuilder` |
| 4 | Ask the PDP. Keep answers for `cache_ttl` at most. | `Pep::decide`, `Pep::check`, `Pep::display` |
| 5 | Send `context.usage` for a use of an action that lists a budget. | `Pep::decide` |
| 6 | Apply each ceiling of `context.limits`. | `Ceilings` |
| 7 | Map each refusal with 10.3. | `Refusal::to_http` |

## Use

An application does these jobs at start. It reads its own configuration. It builds a `PepConfig` and an action document. It gives them to `Pep::new`, with a transport for the link to the PDP.

For each request, the application does these jobs.

1. Call `pep.authenticate(headers)`. A refusal gives HTTP 401.
2. Build the `Operation` from its own data: the action, the node and the chain of the node (4.5).
3. Call `pep.decide(&identity, &operation)`.
4. Send `refusal.to_http()` for a refusal, or apply the ceilings of the `Allowed` value.

```rust
use procurauth_pep::operation::{Operation, node};

let who = pep.authenticate(request_headers)?;
let table = node("datastore", &[("host", "prod"), ("database", "test2"), ("table", "orders")])?;
match pep.decide(&who, &Operation::new("data.read", table)).into_result() {
    Ok(allowed) => {
        // The ceiling lowers the number of rows that the client asked for (7.5).
        let rows = allowed.ceilings().cap("max_rows", requested_rows).value;
    }
    Err(refusal) => { /* send refusal.to_http() */ }
}
```

The type `Refusal` has the status of 10.3. The reason of the PDP stays in the log text of the refusal. The body of the reply never has it.

| Answer of the PDP | `Refusal` | HTTP |
| --- | --- | --- |
| `false`, with no reason or another reason | `Forbidden` | 403 |
| `false` with `budget_exceeded` | `RateLimited` | 429 with `Retry-After` |
| No answer, an HTTP error, or an answer that is not valid | `Unavailable` | 503 |
| `true` with no `context.usage.units` for a use (6.12) | `Forbidden` | 403 |
| `true` with a ceiling that the action does not list (7.5) | `Forbidden` | 403 |
| No valid identity token | `Unauthenticated` | 401 |
| A mistake of the service, for example an action that the document does not declare | `Internal` | 500 |

## The API

| Item | Content |
| --- | --- |
| `PepConfig`, `PdpConfig` | The typed configuration. `check` returns every error. |
| `Pep` | `authenticate`, `decide`, `check`, `display`, `options`, `actions_reply`, `metadata`. |
| `Operation`, `Permission` | One use, the other permissions (5.5a), and several actions for the use (10.1). |
| `Outcome`, `Allowed`, `Granted` | The result of `decide`: the units, and the ceilings of each permission. |
| `Ceilings` | `cap`, `cap_or_ceiling`, `check` and `cap_duration`. |
| `ActionDocumentBuilder`, `load_file`, `ServedDocument` | Build, load and serve the action document (section 5). |
| `OptionsQuery`, `OptionsSource` | The options route (5.6 to 5.8). |
| `PdpTransport`, `HttpTransport` | The link to the PDP. |
| `PdpMetadata` | The endpoints and the four members of this protocol. |
| `mcp` | The helpers of the MCP binding. The feature `mcp` is on by default. |
| `Clock`, `SystemClock`, `ManualClock` | The clock. A test moves a `ManualClock` by hand. |

### Methods of the PEP

- `decide` asks the other permissions first, without `context.usage`. Then it asks the use. For an action that lists a budget, the question of the use has `context.usage`.
- `check` asks without `context.usage` and takes no unit. Use it for a call that asks the client for input or for an approval (binding 3.5, 3.5a).
- `display` asks with `context.match` equal to `subtree` for a list of permissions (4.4). The answers are for the display only. They never let an operation run.
- `options` builds the answer of the options route. It asks one question for each child (5.6).

## Rules that the library follows

| Rule | Paragraph |
| --- | --- |
| The subject has the type `user`. Its id is the `sub` of the token, as opaque text. | 3.3 |
| The question holds no claim other than `sub`. | 9.6 |
| The PEP builds the chain from the data of the service. | 4.5 |
| The PEP reads the token only from the configured header. It never reads `Authorization` or a cookie. | 9.4 |
| The PEP ignores a claim that it does not know. It never uses `owner` in a decision. | 9.4, 9.5 |
| A use of an action that lists a budget sends one question with `context.usage` equal to 1. | 6.4 |
| The PEP never sends the same question without `context.usage` before it. | 10.1 |
| The PEP keeps an answer for `cache_ttl` at most. It never keeps a `true` answer with `units` above 0. | 10.1 |
| The PEP keeps a `budget_exceeded` answer for the lower of `retry_after` and `cache_ttl`. | 10.1 |
| The PEP never sends a question with `context.usage` again after a lost answer. | 10.6 |
| The PEP sends a question again only when the request did not leave the PEP. | 10.6 |
| The PEP waits longer than `procurauth_usage_max_seconds`. | 10.6 |
| The PEP keeps a small fixed number of connections, and it closes an idle one after half of `procurauth_idle_max_seconds`. | 10.7 |
| The PEP splits its questions at the maxima of the PDP. | 10.7a |
| A ceiling that the action does not list makes the answer `false`. | 7.5 |
| The PEP ignores `context.limits` in a `false` answer. | 7.6 |

## Configuration

The application reads the configuration. The library reads no file and no environment variable. `PepConfig::check` follows the rules for the configuration of a program: each error names the key, the expected value and the value found. The check changes no value. Two keys that contradict each other give an error.

| Key | Default |
| --- | --- |
| `pdp.allow_insecure_pdp_link` | `false` |
| `pdp.request_timeout` | 5 seconds |
| `pdp.usage_wait_margin` | 1 second |
| `pdp.idle_close_after` | 5 seconds |
| `pdp.max_connections` | 4 |
| `pdp.evaluations_max_bytes` | 32768 |
| `pdp.evaluations_max_items` | 50 |
| `pdp.max_response_bytes` | 1048576 |
| `pdp.plain_retries` | 1 |
| `pdp.metadata_max_age` | 3600 seconds |
| `cache_ttl` | 0, no kept answer |
| `cache_max_entries` | 10000 |
| `display_max_questions` | 50 |

The credential of the PDP is a `Secret`. Its debug text and its errors never show it.

## The link to the PDP needs TLS

The PEP must secure the link to the PDP (10.0, step 4). The configuration refuses an `http` URL, unless the flag `allow_insecure_pdp_link` is set. Set it only for a test on the loopback address, or for a link that another layer secures.

`HttpTransport` is a synchronous HTTP/1.1 client over `std::net`. It has no TLS. It keeps a small fixed number of connections open. For a deployment, implement the trait `PdpTransport` with a TLS client. The library has no `tls` feature, because a TLS crate adds many dependencies. See `notes/decisions-pep.md`.

The trait tells the PEP how an exchange failed. A request that did not leave the PEP (`NotSent`) is the one case where the PEP can send a question with `context.usage` again (10.6).

## The MCP helpers

The module `mcp` follows the MCP binding. It is a thin layer over `Pep`.

- `ToolMap` holds the tools and their actions (3.2).
- `McpGate::list_tools` asks one display question for each action of the tools (4.1).
- `McpGate::session` asks the action `mcp.session` for a method that has no tool (3.6a).
- `McpGate::call` asks for one call, at the stage `Ask` or `Run` (3.4, 3.5, 3.5a, 3.7).
- `refusal_reply` maps a refusal to the HTTP status and the JSON-RPC error of section 5. It never copies a value of the request.

## Not in the library

- A TLS client for the PDP.
- A server. The application owns its transport and its routes.
- The kept result of a token check (9.7). The PEP checks each token again.
- The Search API of AuthZEN.
