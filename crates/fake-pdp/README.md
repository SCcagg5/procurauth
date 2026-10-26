# fake-pdp

`fake-pdp` is a test decision point (PDP) for ProcurAuth. It answers like a real PDP, from fixed data. A service (a PEP) and the conformance suite can then run without the real backend.

The program serves the AuthZEN 1.0 endpoints and the metadata on one address. It keeps its counters in memory. It reads no environment variable.

The crate is also a library. Other tools start the server in the same process. See the section "Library".

## Build and run

Build with Docker only. Do not install Rust on the host.

```text
scripts/cargo.sh build --release -p fake-pdp
```

Start the server with the example data of protocol section 13.

```text
$ fake-pdp --listen 127.0.0.1:8181 crates/fake-pdp/examples/datastore.json
fake-pdp 0.1.0 on http://127.0.0.1:8181
metadata /.well-known/authzen-configuration
```

The program writes one block to the standard output for each question. It writes the diagnostics and its configuration to the standard error. It stops on SIGINT or SIGTERM and exits with 0.

## Usage

```text
fake-pdp [--listen ADDRESS:PORT] [--clock-start UNIX_SECONDS] [--admin]
         [--credential-file FILE] [--failures FILE] [--workers N]
         [--print-config] <data-file>
```

- `--help` shows the usage and exits with 0.
- `--version` shows the version and the licence line `Apache-2.0`, and exits with 0.
- The program has no colour and no `--format` option.

| Exit code | Meaning |
| --- | --- |
| 0 | The program stopped on request, or `--print-config` or `--help` finished. |
| 1 | The program could not open the port. |
| 2 | The command line is not valid, or a file is bad. |

## Configuration

The data file and the command line are the only sources. The schema is closed. An unknown member, an unknown flag or a duplicate member stops the program at start. Each error message names the key, the expected type or range, and the value.

The program never changes a value to make it fit. It checks all the files before it opens the port. It prints every finding of the data file with its JSON path.

Two keys that contradict each other stop the program. The flag `--clock-start` and the member `clock.now` are such a pair.

The command `--print-config` checks all the files, prints each key with its value and its source, and exits. The program also writes these values to the standard error at start. A secret never shows. The credential shows as its file name only.

### Table of keys

| Key | Source | Value | Default | Meaning |
| --- | --- | --- | --- | --- |
| `data-file` | argument | path | none, mandatory | The data file. |
| `--listen` | flag | ADDRESS:PORT | 127.0.0.1:8181 | The address of the listener. Port 0 chooses a free port. |
| `--clock-start` | flag | whole seconds since the Unix epoch | none, the system clock | A fixed clock. It stops at this time. Do not give it with `clock.now`. |
| `--admin` | flag | no value | off | Enable the admin endpoints under `/__fake/`. |
| `--credential-file` | flag | path | none, no credential | The file with the credential of the PEP. The PDP then requires `Authorization: Bearer`. |
| `--failures` | flag | path | none | A file with more failures. It can use the kinds `close`, `invalid_json` and `no_units`. |
| `--workers` | flag | whole number from 1 to 256 | 8 | The number of worker threads. One open connection uses one thread. |
| `--print-config` | flag | no value | off | Check everything, print the values that apply, and exit with 0. The port stays closed. |
| `clock.now` | data file | whole seconds since the Unix epoch | none, the system clock | A fixed clock. Do not give it with `--clock-start`. |
| `metadata.usage_max_seconds` | data file | whole number from 1 | 5 | The member `procurauth_usage_max_seconds` of the metadata (6.9). |
| `metadata.idle_max_seconds` | data file | whole number from 1 | 30 | The member `procurauth_idle_max_seconds`. The PDP closes an idle connection after this time (10.7). |
| `metadata.evaluations_max_bytes` | data file | whole number from 1 | 1048576 | The member `procurauth_evaluations_max_bytes`. A larger body gets HTTP 413 (10.7a). |
| `metadata.evaluations_max_items` | data file | whole number from 1 | 100 | The member `procurauth_evaluations_max_items`. More items get HTTP 400 (10.7a). |
| `counters, failures, services, subjects` | data file | see the schema `fake-pdp-data` | none | The directory, the first counter values and the failures. |

A test checks that this table is the table of the code. The function `fake_pdp::config::reference_table()` makes it.

## The data file

The data file is a JSON object. The schema is `schemas/fake-pdp-data.schema.json`. The members are:

- `services`: each service has an `id` and its action document. It can have `credential_sha256`.
- `subjects`: the persons and the keys. Each has grants. A key has an `owner` and can have a `state`.
- `counters`: the first values of the counters. They apply to the window of the clock at start.
- `failures`: the failures to make. The kinds are `error_503`, `delay` and `no_answer`.
- `clock` and `metadata`: see the table of keys.

The example `examples/datastore.json` is the data of protocol section 13. It has Alice, her key, Bob and his key. The example `examples/datastore-with-counters.json` also has first counter values, metadata and a failure.

The failure file of the flag `--failures` has the member `failures` only. It uses the same format, and it adds the kinds `close`, `invalid_json` and `no_units`. See `examples/failures.json`.

## Endpoints

| Request | Answer |
| --- | --- |
| `POST /access/v1/evaluation` | One decision. |
| `POST /access/v1/evaluations` | A list of decisions in the member `evaluations`. A request without items gets one decision. |
| `GET /.well-known/authzen-configuration` | The metadata. |

The metadata has `policy_decision_point`, `access_evaluation_endpoint` and `access_evaluations_endpoint`. It also has the four members `procurauth_usage_max_seconds`, `procurauth_idle_max_seconds`, `procurauth_evaluations_max_bytes` and `procurauth_evaluations_max_items`. The program always publishes all four, with the defaults of the table.

The server keeps connections open. It sends `Content-Type: application/json` and a `Content-Length`. It copies the request header `X-Request-ID` to the response. The header `Keep-Alive` gives the idle time of the metadata.

| Status | Cause |
| --- | --- |
| 400 | The request is not valid. The body is `{"error":"Bad Request"}` and gives no detail. |
| 401 | The credential is absent or wrong. The header `WWW-Authenticate: Bearer` is set. |
| 404, 405 | The path is unknown, or the method is wrong. |
| 408 | The client did not send a whole request in 5 seconds. |
| 413 | The body is larger than `procurauth_evaluations_max_bytes`. The server closes the connection. |
| 415 | The `Content-Type` is not `application/json`. |
| 431, 501, 505 | The head is too large, the body is chunked, or the HTTP version is not 1.x. |
| 503 | A failure that the data asks for. |

A bad request gets HTTP 400. A member that AuthZEN requires can be absent. The JSON can be not valid, or it can have a duplicate member. A member of the protocol can be bad (6.4, 4.4, 4.1, 11.1).

These members of the protocol are bad. The value of `context.match` is not `node` or `subtree`. The value of `context.usage` is not `{"units": 1}`. The chain is not an array of objects. In an Access Evaluations request with items, a bad member of an item gives a `false` answer with the reason `invalid_request`.

A request with more items than `procurauth_evaluations_max_items` gets HTTP 400. A body above `procurauth_evaluations_max_bytes` gets HTTP 413. This limit applies to the body of each POST request.

The options `evaluations_semantic` of AuthZEN are supported: `execute_all`, `deny_on_first_deny` and `permit_on_first_permit`.

## Decisions

The PDP decides as the protocol says. The rules in short:

- The PDP checks the subject first (3.3, 3.7, 11.1). These subjects get `unknown_subject`: a type other than `user`, a bad id, and a key that is deleted, revoked or expired. A key without owner gets it too.
- The chain in `resource.properties.ancestors` and the types follow the action document of the service. A bad chain gives `invalid_resource` (4.1, 11.1).
- A grant covers its node and each node below it. A grant on a database does not cover its host (4.3).
- A key gets `true` only when a grant of the key and a grant of its owner both cover the node (3.5). For `subtree`, one node must exist that both sides cover (4.4).
- `context.limits` has the lowest value among the grants of the asked action. A key never goes above its owner (7.3, 8.1, 8.4).
- A `false` answer has a reason only for the four reasons of 11.1. HTTP 200 stays the status.
- A service without a good action document answers `false` with no reason, except for `access` on the service (11.1).

When a credential belongs to one service, the PDP answers `invalid_resource` for a question about another service (12).

## Budgets and the clock

The budgets are on the grant of the action `access` on the service (8.3). The server has one counter for each subject, budget and window. The windows are `second`, `minute`, `hour` and `day`. A window starts at a multiple of its length since the Unix epoch (6.3).

A question with `context.usage` takes one unit from each counter of the use in one atomic step, or from none (6.5). A key uses its own counters and the counters of its owner (6.7). A question without `context.usage` counts nothing (6.6).

A `true` answer to a counted question has `context.usage.units`. The value is 1, or 0 when no budget applies (6.12). A spent counter gives `false` with `budget_exceeded` and `retry_after`. The value of `retry_after` is the number of seconds to the end of the latest window that refuses, rounded up (11.1).

The request with items cannot carry `context.usage`. It gets HTTP 400, and the PDP counts nothing (6.11).

The clock is the system clock, or a fixed clock. The flag `--clock-start` and the member `clock.now` fix the clock at a time. A fixed clock moves only through the admin endpoint or the library. A counter of an older window counts as zero.

## Failures

The data file can make the PDP fail, so that a PEP can be tested against 6.9, 6.12, 10.3 and 10.6. A rule has a `kind`, an optional `when` and an optional `times`. The first rule that matches a question applies.

| Kind | Effect |
| --- | --- |
| `error_503` | HTTP 503 with no decision. The PDP counts nothing (6.9). |
| `delay` | Wait `delay_ms`, then answer as usual. |
| `no_answer` | Decide and count, then never answer (10.6). |
| `close` | Decide and count, then close the connection with no byte (10.6). |
| `invalid_json` | Decide and count, then answer HTTP 200 with a body that is not valid JSON (10.3). |
| `no_units` | Answer as usual, but remove `context.usage.units` from a `true` answer (6.12). |

The members of `when` are `subject`, `action`, `resource`, `usage` and `endpoint`. A rule matches when each member that it has is equal to the question. For a request with items, a rule matches when one item matches.

## Credential of the PEP

The flag `--credential-file` names a file. The program reads the value without the last line end. The PDP then requires `Authorization: Bearer <value>` on each request, except for the metadata. An absent or wrong value gets HTTP 401.

A service of the data file can have `credential_sha256`. The Bearer value of that service must then have this SHA-256 digest. The PDP answers that PEP for its own service only (12).

The program keeps only the SHA-256 digest of the value. It never writes the value to a log. It never takes the value from an argument.

## Log

The program writes one block for each question to the standard output.

```text
q1  key:9b1c…  data.read  host:prod/database:test2
    true  limits {"max_duration":30,"max_rows":5000}  units 1
    counters  key/minute 99  alice/second 9
              alice/minute 299
```

- The first line has the number of the question, the subject, the action and the node below the service. A key id shows four characters of its local part.
- The second line has the decision and the answer. It also shows a failure that the server made.
- The counters show the units spent after the question. `key` is the key of the question.
- The list of counters has the key first, then its owner.

The log also keeps the last 10,000 questions in memory with full values. The admin endpoint `GET /__fake/log` gives them. A rejected request goes to the standard error, with its status, its path and the JSON paths of the findings. It never shows a value.

## Admin endpoints

The flag `--admin` enables the admin endpoints. They share the listener of the PDP. Each path starts with `/__fake/`. Without the flag, each such path gets HTTP 404. Enable the admin endpoints on a trusted network only.

| Request | Effect |
| --- | --- |
| `GET /__fake/clock` | `{"now": T, "now_millis": M, "fixed": true}`. |
| `POST /__fake/clock` | Body `{"advance": N}` or `{"set": T}`, in whole seconds. |
| `PUT /__fake/load` | Body: a data file. Replace the directory, the counters, the failures and the credentials of the services. |
| `POST /__fake/reset` | Put the counters back to the first values of the data file. |
| `GET /__fake/counters` | The counters of the current windows. |
| `GET /__fake/log` | The last questions, with the answers and the counters. |
| `DELETE /__fake/log` | Remove the entries of the log. |
| `GET /__fake/failures` | The failure rules, with the uses that each one has left. |
| `POST /__fake/failures` | Body `{"failures": [...]}`. It replaces all the rules. |

The admin endpoints need the same credential as the PDP endpoints, when the server has one. A system clock becomes a fixed clock when a request moves it. A bad body gets HTTP 400 with the JSON path of each finding.

```text
$ curl -s -X POST -d '{"advance": 60}' http://127.0.0.1:8181/__fake/clock
{"fixed":true,"now":1792569708,"now_millis":1792569708000}
```

## Examples

A question for Alice, with one unit of the budget:

```text
$ curl -s -H 'Content-Type: application/json' http://127.0.0.1:8181/access/v1/evaluation -d '{
    "subject":  {"type": "user", "id": "alice"},
    "action":   {"name": "data.read"},
    "resource": {"type": "table", "id": "orders", "properties": {"ancestors": [
        {"type": "service", "id": "datastore"}, {"type": "host", "id": "prod"},
        {"type": "database", "id": "test2"}]}},
    "context":  {"usage": {"units": 1}}}'
{"context":{"limits":{"max_duration":30,"max_rows":100},"usage":{"units":1}},"decision":true}
```

The same question, when the budget is spent:

```text
{"context":{"reason":"budget_exceeded","retry_after":12},"decision":false}
```

## Library

The library name is `fake_pdp`. A test builds a server from a data file value, binds a port, and gets the address.

```rust
use fake_pdp::{Options, Server};

let data: serde_json::Value = serde_json::from_str(&text)?;
let server = Server::from_value(&data, Options::default())?;
let running = server.start("127.0.0.1:0")?;   // port 0: a free port
let url = running.url();                      // http://127.0.0.1:PORT
running.clock().advance(60)?;                 // the controllable clock
let counters = running.counters();            // the counters in memory
let log = running.log();                      // the last questions
running.shutdown();                           // graceful stop
```

- `Server::from_text` reads a data file text, and it rejects a duplicate member. `Server::from_value` takes a JSON value.
- Both functions return every finding of the data when it is bad.
- `Options` has the admin switch, the clock start, the credential and more failures. It also has the number of workers, the read timeout, and two writers for the log and the diagnostics.
- `RunningServer` has `local_addr`, `url`, `clock`, `settings`, `counters`, `reset_counters`, `log`, `set_faults` and `shutdown`. It stops the server when it is dropped.
- The module `pdp` has the decision logic with no network code. The module `counters` and the module `clock` are separate.

## Tests

```text
scripts/cargo.sh test -p fake-pdp
```

The unit tests check the decisions and the counters. The integration tests start the server on port 0 and send real HTTP requests. A test also runs the cases of the series D of `conformance/D/` against the server. The names of the tests follow the paragraphs of the protocol, for example `p_6_7_...`.

## Differences from the published page

The file `notes/site-differences-fake-pdp.md` lists the differences between this tool and `docs/tools.html`.
