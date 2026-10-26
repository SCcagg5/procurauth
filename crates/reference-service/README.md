# reference-service

`reference-service` is a small service that uses the library `procurauth-pep`. It is the test subject of the series U of the conformance cases. It is the `datastore` example of protocol section 13.

The service has routes for hosts, databases and tables. It has an action document, an options route and an MCP endpoint. The program reads its configuration from one JSON file. It needs a PDP, for example `fake-pdp`.

The routes and the mapping of the conformance operations are in `PROFILE.md`.

## Build and run

Build with Docker only. Do not install Rust on the host.

```text
scripts/cargo.sh build --release -p reference-service
```

Start the test PDP and the service. The data of the PDP has the action document of the service.

```text
$ fake-pdp --credential-file crates/fake-pdp/examples/pep-credential.txt \
    crates/reference-service/examples/pdp-data.json
$ reference-service crates/reference-service/examples/config.json
reference-service 1.0.0 on http://127.0.0.1:8080
```

The service writes one line to the standard error for each request. The line has the method, the path and the status. It never has a header, a query or a body. A refusal also shows its cause in the line. The client never gets the cause.

## Usage

```text
reference-service [--print-config] <config-file>
```

- `--help` shows the usage and exits with 0.
- `--version` shows the version and exits with 0.
- `--print-config` checks the file, prints the value of each key with its source, and exits with 0. The port stays closed.

| Exit code | Meaning |
| --- | --- |
| 0 | The program stopped on request, or `--print-config` finished. |
| 1 | The program could not open the port. |
| 2 | The command line or the configuration is not valid. |

The signals SIGINT and SIGTERM stop the program with the exit code 0.

## Configuration

The configuration file is the only source of the values. The program reads an environment variable only when the file names it with a key that ends in `_env`. It reads the content of a file only when the file names its path with a key that ends in `_file`.

The schema is closed. An unknown member, an unknown form of a key and a duplicate member stop the program at start. Each error names the key, the expected type or range, and the value found. The program never changes a value to make it fit.

A key that accepts indirection takes exactly one of three forms. The form `<name>` gives the value in the file. The form `<name>_env` gives the name of an environment variable. The form `<name>_file` gives the path of a file. The program removes one line end at the end of the content of a file.

A secret takes only `_env` and `_file`. A secret in clear text in the file stops the program. The effective configuration hides each secret, and it shows the source: `file`, `default`, `env:VAR` or `file:/path`.

A variable that does not exist, an empty value, and a file that the program cannot read stop the program. Two keys that contradict each other also stop it. Examples are an `http` URL without `pdp.allow_insecure_pdp_link`, and a `cache_ttl_seconds` above 0 with `cache_max_entries` equal to 0.

The section `pdp` is an object. Its keys have the prefix `pdp.` in the table.

### Table of keys

| Key | Value | Default | Indirection | Meaning |
| --- | --- | --- | --- | --- |
| `listen` | ADDRESS:PORT with an IP address | 127.0.0.1:8080 | `_env` and `_file` | The address of the listener. Port 0 chooses a free port. |
| `workers` | whole number from 1 to 256 | 8 | none | The number of worker threads. One open connection uses one thread. |
| `max_body_bytes` | whole number from 1 to 67108864 | 1048576 | none | The largest body of a request. A larger body gets HTTP 413. |
| `read_timeout_seconds` | whole number from 1 to 3600 | 10 | none | The time to read a whole request after its first byte. |
| `idle_timeout_seconds` | whole number from 1 to 3600 | 30 | none | The time that an idle connection of a client stays open. |
| `service_id` | id of 1 to 256 bytes (4.1) | datastore | none | The id of the service: the `aud` of the tokens and the `server` of the action document. |
| `token_header` | HTTP header name | X-Identity-Token | none | The header with the identity token (9.4). It is never `Authorization`, `Proxy-Authorization` or `Cookie`. |
| `issuer` | text that is not empty | none, mandatory | `_env` and `_file` | The value of the claim `iss` (9.4). |
| `max_token_age_seconds` | whole number from 1 to 86400 | 300 | none | The longest life of a token, `exp` minus `iat` (9.4). |
| `clock_skew_seconds` | whole number from 0 to 3600 | 30 | none | The clock skew for `iat` and `exp` (9.4). |
| `jwks` | JWK Set (RFC 7517) with public keys; the forms `_env` and `_file` give its JSON text | none, mandatory | `_env` and `_file` | The public keys of the edge (9.4). A set with more than one key needs a `kid` in each token. |
| `cache_ttl_seconds` | whole number from 0 to 3600 | 0 | none | The longest life of a kept answer (10.1). 0 keeps no answer. |
| `cache_max_entries` | whole number from 0 to 10000000 | 10000 | none | The most kept answers (10.1b). The value 0 contradicts a `cache_ttl_seconds` above 0. |
| `display_max_questions` | whole number from 1 to 1000 | 50 | none | The most questions that one request to the options route asks (5.6). |
| `mcp_path` | path that starts with a slash | none | none | The path of the MCP endpoint. Without it, the service has no MCP endpoint. |
| `mcp_session_budget` | boolean | false | none | List the budget `requests` on the action `mcp.session`, so that a method with no tool is one use (binding 3.6a). It needs `mcp_path`. |
| `pdp.url` | URL with the scheme `http` (this program has no TLS client) | none, mandatory | `_env` and `_file` | The URL of the PDP. |
| `pdp.credential` | text that is not empty, with visible ASCII characters | none, mandatory | `_env` and `_file` only | The credential of the service for the PDP. The service sends it in `Authorization: Bearer` (10.0). |
| `pdp.allow_insecure_pdp_link` | boolean | false | none | Accept an `http` URL. Set it for a test on the loopback address. Without it, an `http` URL stops the program. |
| `pdp.request_timeout_ms` | whole number from 1 to 600000 | 5000 | none | The longest wait for an answer to a question without `context.usage`. |
| `pdp.usage_wait_margin_ms` | whole number from 1 to 600000 | 1000 | none | The time that the service adds to the time that the PDP publishes for a question with `context.usage` (10.6). |
| `pdp.idle_close_after_ms` | whole number from 1 to 600000 | 5000 | none | The longest idle time of a connection to the PDP. The service also closes it after half of the time that the PDP publishes (10.7). |
| `pdp.max_connections` | whole number from 1 to 256 | 4 | none | The most connections to the PDP at one time (10.7). |
| `pdp.plain_retries` | whole number from 0 to 5 | 1 | none | How many times the service asks again a question without `context.usage` after a lost connection (10.6). |

A test checks that this table is the table of the code. The function `reference_service::config::reference_table()` makes it.

The key `pdp.url` takes only an `http` URL, because this program has no TLS client. The link to the PDP must be secured (10.0, step 4). A deployment builds its own service with the library, and it gives the library a transport with TLS. See the README of `procurauth-pep`.

The key `cache_ttl_seconds` has the default 0. A kept answer can show an old right for `cache_ttl_seconds` at most (3.5). The conformance cases also expect that each request reaches the PDP.

### Examples

- `examples/config.json` runs the service with `fake-pdp` on the loopback address.
- `examples/conformance.json` is the configuration for the runner of the conformance cases. It trusts the two test keys of the edge. It reads the credential from the variable `PROCURAUTH_PDP_CREDENTIAL`. It uses a short timeout, so that a case with a PDP that does not answer ends quickly.
- `examples/conformance-session-budget.json` is the same file with `mcp_session_budget` set to true. The case U95 then runs.
- `examples/conformance-profile.json` and `examples/conformance-profile-session-budget.json` are the profiles of the runner. `scripts/conformance.sh pep` uses them.
- `examples/pdp-data.json` is the data file of `fake-pdp` for this service. It has the action document of the service, Alice, her key, Bob, his key and Carol.

## The data

The service holds a small tree in memory. A write changes it for the life of the process.

| Host | Database | Tables |
| --- | --- | --- |
| `prod` | `test1` | `orders` (30 rows), `customers` (10 rows) |
| `prod` | `test2` | `orders` (2000 rows), `customers` (50 rows) |
| `prod` | `a/b` | `t` (3 rows) |
| `staging` | `test1` | `orders` (5 rows) |

## The actions and the limits

| Action | Types | Limits |
| --- | --- | --- |
| `data.read` | service, host, database, table | `requests`, `max_rows`, `max_duration` |
| `data.write` | service, host, database, table | `requests`, `max_duration` |
| `data.inspect` | service, host, database, table | none |
| `mcp.session` | service | none |

The budget `requests` counts the uses. The ceiling `max_rows` is the most rows of one read. A read without `limit` gives 100 rows at most. The ceiling `max_duration` is the longest run of one use, in seconds.

A read lowers the value of `timeout_seconds` to the ceiling. A write refuses a `timeout_seconds` above the ceiling with HTTP 422. These two routes show the two ways to apply a ceiling.

## How the service follows the protocol

- The route of the action document needs no token and asks no question (5.1).
- Each other route checks the identity token first. A request with no valid token gets HTTP 401 with an empty body, and the service sends no question (9.4, 10.0 step 2).
- The service reads the token only from the header of the configuration. It never reads `Authorization` or a cookie.
- The service builds the chain of the node from its own data (4.5).
- A `false` answer gives HTTP 403. A spent budget gives HTTP 429 with `Retry-After`. No valid answer gives HTTP 503. The body never shows the reason (10.3).
- The service asks the PDP before it looks for the node. A client that has no right learns nothing about the existence of a node.
- The service never sends a question with `context.usage` again after a lost answer (10.6).
- The service keeps its connections to the PDP open, and it splits its questions at the maxima of the PDP (10.7, 10.7a).
