# reference-edge

`reference-edge` is a small reference edge for ProcurAuth. It is an HTTP reverse proxy. It is the edge of protocol sections 8.3 and 9 and of section 6 of the MCP binding. It is the test subject of the series E of the conformance cases.

The edge sits in front of one service. It reads the text of a key from `Authorization: Bearer`. It asks the PDP for the action `access` on the service. It makes an identity token and sends the request to the service. The program reads its configuration from one JSON file. It needs a PDP, for example `fake-pdp`.

## Build and run

Build with Docker only. Do not install Rust on the host.

```text
scripts/cargo.sh build --release -p reference-edge
```

Start the test PDP, the service and the edge from the root of the repository. The data of the PDP has the grants of `access`.

```text
$ fake-pdp --credential-file crates/access-conformance/examples/pdp-credential.txt \
    conformance/directories/access.json
$ reference-service crates/reference-service/examples/conformance.json
$ PROCURAUTH_PDP_CREDENTIAL=example-credential-of-the-service \
    reference-edge crates/reference-edge/examples/config.json
reference-edge 0.1.0 on http://127.0.0.1:8090
```

The service and the edge need the same issuer and the public key of the edge. The example `examples/config.json` signs with the test key of `access-token`. The `jwks` of `crates/reference-service/examples/conformance.json` holds this public key.

The edge writes one line to the standard error for each request. The line has the method, the path and the status. A refusal also shows its cause. The line never has a header, a query, a body, the text of a key or a token. The client never gets the cause.

## Usage

```text
reference-edge [--print-config] <config-file>
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

## What the edge does

For each request the edge does these jobs, in this order. It decides on the head of the request. It reads the body only for a request that it accepts.

1. It reads the text of the key from the header `Authorization` with the scheme `Bearer` (1.4).
2. It checks the form of the text with the key format (3.8). It finds the key by the SHA-256 digest of the text in the keys file.
3. It asks the PDP for the action `access` on the service, for the subject of the key (8.3). The question has no `context.usage`.
4. It makes an identity token for the subject, or it gives a kept token (9.9). The token has the claims `iss`, `sub`, `aud`, `iat` and `exp`. A token for a key also has `owner`. It never has the text of the key.
5. It removes the header `Authorization` and each copy of the token header that the client sent. It sets its own token header (9.1). It sends the request to the service.
6. It sends the answer of the service to the client with the same body form. A stream of events goes through chunk by chunk.

The edge uses the library `procurauth-pep` for the question (`AccessGate`), and the library of `access-token` to sign the token. It signs with `Ed25519` or `ES256`, as the signing key says. It uses its signing key for the identity token only (9.2).

### The refusals

| Case | Answer |
| --- | --- |
| The request has no header `Authorization`, or the scheme is not `Bearer`, or the text is empty. | HTTP 401, `WWW-Authenticate: Bearer`, empty body. |
| The text has a bad form, or the edge does not know it, or its subject has no `access`. | HTTP 401, `WWW-Authenticate: Bearer error="invalid_token"`, empty body. |
| The request has more than one header `Authorization`. | The same as the line above. |
| The PDP gives no valid answer. | HTTP 503, empty body. The edge cannot decide. |
| The service gives no answer. | HTTP 502 or HTTP 504, empty body. |
| The request is not valid HTTP. | HTTP 400, 414, 431, 501 or 505, empty body. |
| The body is larger than `max_body_bytes`, and the key is good. | HTTP 413, empty body. |

Each answer of the first three lines is the same for a text that the edge refuses for any cause. Thus a client learns nothing about the keys. The challenge never has `resource_metadata` (MCP 6.3). The edge never redirects.

The edge does not read the body of a refused request (9.8). It sends the answer, closes its write side, and drops the rest of the request for 2 seconds at most. The connection then closes. A client that sends a large body still reads the answer.

The edge never answers 404 or 405 by itself. It sends each method and each path to the service when the key is good. A status of the service goes to the client as it is (MCP 6.2). The edge answers 400 only for a request that is not valid HTTP. Such a request has no readable key.

## Configuration

The configuration file is the only source of the values. The program reads an environment variable only when the file names it with a key that ends in `_env`. It reads the content of a file only when the file names its path with a key that ends in `_file`.

The schema is closed. An unknown member, an unknown form of a key and a duplicate member stop the program at start. Each error names the key, the expected type or range, and the value found. The program never changes a value to make it fit.

A key that accepts indirection takes exactly one of three forms. The form `<name>` gives the value in the file. The form `<name>_env` gives the name of an environment variable. The form `<name>_file` gives the path of a file. The program removes one line end at the end of the content of a file.

A secret takes only `_env` and `_file`. A secret in clear text in the file stops the program. The effective configuration hides each secret, and it shows the source: `file`, `default`, `env:VAR` or `file:/path`. The edge never writes a secret to a log or to an error.

A variable that does not exist, an empty value, and a file that the program cannot read stop the program. Two keys that contradict each other also stop it. Examples are a `token_life_seconds` above `max_token_age_seconds`, an `upstream.url` equal to `listen`, and an `http` URL for the PDP without `pdp.allow_insecure_pdp_link`.

The sections `upstream`, `signing` and `pdp` are objects. Their keys have the prefix of the section in the table.

### Table of keys

| Key | Value | Default | Indirection | Meaning |
| --- | --- | --- | --- | --- |
| `listen` | ADDRESS:PORT with an IP address | 127.0.0.1:8090 | `_env` and `_file` | The address of the listener. Port 0 chooses a free port. |
| `workers` | whole number from 1 to 256 | 16 | none | The number of worker threads. One open connection uses one thread. |
| `max_body_bytes` | whole number from 1 to 67108864 | 1048576 | none | The largest body of a request that the edge accepts. A larger body gets HTTP 413, after the key is good. |
| `read_timeout_seconds` | whole number from 1 to 3600 | 10 | none | The time to read a whole request after its first byte. |
| `idle_timeout_seconds` | whole number from 1 to 3600 | 30 | none | The time that an idle connection of a client stays open. |
| `service_id` | id of 1 to 256 bytes (4.1) | none, mandatory | none | The id of the service behind the edge: the `aud` of the tokens and the resource of the question for `access`. |
| `token_header` | HTTP header name | X-Identity-Token | none | The header with the identity token (9.4). It is never `Authorization`, `Proxy-Authorization` or `Cookie`. |
| `issuer` | text that is not empty | none, mandatory | `_env` and `_file` | The value of the claim `iss` (9.4). The service must have the same value. |
| `token_life_seconds` | whole number from 1 to 86400 | 60 | none | The life of a token, `exp` minus `iat` (9.2). The value must not be above `max_token_age_seconds`. |
| `max_token_age_seconds` | whole number from 1 to 86400 | 300 | none | The longest life that the service accepts for a token (9.2). A `token_life_seconds` above it stops the program. |
| `token_cache_max_entries` | whole number from 0 to 10000000 | 0 | none | The most tokens that the edge keeps (9.9). 0 keeps no token. When the table is full, the edge signs a new token. |
| `key_format` | key format document (`schemas/key-format.schema.json`); the forms `_env` and `_file` give its JSON text | none, mandatory | `_env` and `_file` | The format of the text of a key (3.8). A text that does not follow it is refused with no look at the keys file. |
| `keys` | keys file document (see the section The keys file); the forms `_env` and `_file` give its JSON text | none, mandatory | `_env` and `_file` | The keys that the edge knows, each with the SHA-256 digest of its text, its subject id and its owner. |
| `upstream.url` | URL with the scheme `http`, a host and no path (this program has no TLS client) | none, mandatory | `_env` and `_file` | The service behind the edge. The edge sends each accepted request there. |
| `upstream.connect_timeout_ms` | whole number from 1 to 600000 | 2000 | none | The longest time to open a connection to the service. A longer time gives HTTP 504. |
| `upstream.response_timeout_seconds` | whole number from 1 to 3600 | 30 | none | The longest wait for a byte of the answer of the service. Before the head, a longer wait gives HTTP 504. |
| `signing.key` | private key of Ed25519 or P-256 in PKCS#8 PEM form | none, mandatory | `_env` and `_file` only | The signing key of the edge. The edge uses it for the identity token only (9.2). Its algorithm is `Ed25519` or `ES256`. |
| `signing.kid` | text of 1 to 128 visible ASCII characters | none | none | The `kid` in the header of each token (9.4). Set it when the service trusts more than one key. |
| `pdp.url` | URL with the scheme `http` (this program has no TLS client) | none, mandatory | `_env` and `_file` | The URL of the PDP. |
| `pdp.credential` | text that is not empty, with visible ASCII characters | none, mandatory | `_env` and `_file` only | The credential of the edge for the PDP. The edge sends it in `Authorization: Bearer` (10.0). |
| `pdp.allow_insecure_pdp_link` | boolean | false | none | Accept an `http` URL. Set it for a test on the loopback address. Without it, an `http` URL stops the program. |
| `pdp.request_timeout_ms` | whole number from 1 to 600000 | 5000 | none | The longest wait for an answer to the question for `access`. A longer wait gives HTTP 503. |
| `pdp.idle_close_after_ms` | whole number from 1 to 600000 | 5000 | none | The longest idle time of a connection to the PDP. The edge also closes it after half of the time that the PDP publishes (10.7). |
| `pdp.max_connections` | whole number from 1 to 256 | 4 | none | The most connections to the PDP at one time (10.7). |
| `pdp.plain_retries` | whole number from 0 to 5 | 1 | none | How many times the edge asks again after a lost connection. The question for `access` has no `context.usage` (10.6). |
| `pdp.metadata_max_age_seconds` | whole number from 1 to 86400 | 3600 | none | The longest age of the metadata of the PDP. After this age the edge reads it again. |
| `pdp.max_response_bytes` | whole number from 1 to 67108864 | 1048576 | none | The largest answer of the PDP that the edge reads. |

A test checks that this table is the table of the code. The function `reference_edge::config::reference_table()` makes it.

The keys `upstream.url` and `pdp.url` take only an `http` URL, because this program has no TLS client. The link to the PDP must be secured (10.0, step 4). Use a proxy that ends TLS, or build an edge with the library and give it a transport with TLS.

The paths in the examples start at the root of the repository. Run the program from there.

### The key format

The key `key_format` is a document of `schemas/key-format.schema.json`. It gives the prefix, the length, the alphabet and the checksum of the text of a key. The edge refuses a text of another form with no look at the keys file. The tool `keycheck` reads the same document.

### The keys file

The key `keys` is the keys file. It has one member, `keys`, with a list. Each entry has these members.

| Member | Meaning |
| --- | --- |
| `sha256` | The SHA-256 digest of the text of the key, with 64 lower-case hexadecimal digits. |
| `subject` | The subject id. A key has `key:<local>` (3.2). A person has an id with no colon (3.1). |
| `owner` | The id of the owner of a key, a person (3.1). A key needs it. A person has none. |

The schema is closed, and a duplicate digest is an error. The edge never keeps the text of a key. The file `examples/keys.test-only.json` holds the digests of the test keys of the conformance runner. These keys are public and for tests only. Never use them in a deployment.

A person is an entry with no `key:` prefix and no owner. The edge gives the token of a person the same checks as the token of a key. The token has no `owner`. This version has no other way to authenticate a person.

### The kept tokens

The key `token_cache_max_entries` sets the size of the table of kept tokens (9.9). With 0, the edge keeps no token. The edge keeps a token for one pair of a subject and a service.

The edge gives a kept token again only after the PDP gave `true` for `access` to this request. It gives it only until a quarter of its life remains. When the table is full, the edge removes the tokens that ended. If the table is still full, the edge signs a new token and keeps nothing.

## The profile of the conformance runner

The runner `access-conformance` tests this edge with the series E. The files are in `examples/`.

| File | Content |
| --- | --- |
| `conformance.json` | The configuration of the edge for the runner. It keeps tokens. |
| `conformance-profile.json` | The profile of the runner. It has `token_cache` true and `mcp_path` equal to `/mcp`. |
| `keys.test-only.json` | The digests of the test keys. |
| `key-format.test-only.json` | The format of the text of the test keys. |

The script `scripts/conformance.sh edge` builds the programs and starts the edge. It runs the runner in one container on the loopback address. The runner starts `fake-pdp` on `127.0.0.1:8181` and the service behind the edge on `127.0.0.1:9000`. The edge listens on `127.0.0.1:8090`.

The edge answers each case of the series E. It keeps tokens, so the cases E15 and E16 run. The key set of the profile has two keys and the edge sets `kid`, so the case E13 runs. The edge has no MCP method of its own, and it forwards `/mcp` like each other path.

## Limits

- The edge has no TLS code. It speaks plain HTTP to the client, the service and the PDP. Put a proxy that ends TLS in front of it.
- The edge opens a new connection to the service for each request. It does not pool connections.
- One open connection of a client uses one thread. A slow client can hold a thread for the time of the timeouts.
- The edge has no rate limit. A client can try many key texts. The format check and the digest lookup make each try cheap.
- The edge never changes the keys file while it runs. Restart it to load a new file.
- The edge sends the whole request body to the service as one block. It reads at most `max_body_bytes`.
- The edge does not support the header `Upgrade`. It removes it.

## Tests

```text
scripts/cargo.sh test -p reference-edge
```

The tests start `fake-pdp`, a small service and the edge in one process. They use real HTTP on the loopback address only. The names of the tests follow the paragraphs of the protocol, for example `p_9_8_...`, and of the MCP binding, for example `mcp_6_2_...`.
