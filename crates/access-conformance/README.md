# access-conformance

`access-conformance` runs the conformance cases of ProcurAuth against a PEP, a PDP or an edge. It is a command-line tool. It prints one line for each case and a summary line.

The cases are data, in the directory `conformance/` of the repository. The program holds a copy of them. Each case cites the paragraph of the protocol that it tests.

The tool needs a profile. The profile tells the runner how to reach and wire the target: the operations, the keys, the listen addresses and the credentials. The schema of the profile is `schemas/conformance-profile.schema.json`.

## Build and test

Do not install Rust on the host. Use Docker, with the script of the repository.

```text
scripts/cargo.sh build --release -p access-conformance
scripts/cargo.sh test -p access-conformance
```

## Use

```text
access-conformance --role pep|pdp|edge --profile FILE [--url URL]
    [--cases ID,ID,...] [--series U|D|E] [--format text|json]
    [--cases-dir DIR] [--print-config]
```

The option `--url` is the target. A PEP and an edge need it. A PDP needs it, unless the profile starts `fake-pdp` in the process. The URL has the scheme `http` and no path. The tool has no TLS code.

```text
$ access-conformance --role pep --profile examples/pep.json --url http://127.0.0.1:8000
U01  pass  3.3,9.6  The PEP sends the subject with the type user and the claim sub as the id.
U02  pass  4.1      The PEP sends the chain of the resource in resource.properties.ancestors.
U04  fail  6.4,10.3,11.1  step "Use of an action that lists a budget": status: expected 429, found 403
U05  skip  5.6      the service has no options route
4 cases: 2 passed, 1 failed, 1 skipped
$ echo $?
1
```

Each line has the id, the result, the paragraphs and a text. The text is the title of a case that passed. It is the reason of a case that the runner skipped. It is the first failed check of a case that failed.

### Results and exit codes

| Result | Meaning |
| --- | --- |
| `pass` | Each step of the case passed. |
| `fail` | A check of a case of a MUST rule failed. |
| `warn` | A check of a case of a SHOULD rule failed. |
| `skip` | The case does not apply to the target. The line gives the reason. |

| Exit code | Meaning |
| --- | --- |
| 0 | Each case that ran passed. A skip and a warning do not change the code. |
| 1 | At least one case failed. |
| 2 | Usage error, bad profile or bad data, or a target that is not reachable. |

The summary line is `N cases: P passed, F failed, S skipped`. It adds `, W warned` only when a case of a SHOULD rule failed.

The option `--format json` writes one JSON document, with the members in the order of their names. The schema is `schemas/conformance-report.schema.json`. A skipped case has a `reason`. A failed case has a list of `failures`, each with the step and the message.

The tool writes the results to the standard output. It writes the diagnostics to the standard error. It uses no colour.

## The three roles

### A PEP: series U

The service under test is at `--url`. The runner acts as the client, as the edge and as the PDP.

- As the edge, it signs the identity tokens with a private key. The service must trust the public key.
- As the PDP, it listens on `pep.pdp.listen`. The service must call this address. The answers follow the script of the case.
- As the client, it sends the requests of the operations. The profile defines each operation.

The runner counts the questions that the service sends to the PDP, and the connections that carry them. A connection that stays open between questions counts one time. The check `pdp_connections` of a case reads this count.

Some cases keep state in the service, for example a kept answer. Give `pep.reset` to clear the state before each case.

### A PDP: series D

The runner sends the questions of the series D to the PDP at `--url`, and it compares the answers.

Each case names a directory of `conformance/directories/`. The PDP under test must hold the same data. The runner proves it before the first case. It asks control questions, and it computes the expected answers from the same directory with the decision code of `fake-pdp`. The control questions have no `context.usage`, so they change no counter.

When the PDP does not hold a directory, the runner stops with the exit code 2 and lists the directories. The key `pdp.directory_check.mode` can switch the check off.

For a test of the runner itself, set `pdp.spawn_fake_pdp` and give no `--url`. The runner then starts `fake-pdp` in the process, with the data of each case. Each case passes.

The cases that use a budget need a clock and counters that the runner controls. The profile gives the way:

- `pdp.load` is a request that loads the data of a case. The body is a document of the schema `fake-pdp-data`, with the directory, the clock and the counters of the case.
- `pdp.reset_url` puts the counters back to their first values before each case.
- `pdp.clock_admin_url` sets the clock. The body is `{"set": T}`.

When the profile gives none of them, the runner skips these cases and prints the reason.

### An edge: series E

The edge under test is at `--url`. The runner acts as the client, as the service behind the edge and as the PDP.

- As the client, it sends the text of a key in the header `Authorization`.
- As the service, it listens on `edge.upstream.listen`. The edge must send its accepted requests there. The runner checks the headers and the identity token that arrive.
- As the PDP, it starts `fake-pdp` on `edge.pdp.listen` with the directory of `edge.pdp`. The edge asks it for the action `access`.

The profile gives three key texts, each in a file. The edge must know the first, and its subject must have `access` in the directory. The edge must know the second, and its subject must have no `access`. The edge must not know the third. The example `examples/edge.json` uses the directory `access.json`.

The runner checks the identity token with the public keys of `edge.trust`.

## The profile

The profile is one JSON file. It has one section for each role: `pep`, `pdp` and `edge`. The run needs only the section of its role. The examples are `examples/pep.json`, `examples/edge.json`, `examples/pdp-fake.json` and `examples/pdp-external.json`.

A path in the profile starts at the directory of the profile. A secret comes only from a file. The file holds the text without the last line end. The tool never prints it.

### Operations

The cases use abstract operations. The profile of a PEP maps each one to a request: a method, a path, headers and a body. These members can hold variables, for example `{{resource_id}}`. The operation also gives the values of the variables `action`, `resource_type`, `resource_id`, `ancestors`, `tool`, `ceiling` and `ceiling_value`.

| Operation | Needs |
| --- | --- |
| `use_plain` | `method`, `path`, `action`, `resource_type`, `resource_id`, `ancestors`. |
| `use_budget`, `use_multi` | The same as `use_plain`. |
| `use_ceiling` | The same as `use_plain`, with `ceiling` and `ceiling_value`. |
| `use_service` | `method`, `path`, `action`. The node is the service. |
| `read_actions`, `list_options` | Nothing. The runner uses the default routes of the protocol. `list_options` needs `options_type`. |
| `mcp_call_plain`, `mcp_call_budget`, `mcp_call_input`, `mcp_call_multi`, `mcp_call_approval` | `tool` and `action`. The runner makes the JSON-RPC `tools/call` with the `arguments` of the operation. |
| `mcp_approve`, `mcp_refuse` | A `body`. Use `capture` to read a value of the answer to the step before. |

An operation that the profile does not define makes the runner skip the steps that use it. The conditions to skip a case come from the profile:

| Condition | True when |
| --- | --- |
| `no_budget_action` | The profile has no `use_budget`. |
| `no_ceiling_action` | The profile has no `use_ceiling`. |
| `no_options_route` | The profile has no `options_type`. |
| `no_answer_cache` | `pep.answer_cache` is false. |
| `no_mcp_endpoint` | The profile has no `mcp` or no `mcp_path`. |
| `no_budget_session` | `pep.mcp.session_budget` is false. |
| `no_input_tool`, `no_approval_tool` | The profile has no `mcp_call_input`, or no `mcp_call_approval`. |
| `no_multi_action` | The profile has no `use_multi` and no `mcp_call_multi`. |
| `no_token_cache` | `edge.token_cache` is false. |
| `single_key_set` | The key set of `edge.trust` holds one key. |

A token of a case can use a key of the algorithm `ES256`. When the profile has no such key, the runner skips the case and gives the reason.

## Configuration

The profile and the command line are the only sources. The program reads no environment variable. The schema is closed. An unknown member, an unknown option or a duplicate member stops the program with an error. The error names the key, the expected type or range, and the value. The program stops before it sends a request.

The program never changes a value to make it fit. It reads the profile one time into a typed structure. Two keys that contradict each other stop the program. The keys `pdp.spawn_fake_pdp` and `--url` are such a pair.

The option `--print-config` checks the profile and the files, prints each key with its value and its source, and exits. The program also writes these lines to the standard error at start. A secret never shows. The line gives the path of the file only.

### Table of keys

| Key | Source | Value | Default | Meaning |
| --- | --- | --- | --- | --- |
| `--role` | flag | `pep`, `pdp` or `edge` | none, mandatory | The implementation under test. |
| `--profile` | flag | path | none, mandatory | The profile of the target. |
| `--url` | flag | http URL with no path | none, see the role | The target. A PEP and an edge need it. A PDP needs it unless the profile starts fake-pdp. |
| `--cases` | flag | ids with commas | none, all the cases of the role | Run only these cases. |
| `--series` | flag | `U`, `D` or `E` | none, the series of the role | Run only this series. It must fit the role. |
| `--format` | flag | `text` or `json` | text | The form of the result. |
| `--cases-dir` | flag | path | none, the copy in the program | Read the cases from a directory with the layout of `conformance/`. |
| `--print-config` | flag | no value | off | Check the profile and the files, print the values that apply, and exit with 0. |
| `timeouts.request_seconds` | profile | whole number from 1 to 600 | 10 | The time for one request to the target. |
| `timeouts.case_seconds` | profile | whole number from 1 to 3600 | 60 | The time for one case. A case that takes longer fails. |
| `timeouts.settle_ms` | profile | whole number from 0 to 10000 | 25 | The wait before the runner counts the questions of the PDP and the requests of the upstream. |
| `pep.service` | profile | id of 1 to 256 bytes | none, mandatory | The id of the service. It is the variable `service` and the claim `aud`. |
| `pep.token.header` | profile | header name | none, mandatory | The header of the identity token. It is the variable `token_header`. |
| `pep.token.iss` | profile | text | none, mandatory | The issuer that the service expects. |
| `pep.token.max_age_seconds` | profile | whole number from 1 to 31536000 | none, mandatory | The longest life of a token that the service accepts. |
| `pep.token.skew_seconds` | profile | whole number from 0 to 86400 | none, mandatory | The clock skew of the service. |
| `pep.token.keys[].alg` | profile | `Ed25519` or `ES256` | none, mandatory | The algorithm of the key. Each algorithm occurs one time. |
| `pep.token.keys[].kid` | profile | text | none | The header `kid` of the tokens that the key signs. |
| `pep.token.keys[].file` | profile | path | none, mandatory | A file with the private key, in PKCS#8 PEM form. The key is a secret. |
| `pep.pdp.listen` | profile | ADDRESS:PORT | none, mandatory | The address of the test PDP. The service calls it. |
| `pep.pdp.credential_file` | profile | path | none, no credential | A file with the credential that the service sends to the PDP. The credential is a secret. |
| `pep.answer_cache` | profile | boolean | false | True when the PEP keeps answers. A false value skips the cases that need a cache. |
| `pep.reset.method` | profile | HTTP method | none, mandatory | The method of the request that clears the state of the service before each case. |
| `pep.reset.path` | profile | path | none, mandatory | The path of that request. |
| `pep.reset.headers.<name>` | profile | text | none | A header of that request. |
| `pep.options_type` | profile | text | none, no options route | The type of the nodes at the first level of the options route. |
| `pep.mcp.path` | profile | path | none, mandatory | The path of the MCP endpoint. It is the variable `mcp_path`. |
| `pep.mcp.session_budget` | profile | boolean | false | True when the action `mcp.session` lists a budget. |
| `pep.operations.<operation>.method` | profile | HTTP method | see the operation | The method of the operation. |
| `pep.operations.<operation>.path` | profile | path template | see the operation | The path of the operation. It can hold variables. |
| `pep.operations.<operation>.headers.<name>` | profile | text | none | A header of the operation. |
| `pep.operations.<operation>.body` | profile | JSON | none | The body template, as JSON. |
| `pep.operations.<operation>.body_text` | profile | text | none | The body template, as text. Do not give it with `body`. |
| `pep.operations.<operation>.action` | profile | text | see the operation | The variable `action`. |
| `pep.operations.<operation>.resource_type` | profile | text | see the operation | The variable `resource_type`. |
| `pep.operations.<operation>.resource_id` | profile | text | see the operation | The variable `resource_id`. |
| `pep.operations.<operation>.ancestors` | profile | array of objects with `type` and `id` | see the operation | The variable `ancestors`. |
| `pep.operations.<operation>.tool` | profile | text | see the operation | The variable `tool`. |
| `pep.operations.<operation>.ceiling` | profile | text | see the operation | The variable `ceiling`. |
| `pep.operations.<operation>.ceiling_value` | profile | whole number | see the operation | The variable `ceiling_value`. |
| `pep.operations.<operation>.arguments` | profile | JSON | none, an empty object | The arguments of the tool of an MCP call. |
| `pep.operations.<operation>.capture.<name>` | profile | JSON Pointer | none | A name for a member of the JSON answer to the step before. The templates of the operation read it as a variable. |
| `pdp.spawn_fake_pdp` | profile | boolean | false | True to start fake-pdp in the process, with the directory of each case. Do not give it with `--url`. |
| `pdp.credential_file` | profile | path | none, no credential | A file with the credential that the PDP asks for. The credential is a secret. |
| `pdp.directory_check.mode` | profile | `control_questions` or `none` | control_questions | How the runner proves that the PDP holds the directory of a case. |
| `pdp.directory_check.max_questions` | profile | whole number from 1 to 10000 | 100 | The most control questions for one directory. |
| `pdp.load.url` | profile | http URL | none, mandatory | The URL that loads the data of a case in the PDP under test. |
| `pdp.load.method` | profile | `PUT` or `POST` | PUT | The method of the load request. |
| `pdp.reset_url` | profile | http URL | none, the counters cannot reset | A URL that the runner posts to before each case, to put the counters back to their first values. |
| `pdp.clock_admin_url` | profile | http URL | none, the clock cannot move | A URL that the runner posts to, with the body `{"set": T}`, to set the clock of the PDP. |
| `edge.service` | profile | id of 1 to 256 bytes | none, mandatory | The id of the service behind the edge. It is the variable `service`. |
| `edge.token_header` | profile | header name | none, mandatory | The header of the identity token. It is the variable `token_header`. |
| `edge.trust.iss` | profile | text | none, mandatory | The issuer that the edge writes in the tokens. |
| `edge.trust.max_age_seconds` | profile | whole number from 1 to 31536000 | none, mandatory | The longest life of a token. |
| `edge.trust.skew_seconds` | profile | whole number from 0 to 86400 | none, mandatory | The clock skew. |
| `edge.trust.jwks_file` | profile | path | none | A JWK Set with the public keys of the edge. Give this key or `pem_keys`. |
| `edge.trust.pem_keys[].file` | profile | path | none, mandatory | A public key in PEM form. |
| `edge.trust.pem_keys[].kid` | profile | text | none | The `kid` of that key. |
| `edge.keys.valid.text_file` | profile | path | none, mandatory | A file with the text of a key that the edge accepts. The text is a secret. |
| `edge.keys.valid.subject` | profile | text | none, mandatory | The subject id of that key. |
| `edge.keys.valid.owner` | profile | text | none, mandatory | The owner of that key. |
| `edge.keys.no_access.text_file` | profile | path | none, mandatory | A file with the text of a key that the edge knows and whose subject has no `access`. The text is a secret. |
| `edge.keys.unknown.text_file` | profile | path | none, mandatory | A file with the text of a key that the edge does not know. The text is a secret. |
| `edge.upstream.listen` | profile | ADDRESS:PORT | none, mandatory | The address of the service behind the edge. The edge sends its requests there. |
| `edge.pdp.listen` | profile | ADDRESS:PORT | none, mandatory | The address of the PDP that the edge calls. |
| `edge.pdp.directory` | profile | name of a directory file | none, give this key or `directory_file` | The data of the PDP, from the directory files of the cases. |
| `edge.pdp.directory_file` | profile | path | none, give this key or `directory` | The data of the PDP, from a file. |
| `edge.pdp.credential_file` | profile | path | none, no credential | A file with the credential that the edge sends to the PDP. The credential is a secret. |
| `edge.mcp_path` | profile | path | none, no MCP endpoint | The path of the MCP endpoint. It is the variable `mcp_path`. |
| `edge.token_cache` | profile | boolean | false | True when the edge keeps identity tokens. |

A test checks that this table is the table of the code. The function `access_conformance::reference_table()` makes it.

## Limits

- The tool speaks plain HTTP. It has no TLS code. Use it on a network that you trust, or with a proxy that ends TLS.
- The runner binds the listen addresses of the profile. A port that is in use stops the program.
- The runner uses the system clock to make tokens. The clock of the service must agree with it, within the skew of the profile.

## Tests

The tests start the runner in the process. The role pdp runs the 74 cases of the series D against `fake-pdp`: all pass. A copy of a case with a changed expectation fails.

The roles pep and edge run against scripted mock servers in `tests/common/`. A mock that behaves like a correct implementation passes. A mock with one defect fails the cases of that defect, and only those. The tests also check the goldens of the output, the schemas and the rules of the source.
