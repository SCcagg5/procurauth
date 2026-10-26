# Architecture

This document is for the developers of the ProcurAuth tools. It describes the crates, the rules of the code, and the way to add a tool. The published texts are in `docs/`, `protocol/` and `bindings/`. Do not change them here.

## Crates

| Crate | Path | Role |
| --- | --- | --- |
| `procurauth-core` | `crates/procurauth-core` | The shared library. Each tool uses it. |
| `procurauth-schema-check` | `conformance/schema-check` | Loads the JSON Schemas and checks the data files. |

Each tool is a crate in `crates/`. It depends on `procurauth-core`. The tools are `access-lint`, `fake-pdp`, `access-token`, `keycheck` and `access-conformance`. The PEP library `procurauth-pep` is a sixth crate. Two reference programs use it: `reference-service` (the test subject of the series U) and `reference-edge` (the test subject of the series E).

Other directories:

| Path | Content |
| --- | --- |
| `schemas/` | The JSON Schemas, one file for each document. |
| `conformance/` | The conformance cases and the test directories. See its README. |
| `scripts/` | `cargo.sh`, `conformance.sh` and `ci.sh`. They run in Docker. |
| `notes/` | The decisions, the questions about the protocol, and the differences from the site. |

## The core crate

The core has no command line, no network code, no clock and no environment access. A tool gives it the text, the keys and the time.

| Module | Content |
| --- | --- |
| `json` | A strict JSON reader. It rejects a duplicate member and gives the JSON path. |
| `finding`, `read` | `Finding`, `Report`, `JsonPath` and `Obj`, the reader of typed members. |
| `names`, `path` | The rules for names and ids, percent-encoding, `NodeRef` and `NodePath`. |
| `action_document` | The typed `ActionDocument` and the check of 5.2, 5.3, 5.3c, 6.1 and 7.1. |
| `options` | The answer of the options route (5.8). |
| `limits`, `grants` | Limit values, windows, `retry_after`, grants and the lowest value (8.1). |
| `subject` | The form of a subject id (3.1, 3.2, 3.7). |
| `coverage` | Coverage (4.3), the decision for a key (3.5) and `subtree` (4.4). |
| `authzen` | The AuthZEN messages, the chain (4.1), the context and the reasons (11.1). |
| `jws`, `identity` | Keys, signatures, claims and the checks of 9.4. |
| `key_format` | The text format of a key, as data, and the checker. |
| `directory` | The data of the test PDP. |

### Findings

A reader returns every problem as a `Finding`. A finding has a severity, a JSON path, the number of the rule, a stable code and a message. The code is for programs. The message is for people, and it names the member, the expected value and the value found.

A document is good when it has no error. A warning does not make a document bad. A warning shows a SHOULD or an input that a rule makes harmless.

### Rules for a new reader

1. Read the text with `json::parse_str`. A duplicate member is an error.
2. Read each member with `read::Obj`. Report all the problems, and then return.
3. Do not change a value to make it fit. A value that is wrong is an error.
4. Return a typed structure. The rest of the code reads only this structure.
5. Write one unit test for each paragraph. Name it after the paragraph, for example `p_5_3_unknown_member_is_bad`.

### Time and randomness

A function that needs the time takes it as an argument, in seconds or in milliseconds. A function never reads the system clock. The keys of the tests come from fixed seeds.

## Schemas and Rust types

A schema and its Rust reader must agree. The test `schema_agreement` in `crates/procurauth-core/tests` has a table of documents for each schema. Each row gives the verdict of the reader and the verdict of the schema. A row where they differ names a rule that a schema cannot state.

When you change a schema, change the Rust reader, and add rows to the table. When you change a reader, run the table.

The tests also check that each `examples` entry of each schema is valid. Each schema has a `title`, a `description` and at least one example.

## Tests and Docker

Do not install Rust on the host. Use Docker only. The script `scripts/cargo.sh` runs cargo in a container.

```text
scripts/cargo.sh test --workspace
scripts/cargo.sh fmt --all -- --check
scripts/cargo.sh clippy --workspace --all-targets -- -D warnings
scripts/ci.sh
```

The script builds the image `procurauth-dev:1` one time. The image is `rust:1-bookworm` with `rustfmt` and `clippy`. The script runs as the host user. The cargo registry and the target directory are in Docker volumes: `procurauth-cargo-registry` and one target volume for each checkout. The first run gives them to the host user. No root-owned file appears in the repository.

`scripts/ci.sh` runs the format check, clippy, the tests and the conformance runs. It stops at the first failure. `scripts/msrv.sh` checks that the workspace builds with the `rust-version` of the root `Cargo.toml`.

### Conformance runs

`scripts/conformance.sh [pep|pdp|edge|all]` runs the runner `access-conformance` against the reference programs. It builds them with `scripts/cargo.sh`. It then starts one container with no network, and it starts all the processes in it, on the loopback address. The container holds the repository read only, and it stops by itself after a time limit. No port opens on the host.

| Mode | Series | Target |
| --- | --- | --- |
| `pep` | U | `reference-service`, with and without a budget on the action `mcp.session`. |
| `pdp` | D | `fake-pdp`, in the process of the runner and as a separate process. |
| `edge` | E | `reference-edge`. |

The profiles are in the `examples/` directory of each target crate. The exit code is 0 when no case failed.

### Test files

| Test | Content |
| --- | --- |
| `src/**` unit tests | One test for each paragraph that the module implements. |
| `tests/schema_agreement.rs` | The table of the agreement between schemas and readers. |
| `tests/data_files.rs` | The strict reading of each data file. |
| `tests/reference_pdp.rs` | A small reference PDP that runs the cases of the series D. |
| `schema-check/tests/schemas.rs` | Each schema is valid, and each example is valid. |
| `schema-check/tests/cases.rs` | The checks of the conformance cases. |
| `schema-check/tests/ste.rs` | The check of the sentences of the documents and of the code. |

## How to add a tool

1. Make the crate `crates/<tool>` with `cargo new`. Add it to the `members` of the root `Cargo.toml`. Set `[lints] workspace = true`.
2. Depend on `procurauth-core` with a path. Add `clap` for the command line. Do not add other crates without a reason.
3. Read the arguments in `main`. Read the configuration of the tool with the rules below. Give the typed result to a function that does the work.
4. Put the work in a library module of the crate, so that tests can call it. `main` only reads the arguments, calls the function and sets the exit code.
5. Follow the common rules of the site: `--help`, `--version`, `--format text|json`, the exit codes 0, 1 and 2.
6. Write the tests in the crate. Add a test that runs the program on a file of `conformance/` or `schemas/`.
7. Write the README of the crate in Simplified Technical English. Update `notes/site-differences.md` when the tool differs from the site.

### Rules for the configuration of a tool

A tool reads its configuration with these rules.

1. The schema is closed. An unknown member, an unknown attribute or a duplicate member stops the program with an error.
2. The error names the key, the expected type or range, and the value. The program stops before it does any work.
3. The program does not change a value to make it fit.
4. The program reads the configuration one time into a typed structure.
5. The program reads no environment variable. The file is the only source.
6. A secret comes from a file or from an environment variable that the configuration names. The configuration never holds it in clear text.

The core already follows these rules for each document that it reads. Use `Obj::finish` with `Unknown::Error` for a configuration.

## What is not in phase 1

- The five tools and the PEP library.
- The query parameters of the options route (5.7). The core reads the answer only.
- The full list of conformance cases, and the runner.
- The profile of the service under test, for `access-conformance`.
