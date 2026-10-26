# procurauth-core

This crate is the shared core of the ProcurAuth tools. It is a library. It has no command line, no network code and no clock.

It reads the documents of the protocol and checks them. It implements the pure rules that a test PDP and a conformance runner need.

## Content

- A strict JSON reader that rejects a duplicate member.
- The action document, the options answer and the data of the test PDP.
- Limit values, windows, grants, coverage and the decision for a key.
- The AuthZEN messages with the chain and the members of the context.
- The identity token: claims, JWS signatures with `Ed25519` and `ES256`, and the checks of paragraph 9.4.
- The text format of a key, as data.

Each reader returns every problem with its JSON path and the number of the rule. The module list is at the start of `src/lib.rs`. The developer guide is `devdocs/architecture.md`.

## Rules

- The crate reads no environment variable.
- A function that needs the time takes it as an argument.
- The code has no `unsafe` block.
- A test for each paragraph has a name that starts with the paragraph, for example `p_5_3_unknown_member_is_bad`.

## Test

Run the tests in Docker.

```text
scripts/cargo.sh test -p procurauth-core
```
