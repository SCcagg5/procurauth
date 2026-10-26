# procurauth-schema-check

This crate loads the JSON Schemas of the directory `schemas/`. It validates documents against them. It reads files of the repository only, and it uses no network.

## Library

The library gives `Schemas::load`, `validate`, `validate_def` and `examples`. The core crate uses it in its tests.

## Tests

The tests of this crate check the data of the repository.

| Test file | Check |
| --- | --- |
| `tests/schemas.rs` | Each schema is valid. Each example of each schema is valid. |
| `tests/cases.rs` | Each conformance case is valid. The cited paragraphs exist. Each test name that starts with a paragraph names a real one. |
| `tests/ste.rs` | The sentences of the documents, of the schemas and of the code follow the rules of Simplified Technical English that a program can check. |

Run them in Docker.

```text
scripts/cargo.sh test -p procurauth-schema-check
```
