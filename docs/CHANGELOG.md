# Changelog

## Unreleased

- The conformance case D75. A resource of depth 1 with no chain, or with an empty chain, gets `invalid_resource` (protocol 4.1, 11.1).
- The conformance data has 192 cases: 99 for a PEP, 75 for a PDP and 18 for an edge.

## 1.0

First version.

- The protocol and the MCP binding.
- The JSON schemas.
- The conformance data: 191 cases for a PEP, a PDP and an edge.
- Seven programs: `keycheck`, `access-token`, `access-lint`, `fake-pdp`, `access-conformance`, `reference-service` and `reference-edge`.
- The Linux programs are static files (musl). They run on any Linux distribution of the same processor.
- The PEP library `procurauth-pep` in Rust.
