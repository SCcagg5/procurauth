# Changelog

## Unreleased

- Protocol 5.2a. A service publishes only the actions that it serves: an action of a feature that the configuration turns off is not in the action document.
- The conformance case D75. A resource of depth 1 with no chain, or with an empty chain, gets `invalid_resource` (protocol 4.1, 11.1).
- Conformance runner. Each request of an MCP case has the headers `Mcp-Method` and, for `tools/call`, `Mcp-Name` (MCP server contract 2.5). The inline steps of 18 cases and the MCP operations send them. A service that refuses a request without them passes these cases.
- Conformance runner. The operation `use_ceiling` of a profile needs a request whose result does not go past `ceiling_value`. A PEP that applies the ceiling then passes the case U37. The case does not change.
- The conformance data has 192 cases: 99 for a PEP, 75 for a PDP and 18 for an edge.

## 1.0

First version.

- The protocol and the MCP binding.
- The JSON schemas.
- The conformance data: 191 cases for a PEP, a PDP and an edge.
- Seven programs: `keycheck`, `access-token`, `access-lint`, `fake-pdp`, `access-conformance`, `reference-service` and `reference-edge`.
- The Linux programs are static files (musl). They run on any Linux distribution of the same processor.
- The PEP library `procurauth-pep` in Rust.
