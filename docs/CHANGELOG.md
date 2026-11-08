# Changelog

## Unreleased

- Protocol 17.3. The effect of an operation is `sha256:` and the SHA-256 of the JCS text (RFC 8785) of `{"v":1,"service","action","resource","op"}`. The numbers of `op` are integers from -(2^53-1) to 2^53-1, and any other number makes `op` invalid (`invalid_op`). The `view` of an approval holds JSON Pointers (RFC 6901) to `op`. Section 17 is new. The header of the protocol stays at version 1.0 until the release.
- The test vectors `conformance/vectors/effect.json` (groups V01 and V02, 24 vectors) and the schema `effect-vectors`. The test `effect_vectors` and a one-off program in Python computed each vector again with separate code. `COVERAGE.md` lists the groups.
- Protocol 5.2a. A service publishes only the actions that it serves: an action of a feature that the configuration turns off is not in the action document.
- The conformance case D75. A resource of depth 1 with no chain, or with an empty chain, gets `invalid_resource` (protocol 4.1, 11.1).
- Conformance runner. Each request of an MCP case has the headers `Mcp-Method` and, for `tools/call`, `Mcp-Name` (MCP server contract 2.5). The inline steps of 18 cases and the MCP operations send them. A service that refuses a request without them passes these cases.
- Conformance runner. The operation `use_ceiling` of a profile needs a request whose result does not go past `ceiling_value`. A PEP that applies the ceiling then passes the case U37. The case does not change.
- Protocol 17.1 to 17.12 and 5.2b, the approval of an effect. An action with the member `approval` can need the approval of the owner when a grant has `confirm`. A question has `context.approval.effect`, and a `false` answer has one of four new reasons: `approval_required`, `approval_pending`, `approval_denied` and `approval_expired`.
- The PEP learns only a verdict, through a narrow API of three routes. Section 17 is optional. The paragraphs 1.3, 10.1, 10.3, 11.1, 12, 14 and 15 change to fit it.
- MCP binding 3.5a is new. The new paragraphs 5.7, 5.7a and 5.7b give the result for a request that waits, the tool errors of an approval and the tool `get_action_status`. The case U30 is rewritten. Section 12 has two more open points.
- The schemas `approval-submission`, `approval-verdict` and `approval-view` are new. The schemas `action-document`, `evaluation-context`, `fake-pdp-data` and `conformance-case` have the new members. The reader of the core reads the member `approval` of an action.
- The conformance data has 26 new cases: U100 to U110, D76 to D89 and E19, and U30 is rewritten. The directory file `approvals.json` holds the data of the series D. The condition `no_approval_support` skips each case of the approval profile, because no reference program gives approvals yet. The runner reads the new members of a case.
- The conformance data has 218 cases: 110 for a PEP, 89 for a PDP and 19 for an edge. The runner skips 26 of them: U30, U100 to U110, D76 to D89 and E19.

## 1.0

First version.

- The protocol and the MCP binding.
- The JSON schemas.
- The conformance data: 191 cases for a PEP, a PDP and an edge.
- Seven programs: `keycheck`, `access-token`, `access-lint`, `fake-pdp`, `access-conformance`, `reference-service` and `reference-edge`.
- The Linux programs are static files (musl). They run on any Linux distribution of the same processor.
- The PEP library `procurauth-pep` in Rust.
