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
- The conformance data has 26 new cases: U100 to U110, D76 to D89 and E19, and U30 is rewritten. The directory file `approvals.json` holds the data of the series D. The condition `no_approval_support` skips each case of the approval profile for a target that gives no approval. The runner reads the new members of a case.
- The conformance data has 218 cases: 110 for a PEP, 89 for a PDP and 19 for an edge. A target that gives no approval skips 26 of them: U30, U100 to U110, D76 to D89 and E19.

- `procurauth-core` has the module `effect`: the canonical text and the effect of 17.3, the check of `op` and the check of a `view` (17.9). The vectors of `conformance/vectors/effect.json` pass with it. The reader of the data reads the member `confirm` of a grant and the list `approvals`. The reasons and the member `evaluation_id` of 17.1 are in the answer model.
- `fake-pdp` gives the approvals of section 17. A grant with `confirm` makes the PDP answer `approval_required`, `approval_pending`, `approval_denied` or `approval_expired`. The PDP consumes the approval and takes the units in one decision (17.2). It serves the three routes of 17.4, with leases, revivals and a long poll. It publishes the bounds in twelve metadata members. The admin routes `/__fake/approvals` and `/__fake/approval-refs` stand in for the owner and for the channel of the agent.
- Conformance runner. The profile key `pdp.approvals` and the key `edge.keys.confirm_access` make the condition `no_approval_support` depend on the target. The runner runs D76 to D89 against `fake-pdp` and E19 against `reference-edge`. The test key `key:ann-k3` and the directory `access.json` have a grant of `access` with `confirm`.

- `procurauth-pep` has the module `approval`. `Pep::decide_approval` follows the steps of 17.7: the question with the effect and no usage, the submission, and the question with usage after the approval. It gives the new value `Outcome::ApprovalRequired`, and the refusal `Refusal::Approval`. The PEP keeps no answer to a question with an effect, and it never reads an intent, an explanation or an `approval_ref`. `Pep::approval_stats` counts what the PEP received from the approval API. The MCP helpers give the result of 5.7, the tool errors of 5.7a and the tool `get_action_status`.
- `reference-service` has the tool `append_rows` with the action `data.append`, which has the member `approval`. It has the tool `get_action_status`. The tool `write_rows` and its request for input are gone. The results of a tool that ran have no `isError`.
- Conformance runner. The profile key `pep.approvals` and the member `approval` of the operation `mcp_call_approval` give the runner the `op` of each call. The runner computes the variables `effect`, `effect_2` and `effect_3`, and it runs the variants of the call. The test PDP serves the approval API and counts its requests for `pdp_approvals`. The reference service runs U30 and U100 to U110, and it passes them.
- MCP binding 3.1, 3.5a and 12. The text follows the contract of the MCP servers, section 9: the service asks the decision point, and a tool that only asks the owner needs no approval. The open point 7 says that the paragraphs 9.2, 9.6, 9.7 and 9.9 are Unused. The items 9 and 10 are new. `approval_rate_limited` has `retry_after` in seconds.

## 1.0

First version.

- The protocol and the MCP binding.
- The JSON schemas.
- The conformance data: 191 cases for a PEP, a PDP and an edge.
- Seven programs: `keycheck`, `access-token`, `access-lint`, `fake-pdp`, `access-conformance`, `reference-service` and `reference-edge`.
- The Linux programs are static files (musl). They run on any Linux distribution of the same processor.
- The PEP library `procurauth-pep` in Rust.
